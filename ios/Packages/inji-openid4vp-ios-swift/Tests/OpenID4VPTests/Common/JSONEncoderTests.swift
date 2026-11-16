import XCTest
@testable import OpenID4VP

final class JSONEncoderTests: XCTestCase {
    // Test struct to verify encoding behavior
    private struct TestPerson: Encodable {
        let name: String
        let age: Int
        let url: String
        let nestedObject: NestedObject
        let arrayOfStrings: [String]
        
        struct NestedObject: Encodable {
            let id: Int
            let value: String
        }
    }
    
    private struct MockInput: Encodable {
        let name: String
        
        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(name)
        }
    }
    
    func testEncodableTojsonData() throws {
        // Create test object with various data types including a URL with slashes
        let testObject = TestPerson(
            name: "John Doe",
            age: 30,
            url: "https://example.com/path/to/resource",
            nestedObject: TestPerson.NestedObject(id: 1, value: "test"),
            arrayOfStrings: ["one", "two", "three"]
        )
        
        // Convert to dictionary using the extension
        let result = try testObject.jsonData()
        
        // Verify the result is a dictionary
        guard let dictionary = result as? [String: Any] else {
            XCTFail("Result should be a dictionary")
            return
        }
        
        // Verify the expected values
        XCTAssertEqual(dictionary["name"] as? String, "John Doe")
        XCTAssertEqual(dictionary["age"] as? Int, 30)
        XCTAssertEqual(dictionary["url"] as? String, "https://example.com/path/to/resource")
        
        // Check nested object
        if let nestedDict = dictionary["nestedObject"] as? [String: Any] {
            XCTAssertEqual(nestedDict["id"] as? Int, 1)
            XCTAssertEqual(nestedDict["value"] as? String, "test")
        } else {
            XCTFail("Nested object not found or not a dictionary")
        }
        
        // Check array
        if let array = dictionary["arrayOfStrings"] as? [String] {
            XCTAssertEqual(array, ["one", "two", "three"])
        } else {
            XCTFail("Array not found or not an array of strings")
        }
    }
    
    func testEncodableToJsonDataForNonJsonInput() throws {
        let testObject = MockInput(name: "mock-value")
        
        let result = try testObject.jsonData()
        
        XCTAssertEqual("mock-value", result as? String)
    }
    
    func testEncodableWithSpecialChars() throws {
        struct SpecialCharsTest: Encodable {
            let path: String
            let query: String
        }
        
        let test = SpecialCharsTest(
            path: "/path/with/slashes",
            query: "param=value&other=123"
        )
        
        let result = try test.jsonData()
        
        guard let dict = result as? [String: String] else {
            XCTFail("Result should be a dictionary of strings")
            return
        }
        
        // Verify slashes are not escaped
        XCTAssertEqual(dict["path"], "/path/with/slashes")
        XCTAssertEqual(dict["query"], "param=value&other=123")
    }
    
    func testJSONEncoderOutputFormatting() {
        XCTAssertTrue(JSON.encoder.outputFormatting.contains(.withoutEscapingSlashes))
    }
    
    func testComplexNestedStructure() throws {
        struct Complex: Encodable {
            let metadata: Metadata
            let data: [DataItem]
            
            struct Metadata: Encodable {
                let version: String
                let timestamp: Date
            }
            
            struct DataItem: Encodable {
                let id: String
                let values: [String: Any]
                
                enum CodingKeys: String, CodingKey {
                    case id, values
                }
                
                func encode(to encoder: Encoder) throws {
                    var container = encoder.container(keyedBy: CodingKeys.self)
                    try container.encode(id, forKey: .id)
                    
                    // Manual encoding for the dictionary
                    let valuesData = try JSONSerialization.data(withJSONObject: values)
                    let valuesString = String(data: valuesData, encoding: .utf8)
                    try container.encode(valuesString, forKey: .values)
                }
            }
        }
        
        let date = Date()
        let complex = Complex(
            metadata: Complex.Metadata(version: "1.0", timestamp: date),
            data: [
                Complex.DataItem(id: "item1", values: ["key1": "value1", "key2": 42])
            ]
        )
        
        XCTAssertNoThrow(try complex.jsonData())
    }
}
