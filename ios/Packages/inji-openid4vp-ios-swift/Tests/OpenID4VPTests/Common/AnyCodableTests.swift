import XCTest
@testable import OpenID4VP

final class AnyCodableTests: XCTestCase {
    
    func testIntEncoding() throws {
        let intValue = AnyCodable(42)
        let encoded = try JSONEncoder().encode(intValue)
        let decoded = try JSONDecoder().decode(AnyCodable.self, from: encoded)
        
        XCTAssertEqual(decoded.value as? Int, 42)
    }
    
    func testDoubleEncoding() throws {
        let doubleValue = AnyCodable(3.14)
        let encoded = try JSONEncoder().encode(doubleValue)
        let decoded = try JSONDecoder().decode(AnyCodable.self, from: encoded)
        
        XCTAssertEqual(decoded.value as? Double, 3.14)
    }
    
    func testStringEncoding() throws {
        let stringValue = AnyCodable("test string")
        let encoded = try JSONEncoder().encode(stringValue)
        let decoded = try JSONDecoder().decode(AnyCodable.self, from: encoded)
        
        XCTAssertEqual(decoded.value as? String, "test string")
    }
    
    func testBoolEncoding() throws {
        let boolValue = AnyCodable(true)
        let encoded = try JSONEncoder().encode(boolValue)
        let decoded = try JSONDecoder().decode(AnyCodable.self, from: encoded)
        
        XCTAssertEqual(decoded.value as? Bool, true)
    }

    
    func testDictionaryEncoding() throws {
        let dict: [String: Any] = ["key1": "value1", "key2": 42, "key3": true]
        let dictValue = AnyCodable(dict)
        let encoded = try JSONEncoder().encode(dictValue)
        let decoded = try JSONDecoder().decode(AnyCodable.self, from: encoded)
        let decodedDict = decoded.value as? [String: Any]
        
        XCTAssertNotNil(decodedDict)
        XCTAssertEqual(decodedDict?["key1"] as? String, "value1")
        XCTAssertEqual(decodedDict?["key2"] as? Int, 42)
        XCTAssertEqual(decodedDict?["key3"] as? Bool, true)
    }
    
    func testArrayEncoding() throws {
        let array: [Any] = ["string", 42, true, 3.14]
        let arrayValue = AnyCodable(array)
        let encoded = try JSONEncoder().encode(arrayValue)
        let decoded = try JSONDecoder().decode(AnyCodable.self, from: encoded)
        let decodedArray = decoded.value as? [Any]
        
        XCTAssertNotNil(decodedArray)
        XCTAssertEqual(decodedArray?.count, 4)
        XCTAssertEqual(decodedArray?[0] as? String, "string")
        XCTAssertEqual(decodedArray?[1] as? Int, 42)
        XCTAssertEqual(decodedArray?[2] as? Bool, true)
        XCTAssertEqual(decodedArray?[3] as? Double, 3.14)
    }
    
    func testNestedStructures() throws {
        let nested: [String: Any] = [
            "string": "value",
            "number": 42,
            "array": [1, 2, 3],
            "dict": ["nested": "value"]
        ]
        
        let nestedValue = AnyCodable(nested)
        let encoded = try JSONEncoder().encode(nestedValue)
        let decoded = try JSONDecoder().decode(AnyCodable.self, from: encoded)
        let decodedNested = decoded.value as? [String: Any]
        
        XCTAssertNotNil(decodedNested)
        XCTAssertEqual(decodedNested?["string"] as? String, "value")
        XCTAssertEqual(decodedNested?["number"] as? Int, 42)
        
        let nestedArray = decodedNested?["array"] as? [Any]
        XCTAssertEqual(nestedArray?.count, 3)
        
        let nestedDict = decodedNested?["dict"] as? [String: Any]
        XCTAssertEqual(nestedDict?["nested"] as? String, "value")
    }
    
    func testInvalidEncoding() {
        let invalidValue = AnyCodable(Date())
        
        XCTAssertThrowsError(try JSONEncoder().encode(invalidValue)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Json encoding failed for  due to this error: Error occured while encoding response",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testDecodeNil() throws {
        // Create JSON with null value
        let jsonData = """
        null
        """.data(using: .utf8)!
        
        let decoded = try JSONDecoder().decode(AnyCodable.self, from: jsonData)
        XCTAssertTrue(decoded.value is Optional<Any>)
    }
    
    func testUnsupportedTypeDecoding() {
        struct UnsupportedType: Decodable {
            init(from decoder: Decoder) throws {
                throw UnsupportedTypeDecoding(
                    message: "Unsupported type encountered while decoding response in AnyCodable",
                    className: AnyCodable.className
                )
            }
        }

        let data = """
        {
          "unsupported": "value"
        }
        """.data(using: .utf8)!

        XCTAssertThrowsError(try JSONDecoder().decode(UnsupportedType.self, from: data)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Unsupported type encountered while decoding response in AnyCodable",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
