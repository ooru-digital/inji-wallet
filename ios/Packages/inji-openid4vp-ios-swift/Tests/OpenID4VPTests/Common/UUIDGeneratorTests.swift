import Foundation
import XCTest
@testable import OpenID4VP

class UUIDGeneratorTests : XCTestCase {
    func testUUIDGeneration() {
        let uuid = UUIDGenerator.generateUUID()
        
        XCTAssertNotNil(uuid, "Generated UUID should not be nil")
    }
    
    func testUUIDGeneration_IsValidFormat() {
        let uuidRegex = "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        let uuid = UUIDGenerator.generateUUID()
        
        XCTAssertTrue(uuid.range(of: uuidRegex, options: .regularExpression) != nil, "UUID does not match expected urn:uuid format")
    }

    
    func testUUIDsGeneratedAreUnique() {
        let uuid1 = UUIDGenerator.generateUUID()
        let uuid2 = UUIDGenerator.generateUUID()
        
        XCTAssertNotEqual(uuid1, uuid2, "Generated UUIDs should be unique")
    }
}
