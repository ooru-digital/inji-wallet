import XCTest
@testable import OpenID4VP

final class MdocVPTokenTests: XCTestCase {
    
    func testEncodingProducesRawStringValue() throws {
        let token = MdocVPToken(base64EncodedDeviceResponse: "sample-mdoc-token-123")
        
        let encoder = JSONEncoder()
        let encodedData = try encoder.encode(token)
        let encodedString = String(data: encodedData, encoding: .utf8)
        
        XCTAssertEqual(encodedString, "\"sample-mdoc-token-123\"")
        XCTAssertNotEqual(encodedString, "{\"base64EncodedDeviceResponse\":\"sample-mdoc-token-123\"}")
    }
}
