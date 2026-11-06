import XCTest
@testable import OpenID4VP

class DecodrTests: XCTestCase {
    //Decode base64 string to JSON
    
    func testDecodeBase64ToJSONSuccessCase() throws {
        let json = "{\"key\":\"value\"}"
        let base64String = Data(json.utf8).base64EncodedString()
        
        do {
            let decodedJSON = try Base64Decoder.decodeBase64ToJSON(base64String)
            XCTAssertEqual(decodedJSON["key"] as? String, "value")
        } catch {
            XCTFail("Expected to decode successfully, but failed with error: \(error)")
        }
    }
    
    func testDecodeBase64ToJSONWithInvalidBase64() {
        let invalidBase64 = "%%InvalidBase64%%"
        
        XCTAssertThrowsError(try Base64Decoder.decodeBase64ToJSON(invalidBase64)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Base64 decoding failed",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testDecodeBase64ToJSONWithEmptyBase64() {
        let emptyBase64 = ""
        
        XCTAssertThrowsError(try Base64Decoder.decodeBase64ToJSON(emptyBase64)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Decoding to json failed",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testDecodeBase64ToJSONWithNonJSONData() {
        let nonJSONString = "This is not JSON"
        let base64String = Data(nonJSONString.utf8).base64EncodedString()
        
        XCTAssertThrowsError(try Base64Decoder.decodeBase64ToJSON(base64String)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Decoding to json failed",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testDecodeBase64ToJSONWithCorruptedJSON() {
        let corruptedJSON = "{\"key\":\"value" //Invalid JSON - Missing closing bracket
        let base64String = Data(corruptedJSON.utf8).base64EncodedString()
        
        XCTAssertThrowsError(try Base64Decoder.decodeBase64ToJSON(base64String)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Decoding to json failed",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testDecodeBase64ToJSONWithInvalidJSONShouldThrowDecodingFailedError() {
            let invalidJsonBase64 = Data("[1,2,3]".utf8).base64EncodedString()

            XCTAssertThrowsError(try Base64Decoder.decodeBase64ToJSON(invalidJsonBase64)) { error in
                assertOpenID4VPException(error,
                    expectedMessage: "Decoding to json failed",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
}
