import XCTest
@testable import OpenID4VP

final class LdpVPTokenSigningResultTests: XCTestCase {
    
    func testValidateSuccess() throws {
        let validMetadata = ldpVPTokenSigningResult
        
        XCTAssertNoThrow(try validMetadata.validate())
    }
    
    func testValidateFailureEmptyString() {
        let invalidMetadata = LdpVPTokenSigningResult(
            jws: "", proofValue: "valid-proof",
            signatureAlgorithm: ldpVPTokenSigningResult.signatureAlgorithm
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid Input: LdpVPTokenSigningResult->jws value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testValidateFailureNullValue() {
        let invalidMetadata = LdpVPTokenSigningResult(
            jws: nil, proofValue: "test",
            signatureAlgorithm: ldpVPTokenSigningResult.signatureAlgorithm
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid Input: LdpVPTokenSigningResult->jws value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}

