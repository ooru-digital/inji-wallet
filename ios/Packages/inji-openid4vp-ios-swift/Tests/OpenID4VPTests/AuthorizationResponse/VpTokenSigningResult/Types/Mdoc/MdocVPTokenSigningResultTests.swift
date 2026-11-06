import XCTest
@testable import OpenID4VP

final class MdocVPTokenSigningResultTests: XCTestCase {
    func testMdocVPTokenSigningResultSuccess() {
        let validDeviceAuth = DeviceAuthentication(
            signature: "validSignature",
            algorithm: "ES256"
        )
        
        let deviceAuthMap = ["org.iso.18013.5.1.mosip": validDeviceAuth]
        let validMetadata = MdocVPTokenSigningResult(docTypeToDeviceAuthentication: deviceAuthMap)
        
        XCTAssertNoThrow(try validMetadata.validate())
    }
    
    func testMdocVPTokenSigningResultWitInvalidDeviceAuthentication() {
        let invalidDeviceAuth = DeviceAuthentication(
            signature: "",
            algorithm: "ES256"
        )
        
        let invalidMetadata = MdocVPTokenSigningResult(
            docTypeToDeviceAuthentication: ["org.iso.18013.5.1.mosip": invalidDeviceAuth]
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            assertOpenID4VPException(error,
                 expectedMessage: "Invalid Input: DeviceAuthentication->signature value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testMdocVPTokenSigningResultWithEmptyInputPassed() {
        let invalidMetadata = MdocVPTokenSigningResult(
            docTypeToDeviceAuthentication: [:]
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            assertOpenID4VPException(error,
                 expectedMessage: "Invalid Input: MdocVPTokenSigningResult->docTypeToDeviceAuthentication value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
