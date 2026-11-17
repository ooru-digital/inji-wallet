import XCTest
@testable import OpenID4VP

final class EncryptionProviderTests: XCTestCase {
    func testGetEncryptorSuccess() throws {
        let encryption = try EncryptionProvider.getEncrypter("A256GCM")

        XCTAssertTrue(encryption is AESGCMEncryption)

    }

    func testGetEncryptorFailureUnsupportedAlgorithm() throws {
        XCTAssertThrowsError(try EncryptionProvider.getEncrypter("UNSUPPORTED")) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Required Encryption algorithm is not supported",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
