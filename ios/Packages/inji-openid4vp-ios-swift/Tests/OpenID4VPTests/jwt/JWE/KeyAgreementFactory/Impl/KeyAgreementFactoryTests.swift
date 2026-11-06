import XCTest
import JSONWebKey
@testable import OpenID4VP

final class KeyAgreementFactoryTests: XCTestCase {

    func testCreateKeyAgreementSuccess() throws {
        let json = """
        {
          "kty": "OKP",
          "use": "enc",
          "crv": "X25519",
          "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
          "alg": "ECDH-ES",
          "kid": "x25519-key1"
        }
        """.data(using: .utf8)!

        let mockJWK = try JSONDecoder().decode(JWK.self, from: json)
        let keyAgreement = try KeyAgreementFactory.createKeyAgreement(for: mockJWK)

        XCTAssertNotNil(keyAgreement)
        XCTAssertTrue(keyAgreement is X25519KeyAgreement)
    }

    func test_createKeyAgreement_unsupportedCurve() throws {
        let json = """
        {
          "kty": "OKP",
          "use": "enc",
          "crv": "Ed25519",
          "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
          "alg": "ECDH-ES",
          "kid": "ed-key1"
        }
        """.data(using: .utf8)!

        let invalidMockJWK = try JSONDecoder().decode(JWK.self, from: json)

        XCTAssertThrowsError(try KeyAgreementFactory.createKeyAgreement(for: invalidMockJWK)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Required Key Agreement algorithm is not supported.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
