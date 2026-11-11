import XCTest
import CryptoKit
import JSONWebKey
@testable import OpenID4VP

public class JWEHandlerTests: XCTestCase {
    let (jweKeyEncryptionAlgorithm, jweContentEncryptionAlgorithm, verifierPublicKey) = (mockClientMetadataObject.authorizationEncryptedResponseAlg!, mockClientMetadataObject.authorizationEncryptedResponseEnc!, mockClientMetadataObject.jwks!.keys[0])



    func testCreateResponseSuccess() throws {
        let jweHandler = JWEHandler(contentEncryptionAlgorithm: jweContentEncryptionAlgorithm, keyEncryptionAlgorithm: jweKeyEncryptionAlgorithm, publicKey: verifierPublicKey, producerInfo: "mock-nonce", recipientInfo: "verifier-nonce")
        let bodyParams: [String: Any] = ["key": "value"]

        let response = try jweHandler.generateEncryptedResponse(payload: bodyParams)

        XCTAssertNotNil(response)
        let parts = response.split(separator: ".", omittingEmptySubsequences: false)
        XCTAssertEqual(parts.count, 5, "JWE should have exactly 5 parts")
    }

    // Decrypts the way a spec-compliant verifier does: Concat KDF over epk, apu and apv,
    // with the protected header as AES-GCM AAD.
    func testResponseDecryptsPerRFC7516() throws {
        let verifierKey = Curve25519.KeyAgreement.PrivateKey()
        let jwkJson = """
        {"kty":"OKP","use":"enc","crv":"X25519","alg":"ECDH-ES","kid":"k1",
         "x":"\(verifierKey.publicKey.rawRepresentation.toBase64UrlEncoded())"}
        """
        let verifierJwk = try JSONDecoder().decode(JWK.self, from: Data(jwkJson.utf8))
        let walletNonce = NonceProvider().generateNonce()
        let jweHandler = JWEHandler(contentEncryptionAlgorithm: "A256GCM", keyEncryptionAlgorithm: "ECDH-ES", publicKey: verifierJwk, producerInfo: walletNonce, recipientInfo: "asnkkzKibcqwy0lOWF3p9g==")

        let jwe = try jweHandler.generateEncryptedResponse(payload: ["state": "s-123"])

        let parts = jwe.components(separatedBy: ".")
        let header = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(Data(base64UrlEncoded: parts[0]))) as? [String: Any])
        XCTAssertEqual(header["apu"] as? String, walletNonce)
        let epk = try XCTUnwrap(header["epk"] as? [String: Any])
        let ephemeralPublic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: XCTUnwrap(Data(base64UrlEncoded: XCTUnwrap(epk["x"] as? String))))
        let z = try verifierKey.sharedSecretFromKeyAgreement(with: ephemeralPublic).withUnsafeBytes { Data($0) }
        let cek = try X25519KeyAgreement.concatKDF(z: z, enc: "A256GCM", apu: walletNonce, apv: "asnkkzKibcqwy0lOWF3p9g==")
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: XCTUnwrap(Data(base64UrlEncoded: parts[2]))),
            ciphertext: XCTUnwrap(Data(base64UrlEncoded: parts[3])),
            tag: XCTUnwrap(Data(base64UrlEncoded: parts[4]))
        )

        let plaintext = try AES.GCM.open(box, using: SymmetricKey(data: cek), authenticating: Data(parts[0].utf8))

        let claims = try XCTUnwrap(JSONSerialization.jsonObject(with: plaintext) as? [String: Any])
        XCTAssertEqual(claims["state"] as? String, "s-123")
        XCTAssertThrowsError(try AES.GCM.open(box, using: SymmetricKey(data: cek)), "Opening without the header as AAD must fail")
    }

    // Only X25519 (OKP) verifier keys are supported; an EC P-256 key fails with a clear error.
    func testCreateResponseThrowsForP256VerifierKey() throws {
        let p256Key = P256.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        let jwkJson = """
        {"kty":"EC","use":"enc","crv":"P-256","alg":"ECDH-ES","kid":"p256-key",
         "x":"\(p256Key.prefix(32).toBase64UrlEncoded())","y":"\(p256Key.suffix(32).toBase64UrlEncoded())"}
        """
        let p256Jwk = try JSONDecoder().decode(JWK.self, from: Data(jwkJson.utf8))
        let jweHandler = JWEHandler(contentEncryptionAlgorithm: "A256GCM", keyEncryptionAlgorithm: "ECDH-ES", publicKey: p256Jwk, producerInfo: "mock-nonce", recipientInfo: "verifier-nonce")

        XCTAssertThrowsError(try jweHandler.generateEncryptedResponse(payload: ["state": "s-123"])) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Required Key Agreement algorithm is not supported.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testCreateResponseThrowsForUnsupportedEnc() {
        let jweHandler = JWEHandler(contentEncryptionAlgorithm: "A256CBC-HS512", keyEncryptionAlgorithm: jweKeyEncryptionAlgorithm, publicKey: verifierPublicKey, producerInfo: "mock-nonce", recipientInfo: "verifier-nonce")

        XCTAssertThrowsError(try jweHandler.generateEncryptedResponse(payload: ["key": "value"])) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Required Encryption algorithm is not supported",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}


