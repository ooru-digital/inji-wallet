import XCTest
@testable import OpenID4VP
import JSONWebKey

final class JWEHandlerTests: XCTestCase {

    let jweKeyEncryptionAlgorithm = "ECDH-ES"
    let jweContentEncryptionAlgorithm = "A256GCM"
    let producerInfo = "bW9jaw"          // base64url("mock")
    let recipientInfo = "dmVyaWZpZXI"   // base64url("verifier")

    let verificationPublicKey = createInstance([
        "kty": "OKP",
        "crv": "X25519",
        "use": "enc",
        "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
        "alg": "ECDH-ES",
        "kid": "ed-key1"
    ], as: JWK.self)

    private func makeHandler() -> JWEHandler {
        JWEHandler(
            contentEncryptionAlgorithm: jweContentEncryptionAlgorithm,
            keyEncryptionAlgorithm: jweKeyEncryptionAlgorithm,
            publicKey: verificationPublicKey,
            producerInfo: producerInfo,
            recipientInfo: recipientInfo
        )
    }

    private func decodeHeader(_ jwe: String) throws -> [String: Any] {
        let encodedHeader = try XCTUnwrap(jwe.split(separator: ".").first.map(String.init))
        let padded = encodedHeader.base64URLToBase64()
        let data = try XCTUnwrap(Data(base64Encoded: padded))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    // MARK: - JWE structure

    func testCreateResponseSuccess() throws {
        let response = try makeHandler().encrypt(toData(["key": "value"]))

        let parts = response.split(separator: ".", omittingEmptySubsequences: false)
        XCTAssertEqual(parts.count, 5)
    }

    func testJWEHeaderContainsCorrectAlgAndEnc() throws {
        let response = try makeHandler().encrypt(toData(["key": "value"]))

        let header = try decodeHeader(response)
        XCTAssertEqual(header["alg"] as? String, jweKeyEncryptionAlgorithm)
        XCTAssertEqual(header["enc"] as? String, jweContentEncryptionAlgorithm)
    }

    func testJWEHeaderContainsKid() throws {
        let response = try makeHandler().encrypt(toData(["key": "value"]))

        let header = try decodeHeader(response)
        // DefaultJWEHeaderImpl for ECDH-ES does not emit a kid field in the protected header
        XCTAssertNotNil(header["kid"], "ECDH-ES protected header must contain a kid field")
    }

    func testJWEHeaderContainsApuMatchingProducerInfo() throws {
        let response = try makeHandler().encrypt(toData(["key": "value"]))

        let header = try decodeHeader(response)
        XCTAssertEqual(header["apu"] as? String, producerInfo)
    }

    func testJWEHeaderContainsApvMatchingRecipientInfo() throws {
        let response = try makeHandler().encrypt(toData(["key": "value"]))

        let header = try decodeHeader(response)
        XCTAssertEqual(header["apv"] as? String, recipientInfo)
    }

    func testJWEHeaderContainsEpkWithExpectedFields() throws {
        let response = try makeHandler().encrypt(toData(["key": "value"]))

        let header = try decodeHeader(response)
        let epk = try XCTUnwrap(header["epk"] as? [String: Any])
        XCTAssertEqual(epk["kty"] as? String, "OKP")
        XCTAssertEqual(epk["crv"] as? String, "X25519")
        XCTAssertNotNil(epk["x"])
    }

    func testJWEEncryptedKeyPartIsEmpty() throws {
        let response = try makeHandler().encrypt(toData(["key": "value"]))

        let parts = response.split(separator: ".", omittingEmptySubsequences: false)
        XCTAssertEqual(String(parts[1]), "", "ECDH-ES uses direct key agreement — encrypted key must be empty")
    }

    func testJWEIVAndCiphertextAndTagAreNonEmpty() throws {
        let response = try makeHandler().encrypt(toData(["key": "value"]))

        let parts = response.split(separator: ".", omittingEmptySubsequences: false)
        XCTAssertFalse(parts[2].isEmpty, "IV must be non-empty")
        XCTAssertFalse(parts[3].isEmpty, "Ciphertext must be non-empty")
        XCTAssertFalse(parts[4].isEmpty, "Auth tag must be non-empty")
    }

    func testDifferentPayloadsProduceDifferentCiphertexts() throws {
        let response1 = try makeHandler().encrypt(toData(["key": "value1"]))
        let response2 = try makeHandler().encrypt(toData(["key": "value2"]))

        let ciphertext1 = response1.split(separator: ".")[3]
        let ciphertext2 = response2.split(separator: ".")[3]
        XCTAssertNotEqual(ciphertext1, ciphertext2)
    }

    // MARK: - header security

    func testEPKDoesNotExposePrivateKey() throws {
        let jwe = try makeHandler().encrypt(toData(["key": "value"]))

        let header = try decodeHeader(jwe)
        let epk = try XCTUnwrap(header["epk"] as? [String: Any])
        XCTAssertNil(epk["d"], "EPK must never contain the private key component 'd'")
    }

    // MARK: - validateRecipientKey — unsupported key configurations

    func testThrowsOnUnsupportedKeyConfiguration() {
        struct TestCase {
            let label: String
            let jwkDict: [String: Any]
            let expectedMessage: String
        }

        let cases: [TestCase] = [
            TestCase(
                label: "OKP key with Ed25519 curve",
                jwkDict: ["kty": "OKP", "crv": "Ed25519",
                          "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4", "alg": "ECDH-ES"],
                expectedMessage: "JWE Encryption failed : Unsupported OKP curve for ECDH-ES: Ed25519. Only X25519 is supported."
            ),
            TestCase(
                label: "EC key with secp256k1 curve",
                jwkDict: ["kty": "EC", "crv": "secp256k1",
                          "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                          "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", "alg": "ECDH-ES"],
                expectedMessage: "JWE Encryption failed : Unsupported EC curve for ECDH-ES: secp256k1. Only P-256, P-384, P-521 are supported."
            ),
            TestCase(
                label: "Symmetric (oct) key type",
                jwkDict: ["kty": "oct", "k": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "alg": "ECDH-ES"],
                expectedMessage: "JWE Encryption failed : Required Key exchange algorithm is not supported"
            )
        ]

        for tc in cases {
            let key = createInstance(tc.jwkDict, as: JWK.self)
            let handler = JWEHandler(
                contentEncryptionAlgorithm: jweContentEncryptionAlgorithm,
                keyEncryptionAlgorithm: jweKeyEncryptionAlgorithm,
                publicKey: key,
                producerInfo: producerInfo,
                recipientInfo: recipientInfo
            )
            XCTAssertThrowsError(try handler.encrypt(toData(["key": "value"])), tc.label) { error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: tc.expectedMessage,
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }

    // MARK: - encrypt — unsupported encryption configuration

    func testThrowsOnUnsupportedKeyEncryptionAlgorithm() {
        struct TestCase {
            let label: String
            let keyEncAlg: String
            let contentEncAlg: String
        }

        let cases: [TestCase] = [
            TestCase(
                label: "unsupported keyEncryptionAlgorithm (RSA-OAEP)",
                keyEncAlg: "RSA-OAEP",
                contentEncAlg: jweContentEncryptionAlgorithm
            ),
            TestCase(
                label: "unsupported contentEncryptionAlgorithm (A128CBC-HS256)",
                keyEncAlg: jweKeyEncryptionAlgorithm,
                contentEncAlg: "A128CBC-HS256"
            ),
            TestCase(
                label: "both algorithms unsupported",
                keyEncAlg: "RSA-OAEP",
                contentEncAlg: "A128CBC-HS256"
            )
        ]

        for tc in cases {
            let handler = JWEHandler(
                contentEncryptionAlgorithm: tc.contentEncAlg,
                keyEncryptionAlgorithm: tc.keyEncAlg,
                publicKey: verificationPublicKey,
                producerInfo: producerInfo,
                recipientInfo: recipientInfo
            )
            let expectedMessage = "Unsupported encryption configuration: keyEncryptionAlgorithm=\(tc.keyEncAlg), contentEncryptionAlgorithm=\(tc.contentEncAlg). Supported configuration: keyEncryptionAlgorithm=ECDH-ES, contentEncryptionAlgorithm=A256GCM"
            XCTAssertThrowsError(try handler.encrypt(toData(["key": "value"])), tc.label) { error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: expectedMessage,
                    expectedCode: "unsupported_operation"
                )
            }
        }
    }

    // MARK: - validateRecipientKey — unsupported JWE algorithm

    func testThrowsOnUnsupportedJWEAlgorithm() {
        let keyWithNoAlg = createInstance([
            "kty": "OKP",
            "crv": "X25519",
            "use": "enc",
            "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
            "kid": "ed-key1",
            "alg": "ECDH-ES+A128KW"
        ], as: JWK.self)

        let handler = JWEHandler(
            contentEncryptionAlgorithm: jweContentEncryptionAlgorithm,
            keyEncryptionAlgorithm: jweKeyEncryptionAlgorithm,
            publicKey: keyWithNoAlg,
            producerInfo: producerInfo,
            recipientInfo: recipientInfo
        )

        XCTAssertThrowsError(try handler.encrypt(toData(["key": "value"]))) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "JWE Encryption failed : Unsupported JWE algorithm: ECDH-ES+A128KW",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - validateRecipientKey — unsupported OKP curve

    func testThrowsOnUnsupportedOKPCurveForECDHES() {
        let keyWithEd25519 = createInstance([
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
            "alg": "ECDH-ES"
        ], as: JWK.self)

        let handler = JWEHandler(
            contentEncryptionAlgorithm: jweContentEncryptionAlgorithm,
            keyEncryptionAlgorithm: jweKeyEncryptionAlgorithm,
            publicKey: keyWithEd25519,
            producerInfo: producerInfo,
            recipientInfo: recipientInfo
        )

        XCTAssertThrowsError(try handler.encrypt(toData(["key": "value"]))) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "JWE Encryption failed : Unsupported OKP curve for ECDH-ES: Ed25519. Only X25519 is supported.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - validateRecipientKey — unsupported EC curve

    func testThrowsOnUnsupportedECCurveForECDHES() {
        let keyWithSecp256k1 = createInstance([
            "kty": "EC",
            "crv": "secp256k1",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "alg": "ECDH-ES"
        ], as: JWK.self)

        let handler = JWEHandler(
            contentEncryptionAlgorithm: jweContentEncryptionAlgorithm,
            keyEncryptionAlgorithm: jweKeyEncryptionAlgorithm,
            publicKey: keyWithSecp256k1,
            producerInfo: producerInfo,
            recipientInfo: recipientInfo
        )

        XCTAssertThrowsError(try handler.encrypt(toData(["key": "value"]))) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "JWE Encryption failed : Unsupported EC curve for ECDH-ES: secp256k1. Only P-256, P-384, P-521 are supported.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testNoThrowsWhenPublicKeyIsMissingAlg() throws {
        // The handler derives the key-management algorithm from its own configuration,
        // not from the JWK's alg field — so a key without alg must still encrypt.
        let keyWithoutAlg = createInstance([
            "kty": "OKP", "crv": "X25519", "use": "enc",
            "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4", "kid": "ed-key1"
        ], as: JWK.self)
        let handler = JWEHandler(
            contentEncryptionAlgorithm: jweContentEncryptionAlgorithm,
            keyEncryptionAlgorithm: jweKeyEncryptionAlgorithm,
            publicKey: keyWithoutAlg,
            producerInfo: producerInfo,
            recipientInfo: recipientInfo
        )

        let jwe = try handler.encrypt(toData(["key": "value"]))
        XCTAssertEqual(jwe.split(separator: ".", omittingEmptySubsequences: false).count, 5)
    }
}
