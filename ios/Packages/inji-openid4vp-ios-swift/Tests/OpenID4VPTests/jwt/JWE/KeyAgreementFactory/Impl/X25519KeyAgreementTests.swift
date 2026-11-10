import XCTest
import JSONWebKey
@testable import OpenID4VP

final class X25519KeyAgreementTests: XCTestCase {
    
    func makeMockJWK() throws -> JWK {
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
        
        return try JSONDecoder().decode(JWK.self, from: json)
    }

    func testGetJWEHeaderSuccess() throws {
        let mockJWK = try makeMockJWK()
        let keyAgreement = X25519KeyAgreement()
        
        let header = keyAgreement.getJWEHeader(
            alg: "ECDH-ES",
            enc: "A256GCM",
            jwk: mockJWK,
            producerInfo: "mock-nonce",
            recipientInfo: "verifier-nonce"
        )
        
        XCTAssertEqual(header["alg"] as? String, "ECDH-ES")
        XCTAssertEqual(header["enc"] as? String, "A256GCM")
        XCTAssertEqual(header["kid"] as? String, "x25519-key1")
        XCTAssertNotNil(header["apu"])
        XCTAssertNotNil(header["apv"])
    }

    func testGetEphemeralKeyReturnNilWhenCalledBeforeDeriveKey() throws {
        let keyAgreement = X25519KeyAgreement()
        let ephemeralPublicKey = keyAgreement.getEphemeralPublicKey()
        
        XCTAssertNil(ephemeralPublicKey)
    }

    func testThrowErrorWhenInvalidPublicKeyIsPassedToDeriveKey() {
        let keyAgreement = X25519KeyAgreement()
        
        XCTAssertThrowsError(try keyAgreement.deriveKey(publicKey: Data(base64UrlEncoded: "someinvaliddata") ?? Data(), enc: "A256GCM", producerInfo: "mock-nonce", recipientInfo: "verifier-nonce")) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Key agreement failed. - The operation couldn’t be completed. (CryptoKit.CryptoKitError error 1.)",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // RFC 7518 Appendix C: ECDH-ES with A128GCM, apu "Alice", apv "Bob".
    func testConcatKDFMatchesRFC7518AppendixC() throws {
        let z = Data([158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156,
                      251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196])

        let key = try X25519KeyAgreement.concatKDF(z: z, enc: "A128GCM", apu: "QWxpY2U", apv: "Qm9i")

        XCTAssertEqual(key.toBase64UrlEncoded(), "VqqN6vgjbSBcIijNcacQGg")
    }

    // Expected bytes are what Nimbus' Base64URL.decode() (Android library) returns for the same input.
    func testPartyInfoDecodesUnpaddedBase64Url() throws {
        XCTAssertEqual(try X25519KeyAgreement.partyInfo("-_8", name: "apv"), Data([0xFB, 0xFF]))
        XCTAssertEqual(try X25519KeyAgreement.partyInfo("+/8=", name: "apv"), Data([0xFB, 0xFF]))
        XCTAssertEqual(try X25519KeyAgreement.partyInfo("VbRRB/LTxLiXmVNZuyMO8A==", name: "apv").count, 16)
    }

    // Not valid base64 (length mod 4 == 1): Nimbus drops the leftover character instead of failing,
    // so a verifier nonce like "nonce" still gives the same key on both platforms, never empty info.
    func testPartyInfoWithInvalidLengthMatchesNimbus() throws {
        XCTAssertEqual(try X25519KeyAgreement.partyInfo("nonce", name: "apv"), Data([0x9E, 0x89, 0xDC]))
        XCTAssertEqual(try X25519KeyAgreement.partyInfo("abcde", name: "apu"), Data([0x69, 0xB7, 0x1D]))

        let z = Data(count: 32)
        XCTAssertNotEqual(
            try X25519KeyAgreement.concatKDF(z: z, enc: "A256GCM", apu: "", apv: "nonce"),
            try X25519KeyAgreement.concatKDF(z: z, enc: "A256GCM", apu: "", apv: "")
        )
    }

    func testConcatKDFThrowsForUnsupportedEnc() {
        XCTAssertThrowsError(try X25519KeyAgreement.concatKDF(z: Data(count: 32), enc: "A256CBC-HS512", apu: "", apv: ""))
    }
}
