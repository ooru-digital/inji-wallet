import XCTest
import CryptoKit
import Base58Swift
@testable import OpenID4VP

final class KeyResolverUtilsTests: XCTestCase {
    
    func testPublicKeyFromMultibaseValidEd25519() {
        let keyHex = "ed01f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691"
        let keyData = Data(hex: keyHex)
        let base58 = Base58.base58Encode([UInt8](keyData))
        let multibase = "z\(base58)"
        
        XCTAssertNoThrowAndVerify(try publicKeyFromMultibase(multibase)) { key in
            assertPublicKey(expectedBase64Encoded: "8g9d/MB0iU2nmgb/9P4Df0TRQm5RJTmaiEk2HkZy5pE=", actualKey: key)
        }
    }
    
    func testPublicKeyFromMultibaseInvalidPrefix() {
        let multibase = "a12345"
        XCTAssertThrowsError(try publicKeyFromMultibase(multibase)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "DID public key decoding failed",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testPublicKeyFromMultibaseInvalidBase58() {
        let multibase = "z!@#$%^"
        XCTAssertThrowsError(try publicKeyFromMultibase(multibase)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "DID public key decoding failed",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testPublicKeyFromMultibaseTooShort() {
        let multibase = "z12"
        XCTAssertThrowsError(try publicKeyFromMultibase(multibase)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "DID public key decoding failed",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testPublicKeyFromMultibaseUnsupportedFormat() {
        // Prefix not supported
        let keyHex = "0001f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691"
        let keyData = Data(hex: keyHex)
        let base58 = Base58.base58Encode([UInt8](keyData))
        let multibase = "z\(base58)"
        XCTAssertThrowsError(try publicKeyFromMultibase(multibase)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "DID public key decoding failed. Unsupported public key format",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testPublicKeyFromJWKValidEd25519() {
        let jwk: [String: Any] = [
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "RzT9xmJDacPBzLg1KXMhzjQD-QV77hYykcD3GDPTMKg"
        ]
        
        XCTAssertNoThrowAndVerify(try publicKeyFromJWK(jwk)) { key in
            assertPublicKey(expectedBase64Encoded: "RzT9xmJDacPBzLg1KXMhzjQD+QV77hYykcD3GDPTMKg=", actualKey: key)
        }
    }
    
    func testPublicKeyFromJWKInvalidKty() {
        let jwk: [String: Any] = [
            "kty": "OKP",
            "crv": "P-256",
            "x": "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691"
        ]
        XCTAssertThrowsError(try publicKeyFromJWK(jwk)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Curve - P-256 is not supported. Supported: Ed25519",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testPublicKeyFromJWKInvalidCurve() {
        let jwk: [String: Any] = [
            "kty": "EC",
            "crv": "Ed25519",
            "x": "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691"
        ]
        XCTAssertThrowsError(try publicKeyFromJWK(jwk)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "KeyType - EC is not supported. Supported: OKP",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testPublicKeyFromJWKMissingX() {
        let jwk: [String: Any] = [
            "kty": "OKP",
            "crv": "Ed25519"
        ]
        XCTAssertThrowsError(try publicKeyFromJWK(jwk)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Missing the public key data in JWK",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testPublicKeyFromJWKInvalidBase64UrlX() {
        let jwk: [String: Any] = [
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "f20f5dfcc074894da79a06invalid426e5125399a8849361e4672e691"
        ]
        XCTAssertThrowsError(try publicKeyFromJWK(jwk)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Invalid base64url encoding for public key data in JWK",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testHexStringToDataValid() {
        let hex = "deadbeef"
        let data = hexStringToData(hex)
        XCTAssertEqual(data, Data([0xde, 0xad, 0xbe, 0xef]))
    }
    
    func testHexStringToDataInvalid() {
        let hex = "deadbeeG"
        XCTAssertNil(hexStringToData(hex))
    }
    
    func testPublicKeyFromHexValid() {
        let keyHex = "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691"
        
        XCTAssertNoThrowAndVerify(try publicKeyFromHex(keyHex)) { key in
            assertPublicKey(expectedBase64Encoded: "8g9d/MB0iU2nmgb/9P4Df0TRQm5RJTmaiEk2HkZy5pE=", actualKey: key!)
        }
    }
    
    func testPublicKeyFromPEMValid() {
        let pem = """
        -----BEGIN PUBLIC KEY-----
        MCowBQYDK2VwAyEAf20f5dfcc074894da79a06fff4fe037f44d1426e5125399a
        -----END PUBLIC KEY-----
        """
        
        XCTAssertNoThrowAndVerify( try publicKeyFromPEM(pem)) {
            key in
            assertPublicKey(expectedBase64Encoded: "f20f5dfcc074894da79a06fff4fe037f44d1426e510=", actualKey: key)
        }
    }
    
    func testPublicKeyFromPEMInvalidFormat() {
        let pem = "-----BEGIN PUBLIC KEY-----\ninvalidpemdata\n-----END PUBLIC KEY-----"
        XCTAssertThrowsError(try publicKeyFromPEM(pem)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Invalid PEM format",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testPublicKeyFromPEMInvalidEd25519Format() {
        let pem = """
        -----BEGIN PUBLIC KEY-----
        MCowBQYDK2VwAyEA7Xq8HZLSz9Y=
        -----END PUBLIC KEY-----
        """
        XCTAssertThrowsError(try publicKeyFromPEM(pem)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Invalid Ed25519 public key format",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testDecodeMultibaseValid() throws {
        let keyHex = "ed01f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691"
        let keyData = Data(hex: keyHex)
        let base58 = Base58.base58Encode([UInt8](keyData))
        let multibase = "z\(base58)"
        let decoded = try decodeMultibase(multibase)
        XCTAssertEqual(decoded, keyData)
    }
    
    func testDecodeMultibaseInvalidPrefix() {
        let multibase = "a12345"
        XCTAssertThrowsError(try decodeMultibase(multibase)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Multibase not starting with base58 prefix",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testDecodeMultibaseInvalidBase58() {
        let multibase = "z!@#$%^"
        XCTAssertThrowsError(try decodeMultibase(multibase)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "DID public key decoding failed",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}

// Helper for hex string to Data
private extension Data {
    init(hex: String) {
        self.init()
        var temp = ""
        for char in hex {
            temp.append(char)
            if temp.count == 2 {
                if let byte = UInt8(temp, radix: 16) {
                    self.append(byte)
                }
                temp = ""
            }
        }
    }
    func toHexString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}
