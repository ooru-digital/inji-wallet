import Foundation
@testable import OpenID4VP

import XCTest
final class DidJwkResolverTests: XCTestCase {
    
    let mockNetworkManager = MockNetworkManager()
    
    // Kty = OKP, Supported Crv = Ed25519

    func testDidJwkSuccessfulResolvingForOKPKeyTypeAndEd25519Curve() async throws {
        let did = "did:jwk:eyJrdHkiOiAiT0tQIiwgImNydiI6ICJFZDI1NTE5IiwgIngiOiAiOGc5ZF9NQjBpVTJubWdiXzlQNERmMFRSUW01UkpUbWFpRWsySGtaeTVwRSIsICJhbGciOiAiRWREU0EiLCAia2V5X29wcyI6IFsidmVyaWZ5Il0sICJ1c2UiOiAic2lnIn0"
        let parsedDid = ParsedDID(did: did, method: .jwk, id: "eyJrdHkiOiAiT0tQIiwgImNydiI6ICJFZDI1NTE5IiwgIngiOiAiOGc5ZF9NQjBpVTJubWdiXzlQNERmMFRSUW01UkpUbWFpRWsySGtaeTVwRSIsICJhbGciOiAiRWREU0EiLCAia2V5X29wcyI6IFsidmVyaWZ5Il0sICJ1c2UiOiAic2lnIn0", didUrl: did)
        let resolver = DidJwkResolver(networkManager: mockNetworkManager)
        
        let key = try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: did)
        assertPublicKey(expectedBase64Encoded: "8g9d/MB0iU2nmgb/9P4Df0TRQm5RJTmaiEk2HkZy5pE=", actualKey: key)
    }
    
    func testInvalidBase64URL() async {
        // Invalid base64url string that cannot be decoded
        let invalidDid = "did:jwk:not@valid%base64"
        let parsedDid = ParsedDID(did: invalidDid, method: .jwk, id: "not@valid%base64", didUrl: invalidDid)
        let resolver = DidJwkResolver(networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: invalidDid)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid base64url encoding for public key data",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testInvalidJSONInJWK() async {
        let invalidJsonDid = "did:jwk:\(encodeBase64Url("not valid json".data(using: .utf8)!))"
        let parsedDid = ParsedDID(did: invalidJsonDid, method: .jwk, id: "", didUrl: invalidJsonDid)
        let resolver = DidJwkResolver(networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: invalidJsonDid)) { error in
            XCTAssertTrue(error is PublicKeyResolutionFailed, "Expected DecodingError but got \(type(of: error)) : \(error)")
            XCTAssertEqual("Failed to decode JWK: The data couldn’t be read because it isn’t in the correct format.", error.localizedDescription)
        }
    }
    
    func testUnsupportedCurve() async {
        let jwk = """
            {
                "kty": "OKP",
                "crv": "P-256",
                "alg": "ES256",
                "use":"sig",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
            }
            """
        let jwkBase64 = encodeBase64Url(jwk.data(using: .utf8)!)
        let unsupportedCurveDid = "did:jwk:\(jwkBase64)"
        let parsedDid =  ParsedDID(did: unsupportedCurveDid, method: .jwk, id: jwkBase64, didUrl: unsupportedCurveDid)
        let resolver = DidJwkResolver(networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: unsupportedCurveDid)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Curve - P-256 is not supported. Supported: Ed25519",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testMissingXCoordinate() async {
        let jwk = """
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA"
            }
            """
        let jwkBase64 = encodeBase64Url(jwk.data(using: .utf8)!)
        let missingXDid = "did:jwk:\(jwkBase64)"
        let parsedDid = ParsedDID(did: missingXDid, method: .jwk, id: jwkBase64, didUrl: missingXDid)
        let resolver = DidJwkResolver(networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: missingXDid)) { error in
            XCTAssertTrue(error is PublicKeyResolutionFailed, "Expected DeserializationFailure but got \(type(of: error))")
        }
    }
    
    func testInvalidXCoordinateBase64() async {
        let jwk = """
            {
                "kty": "OKP",
                "use": "sig",
                "crv": "Ed25519",
                "x": "invalid@base64",
                "alg": "EdDSA"
            }
            """
        let jwkBase64 = encodeBase64Url(jwk.data(using: .utf8)!)
        let invalidXBase64Did = "did:jwk:\(jwkBase64)"
        let parsedDid = ParsedDID(did: invalidXBase64Did, method: .jwk, id: jwkBase64, didUrl: invalidXBase64Did)
        let resolver = DidJwkResolver(networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: invalidXBase64Did)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Failed to decode JWK: The operation couldn’t be completed. (Tools.Base64URL.Error error 0.)",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testInvalidPublicKeyData() async {
        // JWK with valid base64 in x coordinate but data is not a valid Ed25519 key
        let jwk = """
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "aW52YWxpZCBrZXkgZGF0YQ==",
                "alg": "EdDSA",
                "use": "sig"
            }
            """
        let jwkBase64 = encodeBase64Url(jwk.data(using: .utf8)!)
        let invalidKeyDataDid = "did:jwk:\(jwkBase64)"
        let parsedDid = ParsedDID(did: invalidKeyDataDid, method: .jwk, id: jwkBase64, didUrl: invalidKeyDataDid)
        let resolver = DidJwkResolver(networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: invalidKeyDataDid)) { error in
           assertOpenID4VPException(error,
                expectedMessage: "Public key resolution failed. Error: incorrectKeySize",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    private func encodeBase64Url(_ data: Data) -> String {
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    // Kty = EC, Support curve = P-256

    func testDidJwkSuccessfulResolvingForECKeyTypeAndP256Curve() async throws {
        let did = "did:jwk:eyJrdHkiOiJFQyIsImFsZyI6IkVTMjU2IiwiY3J2IjoiUC0yNTYiLCJ4IjoiTUtCQ1ROSWNLVVNEaWkxMXlTczM1MjZpRFo4QWlUbzdUdTZLUEFxdjdENCIsInkiOiI0RXRsNlNSVzJZaUxVck41dmZ2Vkh1aHA3eDhQeGx0bVdXbGJiTTRJRnlNIiwidXNlIjoiZW5jIiwia2lkIjoiMSJ9"
        let parsedDid = ParsedDID(did: did, method: .jwk, id: "eyJrdHkiOiJFQyIsImFsZyI6IkVTMjU2IiwiY3J2IjoiUC0yNTYiLCJ4IjoiTUtCQ1ROSWNLVVNEaWkxMXlTczM1MjZpRFo4QWlUbzdUdTZLUEFxdjdENCIsInkiOiI0RXRsNlNSVzJZaUxVck41dmZ2Vkh1aHA3eDhQeGx0bVdXbGJiTTRJRnlNIiwidXNlIjoiZW5jIiwia2lkIjoiMSJ9", didUrl: did)
        let resolver = DidJwkResolver(networkManager: mockNetworkManager)

        let key = try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: did)
        assertPublicKey(expectedBase64Encoded: "BDCgQkzSHClEg4otdckrN+duog2fAIk6O07uijwKr+w+4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM=", actualKey: key)
    }

    func testUnsupportedCurveForECKeyType() async {
        let jwk = """
        {
          "kty": "EC",
          "use": "sig",
          "key_ops": [
            "sign"
          ],
          "alg": "ES384",
          "kid": "c5366f28-6a78-458d-8c51-a907c9afb10c",
          "crv": "P-384",
          "x": "8bVNf2dECf0yp_ExmT8Awu-YvFUDt1oti3s2lqGWJ7ihI1P3vqYz_0iJImpm9pHM",
          "y": "lStYwazJ0ZCj7rvvT2xPJolXW-tP-EImVdLKddHv9WFioQhpSYBtwqt70MRsu5dr",
          "d": "UGNgu3ElU3v7T0T0vLaymbpjhjJNLN3Rk9MgukqkcCxoFkGc6vOtc7U9kz4S_Kaz"
        }
        """
        let jwkBase64 = encodeBase64Url(jwk.data(using: .utf8)!)
        let unsupportedCurveDid = "did:jwk:\(jwkBase64)"
        let parsedDid =  ParsedDID(did: unsupportedCurveDid, method: .jwk, id: jwkBase64, didUrl: unsupportedCurveDid)
        let resolver = DidJwkResolver(networkManager: mockNetworkManager)

        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: unsupportedCurveDid)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Curve - P-384 is not supported. Supported: P-256",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorOnInvalidXDataInEC_P256Key() async {
        let jwk = """
        {
          "kty": "EC",
          "use": "sig",
          "key_ops": [
            "sign"
          ],
          "alg": "ES256",
          "kid": "c5366f28-6a78-458d-8c51-a907c9afb10c",
          "crv": "P-256",
          "x": "oKuKSOMjPfDaykr_s8Peyihy%dxs1HYQ7a26EGpXXc4",
          "y": "6CBgZYLeTWYrbtliEew8vDo4wAUEbBbQwMauWBWt4xk",
          "d": "6K3j95qPXIX6qJ55WHSrqTkmnf3_4rKedkAMn8HI-TA"
        }
        """
        let jwkBase64 = encodeBase64Url(jwk.data(using: .utf8)!)
        let unsupportedCurveDid = "did:jwk:\(jwkBase64)"
        let parsedDid =  ParsedDID(did: unsupportedCurveDid, method: .jwk, id: jwkBase64, didUrl: unsupportedCurveDid)
        let resolver = DidJwkResolver(networkManager: mockNetworkManager)

        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: unsupportedCurveDid)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Failed to decode JWK: The operation couldn’t be completed. (Tools.Base64URL.Error error 0.)",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // unsupported key type

        func testUnsupportedKeyType() async {
        let jwk = """
                {
                  "kty": "oct",
                  "k": "GawgguFyGrWKav7AX4VKUg",
                  "alg": "HS256",
                  "key_ops": ["sign", "verify"]
                }
            """
        let jwkBase64 = encodeBase64Url(jwk.data(using: .utf8)!)
        let unsupportedCurveDid = "did:jwk:\(jwkBase64)"
        let parsedDid =  ParsedDID(did: unsupportedCurveDid, method: .jwk, id: jwkBase64, didUrl: unsupportedCurveDid)
        let resolver = DidJwkResolver(networkManager: mockNetworkManager)

        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: unsupportedCurveDid)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "KeyType - oct is not supported. Supported: OKP, EC",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}

