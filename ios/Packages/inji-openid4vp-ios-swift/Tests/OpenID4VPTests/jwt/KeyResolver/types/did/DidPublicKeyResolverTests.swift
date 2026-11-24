import XCTest
import CryptoKit
@testable import OpenID4VP

fileprivate let mockNetworkManager: MockNetworkManager! = MockNetworkManager()

class DidPublicKeyResolverTests: XCTestCase {
    let didKeyResolver = DidPublicKeyResolver(networkManager: mockNetworkManager)
    
    let did = "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs"
    let didDocumentUrl = "https://mosip.github.io/inji-mock-services/openid4vp-service/docs/did.json"
    
    let didResponse = """
    {
      "@context": ["https://www.w3.org/ns/did/v1"],
      "id": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
      "alsoKnownAs": [],
      "authentication": [
        "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
      ],
      "assertionMethod": [
        "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
      ],
      "service": [],
      "verificationMethod": [
        {
          "@context": "https://w3id.org/security/suites/ed25519-2020/v1",
          "id": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0",
          "type": "Ed25519VerificationKey2020",
          "controller": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
          "publicKeyMultibase": "z6MkwAm9tLpXZNfeEAqj9jcccFhjdiTwxVD32GhcjyeqGYSo"
        }
      ]
    }
    """
    
    let didResponseWithPublicKeyJwk = """
    {
      "@context": ["https://www.w3.org/ns/did/v1"],
      "id": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
      "alsoKnownAs": [],
      "authentication": [
        "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
      ],
      "assertionMethod": [
        "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
      ],
      "service": [],
      "verificationMethod": [
        {
          "@context": "https://w3id.org/security/suites/ed25519-2020/v1",
          "id": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0",
          "type": "Ed25519VerificationKey2020",
          "controller": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
          "publicKeyJwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "5Gkh7kcvir1nKUxZSbZIfa-CMJ-7K4F8NGamMhRr8B4",
            "alg": "EdDSA",
            "key_ops": [
              "sign",
              "verify"
            ],
            "use": "sig"
          }
        }
      ]
    }
    """
    
    func testValidDidWebPublicKeyResolution() async {
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)
        let keyId = "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
        
        await XCTAssertNoThrowAndVerifyAsync(try await didKeyResolver.resolve(uri: did, keyId: keyId)){ result in
            assertPublicKey(expectedBase64Encoded: "+Fy3lMapzR3wpaYNCFq29GDEn/NoR3pBsc511q1Cxqw=", actualKey: result)
        }
    }
    
    func testThrowErrorWhenKeyIdIsNotMatchingAnyOfTheKeysInDidDocumentResponse() async {
        let testCases: [TestCase] = [
            TestCase(input: ""),
            TestCase(input: "did:example:123#2"),
        ]
        
        for testCase in testCases {
            mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)
            
            await XCTAssertAsyncThrowsError(
                try await didKeyResolver.resolve(uri: did, keyId: testCase.input)
            ) { error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: "Public key extraction failed for kid: \(testCase.input)",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }
    
    func testThrowErrorWhenPublicKeyResolutionFailed() async {
        let invalidDid = "did:peer:xyz"
        
        await XCTAssertAsyncThrowsError(
            try await didKeyResolver.resolve(uri: invalidDid, keyId: "key-0")
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Given did url is not supported",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    // Get JWS Algorithm from the resolved public key
    func testGetJWSAlgorithmFromResolvedPublicKey() async {
        let ecR1DidJwkUri = "did:jwk:eyJrdHkiOiJFQyIsInVzZSI6InNpZyIsImNydiI6IlAtMjU2IiwieCI6IlE2ZExER0pIT3RyalFnX1RQNW5GZkZ6Tlg1LUdjal9kYUhjZ29VT2FWLU0iLCJ5Ijoia1lBa19lejYxQkt2Vi1RUDlpWC01eUEtNS1pSHlqRWprc3RKejZUdVhicyJ9#0" // EC key and secpr1 curve which should resolve to ES256 algorithm
        let rsaDidJwkUri = "did:jwk:eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6InNpZyIsImtpZCI6InpubTJ5NjhzLUxDX1M0a0dITkxoVXJ1YmlteUIwVWNRcXM0cUgzb1poWWsiLCJuIjoicWdoRnNPOWJYcUtiRWpNR2dMZ2NJenJHS3dyVjZxLUV6MFZaNXA1cW1Qdkw0bjQtQUFIbTdSbEpaVGw1Xzg2NDlJUHMxUUQtQWdscEpEaEJrZm1LVXg4ODMxeU95WjJKeGNpNjhILVBXTVgyUU9qYXlycjRoamQzQXRnNXIzY3lPZWJpWG4yUFEzZHZ6MmtlSnF5dUZiSkx0aVNGdHREeXJZT2ZLNnNsUDFZOFhwMHdMNHRZS0JWNEE3LU0yOWlhT2xGOGU4MWtFWDdCUzZ3U2pldGNDLUFybklldU04S3hNNFZXeHRnNXd3WmFGaGtXNjQydnJZa1ZQRlNxZE1wcUV4ZkV4dUNhbWVBN2xDMGdYZEtEOERxRWIyQ2UwNmIzQXRvM0M3TWFqR2ZJZmh2bExRQzVhc2luZTZXOGxGbG1ldFFHMHhGRE8xMGJXdzVSQTJOYmR3In0#0"
        
        let resolvedJWSAlgrithm1 = try? await didKeyResolver.getJWSAlgorithm(uri: ecR1DidJwkUri)
        let resolvedJWSAlgrithm2 = try? await didKeyResolver.getJWSAlgorithm(uri: rsaDidJwkUri)
        
        XCTAssertEqual("ES256", resolvedJWSAlgrithm1)
        XCTAssertEqual("RS256", resolvedJWSAlgrithm2)
    }
    
    func testDidJwkWithBase64UrlPaddingResolvesToSameKeyAsWithoutPadding() async throws {
        let unpaddedDid = "did:jwk:eyJrdHkiOiAiT0tQIiwgImNydiI6ICJFZDI1NTE5IiwgIngiOiAiOGc5ZF9NQjBpVTJubWdiXzlQNERmMFRSUW01UkpUbWFpRWsySGtaeTVwRSIsICJhbGciOiAiRWREU0EiLCAia2V5X29wcyI6IFsidmVyaWZ5Il0sICJ1c2UiOiAic2lnIn0"
        let paddedDid = unpaddedDid + "="
        let expectedJWSAlgorithm = try await didKeyResolver.getJWSAlgorithm(uri: unpaddedDid + "#0")
        
        for did in [paddedDid, paddedDid + "#0", unpaddedDid + "#0"] {
            let publicKey = try await didKeyResolver.resolve(uri: did)
            assertPublicKey(expectedBase64Encoded: "8g9d/MB0iU2nmgb/9P4Df0TRQm5RJTmaiEk2HkZy5pE=", actualKey: publicKey)
            
            let jwsAlgorithm = try await didKeyResolver.getJWSAlgorithm(uri: did)
            XCTAssertEqual(jwsAlgorithm, expectedJWSAlgorithm)
        }
    }
}
