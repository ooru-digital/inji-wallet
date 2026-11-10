import XCTest
@testable import OpenID4VP

final class DidWebResolverTests: XCTestCase {
    let mockNetworkManager = MockNetworkManager()
  
    let didUrl = "did:web:example.com"
    let didHttpsUrl = "https://example.com/.well-known/did.json"
    let keyId = "did:web:example.com#key1"
    let parsedDid = ParsedDID(
        did: "did:web:example.com",
        method: .web,
        id: "example.com",
        didUrl: "did:web:example.com#key1"
    )
    
    func testThrowsErrorWhenVerificationMethodDoesNotHaveId() async throws {
        let didDocJSON = """
        {
            "id": "did:web:example.com",
            "verificationMethod": [{
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            responseBody: didDocJSON
        )

        let resolver = DidWebResolver(networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: "did:web:example.com#key1")) { error in
            assertOpenID4VPException(error, expectedMessage: "Public key extraction failed for kid: did:web:example.com#key1", expectedCode: "invalid_request")
        }
    }
    
    func testNetworkFailure() async {
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            error: NetworkRequestException.networkRequestFailed(message: "Not Found")
        )
        
        let resolver = DidWebResolver(networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: "did:web:example.com#key1")) { error in
            assertOpenID4VPException(error, expectedMessage: "Network request failed with error response - Not Found", expectedCode: "invalid_request")
        }
    }
    
    func testInvalidDidDocument() async {
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            responseBody: "Invalid JSON"
        )
        
        let resolver = DidWebResolver(networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: "did:web:example.com#key1")) { error in
            assertOpenID4VPException(error, expectedMessage: "The data couldn’t be read because it isn’t in the correct format.", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }
    
    func testPathBasedDID() async throws {
        let didDocJSON = """
        {
            "id": "did:web:example.com:path:to:identity",
            "verificationMethod": [{
                "id": "did:web:example.com:path:to:identity#key1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com:path:to:identity",
                "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: "https://example.com/path/to/identity/did.json",
            responseBody: didDocJSON
        )
        
        let parsedDid = ParsedDID(
            did: "did:web:example.com:path:to:identity",
            method: .web,
            id: "example.com:path:to:identity",
            didUrl: "did:web:example.com:path:to:identity#key1"
        )
        let resolver = DidWebResolver(networkManager: mockNetworkManager)
        
        let key = try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: "did:web:example.com:path:to:identity#key1")
        
        XCTAssertTrue(mockNetworkManager.recordedRequests.keys.contains("https://example.com/path/to/identity/did.json"))
        XCTAssertNotNil(key)
    }
    
    func testMissingVerificationMethod() async {
        let didDocJSON = """
        {
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#different-key",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            responseBody: didDocJSON
        )
        
        let resolver = DidWebResolver(networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: "did:web:example.com#key1")) { error in
            assertOpenID4VPException(error, expectedMessage: "Public key extraction failed for kid: did:web:example.com#key1", expectedCode: "invalid_request")
        }
    }
    
    func testEmptyPublicKeyMultibase() async {
        let didDocJSON = """
        {
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#key1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "publicKeyMultibase": ""
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            responseBody: didDocJSON
        )

        let resolver = DidWebResolver(networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: "did:web:example.com#key1")) { error in
            assertOpenID4VPException(error, expectedMessage: "publicKeyMultibase cannot be null or empty", expectedCode: "invalid_request")
        }
    }
    
    func testNoSupportedKeyType() async {
        let didDocJSON = """
        {
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#key1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "unsupportedKeyType": "value"
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            responseBody: didDocJSON
        )

        let resolver = DidWebResolver(networkManager: mockNetworkManager)
        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: "did:web:example.com#key1")) { error in
            assertOpenID4VPException(error, expectedMessage: "Unsupported Public Key type. Supported: publicKeyMultibase, publicKeyJwk, publicKeyHex, publicKeyPem", expectedCode: "invalid_request")
        }
    }
    
    func testSubdomainInDID() async {
        let didDocJSON = """
        {
            "id": "did:web:sub.example.com",
            "verificationMethod": [{
                "id": "did:web:sub.example.com#key1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:sub.example.com",
                "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: "https://sub.example.com/.well-known/did.json",
            responseBody: didDocJSON
        )
        let parsedDid = ParsedDID(
                    did: "did:web:sub.example.com",
                    method: .web,
                    id: "sub.example.com",
                    didUrl: "did:web:sub.example.com#key1"
                )
        
        let resolver = DidWebResolver(networkManager: mockNetworkManager)
        
        await XCTAssertNoThrowAndVerifyAsync(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: "did:web:sub.example.com#key1")) { key in
            XCTAssertTrue(mockNetworkManager.recordedRequests.keys.contains("https://sub.example.com/.well-known/did.json"))
            XCTAssertNotNil(key)
        }
    }
    
    func testThrowsErrorWhenDidResponseHasNon200StatusCode() async throws {
        let didDocJSON = "{\"message\": \"something went wrong\"}"
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            responseBody: didDocJSON,
            statusCode: 400
        )
        
        let resolver = DidWebResolver(networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: "did:web:example.com#key1")) { error in
            assertOpenID4VPException(error, expectedMessage: "Error while resolving did, status code: 400 with body: {\"message\": \"something went wrong\"}", expectedCode: "invalid_request")
        }
    }
    
    func testThrowsErrorWhenDidResponseIsNotValidJson() async throws {
        let didDocJSON = """
            [{
                "id": "did:web:example.com#key1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
            }]
        """
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            responseBody: didDocJSON
        )

        let resolver = DidWebResolver(networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: "did:web:example.com#key1")) { error in
            assertOpenID4VPException(error, expectedMessage: "Conversion failed: resolved DID response is not a valid JSON object", expectedCode: "invalid_request")
        }
    }
    
    func testSuccessfulResolvingKeyIdAsNull() async throws {
        let didDocJSON = """
        {
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#key1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "publicKeyHex": "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691"
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            responseBody: didDocJSON
        )
        
        let resolver = DidWebResolver(networkManager: mockNetworkManager)
        
        await XCTAssertNoThrowAndVerifyAsync(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: nil)) { key in
            assertPublicKey(expectedBase64Encoded: "8g9d/MB0iU2nmgb/9P4Df0TRQm5RJTmaiEk2HkZy5pE=", actualKey: key)
        }
    }

//  verification material -> publicKeyMultibase
    
    func testSuccessfulResolvingWithPublicKeyMultibase() async {
        let didDocJSON = """
        {
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#key1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: didHttpsUrl,responseBody: didDocJSON
        )

        let resolver = DidWebResolver(networkManager: mockNetworkManager)
        
        await XCTAssertNoThrowAndVerifyAsync(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: keyId)) { key in
            assertPublicKey(expectedBase64Encoded: "lJZrfAjkBXdfjebMHEUI9usidAPhAlssitLXR3OYxbI=", actualKey: key)
        }
    }
    
    func testThrowsErrorWhenPublicKeyMultibaseIsNil() async {
        let didDoc = """
        {
          "verificationMethod": [
            {
              "id": "\(keyId)",
              "publicKeyMultibase": null
            }
          ]
        }
        """

        mockNetworkManager.setMockResponse(for: didHttpsUrl, responseBody: didDoc)
        let resolver = DidWebResolver(networkManager: mockNetworkManager)

        await XCTAssertAsyncThrowsError(
            try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: keyId)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "publicKeyMultibase cannot be null or empty",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }


    
    func testThrowsErrorWhenPublicKeyMultibaseIsEmpty() async {
        let didDoc = """
        {
          "verificationMethod": [
            {
              "id": "\(keyId)",
              "publicKeyMultibase": ""
            }
          ]
        }
        """

        mockNetworkManager.setMockResponse(for: didHttpsUrl, responseBody: didDoc)
        let resolver = DidWebResolver(networkManager: mockNetworkManager)

        await XCTAssertAsyncThrowsError(
            try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: keyId)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "publicKeyMultibase cannot be null or empty",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    //  verification material -> publicKeyJwk
    
    func testSuccessfulResolvingWithPublicKeyJWK() async {
        let didDocJSON = """
        {
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#key1",
                "type": "JsonWebKey2020",
                "controller": "did:web:example.com",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "8g9d_MB0iU2nmgb_9P4Df0TRQm5RJTmaiEk2HkZy5pE",
                    "alg": "EdDSA",
                    "use": "sig"
                }
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: didHttpsUrl,
            responseBody: didDocJSON
        )

        let resolver = DidWebResolver(networkManager: mockNetworkManager)
        
        await XCTAssertNoThrowAndVerifyAsync(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: keyId)) { key in
            assertPublicKey(expectedBase64Encoded: "8g9d/MB0iU2nmgb/9P4Df0TRQm5RJTmaiEk2HkZy5pE=", actualKey: key)
        }
    }
    
    //  verification material -> publicKeyPem
    
    func testSuccessfulResolvingWithPEM() async {
        let didDocJSON = """
        {
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#key1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "publicKeyPem": "-----BEGIN PUBLIC KEY-----\\nMCowBQYDK2VwAyEA8g9d/MB0iU2nmgb/9P4Df0TRQm5RJTmaiEk2HkZy5pE=\\n-----END PUBLIC KEY-----"
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            responseBody: didDocJSON
        )

        let resolver = DidWebResolver(networkManager: mockNetworkManager)
        
        await XCTAssertNoThrowAndVerifyAsync(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: keyId)) { key in
            assertPublicKey(expectedBase64Encoded: "8g9d/MB0iU2nmgb/9P4Df0TRQm5RJTmaiEk2HkZy5pE=", actualKey: key)
        }
    }
    
    //  verification material -> publicKeyHex
    
    func testSuccessfulResolvingWithHex() async throws {
        let didDocJSON = """
        {
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#key1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "publicKeyHex": "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691"
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            responseBody: didDocJSON
        )
        
        let resolver = DidWebResolver(networkManager: mockNetworkManager)
        
        await XCTAssertNoThrowAndVerifyAsync(try await resolver.extractPublicKey(parsedDID:parsedDid, keyId: keyId)) { key in
            assertPublicKey(expectedBase64Encoded: "8g9d/MB0iU2nmgb/9P4Df0TRQm5RJTmaiEk2HkZy5pE=", actualKey: key)
        }
    }
}
