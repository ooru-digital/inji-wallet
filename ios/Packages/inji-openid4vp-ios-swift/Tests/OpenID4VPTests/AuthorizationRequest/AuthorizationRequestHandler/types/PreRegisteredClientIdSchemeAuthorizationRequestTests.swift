import Foundation
import XCTest
import JSONWebKey
@testable import OpenID4VP

class PreRegisteredClientIdSchemeTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockNetworkManagerReal: NetworkManager! = NetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    
    let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,[
        AuthorizationRequestFieldConstants.clientId.rawValue: "mock-client",
    ]), applicableFields: authRequestWithPreRegisteredByValueDraft23)
    let requestUri: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
    
    private var walletMetadata: WalletMetadata!
    
    override func setUpWithError() throws {
        walletMetadata = try createWalletMetadataV2()
    }
    
    // Validate client tests
    
    func testThrowExceptionWhenClientIdIsNotAvailableAsTrustedVerifier(){
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId.rawValue: "untrusted-mock-client",
        ])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertThrowsError(try preRegistered.validateClientId()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Verifier is not trusted by the wallet",
                expectedCode: OpenID4VPErrorCodes.invalidClient
            )
        }
    }
    
    
    func testThrowExceptionWhenTrustedVerifiersListIsEmpty(){
        let authorizationRequestParameters: [String : Any] = [AuthorizationRequestFieldConstants.clientId.rawValue: "other-mock-client","response_uri": "https://mock-verifier.com"]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertThrowsError(try preRegistered.validateClientId()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Verifier is not trusted by the wallet",
                expectedCode: OpenID4VPErrorCodes.invalidClient
            )
        }
    }
    
    // Support for Authorization request by reference or by value
    
    func testReturnTrueForAuthorizationRequestByReferenceSupport() {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertTrue(preRegistered.isSignedRequestSupported(), "Pre-registered client id scheme should support authorization request by reference")
    }


    func testisUnsignedRequestSupported_shouldValidateClientFalse_returnsTrue() {
        let authorizationRequestParameters: [String : Any] = [AuthorizationRequestFieldConstants.clientId.rawValue: "mock-client"]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, shouldValidateClient: false, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        XCTAssertTrue(try preRegistered.isUnsignedRequestSupported(), "Should return true when shouldValidateClient is false")
    }

    func testisUnsignedRequestSupported_shouldValidateClientTrue_clientIdNotAvailable_throwsError() {
        let authorizationRequestParameters: [String : Any] = [AuthorizationRequestFieldConstants.clientId.rawValue: "untrusted-client"]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertThrowsError(try preRegistered.isUnsignedRequestSupported()) { error in
            assertOpenID4VPException(error, expectedMessage: "Verifier is not trusted by the wallet", expectedCode: OpenID4VPErrorCodes.invalidClient)
        }
    }

    func testisUnsignedRequestSupported_shouldValidateClientTrue_clientIdAvailable_allowUnsignedFalse_returnsFalse() {
        let trustedVerifiers = [Verifier(clientId: "mock-client", responseUris: ["https://mock-verifier.com"], allowUnsignedRequest: false)]
        let authorizationRequestParameters: [String : Any] = [AuthorizationRequestFieldConstants.clientId.rawValue: "mock-client"]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: trustedVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        XCTAssertFalse(try preRegistered.isUnsignedRequestSupported(), "Should return false when allowUnsignedRequest is false")
    }

    func testisUnsignedRequestSupported_shouldValidateClientTrue_clientIdAvailable_allowUnsignedTrue_returnsTrue() {
        let trustedVerifiers = [Verifier(clientId: "mock-client", responseUris: ["https://mock-verifier.com"], allowUnsignedRequest: true)]
        let authorizationRequestParameters: [String : Any] = [AuthorizationRequestFieldConstants.clientId.rawValue: "mock-client"]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: trustedVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        XCTAssertTrue(try preRegistered.isUnsignedRequestSupported(), "Should return true when allowUnsignedRequest is true")
    }

    
    
    // Validate and parse authorization request - check if verifier is trusted
    
    func testDoesNotThrowExceptionWhenTrustedVerifierDoesNotHaveClientMetadataAndAuthorizationRequestContainsClientMetadata() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue,preRegisteredSchemeClientIdDraft23)) as [String : Any]
        let trustedVerifiersWithoutClientMetadata = [
            Verifier(clientId: "mock-client", responseUris: ["https://mock-verifier.com"])
        ]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: trustedVerifiersWithoutClientMetadata, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil,shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncNoThrowsError(try await preRegistered.validateAndParseRequestFields(), "Error should not happen when client_metadata is not known to wallet but provided in authorization request")
    }
    
    func testThrowExceptionWhenClientIdIsAvailableInTrustedVerifiersButResponseUriIsNotMatching() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
            "response_uri": "https://some-other-url.com"
        ])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil,shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await preRegistered.validateAndParseRequestFields()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "response_uri trust cannot be established",
                                     expectedCode: OpenID4VPErrorCodes.invalidClient
            )
        }
    }
    
    /// Fetch authorization request by value - validate authorization request object and authorization request query paramaters
    
    func testFetchAuthorizationRequestOnValidPreRegisteredSchemeAuthRequestSentByValue() async{
        let expectedAuthorizationRequestParameters: [String : Any] = [
            "response_mode": "direct_post",
            "response_type": "vp_token",
            "client_id": "mock-client",
            "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
            "state": "+mRQe1d6pBoJqF6Ab28klg==",
            "response_uri": "https://mock-verifier.com",
            "client_metadata": (clientMetadata),
            "presentation_definition": [
                "input_descriptors": [[
                    "format": [
                        "ldp_vc": [
                            "proof_type": ["Ed25519Signature2018", "RsaSignature2018"]
                        ]
                    ],
                    "constraints": [
                        "fields": [[
                            "path": ["$.credentialSubject.email"],
                            "filter": [
                                "pattern": "@gmail.com",
                                "type": "string"
                            ]
                        ]]
                    ],
                    "name": "Verifiable Credential",
                    "id": "input_1",
                    "purpose": "To verify identity using Linked Data Proofs"
                ]],
                "id": "vp_presentation_definition"
            ]
        ]
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
        ])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        try? await preRegistered.fetchAuthorizationRequest()
        
        assertDictionariesEqual(expected: expectedAuthorizationRequestParameters, actual: preRegistered.authorizationRequestParameters)
    }
    
    func testProcessingWalletMetadataSuccessfully() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId.rawValue: "mock-client",
        ])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager!)
        
        var expectedWalletMetadata: WalletMetadata = walletMetadata
        expectedWalletMetadata.requestObjectSigningAlgValuesSupported = nil
        
        let processedMetadata = preRegistered.process(walletMetadata: walletMetadata)
        
        assertDictionariesEqual(expected: convertToDictionary(object: expectedWalletMetadata)!, actual: convertToDictionary(object: processedMetadata))
    }
    
    func testExtractPublicKeyThrowErrorWhenPreRegisteredClientNotAvailable() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23, requestParams: mergeMaps(authorizationRequestParamsWithValue, ["client_id": "untrusted-client"])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager!)
        
        await XCTAssertAsyncThrowsError(try await preRegistered.extractPublicKey(keyId: "ed-key2", algorithm: "ECDSA")){ error in
            assertOpenID4VPException(error, expectedMessage: "Verifier is not trusted by the wallet", expectedCode: OpenID4VPErrorCodes.invalidClient)
        }
    }
    
    // clientMetadata available for trusted verifiers does not have jwks
    func testExtractPublicKeyThrowErrorWhenJwksUriNotAvailable() async throws {
        let trustedVerifiers = [
            Verifier(clientId: "mock-client", responseUris: ["https://mock-verifier.com"])
        ]
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: trustedVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager!)
        
        
        await XCTAssertAsyncThrowsError(try await preRegistered.extractPublicKey(keyId: "ed-key2", algorithm: "EdDSA")){ error in
            assertOpenID4VPException(error, expectedMessage: "Public key extraction failed - Public key information not available in pre-registered data to verify the signed Authorization Request", expectedCode: OpenID4VPErrorCodes.invalidRequestObject)
        }
    }
    
    func testClientIdSchemeShouldReturnPreRegistered(){
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertEqual(preRegistered.clientIdScheme(), ClientIdScheme.preRegistered.rawValue, "clientIdScheme should return pre-registered")
    }
    
    
    func testExtractPublicKeySuccessForKeyId() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(
            paramList: authRequestWithPreRegisteredByValueDraft23,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)
        ) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers: preRegisteredVerifiers,
            authorizationRequestParameters: authorizationRequestParameters,
            walletMetadata: walletMetadata,
            shouldValidateClient: true,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager!
        )
        mockNetworkManager.setMockResponse(for: jwksUri, responseBody: jwkSet)
        
        let publicKey = try await preRegistered.extractPublicKey(keyId: "ed-key2", algorithm: "Ed25519")
        
        assertPublicKey(expectedBase64Encoded: "5tvU4k/TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc=", actualKey: publicKey)
    }
    
    func testExtractPublicKeySuccessForAlgorithmAndUsage() async throws {
        let trustedVerifier = Verifier(clientId: "mock-client", responseUris: ["/response-uri"], jwksUri: jwksUri)
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(
            paramList: authRequestWithPreRegisteredByValueDraft23,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)
        ) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers: [trustedVerifier],
            authorizationRequestParameters: authorizationRequestParameters,
            walletMetadata: walletMetadata,
            shouldValidateClient: true,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager!
        )
        mockNetworkManager.setMockResponse(for: jwksUri, responseBody: jwkSet)
        
        
        await XCTAssertNoThrowAndVerifyAsync(try await preRegistered.extractPublicKey(keyId: nil, algorithm: "EdDSA")) { publicKey in
            assertPublicKey(expectedBase64Encoded: "5tvU4k/TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc=", actualKey: publicKey)
        }
    }
    
    func testExtractPublicKeyThrowErrorWhenAlgorithmAndKeyUsageDoesNotMatchInAvailableJWKS() async throws {
        let trustedVerifier = Verifier(clientId: "mock-client", responseUris: ["/response-uri"], jwksUri: "https://mock-verifier.com/jwks.json")
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(
            paramList: authRequestWithPreRegisteredByValueDraft23,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)
        ) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers: [trustedVerifier],
            authorizationRequestParameters: authorizationRequestParameters,
            walletMetadata: walletMetadata,
            shouldValidateClient: true,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager!
        )
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/jwks.json", responseBody: """
{
"keys": [{
                    "kty": "EC",
                    "crv": "P-256",
                    "use": "sig",
                    "alg": "ES256",
                    "kid": "ec-key1",
                    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
}]
}
""")
        
        
        await XCTAssertAsyncThrowsError(try await preRegistered.extractPublicKey(keyId: nil, algorithm: "Ed25519")) { error in
            assertOpenID4VPException(error, expectedMessage: "No public key found for algorithm: Ed25519 with key use: signature", expectedCode: OpenID4VPErrorCodes.invalidRequestObject)
        }
    }
    
    func testExtractPublicKeyThrowErrorWhenMultipleEntriesAreFoundForAlgorithmAndUsage() async throws {
        let trustedVerifier = Verifier(clientId: "mock-client", responseUris: ["/response-uri"], jwksUri: "https://mock-verifier.com/jwks.json")
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(
            paramList: authRequestWithPreRegisteredByValueDraft23,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)
        ) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers: [trustedVerifier],
            authorizationRequestParameters: authorizationRequestParameters,
            walletMetadata: walletMetadata,
            shouldValidateClient: true,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager!
        )
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/jwks.json", responseBody: """
{
"keys": [{
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "alg": "EdDSA",
                    "kid": "ed-key1",
                    "x": "5tvU4k/TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc="
                },
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "alg": "EdDSA",
                    "kid": "ed-key2",
                    "x": "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2o="
                }]
}
""")
        
        
        await XCTAssertAsyncThrowsError(try await preRegistered.extractPublicKey(keyId: nil, algorithm: "EdDSA")) { error in
            assertOpenID4VPException(error, expectedMessage: "Public key extraction failed - Multiple ambiguous keys found for EdDSA with signature usage", expectedCode: OpenID4VPErrorCodes.invalidRequestObject)
        }
    }
    
    func testExtractPublicKeyThrowsWhenUntrustedClient() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(
            paramList: authRequestWithPreRegisteredByValueDraft23,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, ["client_id": "untrusted-client"])
        ) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers: preRegisteredVerifiers,
            authorizationRequestParameters: authorizationRequestParameters,
            walletMetadata: walletMetadata,
            shouldValidateClient: true,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager!
        )
        await XCTAssertAsyncThrowsError(try await preRegistered.extractPublicKey(keyId: "ed-key2", algorithm: "ECDSA")) { error in
            assertOpenID4VPException(error, expectedMessage: "Verifier is not trusted by the wallet", expectedCode: OpenID4VPErrorCodes.invalidClient)
        }
    }

    func testExtractPublicKeyThrowsWhenUntrustedClientAndNullKeyId() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(
            paramList: authRequestWithPreRegisteredByValueDraft23,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, ["client_id": "untrusted-client"])
        ) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers: preRegisteredVerifiers,
            authorizationRequestParameters: authorizationRequestParameters,
            walletMetadata: walletMetadata,
            shouldValidateClient: true,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager!
        )
        await XCTAssertAsyncThrowsError(try await preRegistered.extractPublicKey(keyId: nil, algorithm: "ECDSA")) { error in
            assertOpenID4VPException(error, expectedMessage: "Verifier is not trusted by the wallet", expectedCode: OpenID4VPErrorCodes.invalidClient)
        }
    }
    
    func testExtractPublicKeyThrowsWhenKeyIdNotFound() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(
            paramList: authRequestWithPreRegisteredByValueDraft23,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)
        ) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers: preRegisteredVerifiers,
            authorizationRequestParameters: authorizationRequestParameters,
            walletMetadata: walletMetadata,
            shouldValidateClient: true,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager!
        )
        mockNetworkManager.setMockResponse(for: jwksUri, responseBody: jwkSet)
        
        
        await XCTAssertAsyncThrowsError(try await preRegistered.extractPublicKey(keyId: "non-existent-key", algorithm: "RS256")) { error in
            assertOpenID4VPException(error, expectedMessage: "Public key extraction failed for kid: Optional(\"non-existent-key\")", expectedCode: OpenID4VPErrorCodes.invalidRequestObject)
        }
    }
    
    private func convertToJSONWebKey(_ jsonString: String) throws -> JWK {
        let data = jsonString.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(JWK.self, from: data)
        
        return decoded
    }
}
