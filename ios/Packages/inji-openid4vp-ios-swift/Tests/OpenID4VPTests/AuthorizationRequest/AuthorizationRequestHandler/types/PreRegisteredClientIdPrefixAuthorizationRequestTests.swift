import Foundation
import XCTest
import JSONWebKey
@testable import OpenID4VP

class PreRegisteredClientIdPrefixTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockNetworkManagerReal: NetworkManager! = NetworkManager()
    let clientId: String = "mock-client"
    let mockSetResponseDispatchInfo: (ResponseDispatchInfo) -> Void = { _ in
    }
    
    let requestUriResponse: String = createAuthorizationRequestObject(clientIdPrefix: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,[
        AuthorizationRequestFieldConstants.clientId: "mock-client",
    ]), applicableFields: authRequestWithPreRegisteredByValue)
    let requestUri: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
    
    private var walletConfig: WalletConfig!
    
    override func setUpWithError() throws {
        walletConfig = createWalletConfig()
    }
    
    //     Validate client tests
    
    func testThrowExceptionWhenClientIdIsNotAvailableAsTrustedVerifier(){
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId: "untrusted-mock-client",
        ])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: "untrusted-mock-client", specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig,setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertThrowsError(try preRegistered.validateClientId()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Verifier is not trusted by the wallet",
                expectedCode: OpenID4VPErrorCodes.invalidClient
            )
        }
    }
    
    
    func testThrowExceptionWhenTrustedVerifiersListIsEmpty(){
        let authorizationRequestParameters: [String : Any] = [AuthorizationRequestFieldConstants.clientId: "other-mock-client","response_uri": "https://mock-verifier.com"]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: "other-mock-client", specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig,setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertThrowsError(try preRegistered.validateClientId()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Verifier is not trusted by the wallet",
                expectedCode: OpenID4VPErrorCodes.invalidClient
            )
        }
    }
    
    func testThrowErrorWhenBothResponseUriAndRedirectUriPresentForDirectPost() {
        var authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters)) as [String : Any]
        authorizationRequestParameters[AuthorizationRequestFieldConstants.redirectUri] = "https://mock-verifier.com"
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: clientId, specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig,setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager)

        XCTAssertThrowsError(try preRegistered.prepareDispatchInfo()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "redirect_uri should not be present for given response_mode",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // Support for Authorization request by reference or by value

    func testReturnTrueForAuthorizationRequestByReferenceSupport() {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters)) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: clientId, specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig,setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertTrue(preRegistered.isSignedRequestSupported(), "Pre-registered client id scheme should support authorization request by reference")
    }
    
    
    func testisUnsignedRequestSupported_validatePreregisteredVerifierFalse_returnsTrue() {
        let authorizationRequestParameters: [String : Any] = [AuthorizationRequestFieldConstants.clientId: "mock-client"]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: clientId, specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: createWalletConfig(validatePreregisteredVerifier: false), setResponseDispatchInfo: mockSetResponseDispatchInfo, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        XCTAssertTrue(try preRegistered.isUnsignedRequestSupported(), "Should return true when validatePreregisteredVerifier is false")
    }
    
    func testisUnsignedRequestSupported_validatePreregisteredVerifierTrue_clientIdNotAvailable_throwsError() {
        let authorizationRequestParameters: [String : Any] = [AuthorizationRequestFieldConstants.clientId: "untrusted-client"]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: "untrusted-client", specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig,setResponseDispatchInfo: mockSetResponseDispatchInfo, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertThrowsError(try preRegistered.isUnsignedRequestSupported()) { error in
            assertOpenID4VPException(error, expectedMessage: "Verifier is not trusted by the wallet", expectedCode: OpenID4VPErrorCodes.invalidClient)
        }
    }
    
    func testisUnsignedRequestSupported_validatePreregisteredVerifierTrue_clientIdAvailable_allowUnsignedFalse_returnsFalse() {
        let trustedVerifiers = [Verifier(clientId: "mock-client", responseUris: ["https://mock-verifier.com"], allowUnsignedRequest: false)]
        let authorizationRequestParameters: [String : Any] = [AuthorizationRequestFieldConstants.clientId: "mock-client"]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: clientId, specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: createWalletConfig(trustedVerifiers: trustedVerifiers),setResponseDispatchInfo: mockSetResponseDispatchInfo, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        XCTAssertFalse(try preRegistered.isUnsignedRequestSupported(), "Should return false when allowUnsignedRequest is false")
    }
    
    func testisUnsignedRequestSupported_validatePreregisteredVerifierTrue_clientIdAvailable_allowUnsignedTrue_returnsTrue() {
        let trustedVerifiers = [Verifier(clientId: "mock-client", responseUris: ["https://mock-verifier.com"], allowUnsignedRequest: true)]
        let authorizationRequestParameters: [String : Any] = [AuthorizationRequestFieldConstants.clientId: "mock-client"]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: clientId, specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: createWalletConfig(trustedVerifiers: trustedVerifiers),setResponseDispatchInfo: mockSetResponseDispatchInfo, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        XCTAssertTrue(try preRegistered.isUnsignedRequestSupported(), "Should return true when allowUnsignedRequest is true")
    }
    
    
    
    // Validate and parse authorization request - check if verifier is trusted
    
    func testDoesNotThrowExceptionWhenTrustedVerifierDoesNotHaveClientMetadataAndAuthorizationRequestContainsClientMetadata() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue,preRegisteredSchemeClientIdParameters), addEncryptionClientMetadataParams: false) as [String : Any]
        let trustedVerifiersWithoutClientMetadata = [
            Verifier(clientId: "mock-client", responseUris: ["https://mock-verifier.com"])
        ]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: clientId, specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: createWalletConfig(trustedVerifiers: trustedVerifiersWithoutClientMetadata),setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncNoThrowsError(try await preRegistered.validateAndParseRequestFields(), "Error should not happen when client_metadata is not known to wallet but provided in authorization request")
    }
    
    /// Fetch authorization request by value - validate authorization request object and authorization request query paramaters - spec version draft 23
    
    func testFetchAuthorizationRequestOnValidPreRegisteredSchemeAuthRequestSentByValue() async{
        let expectedAuthorizationRequestParameters: [String : Any] = [
            "response_mode": "direct_post",
            "response_type": "vp_token",
            "client_id": "mock-client",
            "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
            "state": "+mRQe1d6pBoJqF6Ab28klg==",
            "response_uri": "https://mock-verifier.com",
            "client_metadata": (clientMetadataSpecVersionDraft23),
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
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
        ]), specVersion: .draft23) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: clientId, specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig,setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        try? await preRegistered.fetchAuthorizationRequest()
        
        assertDictionariesEqual(expected: expectedAuthorizationRequestParameters, actual: preRegistered.authorizationRequestParameters)
    }
    
    func testProcessingWalletMetadataSuccessfully()async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId: "mock-client",
        ])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: clientId, specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig,setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager!)
        
        let expectedWalletMetadata = [
            "authorization_encryption_alg_values_supported": ["ECDH-ES"],
            "request_object_signing_alg_values_supported": ["EdDSA"],
            "authorization_encryption_enc_values_supported": ["A256GCM"],
            "response_types_supported": ["vp_token"],
            "client_id_prefixes_supported": ["pre-registered", "redirect_uri", "decentralized_identifier"],
            "vp_formats_supported": [
                "mso_mdoc": [:],
                "dc+sd-jwt": [:],
                "ldp_vc": [
                    "proof_type_values": ["Ed25519Signature2020", "JsonWebSignature2020"]
                ]
            ]
        ] as [String : Any]
        
        let processedMetadata = try preRegistered.getWalletMetadata(walletConfig: walletConfig)
        
        assertDictionariesEqual(expected: expectedWalletMetadata, actual: (processedMetadata))
    }
    
    func testShouldThrowErrorForWalletMetadataProcessingWhenRequestObjectSigningAlgValuesSupportedisNil() async throws {
        let walletConfig = createWalletConfig(requestObjectSigningAlgValuesSupported: nil)
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId: "mock-client",
        ])) as [String : Any]
        
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: clientId, specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig,setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager!)
        
        await XCTAssertAsyncThrowsError(try preRegistered.getWalletMetadata(walletConfig: walletConfig)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "request_object_signing_alg_values_supported is not present in wallet metadata.",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testExtractPublicKeyThrowErrorWhenPreRegisteredClientNotAvailable() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue, requestParams: mergeMaps(authorizationRequestParamsWithValue, ["client_id": "untrusted-client"])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: "untrusted-client", specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig,setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager!)
        
        await XCTAssertAsyncThrowsError(try await preRegistered.extractPublicKey(keyId: "ed-key2", algorithm: "ECDSA")){ error in
            assertOpenID4VPException(error, expectedMessage: "Verifier is not trusted by the wallet", expectedCode: OpenID4VPErrorCodes.invalidClient)
        }
    }
    
    // clientMetadata available for trusted verifiers does not have jwks
    func testExtractPublicKeyThrowErrorWhenJwksUriNotAvailable() async throws {
        let trustedVerifiers = [
            Verifier(clientId: "mock-client", responseUris: ["https://mock-verifier.com"])
        ]
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters)) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: clientId, specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: createWalletConfig(trustedVerifiers: trustedVerifiers),setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager!)
        
        
        await XCTAssertAsyncThrowsError(try await preRegistered.extractPublicKey(keyId: "ed-key2", algorithm: "EdDSA")){ error in
            assertOpenID4VPException(error, expectedMessage: "Public key extraction failed - Public key information not available in pre-registered data to verify the signed Authorization Request", expectedCode: OpenID4VPErrorCodes.invalidRequestObject)
        }
    }
    
    func testClientIdPrefixShouldReturnPreRegistered(){
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters)) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: clientId, specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig,setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertEqual(preRegistered.clientIdPrefix(), ClientIdPrefix.preRegistered.rawValue, "clientIdPrefix should return pre-registered")
    }
    
    
    func testExtractPublicKeySuccessForKeyId() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(
            paramList: authRequestWithPreRegisteredByValue,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters)
        ) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: clientId, specVersion: .v1,
                                                                           
                                                                           authorizationRequestParameters: authorizationRequestParameters,
                                                                           walletConfig: walletConfig,
                                                                           setResponseDispatchInfo: mockSetResponseDispatchInfo,
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
            paramList: authRequestWithPreRegisteredByValue,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters)
        ) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: clientId, specVersion: .v1,
                                                                           authorizationRequestParameters: authorizationRequestParameters,
                                                                           walletConfig: createWalletConfig(trustedVerifiers: [trustedVerifier]),
                                                                           setResponseDispatchInfo: mockSetResponseDispatchInfo,
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
            paramList: authRequestWithPreRegisteredByValue,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters)
        ) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: clientId, specVersion: .v1,
                                                                           authorizationRequestParameters: authorizationRequestParameters,
                                                                           walletConfig: createWalletConfig(trustedVerifiers: [trustedVerifier]),
                                                                           setResponseDispatchInfo: mockSetResponseDispatchInfo,
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
            paramList: authRequestWithPreRegisteredByValue,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters)
        ) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: clientId, specVersion: .v1,
                                                                           authorizationRequestParameters: authorizationRequestParameters,
                                                                           walletConfig: createWalletConfig(trustedVerifiers: [trustedVerifier]),
                                                                           setResponseDispatchInfo: mockSetResponseDispatchInfo,
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
            paramList: authRequestWithPreRegisteredByValue,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, ["client_id": "untrusted-client"])
        ) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: "untrusted-client", specVersion: .v1,
                                                                           
                                                                           authorizationRequestParameters: authorizationRequestParameters,
                                                                           walletConfig: walletConfig,
                                                                           setResponseDispatchInfo: mockSetResponseDispatchInfo,
                                                                           walletNonce: "mock-nonce",
                                                                           networkManager: mockNetworkManager!
        )
        await XCTAssertAsyncThrowsError(try await preRegistered.extractPublicKey(keyId: "ed-key2", algorithm: "ECDSA")) { error in
            assertOpenID4VPException(error, expectedMessage: "Verifier is not trusted by the wallet", expectedCode: OpenID4VPErrorCodes.invalidClient)
        }
    }
    
    func testExtractPublicKeyThrowsWhenUntrustedClientAndNullKeyId() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(
            paramList: authRequestWithPreRegisteredByValue,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, ["client_id": "untrusted-client"])
        ) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: "untrusted-client", specVersion: .v1,
                                                                           
                                                                           authorizationRequestParameters: authorizationRequestParameters,
                                                                           walletConfig: walletConfig,
                                                                           setResponseDispatchInfo: mockSetResponseDispatchInfo,
                                                                           walletNonce: "mock-nonce",
                                                                           networkManager: mockNetworkManager!
        )
        await XCTAssertAsyncThrowsError(try await preRegistered.extractPublicKey(keyId: nil, algorithm: "ECDSA")) { error in
            assertOpenID4VPException(error, expectedMessage: "Verifier is not trusted by the wallet", expectedCode: OpenID4VPErrorCodes.invalidClient)
        }
    }
    
    func testExtractPublicKeyThrowsWhenKeyIdNotFound() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(
            paramList: authRequestWithPreRegisteredByValue,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters)
        ) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(clientId: clientId, specVersion: .v1,
                                                                           
                                                                           authorizationRequestParameters: authorizationRequestParameters,
                                                                           walletConfig: walletConfig,
                                                                           setResponseDispatchInfo: mockSetResponseDispatchInfo,
                                                                           walletNonce: "mock-nonce",
                                                                           networkManager: mockNetworkManager!
        )
        mockNetworkManager.setMockResponse(for: jwksUri, responseBody: jwkSet)
        
        
        await XCTAssertAsyncThrowsError(try await preRegistered.extractPublicKey(keyId: "non-existent-key", algorithm: "RS256")) { error in
            assertOpenID4VPException(error, expectedMessage: "Public key extraction failed for kid: Optional(\"non-existent-key\")", expectedCode: OpenID4VPErrorCodes.invalidRequestObject)
        }
    }
    
    func testValidateClientAuthenticity_validateTrustedVerifierFalse_doesNotThrow() {
        let authorizationRequestParameters: [String: Any] = [
            AuthorizationRequestFieldConstants.clientId: "mock-client",
            AuthorizationRequestFieldConstants.responseUri: "https://some-unregistered-uri.com"
        ]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId: clientId,
            specVersion: .v1,
            authorizationRequestParameters: authorizationRequestParameters,
            walletConfig: createWalletConfig(validatePreregisteredVerifier: false),
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        XCTAssertNoThrow(try preRegistered.validateClientAuthenticity())
    }

    func testValidateClientAuthenticity_responseUriMatchesTrustedVerifier_doesNotThrow() {
        let authorizationRequestParameters: [String: Any] = [
            AuthorizationRequestFieldConstants.clientId: "mock-client",
            AuthorizationRequestFieldConstants.responseUri: "https://mock-verifier.com"
        ]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId: clientId,
            specVersion: .v1,
            authorizationRequestParameters: authorizationRequestParameters,
            walletConfig: walletConfig,
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        XCTAssertNoThrow(try preRegistered.validateClientAuthenticity())
    }

    func testValidateClientAuthenticity_responseUriNotInTrustedVerifier_throwsInvalidVerifier() {
        let authorizationRequestParameters: [String: Any] = [
            AuthorizationRequestFieldConstants.clientId: "mock-client",
            AuthorizationRequestFieldConstants.responseUri: "https://untrusted-uri.com"
        ]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId: clientId,
            specVersion: .v1,
            authorizationRequestParameters: authorizationRequestParameters,
            walletConfig: walletConfig,
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        XCTAssertThrowsError(try preRegistered.validateClientAuthenticity()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "response_uri trust cannot be established",
                expectedCode: OpenID4VPErrorCodes.invalidClient
            )
        }
    }

    func testValidateClientAuthenticity_clientIdNotInTrustedVerifiers_throwsInvalidVerifier() {
        let authorizationRequestParameters: [String: Any] = [
            AuthorizationRequestFieldConstants.clientId: "untrusted-client",
            AuthorizationRequestFieldConstants.responseUri: "https://mock-verifier.com"
        ]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId: "untrusted-client",
            specVersion: .v1,
            authorizationRequestParameters: authorizationRequestParameters,
            walletConfig: walletConfig,
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        XCTAssertThrowsError(try preRegistered.validateClientAuthenticity()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Verifier is not trusted by the wallet",
                expectedCode: OpenID4VPErrorCodes.invalidClient
            )
        }
    }

    func testValidateClientAuthenticity_responseUriMissingInRequest_throwsMissingInput() {
        let authorizationRequestParameters: [String: Any] = [
            AuthorizationRequestFieldConstants.clientId: clientId
        ]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId: clientId,
            specVersion: .v1,
            authorizationRequestParameters: authorizationRequestParameters,
            walletConfig: walletConfig,
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        XCTAssertThrowsError(try preRegistered.validateClientAuthenticity()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing Input: response_uri param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testValidateClientAuthenticity_responseUriNotAvailableInTrsutedList_throwsInvalidVerifier() {
        let authorizationRequestParameters: [String: Any] = [
            AuthorizationRequestFieldConstants.clientId: clientId,
            AuthorizationRequestFieldConstants.responseUri: "https://mock-verifier.com"
        ]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId: clientId,
            specVersion: .v1,
            authorizationRequestParameters: authorizationRequestParameters,
            walletConfig: createWalletConfig(trustedVerifiers: [Verifier(clientId: clientId, responseUris: ["https://some-other-verifier.com"])]),
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        XCTAssertThrowsError(try preRegistered.validateClientAuthenticity()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "response_uri trust cannot be established",
                expectedCode: OpenID4VPErrorCodes.invalidClient
            )
        }
    }

    private func convertToJSONWebKey(_ jsonString: String) throws -> JWK {
        let data = jsonString.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(JWK.self, from: data)
        
        return decoded
    }
}
