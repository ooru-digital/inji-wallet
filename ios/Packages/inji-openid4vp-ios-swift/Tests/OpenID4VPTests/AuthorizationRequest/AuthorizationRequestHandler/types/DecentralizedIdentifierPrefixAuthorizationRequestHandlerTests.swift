import Foundation
import XCTest
@testable import OpenID4VP

class DecentralizedIdentifierPrefixAuthorizationRequestHandlerTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let decentralizedIdentifierClientId: String = ClientIdPrefix.decentralizedIdentifier.rawValue + ":"+didUrl
    let mockSetResponseDispatchInfo: (ResponseDispatchInfo) -> Void = { _ in
    }
    
    let requestUri: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!

    private var walletConfig: WalletConfig!

    override func setUpWithError() throws {
        walletConfig = createWalletConfig()
    }
    
    // Support for Authorization request by reference or by value
    
    func testReturnFalseForAuthorizationRequestByReferenceSupport() {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter)) as [String : Any]
        let handler = DecentralizedIdentifierPrefixAuthorizationRequestHandler(clientId: decentralizedIdentifierClientId, specVersion: .v1 ,authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertTrue(handler.isSignedRequestSupported(), "did client_id_prefix should support request by reference")
    }
    
    func testReturnFalseForAuthorizationRequestByValueSupport() {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter)) as [String : Any]
        let handler = DecentralizedIdentifierPrefixAuthorizationRequestHandler(clientId: decentralizedIdentifierClientId, specVersion: .v1 ,authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertFalse(handler.isUnsignedRequestSupported(), "did client_id_prefix should not support request by value")
    }
    
    // SpecVersion and VP request alignment
    func testReturnFalseWhenVPRequestDoesNotAlignWithSpecVersion() {
        // Spec Version 1.0 expects client ID decentralized_identifier:did:...
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        let authorizationRequestParametersByReference1: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.draft23]!), specVersion: .v1) as [String : Any]
        let didSchemeAuthRequestHandler1 = DecentralizedIdentifierPrefixAuthorizationRequestHandler(clientId: didUrl, specVersion: .v1 ,authorizationRequestParameters: authorizationRequestParametersByReference1, walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        
        XCTAssertFalse(didSchemeAuthRequestHandler1.confirmSpecVersionIdentifiedFromRequest(), "handler should return false when client_id does not align with spec version")
        
        // Spec version draft 23 expects Client ID did:...
        let authorizationRequestParametersByReference2: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!), specVersion: .draft23) as [String : Any]
        let didSchemeAuthRequestHandler2 = DecentralizedIdentifierPrefixAuthorizationRequestHandler(clientId: decentralizedIdentifierClientId, specVersion: .draft23 ,authorizationRequestParameters: authorizationRequestParametersByReference2, walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertFalse(didSchemeAuthRequestHandler2.confirmSpecVersionIdentifiedFromRequest(), "handler should return false when client_id does not align with spec version")
    }
    
    func testReturnTrueWhenVPRequestDoesAlignWithSpecVersion() {
        // Spec Version 1.0 expects client ID decentralized_identifier:did:...
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        let authorizationRequestParametersByReference1: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!), specVersion: .v1) as [String : Any]
        let didSchemeAuthRequestHandler1 = DecentralizedIdentifierPrefixAuthorizationRequestHandler(clientId: decentralizedIdentifierClientId, specVersion: .v1 ,authorizationRequestParameters: authorizationRequestParametersByReference1, walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        
        XCTAssertTrue(didSchemeAuthRequestHandler1.confirmSpecVersionIdentifiedFromRequest(), "handler should return true when client_id does align with spec version")
        
        // Spec version draft 23 expects Client ID did:...
        let authorizationRequestParametersByReference2: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.draft23]!), specVersion: .draft23) as [String : Any]
        let didSchemeAuthRequestHandler2 = DecentralizedIdentifierPrefixAuthorizationRequestHandler(clientId: didUrl, specVersion: .draft23 ,authorizationRequestParameters: authorizationRequestParametersByReference2, walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertTrue(didSchemeAuthRequestHandler2.confirmSpecVersionIdentifiedFromRequest(), "handler should return true when client_id does align with spec version")
    }
    
    func testExtractionOfPublicKeyFromDidClientIdSuccess() async {
        // Spec Version 1.0
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!)) as [String : Any]
        let didSchemeAuthRequestHandler = DecentralizedIdentifierPrefixAuthorizationRequestHandler(clientId: decentralizedIdentifierClientId, specVersion: .v1 ,authorizationRequestParameters: authorizationRequestParametersByReference, walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo, walletNonce: "mock-nonce", networkManager: mockNetworkManager)

        await XCTAssertNoThrowAndVerifyAsync(try await didSchemeAuthRequestHandler.extractPublicKey(keyId: JWSUtil.publicKeyId, algorithm: "EdDSA")){ publicKey in
            assertPublicKey(expectedBase64Encoded: "+Fy3lMapzR3wpaYNCFq29GDEn/NoR3pBsc511q1Cxqw=", actualKey: publicKey)
        }
        
        // Spec Version Draft 23
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        let authorizationRequestParametersByReferenceDraft23: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.draft23]!), specVersion: .draft23) as [String : Any]
        let didSchemeAuthRequestHandler2 = DecentralizedIdentifierPrefixAuthorizationRequestHandler(clientId: didUrl, specVersion: .draft23 ,authorizationRequestParameters: authorizationRequestParametersByReferenceDraft23, walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo, walletNonce: "mock-nonce", networkManager: mockNetworkManager)

        await XCTAssertNoThrowAndVerifyAsync(try await didSchemeAuthRequestHandler2.extractPublicKey(keyId: JWSUtil.publicKeyId, algorithm: "EdDSA")){ publicKey in
            assertPublicKey(expectedBase64Encoded: "+Fy3lMapzR3wpaYNCFq29GDEn/NoR3pBsc511q1Cxqw=", actualKey: publicKey)
        }
    }

    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceDoesNotContainJWTContentTypeInHeader() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!)) as [String : Any]
        let didSchemeAuthRequestHandler = DecentralizedIdentifierPrefixAuthorizationRequestHandler(clientId: decentralizedIdentifierClientId, specVersion: .v1 ,authorizationRequestParameters: authorizationRequestParametersByReference, walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, error: NetworkRequestException.networkRequestFailed(message: "Response does not match any acceptable types"))

        await XCTAssertAsyncThrowsError(try await didSchemeAuthRequestHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Authorization Request Object must have content type 'application/oauth-authz-req+jwt'",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testProcessingWalletMetadataSuccessfully() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId: "mock-client",
        ])) as [String : Any]
        let didScheme = DecentralizedIdentifierPrefixAuthorizationRequestHandler(clientId: decentralizedIdentifierClientId, specVersion: .v1 ,authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo, walletNonce: "mock-nonce", networkManager: mockNetworkManager!)
        let expectedWalletMetadata : [String: Any] = [
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

        let processedMetadata = try didScheme.getWalletMetadata(walletConfig: walletConfig)

        assertDictionariesEqual(expected: expectedWalletMetadata, actual: (processedMetadata))
    }

    func testShouldThrowErrorForWalletMetadataProcessingWhenRequestObjectSigningAlgValuesSupportedisNil() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId: "mock-client",
        ])) as [String : Any]

        let walletConfig = createWalletConfig(requestObjectSigningAlgValuesSupported: nil)

        let didScheme = DecentralizedIdentifierPrefixAuthorizationRequestHandler(clientId: decentralizedIdentifierClientId, specVersion: .v1 ,authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo, walletNonce: "mock-nonce", networkManager: mockNetworkManager!)

        await XCTAssertAsyncThrowsError(try didScheme.getWalletMetadata(walletConfig: walletConfig)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "request_object_signing_alg_values_supported is not present in wallet metadata.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
