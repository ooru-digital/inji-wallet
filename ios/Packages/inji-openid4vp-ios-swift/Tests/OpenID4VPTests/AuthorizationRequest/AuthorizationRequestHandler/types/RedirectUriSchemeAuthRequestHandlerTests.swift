import Foundation
import XCTest
@testable import OpenID4VP


class RedirectUriSchemeAuthRequestHandlerTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    let requestUri: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
    
    private var walletMetadata: WalletMetadata!
    
    override func setUpWithError() throws {
        walletMetadata = try createWalletMetadataV2()
    }
    
    func setup(){
        super.setUp()
        mockNetworkManager.clearResponses()
    }
    
    // Support for Authorization request by reference or by value
    
    func testReturnFalseForAuthorizationRequestByReferenceSupport() {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        let handler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertFalse(handler.isSignedRequestSupported(), "redirect_uri client_id_scheme should not support request by reference")
    }
    
    func testReturnTrueForAuthorizationRequestByValueSupport() {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        let handler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertTrue(handler.isUnsignedRequestSupported(), "redirect_uri client_id_scheme should support request by value")
    }
    
    /// validate and parse request fields
    
    func testThrowNoErrorForValidAuthorizationRequestWhileValidateAndParseRequestFields() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncNoThrowsError(try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields())
    }
    
    func testThrowErrorWhenClientIdIsNotEqualToResponseUriWithDirectPostResponseMode() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23, ["response_uri": "http://invalid-mock-verifier.com"])) as [String : Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce",networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "response_uri should be equal to client_id for given client_id_scheme",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowErrorWhenAuthorizationRequestObjectClientIdIsNotMatchingWithRequestParameterClientIdInDirectPostResponseMode() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23, [AuthorizationRequestFieldConstants.responseMode.rawValue: "fragment","redirect_uri": "http://invalid-mock-verifier.com"])) as [String : Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Given response_mode - fragment is not supported",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testProcessingWalletMetadataSuccessfully() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId.rawValue: "mock-client",
        ])) as [String : Any]
        let redirectScheme = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager!)
        
        var expectedWalletMetadata: WalletMetadata = walletMetadata
        expectedWalletMetadata.requestObjectSigningAlgValuesSupported = nil
        
        let processedMetadata = redirectScheme.process(walletMetadata: walletMetadata)
        
        assertDictionariesEqual(expected: convertToDictionary(object: expectedWalletMetadata)!, actual: convertToDictionary(object: processedMetadata))
    }

    func testShouldThrowErrorWhenResponseUriNotEqualToClientId() async {
        let mockClientId = "http://mock-client.com"
        let invalidResponseUri = "http://invalid-mock-client.com"
        
        let authParams: [String: Any] = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdDraft23,
                [
                    "client_id": mockClientId,
                    "client_id_scheme": "redirect_uri",
                    "response_mode": "direct_post",
                    "response_uri": invalidResponseUri,
                    "scope": "openid",
                    "response_type": "vp_token",
                    "nonce": "123456"
                ]
            )
        ) as [String : Any]
        
        let redirectUriSchemeHandler = RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters: authParams,
            walletMetadata: walletMetadata,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        
        await XCTAssertAsyncThrowsError(
            try await redirectUriSchemeHandler.validateAndParseRequestFields()
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "response_uri should be equal to client_id for given client_id_scheme",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowErrorWhenExtractPublicKeyIsInvoked() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        let handler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await handler.extractPublicKey(keyId: nil, algorithm: "edDsa")) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Public key extraction is not supported for redirect_uri client_id_scheme",
                                     expectedCode: "unsupported_operation"
            )
        }
    }
    

    func testValidateAndParseRequestFieldsSucceedsWithIarPostResponseMode() async {
        let params = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdDraft23,
                [
                    "response_mode": "iar-post",
                    "response_uri": "https://mock-verifier.com/redirect"
                ]
            )
        ) as [String : Any]

        let handler = RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters: params,
            walletMetadata: walletMetadata,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }

    func testValidateAndParseRequestFieldsSucceedsWithIarPostJwtResponseMode() async {
        let params = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdDraft23,
                [
                    "response_mode": "iar-post.jwt",
                    "response_uri": "https://mock-verifier.com/redirect"
                ]
            )
        ) as [String : Any]

        let handler = RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters: params,
            walletMetadata: walletMetadata,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }

    func testValidateAndParseRequestFieldsSucceedsWithIarPostWithoutResponseUri() async {
        let params = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdDraft23,
                ["response_mode": "iar-post"]
            )
        ) as [String : Any]

        let handler = RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters: params,
            walletMetadata: walletMetadata,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }

    func testValidateAndParseRequestFieldsSucceedsWithIarPostJwt_WithoutResponseUri() async {
        let params = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdDraft23,
                ["response_mode": "iar-post.jwt"]
            )
        ) as [String : Any]

        let handler = RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters: params,
            walletMetadata: walletMetadata,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }

    func testValidateAndParseRequestFieldsSucceedsWithIarPostMismatchedResponseUri() async {
        let params = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdDraft23,
                [
                    "response_mode": "iar-post",
                    "response_uri": "https://different.com/response"
                ]
            )
        ) as [String : Any]

        let handler = RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters: params,
            walletMetadata: walletMetadata,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }

    func testValidateAndParseRequestFieldsSucceedsWithIarPostJwtMismatchedResponseUri() async {
        let params = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdDraft23,
                [
                    "response_mode": "iar-post.jwt",
                    "response_uri": "https://different.com/response"
                ]
            )
        ) as [String : Any]

        let handler = RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters: params,
            walletMetadata: walletMetadata,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }

}
