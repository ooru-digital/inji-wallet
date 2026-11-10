import Foundation
import XCTest
@testable import OpenID4VP




class ClientIdSchemeBasedAuthorizationRequestTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    var decodedClientMetadata: ClientMetadata?
    var decodedPresentationDefinition: PresentationDefinition?
    
    private var walletMetadata: WalletMetadata!
    
    override func setUpWithError() throws {
        walletMetadata = try createWalletMetadataV2()
    }
    
    override func setUp() {
        super.setUp()
        mockNetworkManager.clearResponses()
    }
    
    ///    Fetch authorization request tests
    
    
    /** Authorization Request passed as URL with encoded params */
    
    func testShouldProceedSuccessfullyWhenAuthorizationRequestIsPassedAsUrlEncodedParams() async {
        let authorizationRequestParametersByValue: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)) as [String : Any]
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByValue, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler.fetchAuthorizationRequest())
    }
    
    
    func testShouldThrowErrorWhenAuthorizationRequestByValueIsNotSupported() async {
        let authorizationRequestParametersByValue: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)) as [String : Any]
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByValue, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager, isUnsignedRequestSupported: false)
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "unsigned request is not supported for given client_id_scheme - pre-registered",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
        
    /** Passing a request object as value **/
    
    func testShouldProceedSuccessfullyWhenAuthorizationRequestIsAvailableInRequestParamAndSignedRequestIsSupported() async {
        let authorizationRequestParametersByValue: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23), isSigned: true) as [String : Any]
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByValue, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager, isUnsignedRequestSupported: false)
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler.fetchAuthorizationRequest())
    }
    
    func testShouldThrowErrorWhenClientIdIsMismatchedBetweenRequestObjectAndParameters() async {
        let authorizationRequestParametersByValue: [String : Any] = mergeMaps(
            createAuthorizationRequest(
                paramList: authRequestWithRedirectUriByValue ,
                requestParams: mergeMaps(authorizationRequestParamsWithValue), // if client id is not sent in requestparams function parameter "" is added in the signed request object
                isSigned: true),
            DidSchemeClientIdDraft23 // attach client id in the request params to simulate the mismatch
        ) as [String : Any]
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByValue, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager, isUnsignedRequestSupported: false)
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Client Id mismatch in Authorization Request parameter and the Request Object",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testSouldThrowErrorWhenRequestValueIsInvalid() async {
        let authorizationRequestParametersByValue: [String : Any] = [
            AuthorizationRequestFieldConstants.request.rawValue: "",
            AuthorizationRequestFieldConstants.clientId.rawValue: "mock-client-id"
        ]
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByValue, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Invalid Input: request value cannot be empty or null",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testShouldThrowErrorWhenClientIdSchemeDoesNotSupportSignedRequestButInputHasSignedRequestViRequestParameter() async {
        let authorizationRequestParametersByValue: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23), isSigned: true) as [String : Any]
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByValue, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager, isSignedRequestSupported: false)
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Signed request (via request) is not supported for given client_id_scheme - did",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    /** Passing a request object by reference **/
    
    func testFetchAuthorizationRequestByReferenceWhenRespectiveClientIdSchemeSupportsSignedRequest() async{
        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdScheme: .did,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23),
            applicableFields: authRequestWithRedirectUriByValue
        )
        let authorizationRequestParameters = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString,responseBody: authorizationRequestObject)
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler.fetchAuthorizationRequest(), "Failed to fetch authorization request")
    }
    
    func testShouldThrowErrorWhenAuthorizationRequestIsPassedByReferenceAndSignedRequestIsNotSupported() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager, isSignedRequestSupported: false)
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Signed request (via request_uri) is not supported for given client_id_scheme - redirect_uri",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testShouldMakeApiCallToRequestUriGetWithCorrectAcceptType() async {
        mockNetworkManager.clearResponses()
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23, ["request_uri_method": "get"])) as [String : Any]
        let requestUriResponse = createRequestUriResponse(createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23, ["wallet_nonce": "mock-nonce"]), applicableFields: authRequestWithDidByValue + ["wallet_nonce"]) )
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler.fetchAuthorizationRequest())
        
        mockNetworkManager.recordedRequests.forEach { (url, recordedRequest) in
            if (url == requestUri.absoluteString) {
                XCTAssertEqual(recordedRequest.requestMethod, HttpMethod.get, "Expected HTTP method to be POST")
                XCTAssertEqual(recordedRequest.requestHeaders?["Accept"], ContentTypes.applicationJwt.rawValue, "Expected Accept header to be \(ContentTypes.applicationJwt.rawValue)")
            }
        }
    }
    
    func testShouldMakeApiCallToRequestUriPostWithCorrectAcceptTypeAndContentTypeWhenWalletMetadataIsAvailable() async {
        mockNetworkManager.clearResponses()
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23, ["request_uri_method": "post"])) as [String : Any]
        let requestUriResponse = createRequestUriResponse(createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23, ["wallet_nonce": "mock-nonce"]), applicableFields: authRequestWithDidByValue + ["wallet_nonce"]) )
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler.fetchAuthorizationRequest())
        
        mockNetworkManager.recordedRequests.forEach { (url, recordedRequest) in
            if (url == requestUri.absoluteString) {
                XCTAssertEqual(recordedRequest.requestMethod, HttpMethod.post, "Expected HTTP method to be POST")
                XCTAssertEqual(recordedRequest.requestHeaders?["Accept"], ContentTypes.applicationJwt.rawValue, "Expected Accept header to be \(ContentTypes.applicationJwt.rawValue)")
                XCTAssertEqual(recordedRequest.requestHeaders?["Content-Type"], ContentTypes.applicationFormUrlEncoded.rawValue, "Expected Content-Type header to be \(ContentTypes.applicationFormUrlEncoded.rawValue)")
                XCTAssertEqual(recordedRequest.requestBody?["wallet_nonce"], "mock-nonce", "Expected wallet_nonce in request body to be mock-nonce")
                XCTAssertTrue(recordedRequest.requestBody?["wallet_metadata"] != nil, "Expected wallet_metadata in request body to be present")
            }
        }
    }
    
    func testShouldMakeApiCallToRequestUriPostWithCorrectAcceptTypeAndContentTypeWhenWalletMetadataIsNotAvailable() async {
        mockNetworkManager.clearResponses()
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23, ["request_uri_method": "post"])) as [String : Any]
        let requestUriResponse = createRequestUriResponse(createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23, ["wallet_nonce": "mock-nonce"]), applicableFields: authRequestWithDidByValue + ["wallet_nonce"]) )
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: nil, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler.fetchAuthorizationRequest())
        
        mockNetworkManager.recordedRequests.forEach { (url, recordedRequest) in
            if (url == requestUri.absoluteString) {
                XCTAssertEqual(recordedRequest.requestMethod, HttpMethod.post, "Expected HTTP method to be POST")
                XCTAssertEqual(recordedRequest.requestHeaders?["Accept"], ContentTypes.applicationJwt.rawValue, "Expected Accept header to be \(ContentTypes.applicationJwt.rawValue)")
                XCTAssertEqual(recordedRequest.requestHeaders?["Content-Type"], ContentTypes.applicationFormUrlEncoded.rawValue, "Expected Content-Type header to be \(ContentTypes.applicationFormUrlEncoded.rawValue)")
                XCTAssertEqual(recordedRequest.requestBody?["wallet_nonce"], "mock-nonce", "Expected wallet_nonce in request body to be mock-nonce")
            }
        }
    }
    
    func testThrowExceptionWhenRequestUriResponseJWTHeaderExtractionFails() async {
        mockNetworkManager.clearResponses()
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23, ["request_uri_method": "post"])) as [String : Any]
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: "eyJ0eXAiOi&vYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJzaWcta2V5MSJ9.eyJjbGllbnRfaWQiOiJtb2NrLWNsaWVudCIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uX3VyaSI6Imh0dHBzOi8vYTc4NzI2ODg0Y2ZmLm5ncm9rLWZyZWUuYXBwL3ZlcmlmaWVyL3ByZXNlbnRhdGlvbl9kZWZpbml0aW9uX3VyaSIsInJlc3BvbnNlX3R5cGUiOiJ2cF90b2tlbiIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJub25jZSI6IkVlOElGV1A5c1kxbEVrQ3VQYUorcXc9PSIsInN0YXRlIjoiYmhNUG1WYWRKTnlLYTYzVmludmdIdz09IiwicmVzcG9uc2VfdXJpIjoiaHR0cHM6Ly9hNzg3MjY4ODRjZmYubmdyb2stZnJlZS5hcHAvdmVyaWZpZXIvdnAtcmVzcG9uc2UifQ.qkdv4np_sfq86sS1f78g3BIXTBXYXe1vWE2nLESGCOGLpbOASTccVcw5l-DIDHpfbCEplMAevO5g0xwoKGh4Aw", httpUrlResponse: httpUrlResponseForJWS))
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Request URI response validation failed - JWS header extraction failed: Base64 decoding failed",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequestObject
            )
        }
    }
    
    func testThrowExceptionWhenRequestUriResponseIsNot2xx() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        
        let requestUriResponse = createRequestUriResponse("{\"message\" : \"Invalid request\"}", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 400, httpVersion: "", headerFields: ["Content-Type": "application/json"])!)
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Unknown error occurred Error while fetching request_uri: Error while fetching request_uri: HTTP status code 400 & body: {\"message\" : \"Invalid request\"}",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowExceptionWhenRequestUriResponseContentTypeIsNotJWT() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        
        let requestUriResponse = createRequestUriResponse("non-jwt", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/json"])!)
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, error: NetworkRequestException.networkRequestFailed(message: "Response does not match any acceptable types"))
        
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Authorization Request Object must have content type 'application/oauth-authz-req+jwt'",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowExceptionWhenRequestUriResponseReturnNetworkRequestException() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        
        let requestUriResponse = createRequestUriResponse("non-jwt", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/json"])!)
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, error: NetworkRequestException.networkRequestFailed(message: "Something went wrong"))
        
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Unknown error occurred Network error while fetching request_uri: Network request failed with error response - Something went wrong",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowExceptionWhenRequestUriResponseReturnAnyException() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        
        let requestUriResponse = createRequestUriResponse("non-jwt", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/json"])!)
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, error: NetworkRequestException.networkRequestFailed(message: "Something went wrong"))
        
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Unknown error occurred Network error while fetching request_uri: Network request failed with error response - Something went wrong",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowExceptionWhenRequestUriResponseIsNotJWT() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        
        let requestUriResponse = createRequestUriResponse("non-jwt")
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Authorization Request Object must be a signed JWT",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowExceptionWhenRequestUriResponseHasDifferentValueThanAuthorizationRequestParameters() async throws {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        
        let authorizationRequestObject = createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, ["client_id": "did:web:hacker-verifier.com"]))
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, response: (authorizationRequestObject, httpUrlResponseForJWS))
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)
        
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Client Id mismatch in Authorization Request parameter and the Request Object",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowErrorWhenWalletNonceAvailableInTheRequestUriResponseIsNotSameAsTheWalletSentNonce() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23, ["request_uri_method": "post"])) as [String : Any]
        
        let authorizationRequestObject = createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,DidSchemeClientIdDraft23, [
            "wallet_nonce": "some-other-nonce",
        ]))
        let requestUriResponse = createRequestUriResponse(authorizationRequestObject)
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString,response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)
        
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "wallet_nonce provided in the authorization request is not the same as shared by wallet",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowErrorWhenPublicKeyReslutionFailedForValidatingRequestUriResponse() async throws {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        
        let authorizationRequestObject = createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23))
        let requestUriResponse = createRequestUriResponse(authorizationRequestObject)
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString,response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        mockAuthHandler.setExtractPublicKeyError(error: PublicKeyResolutionFailed(
            message: "Public key extraction failed for kid: did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0",
            className: "mock"
        ))
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Request URI response validation failed - Public key extraction failed for kid: did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequestObject
            )
        }
    }
    
    func testThrowErrorWhenRequestUriReponseJWTHeaderDoesNotHaveAlgClaim() async throws {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        
        let jwtWithNoAlgClaim = "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"
        let requestUriResponse = createRequestUriResponse(jwtWithNoAlgClaim)
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString,response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Request URI response validation failed - alg is not present in JWS header",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequestObject
            )
        }
    }
    
    func testFetchAuthoruizationRequestPopulateAuthorizationRequestFieldWithRequestUriResponseWhenAllValidationsSucceeds() async{
        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdScheme: .did,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23),
            applicableFields: authRequestWithDidByValue
        )
        let authorizationRequestParameters = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, responseBody: authorizationRequestObject)
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler.fetchAuthorizationRequest(), "Failed to fetch authorization request")
        
        let expected: [String: Any] = [
            "client_id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
            "presentation_definition": [
                "id": "vp_presentation_definition",
                "input_descriptors": [
                    [
                        "constraints": [
                            "fields": [
                                [
                                    "filter": [
                                        "pattern": "@gmail.com",
                                        "type": "string"
                                    ],
                                    "path": ["$.credentialSubject.email"]
                                ]
                            ]
                        ],
                        "format": [
                            "ldp_vc": [
                                "proof_type": [
                                    "Ed25519Signature2018",
                                    "RsaSignature2018"
                                ]
                            ]
                        ],
                        "id": "input_1",
                        "name": "Verifiable Credential",
                        "purpose": "To verify identity using Linked Data Proofs"
                    ]
                ]
            ],
            "response_uri": "https://mock-verifier.com",
            "client_metadata": [
                "authorization_encrypted_response_alg": "ECDH-ES",
                "authorization_encrypted_response_enc": "A256GCM",
                "client_name": "Requester name",
                "jwks": [
                    "keys": [
                        [
                            "alg": "ECDH-ES",
                            "crv": "X25519",
                            "kid": "ed-key1",
                            "kty": "OKP",
                            "use": "enc",
                            "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4"
                        ],
                        [
                            "alg": "EdDSA",
                            "crv": "Ed25519",
                            "kid": "ed-key2",
                            "kty": "OKP",
                            "use": "sig",
                            "x": "5tvU4k_TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc"
                        ]
                    ]
                ],
                "logo_uri": "https://mock-verifier.com/logo",
                "vp_formats": [
                    "ldp_vp": [
                        "proof_type": [
                            "Ed25519Signature2018",
                            "Ed25519Signature2020"
                        ]
                    ]
                ]
            ],
            "state": "+mRQe1d6pBoJqF6Ab28klg==",
            "response_mode": "direct_post",
            "response_type": "vp_token",
            "nonce": "VbRRB/LTxLiXmVNZuyMO8A=="
        ]
        assertDictionariesEqual(expected: expected, actual: mockAuthHandler.authorizationRequestParameters)
    }
    
    
    func testFetchAuthorizationRequestByReferenceAndRequestUriMethodIsPostPassWalletMetadata() async{
        var authorizationRequestWithPostRequestUriMethod = authorizationRequestParamsWithValue
        authorizationRequestWithPostRequestUriMethod[AuthorizationRequestFieldConstants.requestUriMethod.rawValue] = "post"
        
        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdScheme: .preRegistered,
            authorizationRequestParams: mergeMaps(authorizationRequestWithPostRequestUriMethod, DidSchemeClientIdDraft23, ["wallet_nonce": "mock-nonce"]),
            applicableFields: authRequestWithRedirectUriByValue + ["wallet_nonce"]
        )
        let authorizationRequestParameters = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestWithPostRequestUriMethod, DidSchemeClientIdDraft23)) as [String : Any]
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",responseBody: authorizationRequestObject)
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler.fetchAuthorizationRequest(), "Failed to fetch authorization request")
        
        let recordedBody = mockNetworkManager.recordedRequests["https://mock-verifier.com/verifier/get-auth-request-obj"]?.requestBody
        XCTAssertNotNil(recordedBody?["wallet_metadata"], "Expected wallet_metadata to be present in the request body")
    }
    
    func testFetchAuthorizationRequestByValueWithRequestUriMethodNotAvailableInAuthorizationRequestProvided() async{
        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdScheme: .redirectUri,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23),
            applicableFields: authRequestWithRedirectUriByValue
        )
        let authorizationRequestParameters = createAuthorizationRequest(paramList: [AuthorizationRequestFieldConstants.clientId.rawValue, "request_uri"] , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, responseBody: authorizationRequestObject)
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertNoThrowAndVerifyAsync(try await mockAuthHandler.fetchAuthorizationRequest()) {
            XCTAssertEqual(mockNetworkManager.recordedRequests[requestUri.absoluteString]?.requestMethod, .get, "Expected HTTP method to be GET when request_uri_method is not provided")
        }
    }
    
    ///   Authorization request obtained by value: gives all data as url encoded (presentation_definition is also obtained by value)
    
    func testFetchAuthorizationRequestByValue() async{
        let authorizationRequestParameters: [String: Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue.map { $0 == "presentation_definition" ? "presentation_definition_uri" : $0 } , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        do{
            try await mockAuthHandler.fetchAuthorizationRequest()
            
            assertDictionariesEqual(expected: [
                "state": "+mRQe1d6pBoJqF6Ab28klg==",
                "response_type": "vp_token",
                "response_uri": "https://mock-verifier.com",
                "response_mode": "direct_post",
                "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
                "client_id": "redirect_uri:https://mock-verifier.com",
                "presentation_definition_uri": "https://mock-verifier.com/presentation-definition",
                "client_metadata": [
                    "client_name": "Requester name",
                    "authorization_encrypted_response_enc": "A256GCM",
                    "authorization_encrypted_response_alg": "ECDH-ES",
                    "jwks": [
                        "keys": [
                            [
                                "kty": "OKP",
                                "crv": "X25519",
                                "use": "enc",
                                "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                                "alg": "ECDH-ES",
                                "kid": "ed-key1"
                            ],
                            [
                                "kty": "OKP",
                                "crv": "Ed25519",
                                "use": "sig",
                                "x": "5tvU4k_TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc",
                                "alg": "EdDSA",
                                "kid": "ed-key2"
                            ]]
                    ],
                    "vp_formats": [
                        "ldp_vp": [
                            "proof_type": ["Ed25519Signature2018", "Ed25519Signature2020"]
                        ]
                    ],
                    "logo_uri": "https://mock-verifier.com/logo"
                ],
            ], actual: mockAuthHandler.authorizationRequestParameters)
        } catch {
            XCTFail("Error should not occur but got error \(error) - \(error.localizedDescription)")
        }
    }
    
    func testFetchAuthRequestShouldThrowErrorWhenRequestUriIsNotHttpsScheme() async{
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23,["request_uri": "http://invalid-mock-verifier.com"])) as [String : Any]
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "request_uri http://invalid-mock-verifier.com data is not valid",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
            
        }
    }
    
    func testShouldThrowErrorWhenAuthRequestsAlgObtainedByReferenceDoesNotMatchWithWalletMetadata() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        let mockSchemeAuthRequestHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        mockSchemeAuthRequestHandler.shouldValidateWithWalletMetadata = true
        let requestUriResponse = createRequestUriResponse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ10.SflK5c")
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString,response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        
        await XCTAssertAsyncThrowsError(try await mockSchemeAuthRequestHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Request URI response validation failed - request_object_signing_alg is not supported by wallet",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequestObject
            )
        }
    }
    
    func testThrowErrorWhenClientIdSchemeIsNotSupportedAsPerWalletMetadata() async {
        let  minimalWalletMetadata = try! createWalletMetadataV2(clientIdSchemesSupported: [.preRegistered, .redirectUri])
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23, ["request_uri_method": "post"])) as [String : Any]
        let mockSchemeAuthRequestHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: minimalWalletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        mockSchemeAuthRequestHandler.shouldValidateWithWalletMetadata = true
        let requestUriResponse = createRequestUriResponse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ10.SflK5c")
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString,response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        
        await XCTAssertAsyncThrowsError(try await mockSchemeAuthRequestHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "client_id_scheme is not supported by wallet",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testFetchAuthRequestWithInvalidRequestUriValuesThrowError() async {
        let testCases: [TestCase<[String: Any], Void>] = [
            TestCase(
                input: ["request_uri": ""],
                expectedError: "Invalid Input: request_uri value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            ),
            TestCase(
                input: ["request_uri": "nil"],
                expectedError: "Invalid Input: request_uri value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            ),
            TestCase(
                input: ["request_uri": "null"],
                expectedError: "Invalid Input: request_uri value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters: [String: Any] = createAuthorizationRequest(
                paramList: authRequestParamsByReferenceDraft23,
                requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23, testCase.input)
            ) as [String: Any]
            
            let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(
                authorizationRequestParameters: authorizationRequestParameters,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            
            await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: testCase.expectedError!,
                    expectedCode: testCase.expectedCode!
                )
            }
        }
    }
    
    
    //Fetch info for sending response (error or authorization response) to verifier
    func testResponseUrlSetSuccessfullyForResponseModeDirectPost(){
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23))  as [String : Any]
        let expectation = expectation(description: "Handler should be called with expected parameter")
        var responseUri: String?
        let mockSetResponseUri: (String) -> Void = { value in
            responseUri = value
            expectation.fulfill()
        }
        
        let clientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        try? clientIdSchemeBasedAuthorizationRequestHandler.setResponseUrl()
        
        wait(for: [expectation], timeout: 2.0)
        XCTAssertEqual(responseUri, "https://mock-verifier.com", "Handler was called with unexpected parameter")
    }
    
    func testFetchInfoForSendingResponseToVerifierForInvalidResponseModeThrowInvalidResponseModeError() {
        let testCases: [TestCase<[String: String?], Void>] = [
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode.rawValue: "fragment"], expectedError: "Given response_mode - fragment is not supported", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode.rawValue: ""], expectedError: "Given response_mode -  is not supported", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode.rawValue: "nil"], expectedError: "Given response_mode - nil is not supported", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode.rawValue: "null"], expectedError: "Given response_mode - null is not supported", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode.rawValue: nil], expectedError: "Given response_mode -  is not supported", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters = createAuthorizationRequest(
                paramList: authRequestWithPreRegisteredByValueDraft23,
                requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23, testCase.input)
            ) as [String: Any]
            
            let handler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(
                authorizationRequestParameters: authorizationRequestParameters,
                walletMetadata: nil,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            
            XCTAssertThrowsError(try handler.setResponseUrl()) { error in
                assertOpenID4VPException(error, expectedMessage: testCase.expectedError!, expectedCode: testCase.expectedCode!)
            }
        }
    }
    
    
    //Validate fields in authorization request which are mandatory
    
    func testParseAndValidateAuthorizationRequestWithPresentationDefinitionByReferenceSupport() async{
        decodedClientMetadata = createInstance(clientMetadata, as: ClientMetadata.self)
        decodedPresentationDefinition = createInstance(presentationDefinition, as: PresentationDefinition.self)
        let presentationDefinition = convertToJsonString(presentationDefinition)
        let authorizationRequestParameters: [String: Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue.map { $0 == "presentation_definition" ? "presentation_definition_uri" : $0 } , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/presentation-definition",responseBody: presentationDefinition)
        
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        do{
            try await mockAuthHandler.validateAndParseRequestFields()
            
            assertDictionariesEqual(expected: [
                "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
                "presentation_definition": decodedPresentationDefinition!,
                "response_uri": "https://mock-verifier.com",
                "state": "+mRQe1d6pBoJqF6Ab28klg==",
                "response_type": "vp_token",
                "presentation_definition_uri": "https://mock-verifier.com/presentation-definition",
                "client_metadata": decodedClientMetadata!,
                "client_id": "redirect_uri:https://mock-verifier.com",
                "response_mode": "direct_post",
            ], actual: mockAuthHandler.authorizationRequestParameters)
        } catch {
            XCTFail("Error should not occur but got error \(error) - \(error.localizedDescription)")
        }
    }
    
    func testParseAndValidateAuthorizationRequestWithPresentationDefinitionByValueSupport() async{
        decodedClientMetadata = createInstance(clientMetadata, as: ClientMetadata.self)
        decodedPresentationDefinition = createInstance(presentationDefinition, as: PresentationDefinition.self)
        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdScheme: .redirectUri,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23),
            applicableFields: authRequestWithRedirectUriByValue
        )
        let authorizationRequestParameters = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",responseBody: authorizationRequestObject)
        
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        do{
            try await mockAuthHandler.validateAndParseRequestFields()
            
            assertDictionariesEqual(expected: [
                "client_metadata": decodedClientMetadata!,
                "response_mode": "direct_post",
                "client_id": "redirect_uri:https://mock-verifier.com",
                "response_uri": "https://mock-verifier.com",
                "presentation_definition": decodedPresentationDefinition!,
                "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
                "state": "+mRQe1d6pBoJqF6Ab28klg==",
                "response_type": "vp_token"
            ], actual: mockAuthHandler.authorizationRequestParameters)
        } catch {
            XCTFail("Error should not occur but got error \(error) - \(error.localizedDescription)")
        }
    }
    
    func testInvalidRequestFieldThrowErrorForResponseTypeField() async {
        let testCases: [TestCase<[String: Any?], Void>] = [
            TestCase(input: [AuthorizationRequestFieldConstants.responseType.rawValue: "null"], expectedError: "Invalid Input: response_type value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseType.rawValue: ""], expectedError: "Invalid Input: response_type value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseType.rawValue: "nil"], expectedError: "Invalid Input: response_type value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseType.rawValue: nil], expectedError: "Missing Input: response_type param is required", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters = createAuthorizationRequest(
                paramList: authRequestWithPreRegisteredByValueDraft23,
                requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23, testCase.input)
            ) as [String: Any]
            
            let handler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(
                authorizationRequestParameters: authorizationRequestParameters,
                walletMetadata: nil,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            
            await XCTAssertAsyncThrowsError(try await handler.validateAndParseRequestFields()) { error in
                assertOpenID4VPException(error, expectedMessage: testCase.expectedError!, expectedCode: testCase.expectedCode!)
            }
        }
    }
    
    
    func testInvalidRequestFieldErrorForStateField() async {
        let testCases: [TestCase<[String: Any], Void>] = [
            TestCase(input: ["state": "null"], expectedError: "Invalid Input: state value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: ["state": ""], expectedError: "Invalid Input: state value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: ["state": "nil"], expectedError: "Invalid Input: state value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters = createAuthorizationRequest(
                paramList: authRequestWithPreRegisteredByValueDraft23,
                requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23, testCase.input)
            ) as [String: Any]
            
            let handler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(
                authorizationRequestParameters: authorizationRequestParameters,
                walletMetadata: nil,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            
            await XCTAssertAsyncThrowsError(try await handler.validateAndParseRequestFields()) { error in
                assertOpenID4VPException(error, expectedMessage: testCase.expectedError!, expectedCode: testCase.expectedCode!)
            }
        }
    }
    
    
    func testInvalidRequestFieldErrorForResponseModeField() async {
        let testCases: [TestCase<[String: Any], Void>] = [
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode.rawValue: "null"], expectedError: "Invalid Input: response_mode value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode.rawValue: ""], expectedError: "Invalid Input: response_mode value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode.rawValue: "nil"], expectedError: "Invalid Input: response_mode value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters = createAuthorizationRequest(
                paramList: authRequestWithPreRegisteredByValueDraft23,
                requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23, testCase.input)
            ) as [String: Any]
            
            let handler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(
                authorizationRequestParameters: authorizationRequestParameters,
                walletMetadata: nil,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            
            await XCTAssertAsyncThrowsError(try await handler.validateAndParseRequestFields()) { error in
                assertOpenID4VPException(error, expectedMessage: testCase.expectedError!, expectedCode: testCase.expectedCode!)
            }
        }
    }
    
    
    func testInvalidRequestFieldErrorForNonceField() async {
        let testCases: [TestCase<[String: Any?], Void>] = [
            TestCase(input: ["nonce": "null"], expectedError: "Invalid Input: nonce value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: ["nonce": ""], expectedError: "Invalid Input: nonce value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: ["nonce": "nil"], expectedError: "Invalid Input: nonce value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: ["nonce": nil], expectedError: "Missing Input: nonce param is required", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters = createAuthorizationRequest(
                paramList: authRequestWithPreRegisteredByValueDraft23,
                requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23, testCase.input)
            ) as [String: Any]
            
            let handler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(
                authorizationRequestParameters: authorizationRequestParameters,
                walletMetadata: nil,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            
            await XCTAssertAsyncThrowsError(try await handler.validateAndParseRequestFields()) { error in
                assertOpenID4VPException(error, expectedMessage: testCase.expectedError!, expectedCode: testCase.expectedCode!)
            }
        }
    }
    
    func testShouldThrowInvalidDataErrorWhenResponseTypeInAuthorizationRequestIsNotSupported() async {
        decodedClientMetadata = createInstance(clientMetadata, as: ClientMetadata.self)
        decodedPresentationDefinition = createInstance(presentationDefinition, as: PresentationDefinition.self)
        let presentationDefinition = convertToJsonString(presentationDefinition)
        let authorizationRequestParameters: [String: Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue.map { $0 == "presentation_definition" ? "presentation_definition_uri" : $0 } , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23, ["response_type": "vp_token id_token"])) as [String : Any]
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/presentation-definition",responseBody: presentationDefinition)
        
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "response type - vp_token id_token is not supported",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testShouldThrowErrorWhenInvalidClientMetadataIsProvided() async{
        let authorizationRequestParameters: [String : Any] = mergeMaps(resquestUriResponseData,["client_metadata": "{}"])
        let clientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce",networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await clientIdSchemeBasedAuthorizationRequestHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Error during client metadata decoding - Missing Input: client_metadata->vp_formats param is required",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testShouldThrowErrorWhenBothPresenentationDefinitionAndPresenentationDefinitionUriArePresent() async{
        let authorizationRequestParameters: [String : Any] = mergeMaps(resquestUriResponseData,["presentation_definition_uri": "https://mock-verifier.com/presentation-definition", "presentation_definition": presentationDefinition])
        let clientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce",networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await clientIdSchemeBasedAuthorizationRequestHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Either presentation_definition or presentation_definition_uri request param can be provided but not both",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func assertJSONStringEqual(expected: String, actual: String) {
        guard let expectedData = expected.data(using: .utf8),
              let actualData = actual.data(using: .utf8) else {
            XCTFail("Failed to convert JSON strings to Data")
            return
        }
        
        guard let expectedDict = try? JSONSerialization.jsonObject(with: expectedData, options: []) as? [String: Any],
              let actualDict = try? JSONSerialization.jsonObject(with: actualData, options: []) as? [String: Any] else {
            XCTFail("Failed to convert JSON Data to Dictionary")
            return
        }
        
        XCTAssertTrue(NSDictionary(dictionary: expectedDict).isEqual(to: actualDict), "JSONs do not match")
    }
    
    func testShouldThrowErrorWhenPresenentationDefinitionUriIsPresentButNotSupportedByWallet() async throws {
        let requestUriResponse: [String: Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriWithPresentationDefinitionUri , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        let authorizationRequestParameters: [String : Any] = mergeMaps(requestUriResponse,["presentation_definition_uri": "https://mock-verifier.com/presentation-definition"])
        
        let walletMetadata = try createWalletMetadataV2(presentationDefinitionURISupported: false)
        
        let clientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        clientIdSchemeBasedAuthorizationRequestHandler.shouldValidateWithWalletMetadata = true
        
        await XCTAssertAsyncThrowsError(try await clientIdSchemeBasedAuthorizationRequestHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "presentation_definition_uri is not supported",
                                     expectedCode: OpenID4VPErrorCodes.invalidPresentationDefinitionReference
            )
        }
    }
    
    func testShouldThrowErrorWhenTransactionDataIsPresentInAuthorizationRequest() async {
        let authorizationRequestParameters: [String: Any] = mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23, [AuthorizationRequestFieldConstants.transactionData.rawValue: ["foo": "bar"]])
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParameters,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid Request: transaction_data is not supported in the authorization request",
                expectedCode: OpenID4VPErrorCodes.invalidTransactionData
            )
        }
    }
    
    
    // draft 21 specific
    
    func testThrowExceptionWhenRequestUriResponseHasDifferentValueThanAuthorizationRequestParametersForClientIdScheme() async throws {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft21 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft21)) as [String : Any]
        
        let authorizationRequestObject = createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft21, ["client_id_scheme": "pre-registered"]))
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, response: (authorizationRequestObject, httpUrlResponseForJWS))
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)
        
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Client Id Scheme mismatch in Authorization Request parameter and the Request Object",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
