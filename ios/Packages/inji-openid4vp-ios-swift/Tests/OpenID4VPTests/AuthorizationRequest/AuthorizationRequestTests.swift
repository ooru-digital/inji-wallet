import XCTest
@testable import OpenID4VP

final class AuthorizationRequestTests: XCTestCase {
    
    private var mockNetworkManager: MockNetworkManager!
    private var mockSetResponseDispatchInfo: (ResponseDispatchInfo) -> Void = { _ in }
    private var trustedVerifiers: [Verifier]!
    
    override func setUp() {
        super.setUp()
        mockNetworkManager = MockNetworkManager()
        trustedVerifiers = preRegisteredVerifiers
    }
    
    override func tearDown() {
        mockNetworkManager.clearResponses()
        super.tearDown()
    }
    
    // MARK: - validateAndCreateAuthorizationRequest(urlEncodedAuthorizationRequest:)
    
    func testUrlEncodedPathReturnsAuthorizationRequestOnSuccess() async throws {
        let request = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
            urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithResponseUri,
            walletConfig: WalletConfig(trustedVerifiers: trustedVerifiers, validateTrustedVerifier: false),
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        
        XCTAssertEqual(request.responseType, ResponseType.vp_token.rawValue)
        XCTAssertFalse(request.nonce.isEmpty)
        XCTAssertNotNil((request as? AuthorizationPresentationExchangeRequest)?.presentationDefinition)
    }
    
    func testUrlEncodedPathThrowsOnMissingClientId() async {
        let urlWithoutClientId = "OPENID4VP://authorize?response_type=vp_token&nonce=abc"
        
        await XCTAssertAsyncThrowsError(
            try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest: urlWithoutClientId,
                walletConfig: WalletConfig(trustedVerifiers: trustedVerifiers, validateTrustedVerifier: false),
                setResponseDispatchInfo: mockSetResponseDispatchInfo,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing Input: client_id param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    // MARK: - validateAndCreateAuthorizationRequest(authRequest:)
    
    func testDictionaryPathReturnsAuthorizationRequestOnSuccess() async throws {
        let authRequest = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter),
            specVersion: .draft23,
            addEncryptionClientMetadataParams: false
        ) as [String: Any]
        
        let request = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
            authRequest: authRequest,
            walletConfig: WalletConfig(trustedVerifiers: trustedVerifiers, validateTrustedVerifier: false),
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        
        XCTAssertEqual(request.responseType, ResponseType.vp_token.rawValue)
        XCTAssertFalse(request.nonce.isEmpty)
        XCTAssertNotNil((request as? AuthorizationPresentationExchangeRequest)?.presentationDefinition)
    }
    
    func testDictionaryPathPopulatesClientId() async throws {
        let authRequest = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter),
            addEncryptionClientMetadataParams: false
        ) as [String: Any]
        
        let request = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
            authRequest: authRequest,
            walletConfig: WalletConfig(trustedVerifiers: trustedVerifiers, validateTrustedVerifier: false),
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        
        XCTAssertEqual(request.clientId, "redirect_uri:https://mock-verifier.com")
    }
    
    func testDictionaryPathThrowsOnMissingClientId() async {
        let authRequest: [String: Any] = [
            "response_type": "vp_token",
            "nonce": "test-nonce",
            "presentation_definition": presentationDefinition
        ]
        
        await XCTAssertAsyncThrowsError(
            try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
                authRequest: authRequest,
                walletConfig: WalletConfig(trustedVerifiers: trustedVerifiers, validateTrustedVerifier: false),
                setResponseDispatchInfo: mockSetResponseDispatchInfo,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing Input: client_id param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    // MARK: - Spec Version Draft 23 - URL encoded path
    
    func testUrlEncodedPathReturnsRequestWithPresentationDefinition() async throws {
        // draft23: presentation_definition present → AuthorizationPresentationExchangeRequest
        let request = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
            urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithResponseUri,
            walletConfig: WalletConfig(trustedVerifiers: trustedVerifiers, validateTrustedVerifier: false),
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        
        print("Request: \(request)")
        XCTAssertTrue(request is AuthorizationPresentationExchangeRequest)
        XCTAssertNotNil((request as? AuthorizationPresentationExchangeRequest)?.presentationDefinition)
    }
    
    func testUrlEncodedPathPresentationExchangeRequestHasExpectedFields() async throws {
        // draft23: verify all base fields are populated correctly
        let request = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
            urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithResponseUri,
            walletConfig: WalletConfig(trustedVerifiers: trustedVerifiers, validateTrustedVerifier: false),
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        
        XCTAssertEqual(request.responseType, ResponseType.vp_token.rawValue)
        XCTAssertFalse(request.nonce.isEmpty)
        XCTAssertNotNil(request.state)
        XCTAssertNotNil(request.responseUri)
    }
    
    // MARK: - Spec Version 1 - URL encoded path
    
    func testUrlEncodedPathReturnsSpecVersion1RequestWithDcqlQuery() async throws {
        // spec v1: dcql_query present → AuthorizationDcqlRequest
        let v1Params = mergeMaps(
            authorizationRequestParamsWithValue,
            preRegisteredSchemeClientIdParameters,
            ["dcql_query": ["credentials": [["id": "input_1", "format": "vc+sd-jwt", "meta": [:]]]]]
        )
        let urlEncoded = createUrlEncodedAuthorizationRequest(
            requestParams: v1Params,
            clientIdPrefix: .preRegistered,
            applicableFields: ["client_id", "response_uri", "response_type", "response_mode", "nonce", "state", "client_metadata", "dcql_query"],
            addEncryptionClientMetadataParams: false
        )
        
        let request = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
            urlEncodedAuthorizationRequest: urlEncoded,
            walletConfig: WalletConfig(trustedVerifiers: trustedVerifiers, validateTrustedVerifier: false),
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        
        XCTAssertTrue(request is AuthorizationDcqlRequest)
        XCTAssertEqual(request.responseType, ResponseType.vp_token.rawValue)
        XCTAssertFalse(request.nonce.isEmpty)
    }
    
    func testUrlEncodedPathSpecVersion1RequestHasExpectedFields() async throws {
        // spec v1: verify base fields are populated correctly
        let v1Params = mergeMaps(
            authorizationRequestParamsWithValue,
            preRegisteredSchemeClientIdParameters,
            ["dcql_query": ["credentials": [["id": "input_1", "format": "vc+sd-jwt", "meta": [:]]]]]
        )
        let urlEncoded = createUrlEncodedAuthorizationRequest(
            requestParams: v1Params,
            clientIdPrefix: .preRegistered,
            applicableFields: ["client_id", "response_uri", "response_type", "response_mode", "nonce", "state", "client_metadata", "dcql_query"],
            addEncryptionClientMetadataParams: false
        )
        
        let request = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
            urlEncodedAuthorizationRequest: urlEncoded,
            walletConfig: WalletConfig(trustedVerifiers: trustedVerifiers, validateTrustedVerifier: false),
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        
        XCTAssertEqual(request.clientId, "mock-client")
        XCTAssertNotNil(request.state)
        XCTAssertNotNil(request.responseUri)
    }
    
    // MARK: - Spec Version Draft 23 - Dictionary path
    
    func testDictionaryPathReturnsPresentationExchangeRequestWithPresentationDefinition() async throws {
        // draft23: presentation_definition present → AuthorizationPresentationExchangeRequest
        let authRequest = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter),
            specVersion: .draft23,
            addEncryptionClientMetadataParams: false
        ) as [String: Any]
        
        let request = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
            authRequest: authRequest,
            walletConfig: WalletConfig(trustedVerifiers: trustedVerifiers, validateTrustedVerifier: false),
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        
        XCTAssertTrue(request is AuthorizationPresentationExchangeRequest)
        let presentationExchangeRequest = request as? AuthorizationPresentationExchangeRequest
        XCTAssertNotNil(presentationExchangeRequest?.presentationDefinition)
        XCTAssertEqual(presentationExchangeRequest?.presentationDefinition.id, "vp_presentation_definition")
    }
    
    // MARK: - Spec Version 1 - Dictionary path
    
    func testDictionaryPathReturnRequestWithDcqlQuery() async throws {
        // spec v1: dcql_query present → AuthorizationDcqlRequest
        let authRequest = createAuthorizationRequest(
            paramList: ["client_id", "response_uri", "response_type", "response_mode", "nonce", "state", "client_metadata", "dcql_query"],
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                preRegisteredSchemeClientIdParameters,
                ["dcql_query":  dcqlQuery]
            ),
            addEncryptionClientMetadataParams: false
        ) as [String: Any]
        
        let request = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
            authRequest: authRequest,
            walletConfig: WalletConfig(trustedVerifiers: trustedVerifiers, validateTrustedVerifier: false),
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        
        XCTAssertTrue(request is AuthorizationDcqlRequest)
        XCTAssertEqual(request.responseType, ResponseType.vp_token.rawValue)
        XCTAssertFalse(request.nonce.isEmpty)
    }
    
    func testDictionaryPathSpecVersion1PopulatesClientId() async throws {
        // spec v1: verify clientId is extracted correctly
        let authRequest = createAuthorizationRequest(
            paramList: ["client_id", "response_uri", "response_type", "response_mode", "nonce", "state", "client_metadata", "dcql_query"],
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                preRegisteredSchemeClientIdParameters,
                ["dcql_query": dcqlQuery]
            ),
            addEncryptionClientMetadataParams: false
        ) as [String: Any]
        
        let request = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
            authRequest: authRequest,
            walletConfig: WalletConfig(trustedVerifiers: trustedVerifiers, validateTrustedVerifier: false),
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        
        XCTAssertEqual(request.clientId, "mock-client")
    }
    
    func testDictionaryPathSpecVersion1NotContainsPresentationDefinition() async throws {
        // spec v1 (DcqlRequest): must not be cast to draft23 (PresentationExchange) — no presentationDefinition
        let authRequest = createAuthorizationRequest(
            paramList: ["client_id", "response_uri", "response_type", "response_mode", "nonce", "state", "client_metadata", "dcql_query"],
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                preRegisteredSchemeClientIdParameters
            ),
            specVersion: .v1,
            addEncryptionClientMetadataParams: false
        ) as [String: Any]
        
        let request = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
            authRequest: authRequest,
            walletConfig: WalletConfig(trustedVerifiers: trustedVerifiers, validateTrustedVerifier: false),
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        
        XCTAssertNil(request as? AuthorizationPresentationExchangeRequest)
    }
    
    // MARK: - extractQueryParameters edge cases
    
    func testUrlEncodedPathThrowsWhenNoQuerySeparatorInUrl() async {
        let malformedUrl = "OPENID4VP://authorizeclient_id=mock-client&nonce=abc"
        
        await XCTAssertAsyncThrowsError(
            try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest: malformedUrl,
                walletConfig: WalletConfig(trustedVerifiers: trustedVerifiers, validateTrustedVerifier: false),
                setResponseDispatchInfo: mockSetResponseDispatchInfo,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Exception occurred when extracting the query params from Authorization Request :",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    // MARK: - Unsupported client_id_prefix
    
    func testUrlEncodedPathHandledAsPreRegisteredClient() async {
        // default branch: client_id with an unrecognised prefix is handled as pre-registered
        let unsupportedSchemeParams = mergeMaps(
            authorizationRequestParamsWithValue,
            ["client_id": "https://mock-verifier.com"]
        )
        let urlEncoded = createUrlEncodedAuthorizationRequest(
            requestParams: unsupportedSchemeParams,
            clientIdPrefix: .preRegistered,
            applicableFields: authRequestWithPreRegisteredByValue,
            addEncryptionClientMetadataParams: false
        )
        
        await XCTAssertAsyncNoThrowsError(
            try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest: urlEncoded,
                walletConfig: WalletConfig(trustedVerifiers: trustedVerifiers, validateTrustedVerifier: false),
                setResponseDispatchInfo: mockSetResponseDispatchInfo,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
        )
    }
    
    func testDictionaryPathDoesNotErrorOutForUnknownClientIDScheme() async {
        // default branch: same check via the dictionary path
        let authRequest: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId: "https://mock-verifier.com"
        ]), addEncryptionClientMetadataParams: false) as [String : Any]
        
        await XCTAssertAsyncNoThrowsError(
            try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
                authRequest: authRequest,
                walletConfig: WalletConfig(trustedVerifiers: trustedVerifiers, validateTrustedVerifier: false),
                setResponseDispatchInfo: mockSetResponseDispatchInfo,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
        )
    }
}
