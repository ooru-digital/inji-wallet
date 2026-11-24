import Foundation
import XCTest
@testable import OpenID4VP


class RedirectUriSchemeAuthRequestHandlerTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseDispatchInfo: (ResponseDispatchInfo) -> Void = { _ in
    }
    let requestUri: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
    let clientId: String = "redirect_uri:https://mock-verifier.com"
    
    private var walletConfig: WalletConfig!
    
    override func setUpWithError() throws {
        walletConfig = createWalletConfig()
    }
    
    func setup(){
        super.setUp()
        mockNetworkManager.clearResponses()
    }
    
    // Support for Authorization request by reference or by value
    
    func testReturnFalseForAuthorizationRequestByReferenceSupport() {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest( paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter)) as [String : Any]
        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertFalse(handler.isSignedRequestSupported(), "redirect_uri client_id_prefix should not support request by reference")
    }
    
    func testReturnTrueForAuthorizationRequestByValueSupport() {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter)) as [String : Any]
        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertTrue(handler.isUnsignedRequestSupported(), "redirect_uri client_id_prefix should support request by value")
    }
    
    /// validate and parse request fields
    
    func testThrowNoErrorForValidAuthorizationRequestWhileValidateAndParseRequestFields() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter), addEncryptionClientMetadataParams: false) as [String : Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncNoThrowsError(try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields())
    }

    func testThrowErrorWhenBothResponseUriAndRedirectUriPresentForDirectPost() {
        var authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter), addEncryptionClientMetadataParams: false) as [String : Any]
        authorizationRequestParameters[AuthorizationRequestFieldConstants.redirectUri] = "https://mock-verifier.com"
        let redirectUriSchemeAuthRequestHandler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo, walletNonce: "mock-nonce",networkManager: mockNetworkManager)

        XCTAssertThrowsError(try redirectUriSchemeAuthRequestHandler.prepareDispatchInfo()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "redirect_uri should not be present for given response_mode",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorWhenAuthorizationRequestObjectClientIdIsNotMatchingWithRequestParameterClientIdInDirectPostResponseMode() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter, [AuthorizationRequestFieldConstants.responseMode: "fragment","redirect_uri": "http://invalid-mock-verifier.com"])) as [String : Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Given response_mode - fragment is not supported",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testProcessingWalletMetadataSuccessfully() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId: "mock-client",
        ])) as [String : Any]
        let redirectScheme = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager!)
        
        let expectedWalletMetadata : [String: Any] = [
            "authorization_encryption_alg_values_supported": ["ECDH-ES"],
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
        
        let processedMetadata = try redirectScheme.getWalletMetadata(walletConfig: walletConfig)
        
        assertDictionariesEqual(expected: expectedWalletMetadata, actual: (processedMetadata))
    }
    
    func testThrowErrorWhenExtractPublicKeyIsInvoked() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter)) as [String : Any]
        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await handler.extractPublicKey(keyId: nil, algorithm: "edDsa")) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Public key extraction is not supported for redirect_uri client_id_prefix",
                                     expectedCode: "unsupported_operation"
            )
        }
    }
    

    func testValidateAndParseRequestFieldsSucceedsWithIarPostResponseMode() async {
        let params = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdParameter,
                [
                    "response_mode": "iar-post",
                    "response_uri": "https://mock-verifier.com/redirect"
                ]
            ),
            addEncryptionClientMetadataParams: false
        ) as [String : Any]

        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1,
            authorizationRequestParameters: params,
            walletConfig: walletConfig,
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }

    func testValidateAndParseRequestFieldsSucceedsWithIaeResponseModes() async {

        let testCases = [
            ("iae_post", false),
            ("iae_post.jwt", true)
        ]

        for (responseMode, addEncryptionMetadata) in testCases {

            let params = createAuthorizationRequest(
                paramList: authRequestWithRedirectUriByValue,
                requestParams: mergeMaps(
                    authorizationRequestParamsWithValue,
                    redirectUriSchemeClientIdParameter,
                    [
                        "response_mode": responseMode,
                        "response_uri": "https://mock-verifier.com/redirect"
                    ]
                ),
                addEncryptionClientMetadataParams: addEncryptionMetadata
            ) as [String : Any]

            let handler = RedirectUriPrefixAuthorizationRequestHandler(
                clientId: clientId,
                specVersion: .v1,
                authorizationRequestParameters: params,
                walletConfig: walletConfig,
                setResponseDispatchInfo: mockSetResponseDispatchInfo,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )

            await XCTAssertAsyncNoThrowsError(
                try await handler.validateAndParseRequestFields()
            )
        }
    }

    func testValidateAndParseRequestFieldsSucceedsWithIarPostJwtResponseMode() async {
        let params = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdParameter,
                [
                    "response_mode": "iar-post.jwt",
                    "response_uri": "https://mock-verifier.com/redirect"
                ]
            )
        ) as [String : Any]

        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1,
            authorizationRequestParameters: params,
            walletConfig: walletConfig,
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
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
                redirectUriSchemeClientIdParameter,
                ["response_mode": "iar-post"]
            ),
            addEncryptionClientMetadataParams: false
        ) as [String : Any]

        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1,
            authorizationRequestParameters: params,
            walletConfig: walletConfig,
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
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
                redirectUriSchemeClientIdParameter,
                ["response_mode": "iar-post.jwt"]
            )
        ) as [String : Any]

        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1,
            authorizationRequestParameters: params,
            walletConfig: walletConfig,
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }


    func testValidateAndParseRequestFieldsSucceedsWithIaeResponseModesWithoutResponseUri() async {

        let testCases: [(responseMode: String, addEncryptionMetadata: Bool)] = [
            ("iae_post", false),
            ("iae_post.jwt", true)
        ]

        for testCase in testCases {

            let params = createAuthorizationRequest(
                paramList: authRequestWithRedirectUriByValue,
                requestParams: mergeMaps(
                    authorizationRequestParamsWithValue,
                    redirectUriSchemeClientIdParameter,
                    ["response_mode": testCase.responseMode]
                ),
                addEncryptionClientMetadataParams: testCase.addEncryptionMetadata
            ) as [String : Any]

            let handler = RedirectUriPrefixAuthorizationRequestHandler(
                clientId: clientId,
                specVersion: .v1,
                authorizationRequestParameters: params,
                walletConfig: walletConfig,
                setResponseDispatchInfo: mockSetResponseDispatchInfo,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )

            await XCTAssertAsyncNoThrowsError(
                try await handler.validateAndParseRequestFields()
            )
        }
    }

    func testValidateAndParseRequestFieldsSucceedsWithIarPostMismatchedResponseUri() async {
        let params = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdParameter,
                [
                    "response_mode": "iar-post",
                    "response_uri": "https://different.com/response"
                ]
            ),
            addEncryptionClientMetadataParams: false
        ) as [String : Any]

        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1,
            authorizationRequestParameters: params,
            walletConfig: walletConfig,
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
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
                redirectUriSchemeClientIdParameter,
                [
                    "response_mode": "iar-post.jwt",
                    "response_uri": "https://different.com/response"
                ]
            )
        ) as [String : Any]

        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1,
            authorizationRequestParameters: params,
            walletConfig: walletConfig,
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }


    func testValidateClientAuthenticity_responseUriValidationModes_responseUriMissing_throwsMissingField() {
        let responseUriValidationModes = ["direct_post", "direct_post.jwt"]
        for responseMode in responseUriValidationModes {
            let authorizationRequestParameters: [String: Any] = [
                AuthorizationRequestFieldConstants.clientId: "redirect_uri:https://mock-verifier.com",
                AuthorizationRequestFieldConstants.responseMode: responseMode
            ]
            let handler = RedirectUriPrefixAuthorizationRequestHandler(
                clientId: clientId,
                specVersion: .v1,
                authorizationRequestParameters: authorizationRequestParameters,
                walletConfig: walletConfig,
                setResponseDispatchInfo: mockSetResponseDispatchInfo,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            XCTAssertThrowsError(try handler.validateClientAuthenticity(), "responseMode: \(responseMode)") { error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: "Missing Input: response_uri param is required",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }

    func testValidateClientAuthenticity_bypassResponseModes_doesNotValidateResponseUri_doesNotThrow() {
        let bypassModes = ["iar-post", "iar-post.jwt", "iae_post", "iae_post.jwt"]
        for responseMode in bypassModes {
            let authorizationRequestParameters: [String: Any] = [
                AuthorizationRequestFieldConstants.clientId: "redirect_uri:https://mock-verifier.com",
                AuthorizationRequestFieldConstants.responseUri: "https://different-uri.com",
                AuthorizationRequestFieldConstants.responseMode: responseMode
            ]
            let handler = RedirectUriPrefixAuthorizationRequestHandler(
                clientId: clientId,
                specVersion: .v1,
                authorizationRequestParameters: authorizationRequestParameters,
                walletConfig: walletConfig,
                setResponseDispatchInfo: mockSetResponseDispatchInfo,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            XCTAssertNoThrow(try handler.validateClientAuthenticity(), "responseMode: \(responseMode)")
        }
    }

    func testValidateClientAuthenticity_unsupportedResponseMode_throwsInvalidResponseMode() {
        let unsupportedModes: [String?] = ["fragment", nil]
        for responseMode in unsupportedModes {
            var authorizationRequestParameters: [String: Any] = [
                AuthorizationRequestFieldConstants.clientId: "redirect_uri:https://mock-verifier.com",
                AuthorizationRequestFieldConstants.responseUri: "https://mock-verifier.com"
            ]
            if let responseMode {
                authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode] = responseMode
            }
            let handler = RedirectUriPrefixAuthorizationRequestHandler(
                clientId: clientId,
                specVersion: .v1,
                authorizationRequestParameters: authorizationRequestParameters,
                walletConfig: walletConfig,
                setResponseDispatchInfo: mockSetResponseDispatchInfo,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            let expectedMessage = "Given response_mode - \(responseMode ?? "nil") is not supported"
            XCTAssertThrowsError(try handler.validateClientAuthenticity(), "responseMode: \(String(describing: responseMode))") { error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: expectedMessage,
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }

    func testValidateAndParseRequestFieldsSucceedsWithIaeMismatchedResponseUri() async {

        let testCases: [(responseMode: String, addEncryptionMetadata: Bool)] = [
            ("iae_post", false),
            ("iae_post.jwt", true)
        ]

        for testCase in testCases {

            let params = createAuthorizationRequest(
                paramList: authRequestWithRedirectUriByValue,
                requestParams: mergeMaps(
                    authorizationRequestParamsWithValue,
                    redirectUriSchemeClientIdParameter,
                    [
                        "response_mode": testCase.responseMode,
                        "response_uri": "https://different.com/response"
                    ]
                ),
                addEncryptionClientMetadataParams: testCase.addEncryptionMetadata
            ) as [String : Any]

            let handler = RedirectUriPrefixAuthorizationRequestHandler(
                clientId: clientId,
                specVersion: .v1,
                authorizationRequestParameters: params,
                walletConfig: walletConfig,
                setResponseDispatchInfo: mockSetResponseDispatchInfo,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )

            await XCTAssertAsyncNoThrowsError(
                try await handler.validateAndParseRequestFields()
            )
        }
    }
}
