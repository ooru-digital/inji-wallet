import XCTest
@testable import OpenID4VP

class AuthorizationRequestUtilsTests : XCTestCase {
    let mockNetworkManager = MockNetworkManager()
    private var walletConfig: WalletConfig!
    
    override func setUpWithError() throws {
        walletConfig = createWalletConfig()
    }
    
    ///Test Decoding of url encoded paramters to Dictionary
    
    func testDecoding() throws {
        let data = "openid4vp://authorize?client_id=https%3A%2F%2F1333-103-101-213-24.ngrok-free.app%2Fverifier%2Fvp-response&presentation_definition_uri=https%3A%2F%2F1333-103-101-213-24.ngrok-free.app%2Fverifier%2Fpresentation_definition_uri&response_type=vp_token&response_mode=direct_post&nonce=97Ls4N6OTVxeVmI73YlOjg%3D%3D&state=rU8RTzcS04e76lM0LzIvsw%3D%3D&response_uri=https%3A%2F%2F1333-103-101-213-24.ngrok-free.app%2Fverifier%2Fvp-response&client_metadata=%5Bobject+Object%5D&client_id_scheme=pre-registered"
        
        let decoded = try extractQueryParameters(data)
        XCTAssertEqual(["response_mode": "direct_post", "response_uri": "https://1333-103-101-213-24.ngrok-free.app/verifier/vp-response", "response_type": "vp_token", "presentation_definition_uri": "https://1333-103-101-213-24.ngrok-free.app/verifier/presentation_definition_uri", "client_metadata": "[object Object]", "client_id_scheme": "pre-registered", "state": "rU8RTzcS04e76lM0LzIvsw==", "client_id": "https://1333-103-101-213-24.ngrok-free.app/verifier/vp-response", "nonce": "97Ls4N6OTVxeVmI73YlOjg=="], decoded)

    }

    // CredIssuer patch, same as Android's URLDecoder: "+" is a space, %2B a plus, and each value
    // is decoded once.
    func testDecodingIsFormStyleAndSinglePass() throws {
        let data = "openid4vp://authorize?client_metadata=%7B%22client_name%22%3A%22CredIssuer+Verifier+App%22%7D&nonce=a%2Bb%3D&note=100%2525"

        let decoded = try extractQueryParameters(data)

        XCTAssertEqual(decoded["client_metadata"], "{\"client_name\":\"CredIssuer Verifier App\"}")
        XCTAssertEqual(decoded["nonce"], "a+b=")
        XCTAssertEqual(decoded["note"], "100%25")
    }
    
    func testThrowErrorWhenDataIsInvalidWhileExtractingQueryParameters() throws {
        let data = "client_id=https%3A%2F%2F1333-103-101-213-24.ngrok-free.app%2Fverifier%2Fvp-response&presentation_definition_uri=https%3A%2F%2F1333-103-101-213-24.ngrok-free.app%2Fverifier%2Fpresentation_definition_uri&response_type=vp_token&response_mode=direct_post&nonce=97Ls4N6OTVxeVmI73YlOjg%3D%3D&state=rU8RTzcS04e76lM0LzIvsw%3D%3D&response_uri=https%3A%2F%2F1333-103-101-213-24.ngrok-free.app%2Fverifier%2Fvp-response&client_metadata=%5Bobject+Object%5D&client_id_scheme=pre-registered"
        
        XCTAssertThrowsError( try extractQueryParameters(data)){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Exception occurred when extracting the query params from Authorization Request :",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    /// Test validation of attributes
    
    func testValidateAtributeWithInvalidInput() {
        let testCases: [TestCase] = [
            TestCase(input: ["key1": "null"], expectedError: "Invalid Input: key1 value cannot be empty or null"),
            TestCase(input: ["key1": ""], expectedError: "Invalid Input: key1 value cannot be empty or null"),
            TestCase(input: ["key1": "nil"], expectedError: "Invalid Input: key1 value cannot be empty or null"),
            TestCase(input: [:], expectedError: "Missing Input: key1 param is required")
        ]
        
        for testCase in testCases {
            XCTAssertThrowsError(try validateAttribute("key1", values: testCase.input)){ error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: testCase.expectedError!,
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }
    
    func testValidateAtributeWithValidInput() {
        XCTAssertNoThrow(try validateAttribute("key1", values: ["key1": "valid value"]))
    }
    
    ///Test get authorization request handler
    
    func testGetAuthorizationRequestHandlerToGiveRespectiveClientIdBasedAuthorizationRequestHandler(){
        let mockSetResponseDispatchInfo: (ResponseDispatchInfo) -> Void = { _ in
        }
        let didAuthRequestHandler = try? getAuthorizationRequestHandler(authorizationRequestParameters: DidSchemeClientIdDraft23, walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo, walletNonce: "mock-nonce",networkManager: mockNetworkManager)
        let preRegisteredSchemeAuthRequestHandler = try? getAuthorizationRequestHandler(authorizationRequestParameters: preRegisteredSchemeClientIdParameters,  walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo, walletNonce: "mock-nonce",networkManager: mockNetworkManager)
        let preRegisteredSchemeClientWithColonSeparatorAuthRequestHandler = try? getAuthorizationRequestHandler(authorizationRequestParameters:  [
            "client_id": "https://mock-verifier.com",
        ],  walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        let redirectUriSchemeAuthRequestHandler = try? getAuthorizationRequestHandler(authorizationRequestParameters: redirectUriSchemeClientIdParameter,  walletConfig: walletConfig, setResponseDispatchInfo: mockSetResponseDispatchInfo,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        
        XCTAssertTrue(didAuthRequestHandler is DecentralizedIdentifierPrefixAuthorizationRequestHandler)
        XCTAssertTrue(preRegisteredSchemeAuthRequestHandler is PreRegisteredSchemeAuthorizationRequestHandler)
        XCTAssertTrue(preRegisteredSchemeClientWithColonSeparatorAuthRequestHandler is PreRegisteredSchemeAuthorizationRequestHandler)
        XCTAssertTrue(redirectUriSchemeAuthRequestHandler is RedirectUriPrefixAuthorizationRequestHandler)
    }
    
    
    // Validate client tests
    func testThrowInvalidRequestFieldErrorForClientIdFieldWhenGettingAuthRequestHandler() {
        let testCases: [TestCase] = [
            TestCase(input: [AuthorizationRequestFieldConstants.clientId: "null"], expectedError: "Invalid Input: client_id value cannot be empty or null"),
            TestCase(input: [AuthorizationRequestFieldConstants.clientId: ""], expectedError: "Invalid Input: client_id value cannot be empty or null"),
            TestCase(input: [AuthorizationRequestFieldConstants.clientId: "nil"], expectedError: "Invalid Input: client_id value cannot be empty or null"),
            TestCase(input: [:], expectedError: "Missing Input: client_id param is required")
        ]
        
        for testCase in testCases {
            let authorizationRequestParametersWithInvalidClientId: [String : Any] = testCase.input as [String : Any]
            let mockSetResponseDispatchInfo: (ResponseDispatchInfo) -> Void = { _ in }
            
            XCTAssertThrowsError(try getAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersWithInvalidClientId,  walletConfig: WalletConfig(validateTrustedVerifier: false), setResponseDispatchInfo: mockSetResponseDispatchInfo, walletNonce: "mock-nonce",networkManager: mockNetworkManager)){ error in
                assertOpenID4VPException(error,
                                         expectedMessage: testCase.expectedError!,
                                         expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }
    
    ///Extraction of client identifier from Authorization request client_id property
    func testExtractClientIdPartOnlyWithValidInput(){
        let redirectUriSchemeClientId = "redirect_uri:https://client.example.org/cb"
        let preRegisteredSchemeClientId = "example-client"
        let preRegisteredSchemeClientIdWithColonSeparator = "https://client.example.org/cb"
        let didSchemeClientId = "did:example#1"
        
        let result1 = extractClientIdPartOnly(redirectUriSchemeClientId)
        let result2 = extractClientIdPartOnly(preRegisteredSchemeClientId)
        let result3 = extractClientIdPartOnly(preRegisteredSchemeClientIdWithColonSeparator)
        let result4 = extractClientIdPartOnly(didSchemeClientId)
        
        XCTAssertEqual(result1, "https://client.example.org/cb")
        XCTAssertEqual(result2, preRegisteredSchemeClientId)
        XCTAssertEqual(result3, preRegisteredSchemeClientIdWithColonSeparator)
        XCTAssertEqual(result4, didSchemeClientId)
    }
    
    ///Extraction of client identifier scheme from Authorization request client_id property
    
    func testExtractClientIdPrefixWithValidInput(){
        let result1 = try! extractClientIdPrefix(authorizationRequestParams: [AuthorizationRequestFieldConstants.clientId:"mock-client"])
        let result2 = try! extractClientIdPrefix(authorizationRequestParams: [AuthorizationRequestFieldConstants.clientId:"redirect_uri:https://mock-verifier.com"])
        let result3 = try! extractClientIdPrefix(authorizationRequestParams: [AuthorizationRequestFieldConstants.clientId:"did:example#1"])
        let result4 = try! extractClientIdPrefix(authorizationRequestParams: [AuthorizationRequestFieldConstants.clientId:"decentralized_identifier:did:example#1"])
        
        XCTAssertEqual(result1, "pre-registered")
        XCTAssertEqual(result2, "redirect_uri")
        XCTAssertEqual(result3, "did")
        XCTAssertEqual(result4, "decentralized_identifier")
    }
    
    func testFindSpecVersionUsingClientId(){
        let result1 = findSpecVersionUsingClientId(clientId: "decentralized_identifier:did:example#1", clientIdPrefix: ClientIdPrefix.decentralizedIdentifier.rawValue,  trustedVerifiers: [], checkSpecVersionInPreRegisteredList: true)
        let result3 = findSpecVersionUsingClientId(clientId: "did:example#1", clientIdPrefix: ClientIdScheme.did.rawValue, trustedVerifiers: [], checkSpecVersionInPreRegisteredList: true)
        
        XCTAssertEqual(result1, .v1)
        XCTAssertEqual(result3, .draft23)
        
        let result5 = findSpecVersionUsingClientId(clientId: "foo:sample", clientIdPrefix:  ClientIdPrefix.preRegistered.rawValue, trustedVerifiers: [], checkSpecVersionInPreRegisteredList: true)
        let result6 = findSpecVersionUsingClientId(clientId: "foo:sample", clientIdPrefix:  ClientIdPrefix.preRegistered.rawValue, trustedVerifiers: [Verifier(clientId: "foo:sample", responseUris: ["/response-uri"], specVersion: .draft23)], checkSpecVersionInPreRegisteredList: true)
        let result7 = findSpecVersionUsingClientId(clientId: "foo:sample", clientIdPrefix:  ClientIdPrefix.preRegistered.rawValue, trustedVerifiers: [], checkSpecVersionInPreRegisteredList: false)
        
        XCTAssertEqual(result5, .v1)
        XCTAssertEqual(result6, .draft23)
        XCTAssertEqual(result7, .v1)
        
        // In case of  client ID prefix other than Decentralized identifier (or Did) / pre-registered , spec version is deafulted to v1
        let result8 = findSpecVersionUsingClientId(clientId: "redirect_uri:foo:sample", clientIdPrefix:  ClientIdPrefix.redirectUri.rawValue, trustedVerifiers: [Verifier(clientId: "foo:sample", responseUris: ["/response-uri"], specVersion: .draft23)], checkSpecVersionInPreRegisteredList: false)
        
        XCTAssertEqual(result8, .v1)
    }
    
    func testExtractClientidThrowErrorWhenClientIdIsEmpty(){
        XCTAssertThrowsError(try extractClientIdPrefix(authorizationRequestParams: [AuthorizationRequestFieldConstants.clientId:""])){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Invalid Input: client_id value cannot be empty or null",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
