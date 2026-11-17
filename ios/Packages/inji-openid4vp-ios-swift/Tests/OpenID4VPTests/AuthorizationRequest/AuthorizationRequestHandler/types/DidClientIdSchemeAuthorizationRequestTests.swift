import Foundation
import XCTest
@testable import OpenID4VP

class DidClientIdSchemeAuthorizationRequestTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    
    let requestUri: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!

    private var walletMetadata: WalletMetadata!

    override func setUpWithError() throws {
        walletMetadata = try createWalletMetadataV2()
    }
    
    // Support for Authorization request by reference or by value
    
    func testReturnFalseForAuthorizationRequestByReferenceSupport() {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        let handler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertTrue(handler.isSignedRequestSupported(), "did client_id_scheme should support request by reference")
    }
    
    func testReturnFalseForAuthorizationRequestByValueSupport() {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        let handler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertFalse(handler.isUnsignedRequestSupported(), "did client_id_scheme should not support request by value")
    }
    
    func testExtractionOfPublicKeyFromDidClientIdSuccess() async {
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)

        await XCTAssertNoThrowAndVerifyAsync(try await didSchemeAuthRequestHandler.extractPublicKey(keyId: JWSUtil.publicKeyId, algorithm: "EdDSA")){ publicKey in
            assertPublicKey(expectedBase64Encoded: "+Fy3lMapzR3wpaYNCFq29GDEn/NoR3pBsc511q1Cxqw=", actualKey: publicKey)
        }
    }

    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceDoesNotContainJWTContentTypeInHeader() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, error: NetworkRequestException.networkRequestFailed(message: "Response does not match any acceptable types"))

        await XCTAssertAsyncThrowsError(try await didSchemeAuthRequestHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Authorization Request Object must have content type 'application/oauth-authz-req+jwt'",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testProcessingWalletMetadataSuccessfully() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId.rawValue: "mock-client",
        ])) as [String : Any]
        let didScheme = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager!)

        let processedMetadata = try didScheme.process(walletMetadata: walletMetadata)

        assertDictionariesEqual(expected: convertToDictionary(object: walletMetadata)!, actual: convertToDictionary(object: processedMetadata))
    }

    func testShouldThrowErrorForWalletMetadataProcessingWhenRequestObjectSigningAlgValuesSupportedisNil() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId.rawValue: "mock-client",
        ])) as [String : Any]

        let walletMetadata = try createWalletMetadataV2(requestObjectSigningAlgValuesSupported: nil)

        let didScheme = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager!)

        await XCTAssertAsyncThrowsError(try didScheme.process(walletMetadata: walletMetadata)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "request_object_signing_alg_values_supported is not present in wallet metadata.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
