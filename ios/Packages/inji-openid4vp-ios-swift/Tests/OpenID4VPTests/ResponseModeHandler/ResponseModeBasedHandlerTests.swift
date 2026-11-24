import XCTest
import JSONWebKey
@testable import OpenID4VP

private final class ExtensionOnlyResponseModeHandler: ResponseModeBasedHandler {
    func validate(
        clientMetadata: ClientMetadata?,
        walletConfig: WalletConfig,
        shouldValidateWithWalletMetadata: Bool
    ) throws -> ResponseEncryptionSpecification? {
        nil
    }

    func validate(
        clientMetadata: ClientMetadataDraft23?,
        walletConfig: WalletConfig,
        shouldValidateWithWalletMetadata: Bool
    ) throws -> ResponseEncryptionSpecification? {
        nil
    }

    func getVerifierPublicKeyForEncryption(
        authorizationRequest: AuthorizationRequest,
        walletConfig: WalletConfig
    ) throws -> JWK? {
        nil
    }

    func getAuthorizationErrorResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationErrorResponse,
        authorizationRequest: AuthorizationRequest?
    ) throws -> [String: String] {
        [:]
    }

    func sendAuthorizationError(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationErrorResponse,
        authorizationRequest: AuthorizationRequest?,
        networkManager: NetworkManaging
    ) async throws -> NetworkResponse {
        fatalError("Not needed for this test suite")
    }

    func getAuthorizationResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationResponse,
        authorizationRequest: AuthorizationRequest
    ) throws -> [String: String] {
        [:]
    }

    func sendAuthorizationResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationResponse,
        authorizationRequest: AuthorizationRequest,
        networkManager: NetworkManaging
    ) async throws -> NetworkResponse {
        fatalError("Not needed for this test suite")
    }
}

final class ResponseModeBasedHandlerTests: XCTestCase {
    private let handler = ExtensionOnlyResponseModeHandler()

    func testGetResponseEndpointFromMapReturnsResponseUriWhenValid() throws {
        let endpoint = try handler.getResponseEndpoint(authorizationRequestParameters: [
            AuthorizationRequestFieldConstants.responseUri: "https://mock-verifier.com/callback"
        ])

        XCTAssertEqual(endpoint, "https://mock-verifier.com/callback")
    }

    func testGetResponseEndpointFromMapThrowsWhenResponseUriMissing() {
        XCTAssertThrowsError(try handler.getResponseEndpoint(authorizationRequestParameters: [:])) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing Input: response_uri param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testGetResponseEndpointFromMapThrowsWhenResponseUriIsNotValid() {
        XCTAssertThrowsError(try handler.getResponseEndpoint(authorizationRequestParameters: [
            AuthorizationRequestFieldConstants.responseUri: 12345
        ])) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "response_uri data is not valid",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testGetResponseEndpointFromAuthorizationRequestReturnsResponseUri() throws {
        let authorizationRequest = getMockAuthorizationRequest()

        let endpoint = try handler.getResponseEndpoint(authorizationRequest: authorizationRequest)

        XCTAssertEqual(endpoint, "https://mock-verifier.com")
    }

    func testGetResponseEndpointFromAuthorizationRequestReturnsEmptyWhenMissing() throws {
        let authorizationRequest = AuthorizationDcqlRequest(
            clientId: "mock-client",
            responseType: ResponseType.vp_token.rawValue,
            responseMode: ResponseMode.directPost.rawValue,
            responseUri: nil,
            redirectUri: nil,
            nonce: "mock-nonce",
            walletNonce: nil,
            state: nil,
            dcqlQuery: validDcqlQuery,
            clientMetadata: nil
        )

        let endpoint = try handler.getResponseEndpoint(authorizationRequest: authorizationRequest)

        XCTAssertEqual(endpoint, "")
    }
}
