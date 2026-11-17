import Foundation
@testable import OpenID4VP

final class MockNonceProvider: NonceProvider {
    override func generateNonce(entropy: Int = 16) -> String {
        return "mock-nonce"
    }
}

final class MockAuthorizationResponseHandler: AuthorizationResponseHandler {
    var expectedResponse: [String: String] = [:]
    var expectedErrorResponse: [String: String] = [:]

    override func constructAuthorizationResponse(authorizationRequest authRequest: AuthorizationRequest,
                                                 vpTokenSigningResults signingResult: [FormatType: VPTokenSigningResult]) -> [String: String] {
        return expectedResponse
    }

    override func constructAuthorizationErrorResponse(
        authorizationRequest: AuthorizationRequest?,
        exception: Error,
        walletNonce: String
    ) -> [String: Any] {
        return expectedErrorResponse
    }
}

class MockResponseModeHandler: ResponseModeBasedHandler {
    var expectedSuccessResponse: [String: String] = [:]
    var expectedErrorResponse: [String: String] = [:]

    func validate(clientMetadata: ClientMetadata?,
                  walletMetadata: WalletMetadata?,
                  shouldValidateWithWalletMetadata: Bool) throws {}

    func sendAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        url: String,
        networkManager: any NetworkManaging,
        producerInfo: String,
        recipientInfo: String
    ) async throws -> NetworkResponse {
        fatalError("Not needed for unit testing constructAuthorizationResponse")
    }

    func setResponseUrl(authorizationRequestParameters: [String : Any], setResponseUri: (String) -> Void) throws {}

    func getAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        walletNonce: String
    ) throws -> [String: String] {
        return expectedSuccessResponse
    }

    func getAuthorizationErrorResponse(
        authorizationRequest: AuthorizationRequest?,
        authorizationResponse: AuthorizationErrorResponse,
        walletNonce: String
    ) throws -> [String: String] {
        return expectedErrorResponse
    }
}
