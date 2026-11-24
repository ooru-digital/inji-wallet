import Foundation
import JSONWebKey

protocol ResponseModeBasedHandler {
    func validate(clientMetadata: ClientMetadata?,
                  walletConfig: WalletConfig,
                  shouldValidateWithWalletMetadata: Bool) throws -> ResponseEncryptionSpecification?
    
    func validate(clientMetadata: ClientMetadataDraft23?,
                  walletConfig: WalletConfig,
                  shouldValidateWithWalletMetadata: Bool) throws -> ResponseEncryptionSpecification?
    
    func getResponseEndpoint(authorizationRequestParameters: [String : Any]) throws -> String
    func getResponseEndpoint(authorizationRequest: AuthorizationRequest) throws -> String
    
    func getVerifierPublicKeyForEncryption(
        authorizationRequest: AuthorizationRequest,
        walletConfig: WalletConfig
    ) throws -> JWK?
    
    /// Constructs an authorization error response body as per response mode.
    func getAuthorizationErrorResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationErrorResponse,
        authorizationRequest: AuthorizationRequest?
    ) throws -> [String: String]
    
    /// Sends an authorization error response to the verifier.
    func sendAuthorizationError(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationErrorResponse,
        authorizationRequest: AuthorizationRequest?,
        networkManager: NetworkManaging
    ) async throws -> NetworkResponse
    
    /// Constructs an authorization response body as per response mode.
    func getAuthorizationResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationResponse,
        authorizationRequest: AuthorizationRequest
    ) throws -> [String: String]
    
    /// Sends an authorization response to the verifier.
    func sendAuthorizationResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationResponse,
        authorizationRequest: AuthorizationRequest,
        networkManager: NetworkManaging
    ) async throws -> NetworkResponse
}

extension ResponseModeBasedHandler {
    func getResponseEndpoint(authorizationRequestParameters: [String : Any]) throws -> String {
        try validateAttribute(AuthorizationRequestFieldConstants.responseUri, values: authorizationRequestParameters)
        
        let className = String(describing: ResponseModeBasedHandler.self)
        guard let responseUriValue = authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri] as? String else {
            throw InvalidData(
                message: "response_uri data is not valid",
                className: className,
                code: OpenID4VPErrorCodes.invalidRequest
            )
        }
        
        guard isValidUri(responseUriValue) else {
            throw InvalidData(
                message: "response_uri data is not valid",
                className: className,
                code: OpenID4VPErrorCodes.invalidRequest
            )
        }
        
        return responseUriValue
    }
    
    func getResponseEndpoint(authorizationRequest: AuthorizationRequest) throws -> String {
        return authorizationRequest.responseUri ?? ""
    }
}
