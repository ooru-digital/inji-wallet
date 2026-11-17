import Foundation

protocol ResponseModeBasedHandler {
    func validate(clientMetadata: ClientMetadata?,
                  walletMetadata: WalletMetadata?,
                  shouldValidateWithWalletMetadata: Bool) throws
    func sendAuthorizationResponse(authorizationRequest: AuthorizationRequest,
                                   authorizationResponse: AuthorizationResponse,
                                   url: String,
                                   networkManager: NetworkManaging,
                                   producerInfo: String,
                                   recipientInfo: String
    ) async throws -> NetworkResponse
    
    func setResponseUrl(authorizationRequestParameters: [String : Any], setResponseUri: (String) -> Void) throws
    
    func getAuthorizationResponse(
            authorizationRequest: AuthorizationRequest,
            authorizationResponse: AuthorizationResponse,
            walletNonce: String
        ) throws -> [String: String]

        func getAuthorizationErrorResponse(
            authorizationRequest: AuthorizationRequest?,
            authorizationResponse: AuthorizationErrorResponse,
            walletNonce: String
        ) throws -> [String: String]
}

extension ResponseModeBasedHandler {
    
    func setResponseUrl(authorizationRequestParameters: [String : Any], setResponseUri: (String) -> Void) throws {
        
        try validateAttribute(AuthorizationRequestFieldConstants.responseUri.rawValue, values: authorizationRequestParameters)
        
        let className = String(describing: ResponseModeBasedHandler.self)
        let responseUriValue = authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri.rawValue] as! String
        
        guard isValidUri(responseUriValue) else {
            throw InvalidData(
                message: "response_uri data is not valid",
                className: className,
                code: OpenID4VPErrorCodes.invalidRequest
            )
        }
        
        setResponseUri(responseUriValue)
    }
}
