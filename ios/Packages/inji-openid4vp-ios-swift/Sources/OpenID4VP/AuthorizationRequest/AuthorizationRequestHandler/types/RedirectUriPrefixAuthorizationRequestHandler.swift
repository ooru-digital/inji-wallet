import Foundation
class RedirectUriPrefixAuthorizationRequestHandler:  ClientIdPrefixBasedAuthorizationRequestHandler {
    override init(clientId: String,
                  specVersion: SpecVersion,
                  authorizationRequestParameters: [String: Any],
                  walletConfig: WalletConfig,
                  setResponseDispatchInfo: @escaping (ResponseDispatchInfo) -> Void,
                  walletNonce: String,
                  networkManager: NetworkManaging) {
        super.init(clientId: clientId,
                   specVersion: specVersion,
                   authorizationRequestParameters: authorizationRequestParameters,
                   walletConfig: walletConfig,
                   setResponseDispatchInfo: setResponseDispatchInfo,
                   walletNonce: walletNonce,
                   networkManager: networkManager)
        delegate = self
        super.className = String(describing: RedirectUriPrefixAuthorizationRequestHandler.self)
    }
    
    func clientIdPrefix() -> String {
        return ClientIdPrefix.redirectUri.rawValue
    }
    
    func isSignedRequestSupported() -> Bool {
        return false
    }
    
    func isUnsignedRequestSupported() -> Bool {
        return true
    }
    
    func extractPublicKey(keyId: String?, algorithm: String) async throws -> PublicKeyType {
        throw UnsupportedOperationException(message: "Public key extraction is not supported for redirect_uri client_id_prefix", className: className)
    }
    
    func getWalletMetadata(walletConfig: WalletConfig) throws -> [String: Any] {
        return try walletConfig.toWalletMetadata(specVersion: specVersion, excludeSignedRequestConfig: true)
    }

    func validateClientAuthenticity() throws {
        let responseMode = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode])
        switch responseMode {
        case ResponseMode.directPost.rawValue, ResponseMode.directPostJwt.rawValue:
            try validateResponseUriMatchesClientId(authorizationRequestParameters: authorizationRequestParameters)
            break
       case ResponseMode.iarPost.rawValue,
            ResponseMode.iarPostJwt.rawValue,
            ResponseMode.iaePost.rawValue,
            ResponseMode.iaePostJwt.rawValue:
            print("IAR_POST or IAR_POST_JWT or IAE_POST or IAE_POST_JWT response_mode is used")
           break
        default:
            throw InvalidResponseMode(
                message : "Given response_mode - \(responseMode ?? "nil") is not supported",
                className: className
            )
        }
    }

    private func validateResponseUriMatchesClientId(authorizationRequestParameters: [String: Any]) throws {
        try validateAttribute(AuthorizationRequestFieldConstants.responseUri, values: self.authorizationRequestParameters)

        let responseUriValue = authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri]
        let clientIdValue = extractClientIdPartOnly(authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId] as? String ?? "")

        if responseUriValue as? String != clientIdValue {
            throw InvalidData(
                message: "\(AuthorizationRequestFieldConstants.responseUri) should be equal to client_id for given client_id_prefix",
                className: className,
                notifyVerifier: false
            )
        }
    }
    
}
