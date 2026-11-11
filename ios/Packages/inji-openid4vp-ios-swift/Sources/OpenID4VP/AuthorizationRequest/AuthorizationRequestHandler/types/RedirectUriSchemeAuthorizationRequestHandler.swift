import Foundation
class RedirectUriSchemeAuthorizationRequestHandler:  ClientIdSchemeBasedAuthorizationRequestHandler {
    override init(authorizationRequestParameters: [String: Any],
                  walletMetadata: WalletMetadata?,
                  setResponseUri: @escaping (String) -> Void,
                  walletNonce: String,
                  networkManager: NetworkManaging) {
        super.init(authorizationRequestParameters: authorizationRequestParameters,
                   walletMetadata: walletMetadata,
                   setResponseUri: setResponseUri,
                   walletNonce: walletNonce,
                   networkManager: networkManager)
        delegate = self
        super.className = String(describing: RedirectUriSchemeAuthorizationRequestHandler.self)
    }

    func clientIdScheme() -> String {
        return ClientIdScheme.redirectUri.rawValue
    }
    
    func isSignedRequestSupported() -> Bool {
        return false
    }
    
    func isUnsignedRequestSupported() -> Bool {
        return true
    }
    
    func extractPublicKey(keyId: String?, algorithm: String) async throws -> PublicKeyType {
        throw UnsupportedOperationException(message: "Public key extraction is not supported for redirect_uri client_id_scheme", className: className)
    }
    
    func process(walletMetadata: WalletMetadata) -> WalletMetadata {
        var updatedWalletMetadata = walletMetadata
        updatedWalletMetadata.requestObjectSigningAlgValuesSupported = nil
        return updatedWalletMetadata
    }

    override func validateAndParseRequestFields()async throws {
        try await super.validateAndParseRequestFields()
        let responseMode = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode.rawValue])
        switch responseMode {
        case ResponseMode.directPost.rawValue, ResponseMode.directPostJwt.rawValue:
            try validateUriCombinations(authorizationRequestParameters: authorizationRequestParameters, validAttribute: AuthorizationRequestFieldConstants.responseUri.rawValue, inValidAttribute: AuthorizationRequestFieldConstants.redirectUri.rawValue)
            break
        case ResponseMode.iarPost.rawValue, ResponseMode.iarPostJwt.rawValue:
            print("IAR_POST or IAR_POST_JWT response_mode is used")
        default:
            throw InvalidResponseMode(
                message : "Given response_mode \(String(describing: responseMode)) is not supported",
                className: className
            )
        }
        
    }
    
    private func validateUriCombinations(authorizationRequestParameters: [String: Any], validAttribute: String, inValidAttribute: String) throws {
        if authorizationRequestParameters.keys.contains(inValidAttribute) {
            throw InvalidData(message: "\(inValidAttribute) should not be present for given response_mode", className: className)
        } else {
            try validateAttribute(validAttribute, values: self.authorizationRequestParameters)
        }
        
        let validValue = authorizationRequestParameters[validAttribute]
        // Extract client_id if client_id_scheme is also part of client_id in the authorizationRequestParameters otherwise use the client_id directly.
        let clientIdValue = authorizationRequestParameters[AuthorizationRequestFieldConstants.clientIdScheme.rawValue] == nil
        ? extractClientIdPartOnly(authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as? String ?? "") :
        authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as? String ?? ""
        
        if validValue as? String != clientIdValue {
            throw InvalidData(
                message: "\(validAttribute) should be equal to client_id for given client_id_scheme",
                className: className
            )
        }
    }
    
}
