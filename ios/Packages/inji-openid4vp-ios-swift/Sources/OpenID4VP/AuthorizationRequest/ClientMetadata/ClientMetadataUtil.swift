import Foundation

fileprivate let className = String(describing: ClientMetadata.self)

func parseAndValidateClientMetadata(authorizationRequest: [String: Any],
                                    shouldValidateWithWalletMetadata: Bool,
                                    walletMetadata: WalletMetadata?) throws -> [String: Any] {
    let clientMetadataKey = AuthorizationRequestFieldConstants.clientMetadata.rawValue
    var mutableParams = authorizationRequest
    if let clientMetadata = authorizationRequest[AuthorizationRequestFieldConstants.clientMetadata.rawValue] {
        if let clientMetadataInstance = clientMetadata as? ClientMetadata {
            mutableParams[clientMetadataKey] = clientMetadataInstance
        }
        else if let clientMetadataObject = clientMetadata as? NSDictionary{
            let data = try JSONSerialization.data(withJSONObject: clientMetadataObject, options: [])
            let clientMetadata = try ClientMetadata.deserializeAndValidate(clientMetadata: data)
            mutableParams[clientMetadataKey] = clientMetadata
        } else if let clientMetaString = clientMetadata as? String {
            let clientMetadata = try ClientMetadata.deserializeAndValidate(clientMetadata: clientMetaString)
            mutableParams[clientMetadataKey] = clientMetadata
        } else {
            throw InvalidData(message: "client_metadata must be of type String or Map", className: className)
        }
    }
    
    let responseMode = authorizationRequest[AuthorizationRequestFieldConstants.responseMode.rawValue] as? String
    try ResponseModeBasedHandlerFactory.get(responseMode: responseMode).validate(clientMetadata: (mutableParams[clientMetadataKey] as? ClientMetadata),
                                                                                 walletMetadata: walletMetadata,
                                                                                 shouldValidateWithWalletMetadata: shouldValidateWithWalletMetadata)
    
    return mutableParams
}
