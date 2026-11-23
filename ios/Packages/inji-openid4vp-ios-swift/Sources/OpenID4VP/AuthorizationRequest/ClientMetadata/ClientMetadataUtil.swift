import Foundation

fileprivate let className = "ClientMetadataUtil"

enum ClientMetadataSpecVersionHandler {
    case v1, draft23
    
    static func of(_ specVersion: SpecVersion) -> ClientMetadataSpecVersionHandler {
        return specVersion == .draft23 ? .draft23 : .v1
    }
    
    func parseAndValidate(authorizationRequest: [String: Any], shouldValidateWithWalletMetadata: Bool, walletConfig: WalletConfig) throws -> [String: Any] {
        let clientMetadataKey = AuthorizationRequestFieldConstants.clientMetadata
        var mutableParams = authorizationRequest
        if let clientMetadata = authorizationRequest[AuthorizationRequestFieldConstants.clientMetadata] {
            switch self {
            case .draft23:
                if let clientMetadataInstance = clientMetadata as? ClientMetadataDraft23 {
                    mutableParams[clientMetadataKey] = clientMetadataInstance
                }
                else if let clientMetadataObject = clientMetadata as? NSDictionary{
                    let data = try JSONSerialization.data(withJSONObject: clientMetadataObject, options: [])
                    let clientMetadata = try ClientMetadataDraft23.deserializeAndValidate(clientMetadata: data)
                    mutableParams[clientMetadataKey] = clientMetadata
                } else if let clientMetaString = clientMetadata as? String {
                    let clientMetadata = try ClientMetadataDraft23.deserializeAndValidate(clientMetadata: clientMetaString)
                    mutableParams[clientMetadataKey] = clientMetadata
                } else {
                    throw InvalidData(message: "client_metadata must be of type String or Map", className: className)
                }
            case .v1:
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
        }
        
        return mutableParams
    }
        
}
