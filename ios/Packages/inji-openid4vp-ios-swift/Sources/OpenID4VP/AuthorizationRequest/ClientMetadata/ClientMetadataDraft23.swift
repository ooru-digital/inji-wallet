import Foundation
import JSONWebKey

public struct ClientMetadataDraft23: Codable {
    let clientName: String?
    let logoUri:String?
    let authorizationEncryptedResponseAlg: String?
    let authorizationEncryptedResponseEnc: String?
    let vpFormats: [String: [String: [String]]]
    let jwks: JWKSet?
    static let className = String(describing: ClientMetadataDraft23.self)
    
    enum CodingKeys: String, CodingKey {
        case clientName = "client_name"
        case logoUri = "logo_uri"
        case authorizationEncryptedResponseAlg = "authorization_encrypted_response_alg"
        case authorizationEncryptedResponseEnc = "authorization_encrypted_response_enc"
        case vpFormats = "vp_formats"
        case jwks
    }
    
    public init(from decoder: any Decoder) throws {
        do {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            
            self .clientName = try container.decodeRequired(
                String.self,
                forKey: .clientName,
                fieldPath: [AuthorizationRequestFieldConstants.clientMetadata, "client_name"],
                className: ClientMetadataDraft23.className,
                isMandatory: false
            )
            
            self .logoUri = try container.decodeRequired(
                String.self,
                forKey: .logoUri,
                fieldPath: [AuthorizationRequestFieldConstants.clientMetadata, "logo_uri"],
                className: ClientMetadataDraft23.className,
                isMandatory: false
            )
            
            self .authorizationEncryptedResponseAlg = try container.decodeRequired(
                String.self,
                forKey: .authorizationEncryptedResponseAlg,
                fieldPath: [AuthorizationRequestFieldConstants.clientMetadata, "authorization_encrypted_response_alg"],
                className: ClientMetadataDraft23.className,
                isMandatory: false
            )
            
            self .authorizationEncryptedResponseEnc = try container.decodeRequired(
                String.self,
                forKey: .authorizationEncryptedResponseEnc,
                fieldPath: [AuthorizationRequestFieldConstants.clientMetadata, VerifierMetadataConstants.authorizationEncryptedResponseEnc],
                className: ClientMetadataDraft23.className,
                isMandatory: false
            )
            
            self .vpFormats = try container.decodeRequired(
                [String: [String: [String]]].self,
                forKey: .vpFormats,
                fieldPath: [AuthorizationRequestFieldConstants.clientMetadata, "vp_formats"],
                className: ClientMetadataDraft23.className,
                isMandatory: true
            )!
            
            self .jwks = try container.decodeRequired(
                LenientJWKSet.self,
                forKey: .jwks,
                fieldPath: [AuthorizationRequestFieldConstants.clientMetadata, "jwks"],
                className: ClientMetadataDraft23.className,
                isMandatory: false
            )?.jwkSet
            try validate(self)
        } catch {
            throw wrapError(error, customError: { message in InvalidData(message: "Error during client metadata decoding - \(message)", className: ClientMetadataDraft23.className) })
        }
    }
    
    public static func deserializeAndValidate(clientMetadata: Any) throws -> ClientMetadataDraft23 {
        if let encodedData = clientMetadata as? Data {
            return try toClientMetadata(encodedData)
        } else if let data = clientMetadata as? String {
            guard let encodedData = data.data(using: .utf8) else {
                throw UTF8EncodingFailed( fieldPath: [AuthorizationRequestFieldConstants.clientMetadata], className: ClientMetadataDraft23.className)
            }
            return try toClientMetadata(encodedData)
        } else {
            throw InvalidInput(fieldPath: [AuthorizationRequestFieldConstants.clientMetadata], className: ClientMetadataDraft23.className)
        }
    }
    
    fileprivate static func toClientMetadata(_ encodedData: Data)throws -> ClientMetadataDraft23 {
        return try encodedData.toInstance(as: ClientMetadataDraft23.self)
    }
    
    private func validate(_ decodedClientMetadata: ClientMetadataDraft23) throws{
        
        try validateField(decodedClientMetadata.clientName, [AuthorizationRequestFieldConstants.clientMetadata, "client_name"], ClientMetadataDraft23.className)
        try validateField(decodedClientMetadata.logoUri, [AuthorizationRequestFieldConstants.clientMetadata, "logo_uri"], ClientMetadataDraft23.className)
        try validateField(decodedClientMetadata.authorizationEncryptedResponseAlg, [AuthorizationRequestFieldConstants.clientMetadata, "authorization_encrypted_response_alg"], ClientMetadataDraft23.className)
        try validateField(decodedClientMetadata.authorizationEncryptedResponseEnc, [AuthorizationRequestFieldConstants.clientMetadata, VerifierMetadataConstants.authorizationEncryptedResponseEnc], ClientMetadataDraft23.className)
        try validateField(decodedClientMetadata.vpFormats, [AuthorizationRequestFieldConstants.clientMetadata, "vp_formats"], ClientMetadataDraft23.className)
    }
}
