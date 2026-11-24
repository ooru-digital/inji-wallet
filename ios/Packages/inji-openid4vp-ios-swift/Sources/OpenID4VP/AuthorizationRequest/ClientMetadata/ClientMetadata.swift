import Foundation
import JSONWebKey

public struct ClientMetadata: Codable {
    let clientName: String?
    let logoUri: String?
    let vpFormatsSupported: [String: VPFormatSupported]
    let encryptedResponseEncValuesSupported: [String]?
    let jwks: JWKSet?

    static let className = String(describing: ClientMetadata.self)

    enum CodingKeys: String, CodingKey {
        case clientName = "client_name"
        case logoUri = "logo_uri"
        case vpFormatsSupported = "vp_formats_supported"
        case encryptedResponseEncValuesSupported = "encrypted_response_enc_values_supported"
        case jwks
    }

    public init(
        clientName: String? = nil,
        logoUri: String? = nil,
        vpFormatsSupported: [String: VPFormatSupported],
        authorizationEncryptedResponseAlg: String? = nil,
        encryptedResponseEncValuesSupported: [String]? = nil,
        jwks: JWKSet? = nil
    ) {
        self.clientName = clientName
        self.logoUri = logoUri
        self.vpFormatsSupported = vpFormatsSupported
        self.encryptedResponseEncValuesSupported = encryptedResponseEncValuesSupported
        self.jwks = jwks
    }

    public init(from decoder: Decoder) throws {
        do {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.clientName = try container.decodeIfPresent(String.self, forKey: .clientName)
            self.logoUri = try container.decodeIfPresent(String.self, forKey: .logoUri)
            self.encryptedResponseEncValuesSupported = try container.decodeIfPresent([String].self, forKey: .encryptedResponseEncValuesSupported)
            self.jwks = try container.decodeRequired(
                LenientJWKSet.self,
                forKey: .jwks,
                fieldPath: ["client_metadata", "jwks"],
                className: ClientMetadata.className,
                isMandatory: false
            )?.jwkSet

            let vpFormatsContainer = try container.nestedContainer(keyedBy: VPFormatType.self, forKey: .vpFormatsSupported)
            var decodedFormats: [String: VPFormatSupported] = [:]
            for key in vpFormatsContainer.allKeys {
                switch key {
                case .ldp_vc, .ldp_vp:
                    decodedFormats[key.rawValue] = try vpFormatsContainer.decode(LdpVpFormatSupported.self, forKey: key)
                case .mso_mdoc:
                    decodedFormats[key.rawValue] = try vpFormatsContainer.decode(MsoMdocVpFormatSupported.self, forKey: key)
                case .dc_sd_jwt, .vc_sd_jwt:
                    decodedFormats[key.rawValue] = try vpFormatsContainer.decode(SdJwtVpFormatSupported.self, forKey: key)
                }
            }
            self.vpFormatsSupported = decodedFormats
            guard !self.vpFormatsSupported.isEmpty else {
                throw InvalidData(
                    message: "vp_formats_supported cannot be empty in client metadata",
                    className: ClientMetadata.className
                )
            }
        } catch {
            throw wrapError(error, customError: { message in InvalidData(message: "Error during client metadata decoding - \(message)", className: ClientMetadata.className) })
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(clientName, forKey: .clientName)
        try container.encodeIfPresent(logoUri, forKey: .logoUri)
        try container.encodeIfPresent(jwks, forKey: .jwks)
        try container.encodeIfPresent(encryptedResponseEncValuesSupported, forKey: .encryptedResponseEncValuesSupported)

        var vpFormatsContainer = container.nestedContainer(keyedBy: VPFormatType.self, forKey: .vpFormatsSupported)
        for (key, value) in vpFormatsSupported {
            guard let formatType = VPFormatType(rawValue: key) else { continue }
            switch formatType {
            case .ldp_vc, .ldp_vp:
                if let typed = value as? LdpVpFormatSupported {
                    try vpFormatsContainer.encode(typed, forKey: formatType)
                }
            case .mso_mdoc:
                if let typed = value as? MsoMdocVpFormatSupported {
                    try vpFormatsContainer.encode(typed, forKey: formatType)
                }
            case .dc_sd_jwt, .vc_sd_jwt:
                if let typed = value as? SdJwtVpFormatSupported {
                    try vpFormatsContainer.encode(typed, forKey: formatType)
                }
            }
        }
    }
    
    public static func deserializeAndValidate(clientMetadata: Any) throws -> ClientMetadata {
        if let encodedData = clientMetadata as? Data {
            return try toClientMetadata(encodedData)
        } else if let data = clientMetadata as? String {
            guard let encodedData = data.data(using: .utf8) else {
                throw UTF8EncodingFailed( fieldPath: ["client_metadata"], className: ClientMetadata.className)
            }
            return try toClientMetadata(encodedData)
        } else {
            throw InvalidInput(fieldPath: ["client_metadata"], className: ClientMetadata.className)
        }
    }
    
    fileprivate static func toClientMetadata(_ encodedData: Data)throws -> ClientMetadata {
        return try encodedData.toInstance(as: ClientMetadata.self)
    }
}
