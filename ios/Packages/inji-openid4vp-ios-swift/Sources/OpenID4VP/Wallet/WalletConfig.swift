import Foundation

public struct WalletConfig: Codable {
    static let className = "WalletConfig"
    
    
    let vpFormatsSupported: [VPFormatType: VPFormatSupported]
    let clientIdPrefixesSupported: [ClientIdPrefix]
    let requestObjectSigningAlgValuesSupported: [SignatureAlgorithm]?
    let authorizationEncryptionAlgValuesSupported: [EncryptionAlgorithm]?
    let authorizationEncryptionEncValuesSupported: [EncryptionMethod]?
    let responseTypesSupported: [ResponseType]
    let isPresentationDefinitionUriSupported: Bool
    let trustedVerifiers: [Verifier]
    let validateTrustedVerifier: Bool
    
    enum CodingKeys: String, CodingKey {
        case vpFormatsSupported = "vp_formats_supported"
        case clientIdPrefixesSupported = "client_id_prefixes_supported"
        case requestObjectSigningAlgValuesSupported = "request_object_signing_alg_values_supported"
        case authorizationEncryptionAlgValuesSupported = "authorization_encryption_alg_values_supported"
        case authorizationEncryptionEncValuesSupported = "authorization_encryption_enc_values_supported"
        case responseTypesSupported = "response_types_supported"
        case presentationDefinitionUriSupported = "presentation_definition_uri_supported"
        case trustedVerifiers = "trusted_verifiers"
        case validateTrustedVerifier = "validate_trusted_verifier"
    }
    
    public init(
        vpFormatsSupported: [VPFormatType: VPFormatSupported] = WalletConfigDefaults.vpFormatsSupported,
        clientIdPrefixesSupported: [ClientIdPrefix] = WalletConfigDefaults.clientIdPrefixesSupported,
        requestObjectSigningAlgValuesSupported: [SignatureAlgorithm]? = WalletConfigDefaults.requestObjectSigningAlgValuesSupported,
        authorizationEncryptionAlgValuesSupported: [EncryptionAlgorithm]? = WalletConfigDefaults.authorizationEncryptionAlgValuesSupported,
        authorizationEncryptionEncValuesSupported: [EncryptionMethod]? = WalletConfigDefaults.authorizationEncryptionEncValuesSupported,
        responseTypesSupported: [ResponseType] = WalletConfigDefaults.responseTypesSupported,
        isPresentationDefinitionUriSupported: Bool = WalletConfigDefaults.presentationDefinitionUriSupported,
        trustedVerifiers: [Verifier] = WalletConfigDefaults.trustedVerifiers,
        validateTrustedVerifier: Bool = WalletConfigDefaults.validateTrustedVerifier
    ) {
        self.vpFormatsSupported = vpFormatsSupported
        self.clientIdPrefixesSupported = clientIdPrefixesSupported
        self.requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported
        self.authorizationEncryptionAlgValuesSupported = authorizationEncryptionAlgValuesSupported
        self.authorizationEncryptionEncValuesSupported = authorizationEncryptionEncValuesSupported
        self.responseTypesSupported = responseTypesSupported
        self.isPresentationDefinitionUriSupported = isPresentationDefinitionUriSupported
        self.trustedVerifiers = trustedVerifiers
        self.validateTrustedVerifier = validateTrustedVerifier
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.vpFormatsSupported = try WalletConfig.parseVPFormatsSupported(from: container)
        self.clientIdPrefixesSupported = try container.decodeIfPresent([ClientIdPrefix].self, forKey: .clientIdPrefixesSupported) ?? WalletConfigDefaults.clientIdPrefixesSupported
        self.requestObjectSigningAlgValuesSupported = try container.decodeIfPresent([SignatureAlgorithm].self, forKey: .requestObjectSigningAlgValuesSupported) ?? WalletConfigDefaults.requestObjectSigningAlgValuesSupported
        self.authorizationEncryptionAlgValuesSupported = try container.decodeIfPresent([EncryptionAlgorithm].self, forKey: .authorizationEncryptionAlgValuesSupported) ?? WalletConfigDefaults.authorizationEncryptionAlgValuesSupported
        self.authorizationEncryptionEncValuesSupported = try container.decodeIfPresent([EncryptionMethod].self, forKey: .authorizationEncryptionEncValuesSupported) ?? WalletConfigDefaults.authorizationEncryptionEncValuesSupported
        self.responseTypesSupported = try container.decodeIfPresent([ResponseType].self, forKey: .responseTypesSupported) ?? WalletConfigDefaults.responseTypesSupported
        self.isPresentationDefinitionUriSupported = try container.decodeIfPresent(Bool.self, forKey: .presentationDefinitionUriSupported) ?? WalletConfigDefaults.presentationDefinitionUriSupported
        self.trustedVerifiers = try container.decodeIfPresent([Verifier].self, forKey: .trustedVerifiers) ?? WalletConfigDefaults.trustedVerifiers
        self.validateTrustedVerifier = try container.decodeIfPresent(Bool.self, forKey: .validateTrustedVerifier) ?? WalletConfigDefaults.validateTrustedVerifier
    }
    
    private static func parseVPFormatsSupported(from container: KeyedDecodingContainer<CodingKeys>) throws -> [VPFormatType: VPFormatSupported] {
        guard container.contains(.vpFormatsSupported) else {
            return WalletConfigDefaults.vpFormatsSupported
        }
        let vpFormatsContainer = try container.nestedContainer(keyedBy: VPFormatType.self, forKey: .vpFormatsSupported)
        var decodedFormats: [VPFormatType: VPFormatSupported] = [:]
        for key in vpFormatsContainer.allKeys {
            switch key {
            case .ldp_vc, .ldp_vp:
                decodedFormats[key] = try vpFormatsContainer.decode(LdpVpFormatSupported.self, forKey: key)
            case .mso_mdoc:
                decodedFormats[key] = try vpFormatsContainer.decode(MsoMdocVpFormatSupported.self, forKey: key)
            case .dc_sd_jwt, .vc_sd_jwt:
                decodedFormats[key] = try vpFormatsContainer.decode(SdJwtVpFormatSupported.self, forKey: key)
            }
        }
        return decodedFormats
    }
    
    func toWalletMetadata(specVersion: SpecVersion, excludeSignedRequestConfig: Bool = false) throws -> [String: Any] {
        do {
            var walletMetadata: [String: Any] = [:]
            
            switch specVersion {
            case .v1:
                var vpFormatsEncoded: [String: Any] = [:]
                for (key, value) in vpFormatsSupported {
                    let data = try JSONEncoder().encode(value)
                    if let formatDict = try JSONSerialization.jsonObject(with: data) as? [String: Any] {
                        vpFormatsEncoded[key.rawValue] = formatDict
                    }
                }
                walletMetadata[MetadataConstants.vpFormatsSupported] = vpFormatsEncoded
                walletMetadata[WalletMetadataConstants.clientIdPrefixesSupported] = clientIdPrefixesSupported.map { $0.rawValue }
                if let requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported {
                    walletMetadata[WalletMetadataConstants.requestObjectSigningAlgValuesSupported] = requestObjectSigningAlgValuesSupported.map { $0.rawValue }
                }
                if let authorizationEncryptionAlgValuesSupported = authorizationEncryptionAlgValuesSupported {
                    walletMetadata[WalletMetadataConstants.authorizationEncryptionAlgValuesSupported] = authorizationEncryptionAlgValuesSupported.map { $0.rawValue }
                }
                if let authorizationEncryptionEncValuesSupported = authorizationEncryptionEncValuesSupported {
                    walletMetadata[WalletMetadataConstants.authorizationEncryptionEncValuesSupported] = authorizationEncryptionEncValuesSupported.map { $0.rawValue }
                }
                walletMetadata[WalletMetadataConstants.responseTypesSupported] = responseTypesSupported.map { $0.rawValue }
                
            case .draft23:
                let vpFormats: [String: Any] = vpFormatsSupported.reduce(into: [:]) { result, item in
                    let formatKey = item.key.rawValue
                    if let algValues = item.value.toAlgValuesSupported() {
                        result[formatKey] = [MetadataConstants.algValuesSupported: algValues]
                    } else {
                        result[formatKey] = [String: Any]()
                    }
                }
                walletMetadata[WalletMetadataConstants.presentationDefinitionUriSupported] = isPresentationDefinitionUriSupported
                walletMetadata[MetadataConstants.vpFormatsSupported] = vpFormats
                walletMetadata[WalletMetadataConstants.clientIdSchemesSupported] = clientIdPrefixesSupported.map { ClientIdPrefix.toClientIdScheme($0) }
                if let requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported {
                    walletMetadata[WalletMetadataConstants.requestObjectSigningAlgValuesSupported] = requestObjectSigningAlgValuesSupported.map { $0.rawValue }
                }
                if let authorizationEncryptionAlgValuesSupported = authorizationEncryptionAlgValuesSupported {
                    walletMetadata[WalletMetadataConstants.authorizationEncryptionAlgValuesSupported] = authorizationEncryptionAlgValuesSupported.map { $0.rawValue }
                }
                if let authorizationEncryptionEncValuesSupported = authorizationEncryptionEncValuesSupported {
                    walletMetadata[WalletMetadataConstants.authorizationEncryptionEncValuesSupported] = authorizationEncryptionEncValuesSupported.map { $0.rawValue }
                }
                walletMetadata[WalletMetadataConstants.responseTypesSupported] = responseTypesSupported.map { $0.rawValue }
            }
            
            if(excludeSignedRequestConfig) {
                walletMetadata.removeValue(forKey: WalletMetadataConstants.requestObjectSigningAlgValuesSupported)
            }
            
            return walletMetadata
        } catch {
            throw EncodingFailed(errorMessage: "Error encoding wallet metadata", errorCode: OpenID4VPErrorCodes.serverError, className: "WalletConfig")
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        var vpFormatsContainer = container.nestedContainer(keyedBy: VPFormatType.self, forKey: .vpFormatsSupported)
        for (key, value) in vpFormatsSupported {
            switch key {
            case .ldp_vc, .ldp_vp:
                if let v = value as? LdpVpFormatSupported {
                    try vpFormatsContainer.encode(v, forKey: key)
                }
            case .mso_mdoc:
                if let v = value as? MsoMdocVpFormatSupported {
                    try vpFormatsContainer.encode(v, forKey: key)
                }
            case .dc_sd_jwt, .vc_sd_jwt:
                if let v = value as? SdJwtVpFormatSupported {
                    try vpFormatsContainer.encode(v, forKey: key)
                }
            }
        }
        try container.encode(clientIdPrefixesSupported, forKey: .clientIdPrefixesSupported)
        try container.encode(requestObjectSigningAlgValuesSupported, forKey: .requestObjectSigningAlgValuesSupported)
        try container.encode(authorizationEncryptionAlgValuesSupported, forKey: .authorizationEncryptionAlgValuesSupported)
        try container.encode(authorizationEncryptionEncValuesSupported, forKey: .authorizationEncryptionEncValuesSupported)
        try container.encode(responseTypesSupported, forKey: .responseTypesSupported)
        try container.encode(isPresentationDefinitionUriSupported, forKey: .presentationDefinitionUriSupported)
        try container.encode(trustedVerifiers, forKey: .trustedVerifiers)
        try container.encode(validateTrustedVerifier, forKey: .validateTrustedVerifier)
    }
}

@usableFromInline
struct WalletConfigDefaults {
    @usableFromInline
    static let vpFormatsSupported: [VPFormatType: VPFormatSupported] = [
        .ldp_vc: LdpVpFormatSupported(),
        .mso_mdoc: MsoMdocVpFormatSupported(),
        .dc_sd_jwt: SdJwtVpFormatSupported()
    ]
    
    @usableFromInline
    static let clientIdPrefixesSupported: [ClientIdPrefix] = [.preRegistered, .redirectUri, .decentralizedIdentifier]
    
    @usableFromInline
    static let requestObjectSigningAlgValuesSupported: [SignatureAlgorithm] = [.edDsa]
    
    @usableFromInline
    static let authorizationEncryptionAlgValuesSupported: [EncryptionAlgorithm] = [.ecdhES]
    
    @usableFromInline
    static let authorizationEncryptionEncValuesSupported: [EncryptionMethod] = [.a256GCM]
    
    @usableFromInline
    static let responseTypesSupported: [ResponseType] = [.vp_token]
    
    @usableFromInline
    static let presentationDefinitionUriSupported: Bool = true
    
    @usableFromInline
    static let trustedVerifiers: [Verifier] = []
    
    @usableFromInline
    static let validateTrustedVerifier: Bool = true
}
