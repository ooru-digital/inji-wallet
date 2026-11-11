import Foundation

@usableFromInline
internal struct WalletMetadataDefaults: Codable {
    @usableFromInline static let presentationDefinitionURISupported: Bool = true
    @usableFromInline static let vpFormatsSupported: [VPFormatType: VPFormatSupported] = [
        .ldp_vc: VPFormatSupported(algValuesSupported: []),
        .ldp_vp: VPFormatSupported(algValuesSupported: []),
        .mso_mdoc: VPFormatSupported(algValuesSupported: []),
    ]
    @usableFromInline static let clientIdSchemesSupported: [ClientIdScheme] = [.preRegistered, .redirectUri, .did]
    @usableFromInline static let requestObjectSigningAlgValuesSupported: [RequestSigningAlgorithm] = [.edDsa]
    @usableFromInline static let authorizationEncryptionAlgValuesSupported: [KeyManagementAlgorithm] = [.ecdhEs]
    @usableFromInline static let authorizationEncryptionEncValuesSupported: [ContentEncryptionAlgorithm] = [.A256GCM]
    @usableFromInline static let responseTypesSupported: [ResponseType] = [.vp_token]
}

public struct WalletMetadata: Codable {
    let presentationDefinitionURISupported: Bool
    let vpFormatsSupported: [VPFormatType: VPFormatSupported]
    let clientIdSchemesSupported: [ClientIdScheme]
    var requestObjectSigningAlgValuesSupported: [RequestSigningAlgorithm]?
    let authorizationEncryptionAlgValuesSupported: [KeyManagementAlgorithm]?
    let authorizationEncryptionEncValuesSupported: [ContentEncryptionAlgorithm]?
    let responseTypesSupported: [ResponseType]
    static let className = String(describing: WalletMetadata.self)
    
    enum CodingKeys: String, CodingKey {
        case presentationDefinitionURISupported = "presentation_definition_uri_supported"
        case vpFormatsSupported = "vp_formats_supported"
        case clientIdSchemesSupported = "client_id_schemes_supported"
        case requestObjectSigningAlgValuesSupported = "request_object_signing_alg_values_supported"
        case authorizationEncryptionAlgValuesSupported = "authorization_encryption_alg_values_supported"
        case authorizationEncryptionEncValuesSupported = "authorization_encryption_enc_values_supported"
        case responseTypesSupported = "response_types_supported"
    }
    
    @available(*, deprecated, message: "Use the initializer with explicit parameters instead.")
    public init(
        presentationDefinitionURISupported: Bool?,
        vpFormatsSupported: [String: VPFormatSupported],
        clientIdSchemesSupported: [String]?,
        requestObjectSigningAlgValuesSupported: [String]? = nil,
        authorizationEncryptionAlgValuesSupported: [String]? = nil,
        authorizationEncryptionEncValuesSupported: [String]? = nil
    ) throws {
        self.presentationDefinitionURISupported = presentationDefinitionURISupported ?? true
        self.vpFormatsSupported = try parseVPFormatsSupported(vpFormatsSupported)
        self.clientIdSchemesSupported = try parseClientIdSchemesSupported(clientIdSchemesSupported)
        self.requestObjectSigningAlgValuesSupported = try parseRequestObjectSigningAlgValuesSupported(requestObjectSigningAlgValuesSupported)
        self.authorizationEncryptionAlgValuesSupported = try parseAuthorizationEncryptionAlgValuesSupported(authorizationEncryptionAlgValuesSupported)
        self.authorizationEncryptionEncValuesSupported = try parseAuthorizationEncryptionEncValuesSupported(authorizationEncryptionEncValuesSupported)
        self.responseTypesSupported = WalletMetadataDefaults.responseTypesSupported
        
        try validateVPFormatsSupported(self.vpFormatsSupported)
    }
    
    public init(
        presentationDefinitionURISupported: Bool = WalletMetadataDefaults.presentationDefinitionURISupported,
        vpFormatsSupported: [VPFormatType: VPFormatSupported] = WalletMetadataDefaults.vpFormatsSupported,
        clientIdSchemesSupported: [ClientIdScheme] = WalletMetadataDefaults.clientIdSchemesSupported,
        requestObjectSigningAlgValuesSupported: [RequestSigningAlgorithm]? = WalletMetadataDefaults.requestObjectSigningAlgValuesSupported,
        authorizationEncryptionAlgValuesSupported: [KeyManagementAlgorithm]? = WalletMetadataDefaults.authorizationEncryptionAlgValuesSupported,
        authorizationEncryptionEncValuesSupported: [ContentEncryptionAlgorithm]? = WalletMetadataDefaults.authorizationEncryptionEncValuesSupported,
        responseTypesSupported: [ResponseType] = WalletMetadataDefaults.responseTypesSupported
    ) throws {
        self.presentationDefinitionURISupported = presentationDefinitionURISupported
        self.vpFormatsSupported = vpFormatsSupported
        self.clientIdSchemesSupported = clientIdSchemesSupported
        self.requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported
        self.authorizationEncryptionAlgValuesSupported = authorizationEncryptionAlgValuesSupported
        self.authorizationEncryptionEncValuesSupported = authorizationEncryptionEncValuesSupported
        self.responseTypesSupported = responseTypesSupported
        
        try validateVPFormatsSupported(vpFormatsSupported)
    }
}

private func parseClientIdSchemesSupported(_ clientIdSchemesSupported: [String]?) throws -> [ClientIdScheme] {
    guard let schemes = clientIdSchemesSupported else {
        return [.preRegistered]
    }
    return try schemes.compactMap { try parseEnum(valueName: "ClientIdScheme", $0, as: ClientIdScheme.self) }
}

private func parseVPFormatsSupported(_ vpFormatsSupported: [String: VPFormatSupported]) throws -> [VPFormatType: VPFormatSupported] {
    if vpFormatsSupported.keys.contains(where: { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }) {
        throw InvalidData(
            message: "vp_formats_supported cannot have empty keys.",
            className: WalletMetadata.className
        )
    }
    
    
    return try vpFormatsSupported.reduce(into: [VPFormatType: VPFormatSupported]()) { result, entry in
        let parsedVPFormatType = try parseEnum(valueName: "VPFormatType", entry.key, as: VPFormatType.self)
        result[parsedVPFormatType] = entry.value
    }
}

func parseEnum<E: RawRepresentable>(valueName: String, _ value: E.RawValue, as type: E.Type) throws -> E {
    guard let enumCase = E(rawValue: value) else {
        throw InvalidData(
            message: "Invalid \(valueName) value: \(value). Its is not supported by the library.",
            className: WalletMetadata.className
        )
    }
    
    return enumCase
}


private func parseRequestObjectSigningAlgValuesSupported(_ requestObjectSigningAlgValuesSupported: [String]?) throws -> [RequestSigningAlgorithm]? {
    guard let algs = requestObjectSigningAlgValuesSupported else {
        return nil
    }
    return try algs.compactMap { try parseEnum(valueName: "RequestSigningAlgorithm", $0, as: RequestSigningAlgorithm.self) }
}

private func parseAuthorizationEncryptionAlgValuesSupported(_ authorizationEncryptionAlgValuesSupported: [String]?) throws -> [KeyManagementAlgorithm]? {
    guard let algs = authorizationEncryptionAlgValuesSupported else {
        return nil
    }
    return try algs.compactMap { try parseEnum(valueName: "KeyManagementAlgorithm", $0, as: KeyManagementAlgorithm.self) }
}

private func parseAuthorizationEncryptionEncValuesSupported(_ authorizationEncryptionEncValuesSupported: [String]?) throws -> [ContentEncryptionAlgorithm]? {
    guard let encs = authorizationEncryptionEncValuesSupported else {
        return nil
    }
    return try encs.compactMap { try parseEnum(valueName: "ContentEncryptionAlgorithm", $0, as: ContentEncryptionAlgorithm.self) }
}

public struct VPFormatSupported: Codable {
    let algValuesSupported: [String]?
    
    enum CodingKeys: String, CodingKey {
        case algValuesSupported = "alg_values_supported"
    }
    
    public init(algValuesSupported: [String]? = nil) {
        self.algValuesSupported = algValuesSupported
    }
}

private func validateVPFormatsSupported(_ vpFormatsSupported: [VPFormatType: VPFormatSupported]) throws {
    if vpFormatsSupported.isEmpty {
        throw InvalidData(
            message: "vp_formats_supported should at least have one supported vp_format",
            className: WalletMetadata.className
        )
    }
}
