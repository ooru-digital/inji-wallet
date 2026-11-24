import Foundation

public struct DCQLQuery: Codable {
    public let credentials: [CredentialQuery]
    public let credentialSets: [CredentialSetQuery]?
    private let className = String(describing: DCQLQuery.self)

    enum CodingKeys: String, CodingKey {
        case credentials
        case credentialSets = "credential_sets"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.credentials = try container.decodeRequired(
            [CredentialQuery].self,
            forKey: .credentials,
            fieldPath: ["dcql_query", "credentials"],
            className: className,
            isMandatory: true
        )!

        self.credentialSets = try container.decodeRequired(
            [CredentialSetQuery].self,
            forKey: .credentialSets,
            fieldPath: ["dcql_query", "credential_sets"],
            className: className,
            isMandatory: false
        )

        try validate()
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(credentials, forKey: .credentials)
        try container.encodeIfPresent(credentialSets, forKey: .credentialSets)
    }

    func validate() throws {
        if credentials.isEmpty {
            throw InvalidInput(fieldPath: ["dcql_query", "credentials"], className: className)
        }

        let credentialQueryIds = credentials.map { $0.id }
        if credentialQueryIds.count != Set(credentialQueryIds).count {
            throw InvalidData(
                message: "Credential Query ids must be unique within dcql_query",
                className: className
            )
        }

        for credentialQuery in credentials {
            try credentialQuery.validate()
        }

        if let credentialSets = credentialSets {
            if credentialSets.isEmpty {
                throw InvalidInput(fieldPath: ["dcql_query", "credential_sets"], className: className)
            }

            for credentialSet in credentialSets {
                try credentialSet.validateCredentialIdReferences(credentialQueryIds: Set(credentialQueryIds))
            }
        }
    }
}

public struct CredentialQuery: Codable {
    public let id: String
    public let format: String
    public let multiple: Bool
    public let meta: [String: AnyCodable]
    public let requireCryptographicHolderBinding: Bool
    public let claims: [ClaimsQuery]?
    public let claimSets: [[String]]?
    private let className = String(describing: CredentialQuery.self)

    private static let validIdPattern = #"^[a-zA-Z0-9_-]+$"#

    enum CodingKeys: String, CodingKey {
        case id
        case format
        case multiple
        case meta
        case requireCryptographicHolderBinding = "require_cryptographic_holder_binding"
        case claims
        case claimSets = "claim_sets"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.id = try container.decodeRequired(
            String.self,
            forKey: .id,
            fieldPath: ["credential_query", "id"],
            className: className,
            isMandatory: true
        )!

        self.format = try container.decodeRequired(
            String.self,
            forKey: .format,
            fieldPath: ["credential_query", "format"],
            className: className,
            isMandatory: true
        )!

        self.multiple = (try container.decodeIfPresent(Bool.self, forKey: .multiple)) ?? false

        self.meta = try container.decodeRequired(
            [String: AnyCodable].self,
            forKey: .meta,
            fieldPath: ["credential_query", "meta"],
            className: className,
            isMandatory: true
        )!

        self.requireCryptographicHolderBinding = (try container.decodeIfPresent(Bool.self, forKey: .requireCryptographicHolderBinding)) ?? true

        self.claims = try container.decodeRequired(
            [ClaimsQuery].self,
            forKey: .claims,
            fieldPath: ["credential_query", "claims"],
            className: className,
            isMandatory: false
        )

        self.claimSets = try container.decodeRequired(
            [[String]].self,
            forKey: .claimSets,
            fieldPath: ["credential_query", "claim_sets"],
            className: className,
            isMandatory: false
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(format, forKey: .format)
        try container.encode(multiple, forKey: .multiple)
        try container.encode(meta, forKey: .meta)
        try container.encode(requireCryptographicHolderBinding, forKey: .requireCryptographicHolderBinding)
        try container.encodeIfPresent(claims, forKey: .claims)
        try container.encodeIfPresent(claimSets, forKey: .claimSets)
    }

    func validate() throws {
        guard id.range(of: CredentialQuery.validIdPattern, options: .regularExpression) != nil else {
            throw InvalidData(
                message: "Credential Query id must consist of alphanumeric, underscore or hyphen characters",
                className: className
            )
        }

        guard isValidString(format) else {
            throw InvalidInput(fieldPath: ["credential_query", "format"], className: className)
        }

        if let claims = claims {
            if claims.isEmpty {
                throw InvalidInput(fieldPath: ["credential_query", "claims"], className: className)
            }

            let claimIds = claims.compactMap { $0.id }
            if claimIds.count != Set(claimIds).count {
                throw InvalidData(
                    message: "Claim ids must be unique within a Credential Query",
                    className: className
                )
            }

            for claim in claims {
                try claim.validate(isCredentialSetsAvailable: claimSets != nil)
            }
        }

        if let claimSets = claimSets {
            guard let claims = claims else {
                throw InvalidData(
                    message: "claim_sets must not be present when claims is absent",
                    className: className
                )
            }
            if claimSets.isEmpty {
                throw InvalidInput(fieldPath: ["credential_query", "claim_sets"], className: className)
            }
            let validClaimIds = Set(claims.compactMap { $0.id })
            for claimSet in claimSets {
                if claimSet.isEmpty {
                    throw InvalidInput(fieldPath: ["credential_query", "claim_sets"], className: className)
                }
                
                for claimId in claimSet {
                    guard validClaimIds.contains(claimId) else {
                        throw InvalidData(
                            message: "claim_sets references unknown claim id '\(claimId)'",
                            className: className
                        )
                    }
                }
            }
        }
    }
}

public struct CredentialSetQuery: Codable {
    public let options: [[String]]
    public let required: Bool
    private let className = String(describing: CredentialSetQuery.self)

    enum CodingKeys: String, CodingKey {
        case options
        case required
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.options = try container.decodeRequired(
            [[String]].self,
            forKey: .options,
            fieldPath: ["credential_set_query", "options"],
            className: className,
            isMandatory: true
        )!

        self.required = (try container.decodeIfPresent(Bool.self, forKey: .required)) ?? true

        try validate()
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(options, forKey: .options)
        try container.encode(required, forKey: .required)
    }
    
    internal init(options: [[String]], required: Bool) {
        self.options = options
        self.required = required
    }

    func validate() throws {
        if options.isEmpty {
            throw InvalidInput(fieldPath: ["credential_set_query", "options"], className: className)
        }
        for option in options {
            guard !option.isEmpty else {
                throw InvalidInput(fieldPath: ["credential_set_query", "options"], className: className)
            }
        }
    }
    
    func validateCredentialIdReferences(credentialQueryIds: Set<String>) throws {
        for option in options {
            for credentialQueryIdentifier in option {
                guard credentialQueryIds.contains(credentialQueryIdentifier) else {
                    throw InvalidData(
                        message: "credential_sets references unknown credential id '\(credentialQueryIdentifier)'",
                        className: className
                    )
                }
            }
            
        }
    }
}

public enum ClaimValue: Codable, Equatable {
    case string(String)
    case int(Int)
    case bool(Bool)

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let boolValue = try? container.decode(Bool.self) {
            self = .bool(boolValue)
        } else if let intValue = try? container.decode(Int.self) {
            self = .int(intValue)
        } else if let stringValue = try? container.decode(String.self) {
            self = .string(stringValue)
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Claim value must be a string, integer, or boolean"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let v): try container.encode(v)
        case .int(let v):    try container.encode(v)
        case .bool(let v):   try container.encode(v)
        }
    }
}

public struct ClaimsQuery: Codable {
    public let id: String?
    public let path: [AnyCodable]
    public let values: [ClaimValue]?
    private let className = String(describing: ClaimsQuery.self)

    private static let validIdPattern = #"^[a-zA-Z0-9_-]+$"#

    enum CodingKeys: String, CodingKey {
        case id
        case path
        case values
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.id = try container.decodeRequired(
            String.self,
            forKey: .id,
            fieldPath: ["claims_query", "id"],
            className: className,
            isMandatory: false
        )

        self.path = try container.decodeRequired(
            [AnyCodable].self,
            forKey: .path,
            fieldPath: ["claims_query", "path"],
            className: className,
            isMandatory: true
        )!

        self.values = try container.decodeRequired(
            [ClaimValue].self,
            forKey: .values,
            fieldPath: ["claims_query", "values"],
            className: className,
            isMandatory: false
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(id, forKey: .id)
        try container.encode(path, forKey: .path)
        try container.encodeIfPresent(values, forKey: .values)
    }

    func validate(isCredentialSetsAvailable: Bool) throws {
        if(isCredentialSetsAvailable && id == nil) {
            throw InvalidData(
                message: "Claims with claim_sets must have an id",
                className: className
            )
        }
            
        if let id = id {
            guard id.range(of: ClaimsQuery.validIdPattern, options: .regularExpression) != nil else {
                throw InvalidData(
                    message: "Claims Query id must consist of alphanumeric, underscore or hyphen characters",
                    className: className
                )
            }
        }

        if path.isEmpty {
            throw InvalidInput(fieldPath: ["claims_query", "path"], className: className)
        }

        if let values = values {
            if values.isEmpty {
                throw InvalidInput(fieldPath: ["claims_query", "values"], className: className)
            }
        }
    }
}
