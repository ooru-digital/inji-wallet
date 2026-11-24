public protocol VPFormatSupported: Codable {
    func toAlgValuesSupported() -> [String]?
}

public struct LdpVpFormatSupported: VPFormatSupported, Codable {
    let proofTypeValues: [ProofType]?
    let cryptoSuiteValues: [String]?
    
    enum CodingKeys: String, CodingKey {
        case proofTypeValues = "proof_type_values"
        case cryptoSuiteValues = "cryptosuite_values"
    }
    
    public init(proofTypeValues: [ProofType]? = [.ed25519Signature2020, .jsonWebSignature2020], cryptoSuiteValues: [String]? = nil) {
        self.proofTypeValues = proofTypeValues
        self.cryptoSuiteValues = cryptoSuiteValues
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        if container.contains(.proofTypeValues) {
            var proofTypesArray = try container.nestedUnkeyedContainer(forKey: .proofTypeValues)
            var validProofTypes: [ProofType] = []
            
            while !proofTypesArray.isAtEnd {
                let rawValue = try proofTypesArray.decode(String.self)
                if let signatureAlgorithm = ProofType.fromValue(rawValue) {
                    validProofTypes.append(signatureAlgorithm)
                }
            }
            
            self.proofTypeValues = validProofTypes.isEmpty ? nil : validProofTypes
        } else {
            self.proofTypeValues = nil
        }
        
        self.cryptoSuiteValues = try container.decodeIfPresent([String].self, forKey: .cryptoSuiteValues)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(proofTypeValues, forKey: .proofTypeValues)
        try container.encodeIfPresent(cryptoSuiteValues, forKey: .cryptoSuiteValues)
    }
    
    public func toAlgValuesSupported() -> [String]? {
        if let proofTypeValues = proofTypeValues {
            return proofTypeValues.map { $0.rawValue }
        }
        return nil
    }
}

public struct MsoMdocVpFormatSupported: VPFormatSupported, Codable {
    let issuerAuthAlgValues: [Int]?
    let deviceAuthAlgValues: [Int]?
    private let algorithmValueNameMap: [Int: String] = [
        -7: "ES256",
         -9: "ESP256"
    ]
    
    enum CodingKeys: String, CodingKey {
        case issuerAuthAlgValues = "issuerauth_alg_values"
        case deviceAuthAlgValues = "deviceauth_alg_values"
    }
    
    public init(issuerAuthAlgValues: [Int]? = nil, deviceAuthAlgValues: [Int]? = nil) {
        self.issuerAuthAlgValues = issuerAuthAlgValues
        self.deviceAuthAlgValues = deviceAuthAlgValues
    }
    
    public func toAlgValuesSupported() -> [String]? {
        if let deviceAuthAlgValues = deviceAuthAlgValues {
            return deviceAuthAlgValues.map { algorithmValueNameMap[$0] ?? "Unknown(\($0))" }
        }
        return nil
    }
}


public struct SdJwtVpFormatSupported: VPFormatSupported, Codable {
    let sdJwtAlgValues: [String]?
    let kbJwtAlgValues: [String]?
    
    enum CodingKeys: String, CodingKey {
        case sdJwtAlgValues = "sd-jwt_alg_values"
        case kbJwtAlgValues = "kb-jwt_alg_values"
    }
    
    public init(sdJwtAlgValues: [String]? = nil, kbJwtAlgValues: [String]? = nil) {
        self.sdJwtAlgValues = sdJwtAlgValues
        self.kbJwtAlgValues = kbJwtAlgValues
    }
    
    public func toAlgValuesSupported() -> [String]? {
        return kbJwtAlgValues
    }
}
