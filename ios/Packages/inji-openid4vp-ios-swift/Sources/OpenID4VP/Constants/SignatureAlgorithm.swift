import Foundation

public enum SignatureSuite: String, CaseIterable, Codable {
    case dataIntegrityProof = "DataIntegrityProof"
    case ed25519Signature2020 = "Ed25519Signature2020"
    case jsonWebSignature2020 = "JsonWebSignature2020"
    case ed25519Signature2018 = "Ed25519Signature2018"
    case rsaSignature2018 = "RsaSignature2018"
    
    public static func fromValue(_ value: String) -> SignatureSuite? {
        return SignatureSuite(rawValue: value)
    }
}

public enum SignatureAlgorithm: String, CaseIterable, Codable {
    case edDsa = "EdDSA"
    case es256 = "ES256"
    case es256k1 = "ES256k1"
    case rs256 = "RS256"
}
