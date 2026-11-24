import Foundation

public enum ProofType: String, CaseIterable, Codable {
    case ed25519Signature2020 = "Ed25519Signature2020"
    case jsonWebSignature2020 = "JsonWebSignature2020"
    
    public static func fromValue(_ value: String) -> ProofType? {
        return ProofType(rawValue: value)
    }
}
