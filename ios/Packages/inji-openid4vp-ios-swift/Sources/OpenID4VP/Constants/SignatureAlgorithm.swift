import Foundation

public enum SignatureAlgorithm: String, CaseIterable {
    case ed25519Signature2020 = "Ed25519Signature2020"
    case jsonWebSignature2020 = "JsonWebSignature2020"
    case ed25519Signature2018 = "Ed25519Signature2018"
    case rsaSignature2018 = "RSASignature2018"
}
