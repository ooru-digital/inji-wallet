import Foundation

enum PublicKeyVerificationMaterial : String, Codable, CaseIterable {
    case jwk = "publicKeyJwk"
    case hex = "publicKeyHex"
    case multibase = "publicKeyMultibase"
    case pem = "publicKeyPem"
}
