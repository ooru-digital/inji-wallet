import Foundation
import CryptoKit

public enum PublicKeyType {
    case secKey(SecKey)
    case ed25519(Curve25519.Signing.PublicKey)
}
