import Foundation
import JSONWebKey
import CryptoKit
import SwiftCBOR

enum JWSAlgorithm {
    static let eddsa = "EdDSA"
    static let rs256 = "RS256"
    static let es256 = "ES256"
    static let es384 = "ES384"
    static let es256k = "ES256K"

    /// Algorithms supported for holder / key-binding JWS signing.
    /// `none` (unsecured JWS) is intentionally excluded.
    static let supported = [eddsa, rs256, es256, es384, es256k]

    static func normalized(_ value: String) -> String? {
        supported.first { $0.caseInsensitiveCompare(value) == .orderedSame }
    }
}
