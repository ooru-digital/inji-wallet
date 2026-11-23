import Foundation
import JSONWebKey

extension JWK {

    func resolveJWSAlgorithm(className: String) throws -> String {
        if let explicitAlg = algorithm {
            guard let supportedAlg = JWSAlgorithm.normalized(explicitAlg) else {
                throw InvalidData(message: "Unsupported JWK alg '\(explicitAlg)'", className: className)
            }
            return supportedAlg
        }

        switch (keyType, curve) {
        case (.octetKeyPair, .ed25519):    return JWSAlgorithm.eddsa
        case (.ellipticCurve, .p256):      return JWSAlgorithm.es256
        case (.ellipticCurve, .p384):      return JWSAlgorithm.es384
        case (.ellipticCurve, .secp256k1): return JWSAlgorithm.es256k
        case (.rsa, _):                    return JWSAlgorithm.rs256
        default:
            throw InvalidData(
                message: "Cannot determine algorithm from JWK (kty=\(keyType.rawValue), crv=\(curve?.rawValue ?? "nil"))",
                className: className
            )
        }
    }
}
