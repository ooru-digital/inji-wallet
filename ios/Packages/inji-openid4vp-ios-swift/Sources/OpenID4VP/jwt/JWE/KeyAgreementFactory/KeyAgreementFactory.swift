import JSONWebKey

class KeyAgreementFactory {
    static let className = String(describing: KeyAgreementFactory.self)
    
    static func createKeyAgreement(for jwk: JWK) throws -> JWEKeyAgreement {
        switch (jwk.keyType, jwk.curve) {
        case (.octetKeyPair, .x25519):
            return X25519KeyAgreement()
        default:
            throw UnsupportedKeyAgreementAlgorithm(className: KeyAgreementFactory.className)
        }
    }
}
