import Foundation
import JSONWebKey

/**
 * Data class that holds information required for dispatching responses to the verifier.
 */
struct ResponseDispatchInfo {
    let responseMode: String
    let nonce: String?
    let walletNonce: String?
    let state: String?
    let clientId: String
    let responseUrl: String
    var responseEncryptionSpecification: ResponseEncryptionSpecification?
}

/**
 * Specification for encrypting authorization responses.
 *
 * @property keyEncryptionAlg The algorithm used for key encryption (e.g., "ECDH-ES")
 * @property contentEncryptionAlg The algorithm used for content encryption (e.g., "A256GCM")
 * @property verifierPublicKey The verifier's key (JWK) used for encryption
 */
struct ResponseEncryptionSpecification {
    let keyEncryptionAlg: EncryptionAlgorithm
    let contentEncryptionAlg: EncryptionMethod
    let verifierPublicKey: JWK
}
