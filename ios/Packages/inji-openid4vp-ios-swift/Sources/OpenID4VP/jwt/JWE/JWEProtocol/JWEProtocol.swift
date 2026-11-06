import Foundation
import JSONWebKey
import CryptoKit

protocol JWEKeyAgreement {
    /// `enc`, `producerInfo` (apu) and `recipientInfo` (apv) feed the RFC 7518 Concat KDF.
    func deriveKey(publicKey: Data, enc: String, producerInfo: String, recipientInfo: String) throws -> SymmetricKey
    func getEphemeralPublicKey() -> [String: Any]?
    //TODO: should Header come from this class or simply be a map
    func getJWEHeader(alg: String, enc: String, jwk: JWK, producerInfo: String, recipientInfo: String) -> [String: Any]
    func getEncyptionKey() -> String
}

protocol JWEEncryption {
    /// `aad` is the additional authenticated data; for a JWE it is the ASCII of the encoded protected header.
    func encrypt(_ data: Data, with key: SymmetricKey, aad: Data) throws -> (ciphertext: Data, nonce: Data, tag: Data)
}

extension JWEEncryption {
    func encrypt(_ data: Data, with key: SymmetricKey) throws -> (ciphertext: Data, nonce: Data, tag: Data) {
        try encrypt(data, with: key, aad: Data())
    }
}
