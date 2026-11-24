import Foundation
import JSONWebKey
import CryptoKit

protocol JWEKeyAgreement {
    func deriveKey(publicKey: Data, algorithm: String,
                   apu: String,
                   apv: String) throws -> SymmetricKey
    func getEphemeralPublicKey() -> [String: Any]?
    //TODO: should Header come from this class or simply be a map
    func getJWEHeader(alg: String, enc: String, jwk: JWK, producerInfo: String, recipientInfo: String) -> [String: Any]
    func getEncyptionKey() -> String
}

protocol JWEEncryption {
    func encrypt(_ data: Data, with key: SymmetricKey, aad: Data?) throws -> (ciphertext: Data, nonce: Data, tag: Data)
}
