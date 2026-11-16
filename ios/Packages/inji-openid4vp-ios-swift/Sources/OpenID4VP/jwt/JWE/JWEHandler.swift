import Foundation
import JSONWebKey
import CryptoKit

public struct JWEHandler {
    let contentEncryptionAlgorithm: String
    let keyEncryptionAlgorithm: String
    let publicKey: JWK
    let producerInfo: String
    let recipientInfo: String
    
    static let className = String(describing: JWEHandler.self)

    func generateEncryptedResponse(payload: [String:Any]) throws -> String {
        var payloadData: Data
        do {
            payloadData = try toData(payload)
        } catch {
            throw PayloadConversionFailed(className: JWEHandler.className)
        }

        //TODO: Perform key agreement based on keyEncryptionAlgorithm
        let encrypter = try EncryptionProvider.getEncrypter(contentEncryptionAlgorithm)
        let keyAgreement = try KeyAgreementFactory.createKeyAgreement(for: publicKey)
        let sharedKey = try keyAgreement.deriveKey(
            publicKey: publicKey.x ?? Data(),
            enc: contentEncryptionAlgorithm,
            producerInfo: producerInfo,
            recipientInfo: recipientInfo
        )

        var header = keyAgreement.getJWEHeader(alg: publicKey.algorithm ?? "", enc: contentEncryptionAlgorithm, jwk: publicKey, producerInfo: producerInfo, recipientInfo: recipientInfo)
        if let epk = keyAgreement.getEphemeralPublicKey() {
            header["epk"] = epk
        }
        let encodedHeader = try JSONSerialization.data(withJSONObject: header).toBase64UrlEncoded()

        // RFC 7516 section 5.1: the AAD is the ASCII of the encoded protected header.
        let (ciphertext, nonce, tag) = try encrypter.encrypt(payloadData, with: sharedKey, aad: Data(encodedHeader.utf8))

        return encodeJWEComponents(
            encodedHeader: encodedHeader,
            encryptedKey: keyAgreement.getEncyptionKey(),
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag
        )
    }

    private func encodeJWEComponents(
        encodedHeader: String,
        encryptedKey: String,
        nonce: Data,
        ciphertext: Data,
        tag: Data
    ) -> String {
        let encodedEncryptedKey = encryptedKey
        let encodedIV = nonce.toBase64UrlEncoded()
        let encodedCiphertext = ciphertext.toBase64UrlEncoded()
        let encodedAuthTag = tag.toBase64UrlEncoded()
        
        return [
            encodedHeader,
            encodedEncryptedKey,
            encodedIV,
            encodedCiphertext,
            encodedAuthTag
        ].joined(separator: ".")
    }
}
