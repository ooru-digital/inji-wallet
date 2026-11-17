import Foundation
import CryptoKit

class AESGCMEncryption: JWEEncryption {
    let keySize: SymmetricKeySize
    static let className = String(describing: AESGCMEncryption.self)

       init(keySize: SymmetricKeySize = .bits256) {
           self.keySize = keySize
       }
    
    func encrypt(_ data: Data, with key: SymmetricKey, aad: Data) throws -> (ciphertext: Data, nonce: Data, tag: Data) {

        guard key.bitCount == keySize.bitCount else {

            throw InvalidEncryptionKeySize(className: AESGCMEncryption.className)
        }

        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(data, using: key, nonce: nonce, authenticating: aad)
        
        return (
            sealedBox.ciphertext,
            sealedBox.nonce.withUnsafeBytes { Data($0) },
            sealedBox.tag
        )
    }
}
