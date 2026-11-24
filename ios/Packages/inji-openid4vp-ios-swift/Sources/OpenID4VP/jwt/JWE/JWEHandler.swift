import Foundation
import JSONWebKey
import CryptoKit
import JSONWebEncryption
import JSONWebAlgorithms

public struct JWEHandler {
    let contentEncryptionAlgorithm: String
    let keyEncryptionAlgorithm: String
    let publicKey: JWK
    let producerInfo: String
    let recipientInfo: String
    
    static let className = String(describing: JWEHandler.self)
    
    func encrypt(_ payload: Data) throws -> String {
        guard (keyEncryptionAlgorithm == KeyManagementAlgorithm.ecdhES.rawValue && contentEncryptionAlgorithm == ContentEncryptionAlgorithm.a256GCM.rawValue) else {
            throw UnsupportedOperationException(message: "Unsupported encryption configuration: keyEncryptionAlgorithm=\(keyEncryptionAlgorithm), contentEncryptionAlgorithm=\(contentEncryptionAlgorithm). Supported configuration: keyEncryptionAlgorithm=ECDH-ES, contentEncryptionAlgorithm=A256GCM", className: JWEHandler.className)
        }
        
        do {
            let recipientKey: JWK = publicKey
            try validateRecipientKey(recipientKey)
            
            var header = DefaultJWEHeaderImpl()
            header.keyManagementAlgorithm = .ecdhES
            header.encodingAlgorithm = .a256GCM
            header.agreementPartyUInfo = Data(base64UrlEncoded: producerInfo)
            header.agreementPartyVInfo = Data(base64UrlEncoded: recipientInfo)
            header.keyID = recipientKey.keyID
            
            let payloadData: Data = payload
            let jwe = try JWE(payload: payloadData, protectedHeader: header, recipientKey: recipientKey)
            
            return jwe.compactSerialization()
        } catch {
            throw JweEncryptionFailure(
                message: "JWE Encryption failed : \(error.localizedDescription)",
                className: Self.className
            )
        }
    }
    
    private func validateRecipientKey( _ jwk: JWK) throws {
        
        let supportedAlgorithms: Set<KeyManagementAlgorithm> = [
            .ecdhES
        ]
        let algorithm = KeyManagementAlgorithm(rawValue: jwk.algorithm ?? keyEncryptionAlgorithm)
        
        guard let algorithm = algorithm,
              supportedAlgorithms.contains(algorithm) else {
            throw JweEncryptionFailure(
                message: "Unsupported JWE algorithm: \(algorithm?.rawValue ?? "nil")",
                className: Self.className
            )
        }
        
        let kty = jwk.keyType
        
        switch kty {
            
        case .octetKeyPair:
            let crv = jwk.curve
            
            guard crv == .x25519 else {
                throw JweEncryptionFailure(
                    message: "Unsupported OKP curve for ECDH-ES: \(crv?.rawValue ?? "nil"). Only X25519 is supported.",
                    className: Self.className
                )
            }
            
        case .ellipticCurve:
            let crv = jwk.curve
            
            guard [.p256, .p384, .p521].contains(crv) else {
                throw JweEncryptionFailure(
                    message: "Unsupported EC curve for ECDH-ES: \(crv?.rawValue ?? "nil"). Only P-256, P-384, P-521 are supported.",
                    className: Self.className
                )
            }
            
        default:
            throw UnsupportedKeyExchangeAlgorithm(
                className: Self.className
            )
        }
    }
}
