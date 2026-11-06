import Foundation
import JSONWebKey
import CryptoKit

class X25519KeyAgreement: JWEKeyAgreement {
    static let className = String(describing: X25519KeyAgreement.self)
    private var ephemeralKeyPair: (privateKey: Curve25519.KeyAgreement.PrivateKey,
                                   publicKey: Curve25519.KeyAgreement.PublicKey)?
    
    func deriveKey(publicKey: Data, enc: String, producerInfo: String, recipientInfo: String) throws -> SymmetricKey {
        do {
            let privateKey = Curve25519.KeyAgreement.PrivateKey()
            let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)

            ephemeralKeyPair = (privateKey, privateKey.publicKey)

            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
            let z = sharedSecret.withUnsafeBytes { Data($0) }

            return SymmetricKey(data: try Self.concatKDF(z: z, enc: enc, apu: producerInfo, apv: recipientInfo))
        } catch {
            throw wrapError(
                error,
                customError: { msg in KeyAgreementFailed(message: msg, className: X25519KeyAgreement.className) }
            )
        }
    }

    /// RFC 7518 section 4.6.2 Concat KDF for direct ECDH-ES (no key wrap), where AlgorithmID is `enc`
    /// and the key length is the content encryption key length. Android's library (Nimbus) and
    /// spec-compliant verifiers derive the key this way.
    static func concatKDF(z: Data, enc: String, apu: String, apv: String) throws -> Data {
        guard let keyBits = contentKeyBits[enc] else {
            throw UnsupportedEncryptionAlgorithm(className: className)
        }
        var otherInfo = lengthPrefixed(Data(enc.utf8))
        otherInfo += lengthPrefixed(partyInfo(apu))
        otherInfo += lengthPrefixed(partyInfo(apv))
        otherInfo += uint32BigEndian(keyBits)

        // Each SHA-256 round gives 256 bits; one round covers every supported key length.
        let digest = SHA256.hash(data: uint32BigEndian(1) + z + otherInfo)
        return Data(digest).prefix(keyBits / 8)
    }

    private static let contentKeyBits = ["A128GCM": 128, "A192GCM": 192, "A256GCM": 256]

    /// apu/apv header values are base64url. Decode leniently (both alphabets, no padding), as
    /// Nimbus and the verifier do, so all sides derive the same key.
    private static func partyInfo(_ value: String) -> Data {
        let base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            .filter { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "+" || $0 == "/") }
        let padded = base64 + String(repeating: "=", count: (4 - base64.count % 4) % 4)
        return Data(base64Encoded: padded) ?? Data()
    }

    private static func lengthPrefixed(_ data: Data) -> Data {
        uint32BigEndian(data.count) + data
    }

    private static func uint32BigEndian(_ value: Int) -> Data {
        withUnsafeBytes(of: UInt32(value).bigEndian) { Data($0) }
    }
    
    func getEphemeralPublicKey() -> [String: Any]? {
        guard let publicKey = ephemeralKeyPair?.publicKey else { return nil }
        return [
            "kty": "OKP",
            "crv": "X25519",
            "x": base64URLEscaped(publicKey.rawRepresentation.base64EncodedString())
        ]
    }
    
    func getJWEHeader(alg: String, enc: String, jwk: JWK, producerInfo: String, recipientInfo: String) -> [String: Any] {
        return [
            "alg": alg,
            "enc": enc,
            "kid": jwk.keyID ?? "",
            "apu": producerInfo,
            "apv": recipientInfo,
        ]
    }
    
    func getEncyptionKey() -> String {
        return ""
    }
}
