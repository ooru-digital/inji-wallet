import Foundation
import JSONWebKey
import Base58Swift
import CryptoKit

private let className = "PublicKeyResolverUtils"

func publicKeyFromMultibase(_ publicKeyMultibase: String) throws -> PublicKeyType {
    guard publicKeyMultibase.first == "z" else {
        throw JsonDecodingFailed(
            message: "DID public key decoding failed",
            className: className
        )
    }
    
    let base58Part = String(publicKeyMultibase.dropFirst())
    guard let decoded = Base58.base58Decode(base58Part) else{
        throw JsonDecodingFailed(
            message: "DID public key decoding failed",
            className: className
        )
    }
    
    guard decoded.count > 2 else {
        throw JsonDecodingFailed(
            message: "DID public key decoding failed",
            className: className
        )
    }
    
    let prefix = Array(decoded.prefix(2))
    let keyData = Data(decoded.dropFirst(2))
    
    switch prefix {
    case [0xed, 0x01]:
        guard keyData.count == 32 else {
            throw JsonDecodingFailed(
                message: "DID public key decoding failed",
                className: className
            )
        }
        return try toEd25519Key(publicKeyData: keyData)
        
    case [0x12, 0x00]:
        return try createSecKey(from: keyData).map { .secKey($0) } ?? {
            throw JsonDecodingFailed(
                message: "DID public key decoding failed",
                className: className
            )
        }()
        
    default:
        throw JsonDecodingFailed(
            message: "DID public key decoding failed. Unsupported public key format",
            className: className
        )
    }
}

func publicKeyFromJWK(_ jwk: [String: Any]) throws -> PublicKeyType {
    if let kty = jwk["kty"] as? String, kty != "OKP"  {
        throw PublicKeyResolutionFailed(
            message: "KeyType - \(kty) is not supported. Supported: OKP",
            className: className
        )
    }
    
    if let crv = jwk["crv"] as? String, crv != "Ed25519" {
        throw PublicKeyResolutionFailed(
            message: "Curve - \(crv) is not supported. Supported: Ed25519",
            className: className
        )
    }
    
    guard let x = jwk["x"] as? String else {
        throw PublicKeyResolutionFailed(
            message: "Missing the public key data in JWK",
            className: className
        )
    }
    
    guard let keyData = Data(base64UrlEncoded: x) else {
        throw PublicKeyResolutionFailed(
            message: "Invalid base64url encoding for public key data in JWK",
            className: className
        )
    }
    return try toEd25519Key(publicKeyData: keyData)
}


func hexStringToData(_ hex: String) -> Data? {
    var data = Data()
    var temp = ""
    for char in hex {
        temp.append(char)
        if temp.count == 2 {
            if let byte = UInt8(temp, radix: 16) {
                data.append(byte)
                temp = ""
            } else {
                return nil
            }
        }
    }
    return data
}


func publicKeyFromHex(_ hexKey: String) throws -> PublicKeyType? {
    let hexData = hexStringToData(hexKey)!
    return try toEd25519Key(publicKeyData: hexData)
}


func publicKeyFromPEM(_ pem: String) throws -> PublicKeyType {
    let base64Key = pem
        .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
        .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
        .replacingOccurrences(of: "\n", with: "")
        .replacingOccurrences(of: "\r", with: "")

    guard let derData = Data(base64Encoded: base64Key) else {
        throw PublicKeyResolutionFailed(
            message: "Invalid PEM format",
            className: className
        )
    }

    let expectedHeader: [UInt8] = [
        0x30, 0x2a,
        0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x70,
        0x03
    ]

    var offset = 0
    for i in 0..<derData.count {
        if derData[i...].starts(with: expectedHeader) {
            offset = i + 12
            break
        }
    }

    guard offset > 0, derData.count >= offset + 32 else {
        throw PublicKeyResolutionFailed(
            message: "Invalid Ed25519 public key format",
            className: className
        )
    }

    let publicKeyBytes = derData[offset..<offset + 32]

    return try toEd25519Key(publicKeyData: publicKeyBytes)
}

private func createSecKey(from publicKeyData: Data) -> SecKey? {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits as String: 256,
        kSecReturnPersistentRef as String: false
    ]
    
    return SecKeyCreateWithData(publicKeyData as CFData,
                                attributes as CFDictionary,
                                nil)
}


func decodeMultibase(_ multibaseKey: String) throws -> Data {
    guard multibaseKey.starts(with: "z") else {  throw JsonDecodingFailed(
        message: "Multibase not starting with base58 prefix",
        className: className
    ) } // "z" = base58btc
    
    let encoded = String(multibaseKey.dropFirst())
    guard let decoded = Base58.base58Decode(encoded) else {
        throw JsonDecodingFailed(
            message: "DID public key decoding failed",
            className: className
        )
    }
    return Data(decoded)
}

func toEd25519Key(publicKeyData: Data) throws -> PublicKeyType {
    do {
        let edKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
        return .ed25519(edKey)
    } catch {
        throw PublicKeyResolutionFailed(message: "Public key resolution failed. Error: \(error)", className: className)
    }
}

internal func toEdPublicKey(jwk: JWK) throws -> PublicKeyType {
    guard jwk.curve == .ed25519 else {
        throw PublicKeyResolutionFailed(
            message: "Curve - \(jwk.curve?.rawValue ?? "") is not supported. Supported: Ed25519",
            className: className
        )
    }
    
    guard let publicKeyData = jwk.x else {
        throw PublicKeyResolutionFailed(message: "Invalid base64url encoding for public key data", className: className)
    }
    
    return try toEd25519Key(publicKeyData: publicKeyData)
}

internal func toECPublicKey(jwk: JWK) throws -> PublicKeyType {
    guard jwk.curve == .p256 else {
        throw PublicKeyResolutionFailed(
            message: "Curve - \(jwk.curve?.rawValue ?? "") is not supported. Supported: P-256",
            className: className
        )
    }
    
    guard let xData = jwk.x, let yData = jwk.y else {
        throw PublicKeyResolutionFailed(message: "Invalid base64url encoding for public key data", className: className)
    }
    
    var keyData = Data([0x04])
    keyData.append(xData)
    keyData.append(yData)
    
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits as String: 256
    ]
    
    var error: Unmanaged<CFError>?
    guard let secKey = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
        throw PublicKeyResolutionFailed(
            message: "Public key creation failed: \(error?.takeRetainedValue().localizedDescription ?? "unknown error")",
            className: className
        )
    }
    
    return .secKey(secKey)
}

func extractSigningAlgorithm(from publicKey : PublicKeyType) -> String {
    switch publicKey {
    case .ed25519(_):
        return "EdDSA"
    case .secKey(_):
        return "ES256"
    }
}

func jwkToPublicKey(_ jwk: JWK, className: String) throws -> PublicKeyType {
    switch jwk.keyType {
    case .octetKeyPair:
        return try toEdPublicKey(jwk: jwk)
        
    case .ellipticCurve:
        return try toECPublicKey(jwk: jwk)
        
    default:
        throw PublicKeyResolutionFailed(
            message: "KeyType - \(jwk.keyType.rawValue) is not supported. Supported: OKP, EC",
            className: className
        )
    }
}
