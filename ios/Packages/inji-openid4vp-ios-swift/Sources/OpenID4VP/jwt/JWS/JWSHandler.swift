import Foundation
import CryptoKit
import JSONWebSignature
import Base58Swift

struct JWSHandler {
    static let className = String(describing: JWSHandler.self)
    
    static func verify(jws: String, publicKey: PublicKeyType) async throws {
        do {
            let jws = try JWS(jwsString: jws)
            
            switch publicKey {
            case .ed25519(let edKey):
                guard try jws.verify(key: edKey) else {
                    throw InvalidSignature(
                        className: JWSHandler.className
                    )
                }
            case .secKey(let secKey):
                guard try jws.verify(key: secKey) else {
                    throw InvalidSignature(
                        className: JWSHandler.className
                    )
                }
            }
        } catch {
            throw VerificationFailure(
                message: error.localizedDescription,
                className: JWSHandler.className
            )
        }
    }
    
    static func createUnsignedJWS(header: [String: Any], payload: [String: Any]) throws -> String {
        do {
            let headerEncoded = try JSONSerialization.data(withJSONObject: header, options: []).toBase64UrlEncoded()
            let payloadJson = try JSONSerialization.data(withJSONObject: payload, options: [])
            let payloadEncoded = payloadJson.toBase64UrlEncoded()
            return "\(headerEncoded).\(payloadEncoded)"
        } catch {
            throw GenericFailure(message: "JWS creation failed: \(error.localizedDescription)", className: JWSHandler.className)
        }
    }

    static func extractDataJsonFromJws(jws: String, jwsPart: JWSPart) throws -> [String:Any] {
        let components = jws.split(separator: ".")
        let payload = String(components[jwsPart.rawValue])
        return try Base64Decoder.decodeBase64ToJSON(payload)
    }
}

