import Foundation
import JSONWebKey
import CryptoKit
import Base58Swift

class DidJwkResolver : BaseDidPublicKeyResolver {
    private static let className = String(describing: DidJwkResolver.self)
    let networkManager: NetworkManaging
    
    init(networkManager: NetworkManaging)  {
        self.networkManager = networkManager
    }
    
    func extractPublicKey(parsedDID: ParsedDID, keyId: String? = nil) async throws -> PublicKeyType {
        let base64urlJwk = String(parsedDID.id)
        let jwk = try decodeJWK(base64urlJwk)
        
        return try jwkToPublicKey(jwk, className: Self.className)
    }
    
    func extractJWSAlgorithm(parsedDid: ParsedDID) async throws -> String {
        let base64urlJwk = String(parsedDid.id)
        let jwk = try decodeJWK(base64urlJwk)

        return try jwk.resolveJWSAlgorithm(className: Self.className)
    }
    
    private func decodeJWK(_ base64urlJwk: String) throws -> JWK {
        guard let jwkData = Data(base64UrlEncoded: base64urlJwk) else {
            throw PublicKeyResolutionFailed(message: "Invalid base64url encoding for public key data", className: "Utils")
        }
        
        let jwk = try {
            do {
                return try JSONDecoder().decode(JWK.self, from: jwkData)
            } catch {
                throw PublicKeyResolutionFailed(
                    message: "Failed to decode JWK: \(error.localizedDescription)",
                    className: "Utils"
                )
            }
        }()
        
        return jwk
    }
}
