import Foundation
import CryptoKit
import Base58Swift

class DidKeyResolver : BaseDidPublicKeyResolver{
    private static let className = String(describing: DidKeyResolver.self)
    let networkManager: NetworkManaging
    static let keySize = 34
    static let edKeyPrefix = 0xed
    static let multiCodecTrailingByte = 0x01
    
    
    init(networkManager: NetworkManaging) {
        self.networkManager = networkManager
    }
    
    func extractPublicKey(parsedDID: ParsedDID, keyId: String? = nil) async throws -> PublicKeyType {
        let decodedBytes = try decodeMultibase(parsedDID.id)
        
        guard decodedBytes.count == Self.keySize,
              decodedBytes[0] == Self.edKeyPrefix,
              decodedBytes[1] == Self.multiCodecTrailingByte else {
            throw PublicKeyResolutionFailed(message: "Provided key is not supported. Supported: Ed25519", className: Self.className)
        }
        
        let keyBytes = decodedBytes[2..<34]
        
        return try toEd25519Key(publicKeyData: keyBytes)
    }
}
