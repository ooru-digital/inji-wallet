import Foundation
import CryptoKit
import Base58Swift

class DidKeyResolver : BaseDidPublicKeyResolver{
    private enum MulticodecPrefix {
        static let ed25519 = "z6M"    // Ed25519
        static let p256 = "zDn"       // P-256
        static let p384 = "z82"       // P-384
        static let secp256k1 = "zQ3"  // secp256k1
    }
    
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
    
    func extractJWSAlgorithm(parsedDid: ParsedDID) async throws -> String {
        let identifier = parsedDid.id.replacingOccurrences(of: "did:key:", with: "")
        
        if identifier.hasPrefix(MulticodecPrefix.ed25519) { return JWSAlgorithm.eddsa }
        if identifier.hasPrefix(MulticodecPrefix.p256)    { return JWSAlgorithm.es256 }
        if identifier.hasPrefix(MulticodecPrefix.p384)    { return JWSAlgorithm.es384 }
        if identifier.hasPrefix(MulticodecPrefix.secp256k1) { return JWSAlgorithm.es256k }
        
        throw UnsupportedOperationException(message: "Unsupported DID key type. Supported types: Ed25519, P-256, P-384, secp256k1", className: Self.className)
    }
}
