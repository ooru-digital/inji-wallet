import XCTest
import CryptoKit
import Base58Swift
@testable import OpenID4VP

fileprivate let mockNetworkManager = MockNetworkManager()

final class DidKeyResolverTests: XCTestCase {
    let resolver = DidKeyResolver(networkManager: mockNetworkManager)
    
    func testResolveValidEd25519DidKey() async throws {
        let validDidKey = "did:key:z6MkpiJgQdNWUzyojaFuCzQ1MWvSSaxUfL1tvbcRfqWFoJRK"
        let parsedDid = ParsedDID(did: validDidKey, method: .key, id: "z6MkkXReNrZa6qLkqnQcffhNPEK1SJvJoK1cRezKEWnJ8PuS", didUrl: validDidKey)
        
        await XCTAssertNoThrowAndVerifyAsync(try await resolver.extractPublicKey(parsedDID: parsedDid, keyId: validDidKey)){ key in
            assertPublicKey(expectedBase64Encoded: "WjdMndEkwsijxJeYqZGSaYeNiILXtlYPW8H9ZDqTjQE=", actualKey: key)
        }
    }
    
    func testInvalidBase58EncodedKey() async {
        let invalidBase58DidKey = "did:key:z1nval1dBase58String"
        let parsedDid = ParsedDID(did: invalidBase58DidKey, method: .key, id: "z1nval1dBase58String", didUrl: invalidBase58DidKey)
        
        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID: parsedDid, keyId: invalidBase58DidKey)) { error in
            assertOpenID4VPException(error, expectedMessage: "DID public key decoding failed", expectedCode: "invalid_request")
        }
    }
    
    func testUnsupportedKeyTypeWithIncorrectMultiCodeCPrefix() async {
        let keyBytes = [UInt8](repeating: 0, count: 32)
        let prefixedKeyBytes = [0x12, 0x20] + keyBytes // Using different prefix (e.g., secp256k1)
        let base58Key = Base58.base58Encode(prefixedKeyBytes)
        let invalidTypeDidKey = "did:key:z\(base58Key)"
        let parsedDid = ParsedDID(did: invalidTypeDidKey, method: .key, id: "z\(base58Key)", didUrl: invalidTypeDidKey)
        
        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID: parsedDid, keyId: invalidTypeDidKey)) { error in
            assertOpenID4VPException(error, expectedMessage: "Provided key is not supported. Supported: Ed25519", expectedCode: "invalid_request")
        }
    }
    
    func testInvalidKeyDataWithKeyBytesLesserThan32() async {
        let invalidKeyBytes = [UInt8](repeating: 0, count: 16)
        let prefixedKeyBytes = [0xed, 0x01] + invalidKeyBytes
        let invalidBase58 = Base58.base58Encode(prefixedKeyBytes)
        let invalidDataDidKey = "did:key:z\(invalidBase58)"
        let parsedDid = ParsedDID(did: invalidDataDidKey, method: .key, id: "z\(invalidBase58)", didUrl: invalidDataDidKey)
        
        await XCTAssertAsyncThrowsError(try await resolver.extractPublicKey(parsedDID: parsedDid, keyId: invalidDataDidKey)) { error in
            assertOpenID4VPException(error, expectedMessage: "Provided key is not supported. Supported: Ed25519", expectedCode: "invalid_request")
        }
    }
    
    func testValidEd25519KeyWithFragment() async throws {
        let validDidKey = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#key-1"
        let parsedDid = ParsedDID(did: validDidKey, method: .key, id: "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", didUrl: validDidKey, fragment: "key-1")
        
        await XCTAssertNoThrowAndVerifyAsync(try await resolver.extractPublicKey(parsedDID: parsedDid, keyId: validDidKey)) { key in
            assertPublicKey(expectedBase64Encoded: "Lm/M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY=", actualKey: key)
        }
    }
}
