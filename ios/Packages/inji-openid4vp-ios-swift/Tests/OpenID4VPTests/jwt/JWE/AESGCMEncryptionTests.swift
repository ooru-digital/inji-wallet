import XCTest
import CryptoKit

@testable import OpenID4VP

final class AESGCMEncryptionTests: XCTestCase {
    private func decryptData(ciphertext: Data, nonce: Data, tag: Data, key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(sealedBox, using: key)
    }
    
    func testEncryptionSuccess() throws {
        let data = "Hello, World!".data(using: .utf8)!
        let key = SymmetricKey(size: .bits256)
        
        let (ciphertext, nonce, tag) = try AESGCMEncryption().encrypt(data, with: key)
        
        XCTAssertFalse(ciphertext.isEmpty, "Ciphertext should be available")
        XCTAssertEqual(try decryptData(ciphertext: ciphertext, nonce: nonce, tag: tag, key: key), data, "Decrypted data should match the original")
        XCTAssertFalse(nonce.isEmpty, "Nonce should be available")
        XCTAssertFalse(tag.isEmpty, "Tag should be available")
    }
    
    func testEncryptionProducesUniqueOutputs() throws {
        let data = "Sensitive Data".data(using: .utf8)!
        let key = SymmetricKey(size: .bits256)
        
        let (ciphertext1, nonce1, tag1) = try AESGCMEncryption().encrypt(data, with: key)
        let (ciphertext2, nonce2, tag2) = try AESGCMEncryption().encrypt(data, with: key)
        
        XCTAssertNotEqual(ciphertext1, ciphertext2, "Ciphertext should be unique for each encryption")
        XCTAssertNotEqual(nonce1, nonce2, "Nonce should be unique for each encryption")
        XCTAssertNotEqual(tag1, tag2, "Tag should be unique for each encryption")
    }
    
    func testEncryptionThrowErrorIfKeySizeInInitializerAndSymmetricKeysizeMismatches() throws {
        let data = "Invalid Key Test".data(using: .utf8)!        
        let invalidKey = SymmetricKey(size: .bits128)
        
        XCTAssertThrowsError(try AESGCMEncryption(keySize: .bits256).encrypt(data, with: invalidKey)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid Key size provided for encryption.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
