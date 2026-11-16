import XCTest
@testable import OpenID4VP

final class NonceProviderTests: XCTestCase {
    
    var nonceProvider: NonceProvider!
    
    override func setUp() {
        super.setUp()
        nonceProvider = NonceProvider()
    }
    
    override func tearDown() {
        nonceProvider = nil
        super.tearDown()
    }
    
    func testGenerateNonceWithDefaultEntropy() {
        let nonce = nonceProvider.generateNonce()
        
        XCTAssertFalse(nonce.isEmpty)
        assertBase64UrlEncoded(nonce)
        // Base64 encoding expands 16 bytes to ~22 characters
        XCTAssertEqual(nonce.count, 22, "Nonce should be about 22 characters for 16 bytes of entropy")
    }
    
    func testGenerateNonceWithCustomEntropy() {
        let testEntropies = [8, 24, 32]
        
        for entropy in testEntropies {
            let nonce = nonceProvider.generateNonce(entropy: entropy)
            
            XCTAssertFalse(nonce.isEmpty)
            assertBase64UrlEncoded(nonce)
            // Base64 encoding: 4 characters per 3 bytes
            // For URL-safe base64 without padding: ceil(entropy * 8 / 6) characters
            let expectedLength = Int(ceil(Double(entropy) * 8.0 / 6.0))
            XCTAssertEqual(nonce.count, expectedLength, "Nonce length should match expected for \(entropy) bytes")
        }
    }
    
    func testGeneratedNoncesAreAllUnique() {
        let count = 100
        var nonces = Set<String>()
        
        for _ in 0..<count {
            let nonce = nonceProvider.generateNonce()
            nonces.insert(nonce)
        }
        
        XCTAssertEqual(nonces.count, count, "All generated nonces should be unique")
    }
    
    func testGenerateNonceWithZeroEntropyReturnsEmptyString() {
        let nonce = nonceProvider.generateNonce(entropy: 0)
        
        XCTAssertEqual(nonce, "")
    }
    
    fileprivate func assertBase64UrlEncoded(_ input: String) {
        XCTAssertFalse(input.contains("+"))
        XCTAssertFalse(input.contains("/"))
        XCTAssertFalse(input.contains("="))
    }
}
