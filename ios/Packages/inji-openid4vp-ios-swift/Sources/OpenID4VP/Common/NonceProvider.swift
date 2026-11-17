import Foundation

class NonceProvider {
    func generateNonce(entropy: Int = 16) -> String {
        var randomData = Data(count: entropy)
        _ = randomData.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, entropy, $0.baseAddress!)
        }
        return randomData.toBase64UrlEncoded()
    }
}
