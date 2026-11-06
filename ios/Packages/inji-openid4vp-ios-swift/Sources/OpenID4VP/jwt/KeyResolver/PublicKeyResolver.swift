import Foundation
import CryptoKit

protocol PublicKeyResolver {
    func resolve(uri: String, keyId : String?)async throws -> PublicKeyType
}


