import Foundation
import CryptoKit
import JSONWebKey
import SwiftCBOR

extension Optional where Wrapped == JWK {
    func toJWKThumbprintBstr() throws -> CBOR {
        guard let jwk = self else { return CBOR.null }
        return try jwk.toJWKThumbprintBstr()
    }
}

extension JWK {
    func toJWKThumbprintBstr() throws -> CBOR {
        let thumbprintBase64url = try thumbprint(with: SHA256())
        guard let thumbprintData = Data(base64Encoded: thumbprintBase64url.base64URLToBase64()) else {
            throw InvalidData(message: "Failed to decode JWK thumbprint bytes", className: "JWK+ThumbprintBstr")
        }
        return CBOR.byteString([UInt8](thumbprintData))
    }
}
