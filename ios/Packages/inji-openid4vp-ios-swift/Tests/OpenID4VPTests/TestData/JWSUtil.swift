import CryptoKit
import Foundation
import OpenID4VP
import JSONWebSignature
@testable import OpenID4VP

struct JWSUtil {
    private static let ed25519PrivateKey = "7JGq310it2uq1_KZ3kARpoUB36KaVO2Ki5VeqQ_856A"
    private static let baseUrl = "https://mock-verifier.com"
    private static let responseUri = "\(baseUrl)/verifier/vp-response"
    internal static let publicKeyId = "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0"

    private static let jwsHeader: [String: Any] = [
        "typ": "oauth-authz-req+jwt",
        "alg": "EdDSA",
        "kid": publicKeyId
    ]

    private static func base64UrlEncode(_ data: Data) -> String {
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=+$", with: "", options: .regularExpression)
    }

    private static func signEd25519(privateKey: Data, message: Data) -> String? {
        guard let privateKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: privateKey) else {
            return nil
        }
        let signature = (try? privateKey.signature(for: message))!
        return base64UrlEncode(signature)
    }

    static func create(header: [String:Any]? = nil,payload: [String:Any],addValidSignature: Bool = true) -> String{
        let privateKeyData = Data(base64UrlEncoded: ed25519PrivateKey)
        let jwsHeader = header == nil ? self.jwsHeader : header
        let headerData = try? JSONSerialization.data(withJSONObject: jwsHeader as Any)
        let header64 = base64UrlEncode(headerData!)
        let payloadData = try? JSONSerialization.data(withJSONObject: payload)
        let payload64 = base64UrlEncode(payloadData!)
        let message = "\(header64).\(payload64)".data(using: .utf8)!

        let signature64: String
        if addValidSignature, let validSignature = signEd25519(privateKey: privateKeyData!, message: message) {
            signature64 = validSignature
        } else {
            signature64 = "aW52YWxpZC1zaWdu"
        }
        return "\(header64).\(payload64).\(signature64)"
    }
}




