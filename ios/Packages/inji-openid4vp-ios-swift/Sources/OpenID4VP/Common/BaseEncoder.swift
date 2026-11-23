import Foundation
import MultiformatsKit

struct BaseEncoding {
    static func base58BtcEncode(_ bytes: Data) -> String {
        return Multibase.base58btc.encode(bytes)
    }
    
    static func base64URLEncode(_ input: [String: Any]) throws -> String {
        guard let jsonData = try? JSONSerialization.data(withJSONObject: input, options: []) else {
            throw InvalidData(message: "Failed to serialize JSON", className: "Base64Encoder")
        }
        
        return jsonData.toBase64UrlEncoded()
    }
}
