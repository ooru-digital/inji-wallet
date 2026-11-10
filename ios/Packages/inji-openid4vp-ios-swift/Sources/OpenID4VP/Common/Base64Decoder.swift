import Foundation

class Base64Decoder {
    static let className = String(describing: Base64Decoder.self)
    static func decodeBase64ToData(_ base64String: String) throws -> Data {
        guard let decodedData = Data(base64UrlEncoded: base64String) else {
            throw Base64DecodingFailed(message: "Base64 decoding failed" ,className: Base64Decoder.className)
        }
        return decodedData
    }
    
    static func decodeBase64ToJSON(_ base64String: String) throws -> [String: Any] {
        let decodedData = try decodeBase64ToData(base64String)
        do{
            guard let jsonObject = try JSONSerialization.jsonObject(with: decodedData, options: []) as? [String: Any]  else {
                throw InvalidData(
                    message: "Decoding failed",
                    className: Base64Decoder.className
                )
            }
            return jsonObject
        } catch {
            throw JsonDecodingFailed(message: "Decoding to json failed", className: Base64Decoder.className)
        }
    }
}
