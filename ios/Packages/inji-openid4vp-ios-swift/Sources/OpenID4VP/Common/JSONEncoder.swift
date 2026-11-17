import Foundation

struct JSON {
    // Create JSON encoder with custom settings - without escaping slashes
    static let encoder = JSONEncoder()
}

extension Encodable {
    func jsonData() throws -> Any {
        JSON.encoder.outputFormatting = [ .withoutEscapingSlashes]
        let encoded = try JSON.encoder.encode(self)
        //         In case of JSON, convert it else return encoded
        do {
            return try JSONSerialization.jsonObject(with: encoded)
        } catch {
            return try JSONDecoder().decode(String.self, from: encoded)
        }
    }
}

func encode<T: Encodable>(_ data: T, fieldName: String, className: String) throws -> String {
    do {
        let encoder = JSON.encoder
        encoder.outputFormatting = .withoutEscapingSlashes
        let jsonData = try encoder.encode(data)
        return String(decoding: jsonData, as: UTF8.self)
    } catch {
        throw JsonEncodingFailed(
            fieldPath: [fieldName],
            errorMessage: error.localizedDescription,
            className: className
        )
    }
}
