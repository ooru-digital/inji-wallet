import Foundation

struct AuthorizationErrorResponse: Codable {
    let error: String
    let errorDescription: String
    let state: String?

    enum CodingKeys: String, CodingKey {
        case error
        case errorDescription = "error_description"
        case state
    }

    func toJsonEncodedMap() -> [String: String] {
        var map: [String: String] = [
            "error": error,
            "error_description": errorDescription
        ]
        if let state = state {
            map["state"] = state
        }
        return map
    }
}

