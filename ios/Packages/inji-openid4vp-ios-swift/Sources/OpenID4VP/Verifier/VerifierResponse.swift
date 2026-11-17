import Foundation

public struct VerifierResponse : Codable {
    public let statusCode: Int
    /// Holds redirect_uri from the Verifier response body
    public let redirectUri: String?
    /// Holds additional parameters in JSON string format other than redirect_uri
    public let additionalParams: String?
    public let headers: [String: String]
    private let responseBody: String
    
    init(statusCode: Int, responseBody: String = "", redirectUri: String? = nil, additionalParams: String? = nil, headers: [String: String]) {
        self.statusCode = statusCode
        self.responseBody = responseBody
        self.redirectUri = redirectUri
        self.additionalParams = additionalParams
        self.headers = headers
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        statusCode = try container.decode(Int.self, forKey: .statusCode)
        redirectUri = try container.decodeIfPresent(String.self, forKey: .redirectUri)
        additionalParams = try container.decodeIfPresent(String.self, forKey: .additionalParams)
        headers = try container.decode([String: String].self, forKey: .headers)
        responseBody = ""
    }
    
    enum CodingKeys: String, CodingKey {
        case statusCode
        case redirectUri
        case additionalParams
        case headers
    }
    
    public func isOk() -> Bool {
        return (200...299).contains(statusCode)
    }
    
    internal func body() -> String {
        return responseBody
    }
}
