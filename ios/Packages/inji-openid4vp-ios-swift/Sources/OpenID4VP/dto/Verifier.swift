import Foundation

public struct Verifier : Codable {
    public let clientId: String
    public let responseUris: [String]
    public let jwksUri: String?
    public let allowUnsignedRequest: Bool
    // specification version that the verifier supports, default is v1
    public let specVersion: SpecVersion
    
    public init(clientId: String, responseUris: [String], jwksUri: String? = nil, allowUnsignedRequest: Bool = false, specVersion: SpecVersion = .v1) {
        self.clientId = clientId
        self.responseUris = responseUris
        self.jwksUri = jwksUri
        self.allowUnsignedRequest = allowUnsignedRequest
        self.specVersion = specVersion
    }
    
    enum CodingKeys: String, CodingKey {
        case clientId = "client_id"
        case responseUris = "response_uris"
        case jwksUri = "jwks_uri"
        case allowUnsignedRequest = "allow_unsigned_request"
        case specVersion = "spec_version"
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.clientId = try container.decode(String.self, forKey: .clientId)
        self.responseUris = try container.decode([String].self, forKey: .responseUris)
        self.jwksUri = try container.decodeIfPresent(String.self, forKey: .jwksUri)
        self.allowUnsignedRequest = try container.decodeIfPresent(Bool.self, forKey: .allowUnsignedRequest) ?? false
        self.specVersion = try container.decodeIfPresent(SpecVersion.self, forKey: .specVersion) ?? .v1
    }
}
