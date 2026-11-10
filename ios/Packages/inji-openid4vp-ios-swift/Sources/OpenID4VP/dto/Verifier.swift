import Foundation

public struct Verifier {
    public let clientId: String
    public let responseUris: [String]
    public let jwksUri: String?
    public let allowUnsignedRequest: Bool

    public init(clientId: String, responseUris: [String], jwksUri: String? = nil, allowUnsignedRequest: Bool = false) {
        self.clientId = clientId
        self.responseUris = responseUris
        self.jwksUri = jwksUri
        self.allowUnsignedRequest = allowUnsignedRequest
    }
}
