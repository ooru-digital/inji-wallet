import Foundation

public enum ClientIdPrefix: String, Codable, CaseIterable {
    case preRegistered = "pre-registered"
    case redirectUri = "redirect_uri"
    case decentralizedIdentifier = "decentralized_identifier"
    
    public static func fromValue(_ value: String) -> ClientIdPrefix? {
        return ClientIdPrefix(rawValue: value)
    }
    
    static func toClientIdScheme(_ clientIdPrefix: ClientIdPrefix) -> String {
        switch clientIdPrefix {
        case .preRegistered:
            return ClientIdScheme.preRegistered.rawValue
        case .redirectUri:
            return ClientIdScheme.redirectUri.rawValue
        case .decentralizedIdentifier:
            return ClientIdScheme.did.rawValue
        }
    }
}

internal enum ClientIdScheme: String, Codable, CaseIterable {
    case preRegistered = "pre-registered"
    case redirectUri = "redirect_uri"
    case did = "did"
    
    public static func fromValue(_ value: String) -> ClientIdScheme? {
        return ClientIdScheme(rawValue: value)
    }
}
