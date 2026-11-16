import Foundation

public enum ClientIdScheme: String, Codable, CaseIterable {
    case preRegistered = "pre-registered"
    case redirectUri = "redirect_uri"
    case did = "did"
    
    public static func fromValue(_ value: String) -> ClientIdScheme? {
        return ClientIdScheme(rawValue: value)
    }
}
