import Foundation

public enum ResponseType: String, Codable {
    case vp_token = "vp_token"
    
    public static func fromValue(_ value: String) -> ResponseType? {
        return ResponseType(rawValue: value)
    }
}
