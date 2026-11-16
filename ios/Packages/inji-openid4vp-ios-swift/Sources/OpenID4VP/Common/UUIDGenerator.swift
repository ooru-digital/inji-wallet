import Foundation

public struct UUIDGenerator {
    public static func generateUUID() -> String {
        return "urn:uuid:\(UUID().uuidString.lowercased())"
    }
}
