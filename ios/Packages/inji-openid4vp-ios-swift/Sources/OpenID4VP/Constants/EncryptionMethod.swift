// Content Encryption Algorithms
public enum EncryptionMethod: String, Codable {
    case a256GCM = "A256GCM"
    
    public static func fromValue(_ value: String) -> EncryptionMethod? {
        return EncryptionMethod(rawValue: value)
    }
}
