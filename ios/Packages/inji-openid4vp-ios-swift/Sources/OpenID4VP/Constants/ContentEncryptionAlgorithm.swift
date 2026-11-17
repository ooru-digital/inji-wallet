public enum ContentEncryptionAlgorithm : String, Codable, CaseIterable {
    case A256GCM
    
    public static func fromValue(_ value: String) -> ContentEncryptionAlgorithm? {
        return ContentEncryptionAlgorithm(rawValue: value)
    }
}
