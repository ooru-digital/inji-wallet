public enum KeyManagementAlgorithm : String, Codable, CaseIterable {
    case ecdhEs = "ECDH-ES"
    
    public static func fromValue(_ value: String) -> KeyManagementAlgorithm? {
        return KeyManagementAlgorithm(rawValue: value)
    }
}
