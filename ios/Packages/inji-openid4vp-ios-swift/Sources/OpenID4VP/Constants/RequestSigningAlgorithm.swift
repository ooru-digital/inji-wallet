public enum RequestSigningAlgorithm : String, Codable, CaseIterable {
    case edDsa = "EdDSA"
    
    public static func fromValue(_ value: String) -> RequestSigningAlgorithm? {
        return RequestSigningAlgorithm(rawValue: value)
    }
}


