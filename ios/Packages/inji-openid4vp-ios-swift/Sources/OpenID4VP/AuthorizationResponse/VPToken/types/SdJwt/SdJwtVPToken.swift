struct SdJwtVPToken: Encodable, VPToken {
    let value: String
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(value)
    }
}
