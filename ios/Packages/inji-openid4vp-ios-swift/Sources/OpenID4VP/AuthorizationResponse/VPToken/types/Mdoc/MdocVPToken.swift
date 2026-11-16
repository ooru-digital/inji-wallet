struct MdocVPToken: Encodable, VPToken {
    let base64EncodedDeviceResponse: String
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(base64EncodedDeviceResponse)
    }
}
