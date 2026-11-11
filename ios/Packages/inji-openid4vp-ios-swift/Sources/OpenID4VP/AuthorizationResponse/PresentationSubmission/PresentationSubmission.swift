struct DescriptorMap: Encodable{
    let id: String
    let format: VPFormatType
    let path: String
    let pathNested: PathNested?
    
    enum CodingKeys: String, CodingKey {
        case id
        case format
        case path
        case pathNested = "path_nested"
    }
}

struct PathNested : Encodable {
    let id: String
    let format: FormatType
    let path: String
}

struct PresentationSubmission: Encodable{
    let id: String = UUIDGenerator.generateUUID()
    let definitionId: String
    let descriptorMap: [DescriptorMap]
    
    enum CodingKeys: String, CodingKey {
        case id
        case definitionId = "definition_id"
        case descriptorMap = "descriptor_map"
    }
}
