import Foundation

public struct PresentationDefinition: Codable {
    let id: String
    let name: String?
    let purpose: String?
    let inputDescriptors: [InputDescriptor]
    let format: [String: [String: [String]]]?
    let className = String(describing: PresentationDefinition.self)
    
    enum CodingKeys: String, CodingKey {
        case id
        case name
        case purpose
        case inputDescriptors = "input_descriptors"
        case format
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
          
        
        self.id = try container.decodeRequired(
            String.self,
            forKey: .id,
            fieldPath: ["presentation_definition", "id"],
            className: className,
            isMandatory: true
        )!
        
        self.inputDescriptors = try container.decodeRequired(
            [InputDescriptor].self,
            forKey: .inputDescriptors,
            fieldPath: ["presentation_definition", "input_descriptors"],
            className: className,
            isMandatory: true
        )!
        
        self.name = try container.decodeRequired(
            String.self,
            forKey: .name,
            fieldPath: ["presentation_definition", "name"],
            className: className,
            isMandatory: false)

        self.purpose = try container.decodeRequired(
            String.self,
            forKey: .purpose,
            fieldPath: ["presentation_definition", "purpose"],
            className: className,
            isMandatory: false)
        
        self.format = try container.decodeRequired(
            [String: [String: [String]]].self,
            forKey: .format,
            fieldPath: ["presentation_definition", "format"],
            className: className,
            isMandatory: false)
        
        try validate()
    }
    
    func validate() throws {
        guard isNeitherNullNorEmpty(field: id) else {
            throw InvalidInput(fieldPath: ["presentation_definition","id"], className: className)
        }
        
        guard !inputDescriptors.isEmpty else {
            throw InvalidInput(fieldPath: ["presentation_definition","input_descriptors"], className: className)
        }
        
        try validateField(name, ["presentation_definition","name"], className)
        try validateField(purpose, ["presentation_definition","purpose"], className)
        try validateField(format, ["presentation_definition","format"], className)
        
        for descriptor in inputDescriptors {
            try descriptor.validate()
        }
    }
}
