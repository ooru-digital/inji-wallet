import Foundation

struct InputDescriptor: Codable {
    let id: String
    let name: String?
    let purpose: String?
    let constraints: Constraints
    let format: [String: [String: [String]]]?
    let className = String(describing: InputDescriptor.self)
    
    enum CodingKeys: String, CodingKey {
        case id
        case name
        case purpose
        case constraints
        case format
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        self.id = try container.decodeRequired(
            String.self,
            forKey: .id,
            fieldPath: ["input_descriptor", "id"],
            className: className,
            isMandatory: true
        )!
        
        self.constraints = try container.decodeRequired(
            Constraints.self,
            forKey: .constraints,
            fieldPath: ["input_descriptor", "constraints"],
            className: className,
            isMandatory: true
        )!
        
        self.name = try container.decodeRequired(
            String.self,
            forKey: .name,
            fieldPath: ["input_descriptor", "name"],
            className: className,
            isMandatory: false)
        
        self.purpose = try container.decodeRequired(
            String.self,
            forKey: .purpose,
            fieldPath: ["input_descriptor", "purpose"],
            className: className,
            isMandatory: false)
        
        self.format = try container.decodeRequired(
            [String: [String: [String]]].self,
            forKey: .format,
            fieldPath: ["input_descriptor", "format"],
            className: className,
            isMandatory: false)
        
        try validate()
    }
    
    func validate() throws {
        guard isNeitherNullNorEmpty(field: id) else {
            throw InvalidInput(fieldPath: ["input_descriptor","id"], className: className)
        }
        
        try validateField(name, ["input_descriptor","name"], className)
        try validateField(purpose, ["input_descriptor","purpose"], className)
        try validateField(format, ["input_descriptor","format"], className)
        
        try constraints.validate()
    }
}
