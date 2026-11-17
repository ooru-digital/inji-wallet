import Foundation

struct Filter: Codable {
    let type: String
    let pattern: String
    let className = String(describing: Filter.self)
    
    enum CodingKeys: String, CodingKey {
        case type
        case pattern
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.type = try container.decodeRequired(
            String.self,
            forKey: .type,
            fieldPath: ["filter", "type"],
            className: className,
            isMandatory: true
        )!
        
        self.pattern = try container.decodeRequired(
            String.self,
            forKey: .pattern,
            fieldPath: ["filter", "pattern"],
            className: className,
            isMandatory: true
        )!
        
        try validate()
    }
    
    func validate() throws {
        try validateField(type, ["filter","type"], className)
        try validateField(pattern, ["filter","pattern"], className)
    }
}
