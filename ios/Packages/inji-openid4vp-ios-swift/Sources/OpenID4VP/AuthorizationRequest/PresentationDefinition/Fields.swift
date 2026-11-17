import Foundation

struct Fields: Codable {
    let path: [String]
    let id: String?
    let name: String?
    let purpose: String?
    let filter: Filter?
    let optional: Bool?
    let className = String(describing: Fields.self)
    
    enum CodingKeys: String, CodingKey {
        case path
        case id
        case name
        case purpose
        case filter
        case optional
    }
    
    init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            
            self.path = try container.decodeRequired(
                [String].self,
                forKey: .path,
                fieldPath: ["fields", "path"],
                className: className,
                isMandatory: true
            )!
            
            self.id = try container.decodeRequired(
                String.self,
                forKey: .id,
                fieldPath: ["fields", "id"],
                className: className,
                isMandatory: false)
            
            self.name = try container.decodeRequired(
                String.self,
                forKey: .name,
                fieldPath: ["fields", "name"],
                className: className,
                isMandatory: false)
            
            self.purpose = try container.decodeRequired(
                String.self,
                forKey: .purpose,
                fieldPath: ["fields", "purpose"],
                className: className,
                isMandatory: false)
            
            self.filter = try container.decodeRequired(
                Filter.self,
                forKey: .filter,
                fieldPath: ["fields", "filter"],
                className: className,
                isMandatory: false)
            
            self.optional = try container.decodeRequired(
                Bool.self,
                forKey: .optional,
                fieldPath: ["fields", "optional"],
                className: className,
                isMandatory: false)
            
            try validate()
        }
    
    func validate() throws {
        guard !path.isEmpty else {
            throw InvalidInput(fieldPath: ["fields","path"], className: className)
        }
        
        let pathPrefixArray = ["$.","$["]
        if !path.allSatisfy({ p in pathPrefixArray.contains(where: { p.hasPrefix($0) }) }) {
            throw InvalidInputPattern(fieldPath: ["fields","path"], className: className)
        }
        
        try validateField(id, ["fields","id"], className)
        try validateField(name, ["fields","name"], className)
        try validateField(purpose, ["fields","purpose"], className)

        if let filter = filter {
            try filter.validate()
        }
    }
}
