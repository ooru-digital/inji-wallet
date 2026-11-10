struct Constraints: Codable {
    let fields: [Fields]?
    private let rawLimitDisclosure: String?
    var limitDisclosure: LimitDisclosure? {
        guard let raw = rawLimitDisclosure else { return nil }
        return LimitDisclosure(rawValue: raw)
    }

    let className = String(describing: Constraints.self)

    enum CodingKeys: String, CodingKey {
        case fields
        case rawLimitDisclosure = "limit_disclosure"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.fields = try container.decodeRequired(
            [Fields].self,
            forKey: .fields,
            fieldPath: ["constraints", "fields"],
            className: className,
            isMandatory: false
        )

        self.rawLimitDisclosure = try container.decodeRequired(
            String.self,
            forKey: .rawLimitDisclosure,
            fieldPath: ["constraints", "limit_disclosure"],
            className: className,
            isMandatory: false
        )

        try validate()
    }

    func validate() throws {
        if let fields = fields, !fields.isEmpty {
            try fields.forEach { try $0.validate() }
        }

        if let raw = rawLimitDisclosure {
            guard isNeitherNullNorEmpty(field: raw) else {
                throw InvalidInput(
                    fieldPath: ["constraints", "limit_disclosure"],
                    className: className
                )
            }

            guard LimitDisclosure(rawValue: raw) == .preferred else {
                throw InvalidLimitDisclosure(
                    className: className
                )
            }
        }
    }
}
