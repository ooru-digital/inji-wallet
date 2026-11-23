import Foundation

public struct AnyCodable: Codable {
    public var value: Any
    static let className = String(describing: AnyCodable.self)

    public init(_ value: Any) {
        // Normalise NSNull (arriving from JS null via ObjC bridge) to Swift Optional.none
        if value is NSNull {
            self.value = Optional<Any>.none as Any
        } else {
            self.value = value
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            value = Optional<Any>.none as Any
        } else if let int = try? container.decode(Int.self) {
            value = int
        } else if let double = try? container.decode(Double.self) {
            value = double
        } else if let string = try? container.decode(String.self) {
            value = string
        } else if let bool = try? container.decode(Bool.self) {
            value = bool
        } else if let nestedDict = try? container.decode([String: AnyCodable].self) {
            value = nestedDict.mapValues { $0.value }
        } else if let nestedArray = try? container.decode([AnyCodable].self) {
            value = nestedArray.map { $0.value }
        } else {
            throw UnsupportedTypeDecoding(
                message: "Unsupported type encountered while decoding response in AnyCodable",
                className: AnyCodable.className
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        // Handle NSNull and Swift nil-wrapped-as-Any
        if value is NSNull {
            try container.encodeNil()
            return
        }
        // Mirror check for Optional<Any>.none wrapped as Any
        let mirror = Mirror(reflecting: value)
        if mirror.displayStyle == .optional && mirror.children.isEmpty {
            try container.encodeNil()
            return
        }
        if let int = value as? Int {
            try container.encode(int)
        } else if let double = value as? Double {
            try container.encode(double)
        } else if let string = value as? String {
            try container.encode(string)
        } else if let bool = value as? Bool {
            try container.encode(bool)
        } else if let nestedDict = value as? [String: Any] {
            try container.encode(nestedDict.mapValues { AnyCodable($0) })
        } else if let nestedArray = value as? [Any] {
            try container.encode(nestedArray.map { AnyCodable($0) })
        } else {
            throw JsonEncodingFailed(errorMessage: "Error occured while encoding response", className: AnyCodable.className)
        }
    }
}
