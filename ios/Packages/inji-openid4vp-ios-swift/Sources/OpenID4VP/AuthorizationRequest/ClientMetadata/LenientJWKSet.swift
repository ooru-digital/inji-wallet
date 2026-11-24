import Foundation
import JSONWebKey

struct FailableDecodable<T: Decodable>: Decodable {
    let value: T?

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.value = try? container.decode(T.self)
    }
}

struct LenientJWKSet: Decodable {
    let keys: [JWK]

    private enum CodingKeys: String, CodingKey {
        case keys
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decodedKeys = try container.decodeIfPresent([FailableDecodable<JWK>].self, forKey: .keys) ?? []
        self.keys = decodedKeys.compactMap { $0.value }
    }

    var jwkSet: JWKSet {
        JWKSet(keys: keys)
    }
}
