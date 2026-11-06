import Foundation

extension Data {
    func toInstance<T: Decodable>(as type: T.Type) throws -> T {
        return try JSONDecoder().decode(T.self, from: self)
    }
}
