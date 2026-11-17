import Foundation
import Base58Swift

struct ParsedDID : Equatable {
    let did: String
    let method: DIDMethod
    let id: String
    let didUrl: String
    var params: [String: String]?
    var path: String?
    var query: String?
    var fragment: String?
}
