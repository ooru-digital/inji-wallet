import Foundation

// Input: VP with no signature in stringified JSON
// output: base64url encoded canonicalized JSON-LD string of the data
public typealias JsonLdCanonicalizerCallback = (_ data: String) async throws -> String

// Input: Json stringified data, output: canonicalized JSON-LD of the data
public typealias JsonLdNormalizerCallback = (_ data: String) async throws -> Data

// Input: credential data in Dict form, output: expanded data in Dict form
public typealias JsonLdExpanderCallback = (_ data: [String: Any]) async throws -> [String: Any]
