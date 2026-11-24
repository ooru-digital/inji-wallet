import Foundation

let vcdmV1Context = "https://www.w3.org/2018/credentials/v1"
let vcdmV2Context = "https://www.w3.org/ns/credentials/v2"

func isVcdm2Credential(_ credential: AnyCodable, className: String) throws -> Bool {
    guard let credentialDict = credential.value as? [String: Any] else {
        throw InvalidData(message: "Credential is not a valid JSON object", className: className)
    }

    guard let contexts = credentialDict["@context"] as? [Any] else {
        throw InvalidData(message: "Credential @context must be an ordered array", className: className)
    }

    guard let first = contexts.first as? String else {
        throw InvalidData(message: "Credential @context is missing", className: className)
    }

    if first == vcdmV2Context { return true }

    if first == vcdmV1Context {
        let remaining = contexts.dropFirst().compactMap { $0 as? String }
        if remaining.contains(vcdmV2Context) {
            throw InvalidData(message: "VC 2.0 context must be the first @context entry", className: className)
        }
        return false
    }

    throw InvalidData(message: "Unsupported credential data model context: \(first)", className: className)
}
