import Foundation

protocol TaggedCredential {
    var credentialFormat: FormatType { get }
    var hasCryptographicHolderBinding: Bool { get }
}

struct W3cTaggedCredential: TaggedCredential {
    let credentialFormat: FormatType
    let hasCryptographicHolderBinding: Bool
    let types: [String]
    let holderId: String?
    let isVcdm2: Bool
    // CredIssuer patch: the credential's "type" values as written, before JSON-LD expansion.
    // See DCQLEvaluator.localTypeMatches.
    var rawTypes: [String] = []
}

struct MdocTaggedCredential: TaggedCredential {
    let credentialFormat: FormatType = .mso_mdoc
    let hasCryptographicHolderBinding: Bool
    let doctype: String
}

struct SdJwtTaggedCredential: TaggedCredential {
    let credentialFormat: FormatType
    let hasCryptographicHolderBinding: Bool
    let vct: String
}
