protocol ProcessedCredential {
    var credentialId: String { get }
    var credentialFormat: FormatType { get }
}

struct W3cProcessedCredential: ProcessedCredential {
    let credentialId: String
    let credentialFormat: FormatType
    let claims: [String: Any]

    init(credentialId: String, credentialFormat: FormatType, claims: [String: Any]) {
        self.credentialId = credentialId
        self.credentialFormat = credentialFormat
        self.claims = claims
    }
}

struct MdocProcessedCredential: ProcessedCredential {
    let credentialId: String
    let credentialFormat: FormatType = .mso_mdoc
    let namespaces: [String: [String: Any]]

    init(credentialId: String, namespaces: [String: [String: Any]]) {
        self.credentialId = credentialId
        self.namespaces = namespaces
    }
}

struct SdJwtProcessedCredential: ProcessedCredential {
    let credentialId: String
    let credentialFormat: FormatType
    let claims: [String: Any]

    init(credentialId: String, credentialFormat: FormatType, claims: [String: Any]) {
        self.credentialId = credentialId
        self.credentialFormat = credentialFormat
        self.claims = claims
    }
}

