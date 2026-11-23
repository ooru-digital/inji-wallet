import Foundation

internal struct CredentialToCredentialQueryIdMapping {
    let format: FormatType
    let credential: AnyCodable
    let credentialQueryId: String
    var identifier: String?
    
    init(format: FormatType, credential: AnyCodable, identifier: String? = nil, credentialQueryId: String) {
        self.format = format
        self.credential = credential
        self.credentialQueryId = credentialQueryId
        self.identifier = identifier
    }
}
