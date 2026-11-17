import Foundation

public struct VPResponseMetadata {
    public let jws: String
    public let signatureAlgorithm: String
    public let publicKey: String
    public let domain: String
    static let className = String(describing: VPResponseMetadata.self)

    public init(jws: String, signatureAlgorithm: String, publicKey: String, domain: String) {
        self.jws = jws
        self.signatureAlgorithm = signatureAlgorithm
        self.publicKey = publicKey
        self.domain = domain
    }
    
    
        func validate() throws {
            let requiredParams: [String: String] = [
                "jws": jws,
                "signatureAlgorithm": signatureAlgorithm,
                "publicKey": publicKey,
                "domain": domain
            ]

            for (_, value) in requiredParams {
                if value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || value == "null" {
                    throw InvalidInput(fieldPath: ["vp response metadata",value], className: VPResponseMetadata.className)
                }
            }
        }
}
