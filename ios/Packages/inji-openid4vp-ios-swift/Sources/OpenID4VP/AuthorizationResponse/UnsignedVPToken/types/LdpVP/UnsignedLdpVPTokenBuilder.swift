import Foundation

private let className = "UnsignedLdpVPTokenBuilder"

public class UnsignedLdpVPTokenBuilder: UnsignedVPTokenBuilder {
    private let id: String
    private let holder: String
    private let challenge: String
    private let domain: String
    private let signatureSuite: String
    
    static let internalPath: String = "verifiableCredential"
    
    public init(
        id: String,
        holder: String,
        challenge: String,
        domain: String,
        signatureSuite: String
    ) {
        self.id = id
        self.holder = holder
        self.challenge = challenge
        self.domain = domain
        self.signatureSuite = signatureSuite
    }
    
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (vpTokenSigningPayload: VPTokenSigningPayload?, unsignedVPToken: any UnsignedVPToken) {
        var context: [String] = ["https://www.w3.org/2018/credentials/v1"]
        if signatureSuite == SignatureAlgorithm.ed25519Signature2020.rawValue {
            context.append("https://w3id.org/security/suites/ed25519-2020/v1")
        } else if signatureSuite == SignatureAlgorithm.jsonWebSignature2020.rawValue {
            context.append("https://w3id.org/security/suites/jws-2020/v1")
        }
        
        var verifiableCredentials: [AnyCodable] = []
        
        for index in 0..<credentialInputDescriptorMappings.count {
            let mapping = credentialInputDescriptorMappings[index]
            verifiableCredentials.append(mapping.credential)
            credentialInputDescriptorMappings[index] = CredentialInputDescriptorMapping(
                format: mapping.format, credential: mapping.credential, inputDescriptorId: mapping.inputDescriptorId,
                nestedPath: "$.\(Self.internalPath)[\(index)]"
            )
        }
        
        let proof = Proof(
            type: signatureSuite,
            created: nil,
            challenge: challenge,
            domain: domain,
            verificationMethod: holder,
            proofValue: nil
        )
        
        let vpTokenSigningPayload = LdpVPToken(
            context: context,
            type: ["VerifiablePresentation"],
            verifiableCredential: verifiableCredentials,
            id: id,
            holder: holder,
            proof: proof
        )
        
        guard let dataToSign = try? JSONEncoder().encode(vpTokenSigningPayload),
              let jsonString = String(data: dataToSign, encoding: .utf8) else {
            throw InvalidData(message: "Failed to encode LdpVPToken for signing.", className: className)
        }
        
        return (vpTokenSigningPayload, UnsignedLdpVPToken(dataToSign:jsonString))
    }
}
