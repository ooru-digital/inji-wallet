import Foundation

private let className = "UnsignedLdpVPTokenBuilder"

private let eddsaRdfc2022 = "eddsa-rdfc-2022"
private let ecdsaRdfc2019 = "ecdsa-rdfc-2019"

class UnsignedLdpVPTokenBuilder: UnsignedVPTokenBuilder {
    private let id: String
    public let specVersion: SpecVersion
    public let authorizationRequest: AuthorizationRequest
    public let walletConfig: WalletConfig
    // CredIssuer patch: see resolveHolder.
    private let fallbackHolderId: String?

    static let internalPath: String = "verifiableCredential"

    public init(
        authorizationRequest: AuthorizationRequest,
        specVersion: SpecVersion,
        id: String,
        walletConfig: WalletConfig = WalletConfig(),
        fallbackHolderId: String? = nil
    ) {
        self.authorizationRequest = authorizationRequest
        self.specVersion = specVersion
        self.id = id
        self.walletConfig = walletConfig
        self.fallbackHolderId = fallbackHolderId
    }

    /// CredIssuer patch: the credential's credentialSubject.id is the VP holder when it is a
    /// supported DID. Otherwise (CredIssuer issues "urn:uuid:..." subject ids, which have no key to
    /// sign with) the wallet's own DID, when given, holds and signs the VP instead of the
    /// presentation failing. Without a fallback the original error is thrown unchanged. Same as
    /// the Android library patch.
    private func resolveHolder(_ credentialHolderId: String) throws -> String {
        do {
            return try validateHolderId(credentialHolderId)
        } catch let error as InvalidData {
            guard let fallbackHolderId = fallbackHolderId else { throw error }
            return try validateHolderId(fallbackHolderId)
        }
    }
    
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) {
        guard (authorizationRequest as? AuthorizationPresentationExchangeRequest) != nil else {
            throw InvalidData(message: "Expected AuthorizationPresentationExchangeRequest for Presentation Exchange flow", className: className)
        }
        
        var unsignedVPTokens: [UnsignedVPToken] = []
        var vpTokenSigningPayloads : [String: LdpVP] = [:]
        
        for index in 0..<credentialInputDescriptorMappings.count {
            var credentialInputDescriptorMapping = credentialInputDescriptorMappings[index]
            let identifier = UUIDGenerator.generateUUID()
            
            credentialInputDescriptorMapping.identifier = identifier
            credentialInputDescriptorMapping.nestedPath = "$.\(Self.internalPath)[0]"
            credentialInputDescriptorMappings[index] = credentialInputDescriptorMapping
            
            let credential = credentialInputDescriptorMapping.credential
            
            let verifiableCredentials: [AnyCodable] = [credential]

            
            let result = try extractHolderAndSignatureSuite(credential)
            
            let (vpTokenSigningPayload, unsignedVPToken) = try await buildPayloadAndUnsignedVPToken(
                identifier: identifier,
                with: verifiableCredentials,
                signatureSuite: result.signatureSuite,
                holder: try resolveHolder(result.holder),
                isVcdm2: try isVcdm2Credential(credential, className: className)
            )
            
            vpTokenSigningPayloads[identifier] = vpTokenSigningPayload
            if let unsignedVPToken = unsignedVPToken {
                unsignedVPTokens.append(unsignedVPToken)
            }
            
        }
        
        return (vpTokenSigningPayloads, unsignedVPTokens)
    }
    
    func build(credentialToCredentialQueryIdMappings: inout [CredentialToCredentialQueryIdMapping]) async throws -> (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) {
        guard let authorizationRequest = authorizationRequest as? AuthorizationDcqlRequest else {
            throw InvalidData(message: "Expected AuthorizationDcqlRequest for DCQL flow", className: className)
        }
        var unsignedVPTokens: [UnsignedVPToken] = []
        var vpTokenSigningPayloads : [String: LdpVP] = [:]
        
        for index in 0..<credentialToCredentialQueryIdMappings.count {
            var credentialToCredentialQueryIdMapping = credentialToCredentialQueryIdMappings[index]
            let identifier = UUIDGenerator.generateUUID()
            
            credentialToCredentialQueryIdMapping.identifier = identifier
            credentialToCredentialQueryIdMappings[index] = credentialToCredentialQueryIdMapping
            
            let (credential, credentialQueryId) = (credentialToCredentialQueryIdMapping.credential, credentialToCredentialQueryIdMapping.credentialQueryId)
            
            let verifiableCredentials: [AnyCodable] = [credential]
            
            let mappedCredentialQuery = try authorizationRequest.dcqlQuery.credentials.first(where: { $0.id == credentialQueryId }) ?? {
                throw InvalidData(message: "No matching credential query found for credential query id: \(credentialQueryId)", className: className)
            }()
            
            if(!mappedCredentialQuery.requireCryptographicHolderBinding) {
                vpTokenSigningPayloads[identifier] = .vc(LdpVCToken(verifiableCredential: credential))
                continue
            }
            
            let result = try extractHolderAndSignatureSuite(credential)
            let (vpTokenSigningPayload, unsignedVPToken) = try await buildPayloadAndUnsignedVPToken(
                identifier: identifier,
                with: verifiableCredentials,
                signatureSuite: result.signatureSuite,
                holder: try resolveHolder(result.holder),
                isVcdm2: try isVcdm2Credential(credential, className: className)
            )
            
            vpTokenSigningPayloads[identifier] = vpTokenSigningPayload
            if let unsignedVPToken = unsignedVPToken {
                unsignedVPTokens.append(unsignedVPToken)
            }
            
        }
        
        return (vpTokenSigningPayloads, unsignedVPTokens)
    }
    
    private func buildPayloadAndUnsignedVPToken(identifier: String, with credentials: [AnyCodable], signatureSuite: String?, holder: String?, isVcdm2: Bool) async throws -> (vpTokenSigningPayload: LdpVP, unsignedVPToken: UnsignedVPToken?) {
        var context: [String] = [isVcdm2 ? vcdmV2Context : vcdmV1Context]
        if signatureSuite == SignatureSuite.ed25519Signature2020.rawValue {
            context.append("https://w3id.org/security/suites/ed25519-2020/v1")
        } else if signatureSuite == SignatureSuite.jsonWebSignature2020.rawValue {
            context.append("https://w3id.org/security/suites/jws-2020/v1")
        }
        
        guard let holder = holder else {
            throw InvalidData(message: "Holder is required for LDP VP Tokens", className: className)
        }
        
        guard let signatureSuite = signatureSuite else {
            throw InvalidData(message: "Signature suite is required for LDP VP Tokens", className: className)
        }
        
        let signatureAlgorithm: String = try await getJWSAlgorithm(from: holder)

        var cryptosuite: String? = nil
        if isVcdm2 {
            switch signatureAlgorithm {
            case SignatureAlgorithm.edDsa.rawValue: cryptosuite = eddsaRdfc2022
            case SignatureAlgorithm.es256.rawValue: cryptosuite = ecdsaRdfc2019
            default:
                throw UnsupportedVcdm2HolderKey(algorithm: signatureAlgorithm, className: className)
            }
        }

        let proof = Proof(
            type: isVcdm2 ? SignatureSuite.dataIntegrityProof.rawValue : signatureSuite,
            created: nil,
            challenge: authorizationRequest.nonce,
            domain: authorizationRequest.clientId,
            proofPurpose: isVcdm2 ? ProofPurpose.vpProofPurpose : nil,
            verificationMethod: holder,
            proofValue: nil,
            cryptosuite: cryptosuite
        )
        
        let vpTokenSigningPayload : LdpVP = .vp(
            LdpVPToken(
                context: context,
                type: ["VerifiablePresentation"],
                verifiableCredential: credentials,
                id: id,
                holder: holder,
                proof: proof
            )
        )
        
        guard let dataToSign = try? JSONEncoder().encode(vpTokenSigningPayload),
              let jsonString = String(data: dataToSign, encoding: .utf8) else {
            throw InvalidData(message: "Failed to encode LdpVPToken for signing.", className: className)
        }
        
        
        guard let jsonLdCanonicalizer = JsonLd.canonicalizer else {
            throw InvalidData(message: "Failed to get JsonLd canonicalizer.", className: className)
        }
        
        let canonicalizedData = try await jsonLdCanonicalizer(jsonString)
        let normalizedCredentialData = try Base64Decoder.decodeBase64ToData(canonicalizedData)
        
        var signingInput = Data()

        // Data Integrity signs the canonicalization output directly: the canonicalizer already
        // returns sha256(canonical proof config) || sha256(canonical document).
        if isVcdm2 {
            signingInput = normalizedCredentialData
            let unsignedVPToken = UnsignedVPToken(
                id: identifier,
                format: .ldp_vc,
                holderKeyReference: holder,
                signatureAlgorithm: signatureAlgorithm,
                dataToSign: signingInput
            )
            return (vpTokenSigningPayload, unsignedVPToken)
        }

        switch signatureSuite {
        case SignatureSuite.jsonWebSignature2020.rawValue,
            SignatureSuite.ed25519Signature2018.rawValue:
            let jwsHeader = try BaseEncoding.base64URLEncode([
                "alg": signatureAlgorithm,
                // the payload is not Base64URL-encoded
                "crit" : ["b64"],
                "b64": false
            ])
            let headerBytes = Data(jwsHeader.utf8)
            let dot = Data([0x2E]) // "."
            
            signingInput.append(headerBytes)
            signingInput.append(dot)
            signingInput.append(normalizedCredentialData)
        case SignatureSuite.ed25519Signature2020.rawValue,
            SignatureSuite.rsaSignature2018.rawValue:
            signingInput.append(normalizedCredentialData)
        default:
            throw UnsupportedOperationException(message: "Unsupported signature suite: \(signatureSuite)", className: className)
        }
        
        
        let unsignedVPToken = UnsignedVPToken(
            id: identifier,
            format: .ldp_vc,
            holderKeyReference: holder,
            signatureAlgorithm: signatureAlgorithm,
            dataToSign: signingInput
        )
        
        
        return (vpTokenSigningPayload, unsignedVPToken)
    }
    
    private func extractHolderAndSignatureSuite(_ credential: AnyCodable) throws -> (holder: String, signatureSuite: String) {
        guard let credentialDict = credential.value as? [String: Any] else {
            throw InvalidData(message: "Credential is not a valid JSON object", className: className)
        }
        
        guard let credentialSubject = credentialDict["credentialSubject"] as? [String: Any], let holderId = credentialSubject["id"] as? String else {
            throw InvalidData(message: "Holder ID not available in the credential", className: className)
        }
        
        
        let signatureSuite = try isVcdm2Credential(credential, className: className)
            ? SignatureSuite.dataIntegrityProof.rawValue
            : SignatureSuite.jsonWebSignature2020.rawValue

        return (holder: holderId, signatureSuite: signatureSuite)
    }
    
    func validateHolderId(_ holderId: String) throws -> String {
        let sanitizedHolderId = stripDidJwkPadding(holderId)

        let hasValidDidSyntax = sanitizedHolderId.range(of: supportedHolderDidPattern, options: .regularExpression) != nil
        let hasValidDidKeyFragment: Bool
        if holderId.hasPrefix("did:key:"), let separatorIndex = holderId.firstIndex(of: "#") {
            let fingerprint = holderId[holderId.index(holderId.startIndex, offsetBy: "did:key:".count)..<separatorIndex]
            let fragment = holderId[holderId.index(after: separatorIndex)...]
            hasValidDidKeyFragment = fragment == fingerprint
        } else {
            hasValidDidKeyFragment = true
        }

        guard hasValidDidSyntax, hasValidDidKeyFragment else {
            throw InvalidData(message: "Holder ID must be a valid did:jwk, did:key, or did:web identifier: \(holderId)", className: className)
        }

        return holderId
    }
}
