import Foundation

class LdpVPTokenBuilder: VPTokenBuilder {
    private let className = "LdpVPTokenBuilder"
    
    let authorizationRequest: AuthorizationRequest
    
    init(authorizationRequest: AuthorizationRequest) {
        self.authorizationRequest = authorizationRequest
    }
    
    func build(
        credentialInputDescriptorMappings: [CredentialInputDescriptorMapping],
        unsignedVPTokenResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]),
        vpTokenSigningResults: [VPTokenSigningResult],
        rootIndex: Int
    ) throws -> (vpTokens: [VPToken], DescriptorMaps: [DescriptorMap], nextIndex: Int) {
        guard !vpTokenSigningResults.isEmpty else {
            throw InvalidData(message: "Missing LDP signature", className: className)
        }
        guard vpTokenSigningResults.count == credentialInputDescriptorMappings.count else {
            throw InvalidData(message: "LDP signing results count does not match selected credentials count", className: className)
        }
        guard let payloadMap = unsignedVPTokenResult.vpTokenSigningPayload as? [String: LdpVP] else {
            throw InvalidData(message: "Expected List<LdpVPToken> as payload", className: className)
        }
        let unsignedVPTokens = unsignedVPTokenResult.unsignedVPTokens
        
        var descriptorMaps: [DescriptorMap] = []
        var ldpVPTokens: [VPToken] = []
        
        for (index, credentialInputDescriptorMapping) in credentialInputDescriptorMappings.enumerated() {
            guard let identifier = credentialInputDescriptorMapping.identifier else {
                throw InvalidData(message: "Identifier is expected in the credential request id mapping", className: className)
            }
            guard case .vp(let ldpVPTokenPayload) = payloadMap[identifier] else {
                throw InvalidData(message: "Expected LdpVPToken as payload", className: className)
            }
            let ldpVPToken = try buildVPToken(
                ldpVPTokenPayload: ldpVPTokenPayload,
                vpTokenSigningResults: vpTokenSigningResults,
                unsignedVPTokens: unsignedVPTokens,
                identifier: identifier
            )
            
            ldpVPTokens.append(ldpVPToken)
            descriptorMaps.append(
                DescriptorMap(
                    id: credentialInputDescriptorMapping.inputDescriptorId,
                    format: .ldp_vp,
                    path: createDescriptorMapPath(rootIndex + index),
                    pathNested: createNestedPath(
                        id: credentialInputDescriptorMapping.inputDescriptorId,
                        nestedPath: credentialInputDescriptorMapping.nestedPath,
                        format: .ldp_vc
                    )
                )
            )
        }
        
        return (ldpVPTokens, descriptorMaps, rootIndex + ldpVPTokens.count)
    }
    
    func build(
        credentialToCredentialQueryIdMappings: [CredentialToCredentialQueryIdMapping],
        unsignedVPTokenResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]),
        vpTokenSigningResults: [VPTokenSigningResult]
    ) throws -> [String: [VPToken]] {
        guard let payloadMap = unsignedVPTokenResult.vpTokenSigningPayload as? [String: LdpVP] else {
            throw InvalidData(message: "Expected Map<String, Any> as payload for DCQL LDP flow", className: className)
        }
        let unsignedVPTokens = unsignedVPTokenResult.unsignedVPTokens
        var vpTokenResult: [String: [VPToken]] = [:]
        
        for credentialToCredentialQueryIdMapping in credentialToCredentialQueryIdMappings {
            guard let identifier = credentialToCredentialQueryIdMapping.identifier else {
                throw InvalidData(message: "Missing identifier in credential mapping", className: className)
            }
            guard let payload = payloadMap[identifier] else {
                throw InvalidData(message: "No payload found for identifier: \(identifier)", className: className)
            }
            let vpToken: VPToken
            switch payload {
            case .vp(let ldpVPToken):
                vpToken = try buildVPToken(
                    ldpVPTokenPayload: ldpVPToken,
                    vpTokenSigningResults: vpTokenSigningResults,
                    unsignedVPTokens: unsignedVPTokens,
                    identifier: identifier
                )
            case .vc:
                vpToken = payload
            }
            vpTokenResult[credentialToCredentialQueryIdMapping.credentialQueryId, default: []].append(vpToken)
        }
        
        return vpTokenResult
    }
    
    private func buildVPToken(
        ldpVPTokenPayload: LdpVPToken,
        vpTokenSigningResults: [VPTokenSigningResult],
        unsignedVPTokens: [UnsignedVPToken],
        identifier: String
    ) throws -> LdpVPToken {
        var proof = ldpVPTokenPayload.proof
        let proofType = proof?.type ?? ""

        let unsignedVPToken = try getUnsignedVPToken(unsignedVPTokens: unsignedVPTokens, identifier: identifier, className: className)
        let vpTokenSigningResult = try getVPTokenSigningResult(vpTokenSigningResults: vpTokenSigningResults, identifier: identifier, className: className)
        
        switch proofType {
        case SignatureSuite.jsonWebSignature2020.rawValue,
            SignatureSuite.ed25519Signature2018.rawValue:
            proof?.jws = getHeader(unsignedVPToken) + ".." + vpTokenSigningResult.signedData.toBase64UrlEncoded()
        case SignatureSuite.rsaSignature2018.rawValue:
            proof?.signatureValue = vpTokenSigningResult.signedData.toBase64UrlEncoded()
        case SignatureSuite.dataIntegrityProof.rawValue:
            guard vpTokenSigningResult.signedData.count == 64 else {
                throw InvalidSignature(message: "Data Integrity Ed25519 and P-256 signatures must be exactly 64 bytes", className: className)
            }
            proof?.proofValue = BaseEncoding.base58BtcEncode(vpTokenSigningResult.signedData)
        default:
            proof?.proofValue = BaseEncoding.base58BtcEncode(vpTokenSigningResult.signedData)
        }
        
        return LdpVPToken(
            context: ldpVPTokenPayload.context,
            type: ldpVPTokenPayload.type,
            verifiableCredential: ldpVPTokenPayload.verifiableCredential,
            id: ldpVPTokenPayload.id,
            holder: ldpVPTokenPayload.holder,
            proof: proof
        )
    }
    
    private func getHeader(_ unsignedVPToken: UnsignedVPToken) -> String {
        let dataToSign = unsignedVPToken.dataToSign
        let dotIndex = dataToSign.firstIndex(of: 0x2E)
        let headerData = dataToSign.prefix(upTo: dotIndex ?? Data.Index())
        let header = String(data: headerData, encoding: .utf8) ?? ""
        
        return header
    }
}
