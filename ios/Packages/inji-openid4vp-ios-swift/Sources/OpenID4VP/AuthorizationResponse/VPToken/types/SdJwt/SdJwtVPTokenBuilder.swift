import Foundation

class SdJwtVPTokenBuilder : VPTokenBuilder {
    let authorizationRequest: AuthorizationRequest
    
    init(authorizationRequest: AuthorizationRequest) {
        self.authorizationRequest = authorizationRequest
    }
    
    private let className = String(describing: SdJwtVPTokenBuilder.self)
    
    func build(
        credentialInputDescriptorMappings: [CredentialInputDescriptorMapping],
        unsignedVPTokenResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]),
        vpTokenSigningResults: [VPTokenSigningResult],
        rootIndex: Int
    ) throws -> (vpTokens: [VPToken], DescriptorMaps: [DescriptorMap], nextIndex: Int) {
        var vpIndex = rootIndex
        let identifierToUnsignedKBT = try extractIdentifierToUnsignedKBT(from: unsignedVPTokenResult)
        var vpTokens: [VPToken] = []
        var descriptorMaps: [DescriptorMap] = []

        for mapping in credentialInputDescriptorMappings {
            let identifier = try extractIdentifier(from: mapping.identifier)
            let sdJwtCredential = try extractSDJwtString(from: mapping.credential, className: className)
            let unsignedKBJwt = identifierToUnsignedKBT[identifier]
            let finalVPToken = try buildFinalToken(
                identifier: identifier,
                sdJwtCredential: sdJwtCredential,
                unsignedKBJwt: unsignedKBJwt,
                vpTokenSigningResults: vpTokenSigningResults
            )
            vpTokens.append(SdJwtVPToken(value: finalVPToken))
            descriptorMaps.append(
                DescriptorMap(
                    id: mapping.inputDescriptorId,
                    format: vpFormat(mapping.format),
                    path: createDescriptorMapPath(vpIndex),
                    pathNested: createNestedPath(id: mapping.inputDescriptorId, nestedPath: mapping.nestedPath, format: mapping.format)
                )
            )
            vpIndex += 1
        }

        return (vpTokens, descriptorMaps, vpIndex)
    }

    func build(
        credentialToCredentialQueryIdMappings: [CredentialToCredentialQueryIdMapping],
        unsignedVPTokenResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]),
        vpTokenSigningResults: [VPTokenSigningResult]
    ) throws -> [String: [VPToken]] {
        let identifierToUnsignedKBT = try extractIdentifierToUnsignedKBT(from: unsignedVPTokenResult)
        var vpTokenResult: [String: [VPToken]] = [:]
        
        for mapping in credentialToCredentialQueryIdMappings {
            let identifier = try extractIdentifier(from: mapping.identifier)
            let sdJwtCredential = try extractSDJwtString(from: mapping.credential, className: className)
            let unsignedKBJwt = identifierToUnsignedKBT[identifier]
            
            let finalVPToken: String = try buildFinalToken(
                identifier: identifier,
                sdJwtCredential: sdJwtCredential,
                unsignedKBJwt: unsignedKBJwt,
                vpTokenSigningResults: vpTokenSigningResults
            )
            
            vpTokenResult[mapping.credentialQueryId, default: []].append(SdJwtVPToken(value: finalVPToken))
        }
        
        return vpTokenResult
    }

    private func extractIdentifierToUnsignedKBT(
        from unsignedVPTokenResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken])
    ) throws -> [String: String] {
        guard let identifierToUnsignedKBT = unsignedVPTokenResult.vpTokenSigningPayload as? [String: String] else {
            throw InvalidData(message: "Missing identifierToUnsignedKBT in payload", className: className)
        }
        return identifierToUnsignedKBT
    }

    private func extractIdentifier(from identifier: String?) throws -> String {
        guard let identifier = identifier else {
            throw InvalidData(message: "identifier is null in CredentialInputDescriptorMapping for SD-JWT", className: className)
        }
        return identifier
    }

    private func buildFinalToken(
        identifier: String,
        sdJwtCredential: String,
        unsignedKBJwt: String?,
        vpTokenSigningResults: [VPTokenSigningResult]
    ) throws -> String {
        guard let unsignedKBJwt else {
            return sdJwtCredential
        }
        let vpTokenSigningResult = try getVPTokenSigningResult(vpTokenSigningResults: vpTokenSigningResults, identifier: identifier, className: className)
        let signature = vpTokenSigningResult.signedData.toBase64UrlEncoded()
        return "\(sdJwtCredential)\(unsignedKBJwt).\(signature)"
    }
    
    private func vpFormat(_ value: FormatType) -> VPFormatType {
         switch value {
        case .dc_sd_jwt:
             return .dc_sd_jwt
        default:
             return .vc_sd_jwt
        }
    }
}
