import Foundation

class SdJwtVPTokenBuilder : VPTokenBuilder {
    private let className = String(describing: SdJwtVPTokenBuilder.self)
    
    func build(
        credentialInputDescriptorMappings: [CredentialInputDescriptorMapping],
        unsignedVPTokenResult: (vpTokenSigningPayload: VPTokenSigningPayload?, unsignedVPToken: UnsignedVPToken),
        vpTokenSigningResult: VPTokenSigningResult,
        rootIndex: Int
    ) throws -> (vpTokens: [VPToken], DescriptorMaps: [DescriptorMap], nextIndex: Int) {
        var vpIndex = rootIndex
        guard let sdJwtVPTokenSigningResult = vpTokenSigningResult as? SdJwtVpTokenSigningResult else {
            throw InvalidData(message: "vpTokenSigningResult is not SdJwtVpTokenSigningResult", className: className)
        }
        guard let unsignedSdJwtVPToken = unsignedVPTokenResult.unsignedVPToken as? UnsignedSdJwtVPToken else {
            throw InvalidData(message: "unsignedVPTokenResult.unsignedVPToken is not UnsignedSdJwtVPToken", className: className)
        }
        var vpTokens: [VPToken] = []
        var descriptorMaps: [DescriptorMap] = []
        for mapping in credentialInputDescriptorMappings {
            guard let uuid = mapping.identifier else {
                throw InvalidData(message: "identifier is null in CredentialInputDescriptorMapping for SD-JWT", className: className)
            }
            guard let sdJwtCredential = mapping.credential.value as? String else {
                throw InvalidData(message: "SD-JWT credential is not a String", className: className)
            }
            let unsignedKBJwt = unsignedSdJwtVPToken.uuidToUnsignedKBT[uuid]
            let signature = sdJwtVPTokenSigningResult.uuidToKbJWTSignature[uuid]
            let finalVPToken: String
            
            if unsignedKBJwt == nil && signature == nil {
                finalVPToken = sdJwtCredential
            } else if let unsignedKBJwt = unsignedKBJwt, let signature = signature {
                finalVPToken = "\(sdJwtCredential)\(unsignedKBJwt).\(signature)"
            } else if unsignedKBJwt != nil, signature == nil {
                throw MissingInput(fieldPath: uuid, message: "Missing Key Binding JWT signature for uuid: \(uuid)", className: className)
            } else {
                throw InvalidData(message: "Signature present but unsigned KB-JWT missing for uuid: \(uuid)", className: className)
            }
            
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
    
    private func vpFormat(_ value: FormatType) -> VPFormatType {
         switch value {
        case .dc_sd_jwt:
             return .dc_sd_jwt
        default:
             return .vc_sd_jwt
        }
    }
}
