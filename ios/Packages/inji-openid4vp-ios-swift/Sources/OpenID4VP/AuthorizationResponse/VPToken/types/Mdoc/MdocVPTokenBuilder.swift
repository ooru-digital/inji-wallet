import Foundation
import SwiftCBOR

class MdocVPTokenBuilder : VPTokenBuilder {
    private let className = String(describing: MdocVPTokenBuilder.self)
    
    func build(
        credentialInputDescriptorMappings: [CredentialInputDescriptorMapping],
        unsignedVPTokenResult: (vpTokenSigningPayload: VPTokenSigningPayload?, unsignedVPToken: UnsignedVPToken),
        vpTokenSigningResult: VPTokenSigningResult,
        rootIndex: Int
    ) throws -> (vpTokens: [VPToken], DescriptorMaps: [DescriptorMap], nextIndex: Int) {
        var documents : [CBOR] = []
        guard let mdocVPTokenSigningResult = vpTokenSigningResult as? MdocVPTokenSigningResult else {
            throw InvalidType(
                message: "Invalid MSO-MDOC token or signing result type",
                className: VPTokenFactory.className
            )
        }
        
        try mdocVPTokenSigningResult.validate()
        var descriptorMaps : [DescriptorMap] = []
        
        try credentialInputDescriptorMappings.forEach { credentialInputDescriptorMapping in
            guard let mdocCredential = credentialInputDescriptorMapping.credential.value as? String else {
                throw InvalidType(
                    message: "Invalid MSO-MDOC token or signing result type",
                    className: VPTokenFactory.className
                )
            }
            guard var document = try? decodeCBOR(base64EncodedInput: mdocCredential) else {
                throw InvalidData( message: "Invalid Verifiable Credential: Error while decoding credential", className: className)
            }
            guard let docType = getValueFromCBORMap(cborMap: document, key: "docType") else {
                throw InvalidData( message: "Invalid Verifiable Credential: docType not available in credential", className: className)
            }
            let docTypeString = extractStringFromCBOR(docType)!
            
            guard let deviceAuthSignature: DeviceAuthentication = mdocVPTokenSigningResult.docTypeToDeviceAuthentication[docTypeString] else {
                throw MissingInput (
                    fieldPath: ["mdocVPTokenSigningResult","docTypeToDeviceAuthentication","DeviceAuthentication"],
                    message: "Device authentication signature not found for mdoc credential docType \(docTypeString)",
                                    className: className)
            }
            
            let deviceSignature = try createDeviceSignature(deviceAuthSignature)
            
            let deviceAuth = CBOR.map([.utf8String("deviceSignature"): deviceSignature])
            let deviceNamespacesBytes = wrapCBORInputWithTag24(input: CBOR.map([:]))!
            // ISO 18013-5 DeviceSigned = { "nameSpaces": DeviceNameSpacesBytes, "deviceAuth": DeviceAuth },
            // the keys the Android library writes and readers look up.
            let deviceSigned = CBOR.map([
                .utf8String("deviceAuth"): deviceAuth,
                .utf8String("nameSpaces"): deviceNamespacesBytes,
            ])
            
            // attach deviceSigned to cborCredential
            document[CBOR.utf8String("deviceSigned")] = deviceSigned
            
            documents.append(document)
            descriptorMaps.append(
                DescriptorMap(
                    id: credentialInputDescriptorMapping.inputDescriptorId,
                    format: .mso_mdoc,
                    path: createDescriptorMapPath(rootIndex),
                    pathNested: createNestedPath(
                        id: credentialInputDescriptorMapping.inputDescriptorId,
                        nestedPath: credentialInputDescriptorMapping.nestedPath,
                        format: .mso_mdoc
                    )
                )
            )
        }
        
        let deviceResponse = CBOR.map([
            .utf8String("version"): .utf8String("1.0"),
            .utf8String("documents"): .array(documents),
            .utf8String("status"): .unsignedInt(UInt64(0)), // Status = OK
        ])
        
        //base64 url encode without padding the deviceResponse
        let encodedDeviceResponseBase64Url = Data(cborEncode(deviceResponse)).toBase64UrlEncoded()
        let mdocVPToken = MdocVPToken(base64EncodedDeviceResponse: encodedDeviceResponseBase64Url)
        
        return ([mdocVPToken], descriptorMaps, rootIndex + 1)
    }
    
    // DeviceSignature is of COSE_Sign1 structure
    /**
     COSE_Sign1 = [
     Headers, //protected , unprotected in order
     payload : bstr / nil,
     signature : bstr
     ]
     */
    private func createDeviceSignature(_ vpResponseMetadata: DeviceAuthentication) throws -> CBOR {
        let base64DecodedSignature = try Base64Decoder.decodeBase64ToData(vpResponseMetadata.signature)
        let cborEncodedSignature = cborEncode(toCBOR(base64DecodedSignature))
        let protectedHeaders = CBOR.map([
            .unsignedInt(1): try mapSigningAlgorithmToProtectedAlg(algorithm: vpResponseMetadata.algorithm)
        ])
        let unprotectedHeaders = CBOR.map([:])
        //Payload is available as detached content
        let payload = CBOR.null
        
        return CBOR.array([
            .byteString(cborEncode(protectedHeaders)),
            unprotectedHeaders,
            payload,
            .byteString(cborEncodedSignature),
        ])
    }
}
