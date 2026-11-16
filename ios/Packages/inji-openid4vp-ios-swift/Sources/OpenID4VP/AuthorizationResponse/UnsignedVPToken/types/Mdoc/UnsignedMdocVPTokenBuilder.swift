import Foundation
import SwiftCBOR

struct UnsignedMdocVPTokenBuilder: UnsignedVPTokenBuilder {
    private let clientId: String
    private let responseUri: String
    private let verifierNonce: String
    private let mdocGeneratedNonce: String
    static let className = String(describing: UnsignedMdocVPTokenBuilder.self)

    init(
        clientId: String,
        responseUri: String,
        verifierNonce: String,
        mdocGeneratedNonce: String
    ) {
        self.clientId = clientId
        self.responseUri = responseUri
        self.verifierNonce = verifierNonce
        self.mdocGeneratedNonce = mdocGeneratedNonce
    }
    
    
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (vpTokenSigningPayload: VPTokenSigningPayload?, unsignedVPToken: UnsignedVPToken) {
        var docTypeToDeviceAuthenticationBytes: [String: String] = [:]

        let clientIdToHash = CBOR.array([.utf8String(clientId), .utf8String(mdocGeneratedNonce)])
        let clientIdHash = CBOR.byteString(sha256Hash(from: clientIdToHash))

        let responseUriToHash = CBOR.array([.utf8String(responseUri), .utf8String(mdocGeneratedNonce)])
        let responseUriHash = CBOR.byteString(sha256Hash(from: responseUriToHash))

        let openID4VPHandover = CBOR.array([clientIdHash, responseUriHash, .utf8String(verifierNonce)])
        let sessionTranscript = CBOR.array([.null, .null, openID4VPHandover])

        let deviceNamespaces = CBOR.map([:])
        let deviceNamespacesBytes = wrapCBORInputWithTag24(input: deviceNamespaces)!

        for index in 0..<credentialInputDescriptorMappings.count {
            let credentialInputDescriptorMapping = credentialInputDescriptorMappings[index]
            guard let mdocCredential = credentialInputDescriptorMapping.credential.value as? String else {
                throw InvalidData(
                    message: "MDOC credential is not a String",
                    className: AuthorizationResponseHandler.className
                )
            }
            guard let credential = try? decodeCBOR(base64EncodedInput: mdocCredential) else {
                throw InvalidData(
                    message: "Invalid Verifiable Credential: Error while decoding credential",
                    className: Self.className
                )
            }

            guard let docType = getValueFromCBORMap(cborMap: credential, key: "docType"),
                  let docTypeString = extractStringFromCBOR(docType) else {
                throw InvalidData(
                    message: "docType missing or invalid in credential",
                    className: Self.className
                )
            }

            if docTypeToDeviceAuthenticationBytes[docTypeString] != nil {
                throw InvalidData(
                    message: "Duplicate Mdoc Credentials with same doctype found",
                    className: Self.className
                )
            }

            let deviceAuthentication = CBOR.array([
                .utf8String("DeviceAuthentication"),
                sessionTranscript,
                docType,
                deviceNamespacesBytes
            ])

            let wrapped = wrapCBORInputWithTag24(input: deviceAuthentication)!
            docTypeToDeviceAuthenticationBytes[docTypeString] = cborToByteString(cbor: wrapped)
            credentialInputDescriptorMappings[index] = CredentialInputDescriptorMapping(
                format: credentialInputDescriptorMapping.format,
                credential: credentialInputDescriptorMapping.credential,
                inputDescriptorId: credentialInputDescriptorMapping.inputDescriptorId,
                identifier: docTypeString
                )
        }

        let unsignedMdocVPToken = UnsignedMdocVPToken(docTypeToDeviceAuthenticationBytes: docTypeToDeviceAuthenticationBytes) 

        return (
            vpTokenSigningPayload: nil,
            unsignedVPToken: unsignedMdocVPToken
        )
    }
}
