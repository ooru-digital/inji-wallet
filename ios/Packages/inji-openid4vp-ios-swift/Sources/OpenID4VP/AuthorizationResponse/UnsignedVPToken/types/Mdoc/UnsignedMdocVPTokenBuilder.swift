import Foundation
import CryptoKit
import JSONWebKey
import SwiftCBOR

struct UnsignedMdocVPTokenBuilder: UnsignedVPTokenBuilder {
    let authorizationRequest: AuthorizationRequest
    let specVersion: SpecVersion
    let walletConfig: WalletConfig
    private let responseUri: String
    private let mdocGeneratedNonce: String
    
    static let className = String(describing: UnsignedMdocVPTokenBuilder.self)
    
    init(
        authorizationRequest: AuthorizationRequest,
        specVersion: SpecVersion,
        mdocGeneratedNonce: String,
        walletConfig: WalletConfig = WalletConfig()
    ) throws {
        self.authorizationRequest = authorizationRequest
        self.specVersion = specVersion
        self.walletConfig = walletConfig
        self.responseUri = try ResponseModeBasedHandlerFactory
            .get(responseMode: authorizationRequest.responseMode)
            .getResponseEndpoint(authorizationRequest: authorizationRequest)
        self.mdocGeneratedNonce = mdocGeneratedNonce
    }
    
    
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) {
        var uuidToDeviceAuthenticationBytes: [String: String] = [:]
        var unsignedVPTokens: [UnsignedVPToken] = []
        
        let sessionTranscript = try getSessionTranscript()
        let deviceNamespacesBytes = getDeviceNamespacesBytes()
        
        var existingDocTypes: Set<String> = []
        
        for index in 0..<credentialInputDescriptorMappings.count {
            let credentialInputDescriptorMapping = credentialInputDescriptorMappings[index]
            let (_, _, unsignedVPToken) = try await buildPayloadAndUnsignedVPToken(
                with: credentialInputDescriptorMapping.credential,
                sessionTranscript: sessionTranscript,
                deviceNamespacesBytes: deviceNamespacesBytes,
                uuidToDeviceAuthenticationBytes: &uuidToDeviceAuthenticationBytes,
                updateIdentifier: { identifier in
                    credentialInputDescriptorMappings[index].identifier = identifier
                },
                existingDocTypes: &existingDocTypes
            )

            unsignedVPTokens.append(unsignedVPToken)
        }
        
        return (
            vpTokenSigningPayload: uuidToDeviceAuthenticationBytes,
            unsignedVPTokens: unsignedVPTokens
        )
    }
    
    func build(credentialToCredentialQueryIdMappings: inout [CredentialToCredentialQueryIdMapping]) async throws -> (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) {
        var uuidToDeviceAuthenticationBytes: [String: String] = [:]
        var unsignedVPTokens: [UnsignedVPToken] = []
        
        let sessionTranscript = try getSessionTranscript()
        let deviceNamespacesBytes = getDeviceNamespacesBytes()
        var existingDocTypes: Set<String> = []
        
        for index in 0..<credentialToCredentialQueryIdMappings.count {
            let credentialToCredentialQueryIdMapping = credentialToCredentialQueryIdMappings[index]
            let (_, _, unsignedVPToken) = try await buildPayloadAndUnsignedVPToken(
                with: credentialToCredentialQueryIdMapping.credential,
                sessionTranscript: sessionTranscript,
                deviceNamespacesBytes: deviceNamespacesBytes,
                uuidToDeviceAuthenticationBytes: &uuidToDeviceAuthenticationBytes,
                updateIdentifier: { identifier in
                    credentialToCredentialQueryIdMappings[index].identifier = identifier
                }, existingDocTypes: &existingDocTypes
            )
            
            unsignedVPTokens.append(unsignedVPToken)
        }
        
        return (
            vpTokenSigningPayload: uuidToDeviceAuthenticationBytes,
            unsignedVPTokens: unsignedVPTokens
        )
    }
    
    private func getSessionTranscript() throws -> CBOR {
        let openID4VPHandover = try SpecVersionHandler.from(specVersion).buildOpenID4VPHandover(
            authorizationRequest: authorizationRequest,
            mdocGeneratedNonce: mdocGeneratedNonce,
            responseUri: responseUri,
            walletConfig: walletConfig
        )
        let sessionTranscript = CBOR.array([.null, .null, openID4VPHandover])
        
        return sessionTranscript
    }
    
    private func getDeviceNamespacesBytes() -> CBOR {
        let deviceNamespaces = CBOR.map([:])
        return wrapCBORInputWithTag24(input: deviceNamespaces)!
    }
    
    private func buildPayloadAndUnsignedVPToken(with credential: AnyCodable,
                                                sessionTranscript: CBOR,
                                                deviceNamespacesBytes: CBOR,
                                                uuidToDeviceAuthenticationBytes: inout [String: String],
                                                updateIdentifier: (String) -> Void,
                                                existingDocTypes: inout Set<String>
    ) async throws -> (docType: String, deviceAuthenticationBytes: String, unsignedVPToken: UnsignedVPToken) {
        let (mdocCredential, decodedMdocCredential) = try decodeMdoc(credential, className: Self.className)
        
        let issuerSigned = try getIssuerSigned(from: decodedMdocCredential, className: Self.className)
        let (_, docTypeString) = try extractMdocDocType(from: issuerSigned, className: Self.className)
        
        if existingDocTypes.contains(docTypeString) {
            throw InvalidData(
                message: "Duplicate Mdoc Credentials with same doctype found",
                className: Self.className
            )
        }
        existingDocTypes.insert(docTypeString)
        
        let deviceAuthentication = CBOR.array([
            .utf8String("DeviceAuthentication"),
            sessionTranscript,
            .utf8String(docTypeString),
            deviceNamespacesBytes
        ])
        
        let wrapped = wrapCBORInputWithTag24(input: deviceAuthentication)!
        let deviceAuthenticationBytes = cborEncode(wrapped)
        let (keyRef, alg) = try resolveMdocKeyAndAlg(mdocCredential)
        let signature1Bytes = try CoseSignature1Utils.createSignature1Structure(payload: deviceAuthenticationBytes, alg: alg)
        let dataToSign = signature1Bytes.map { String(format: "%02x", $0) }.joined()
        let identifier = UUIDGenerator.generateUUID()
        
        updateIdentifier(identifier)
        uuidToDeviceAuthenticationBytes[identifier] = dataToSign
        
        return (
            docTypeString,
            dataToSign,
            UnsignedVPToken(
                id: identifier,
                format: .mso_mdoc,
                holderKeyReference: keyRef,
                signatureAlgorithm: alg,
                dataToSign: Data(signature1Bytes)
            )
        )
    }
    
    private enum SpecVersionHandler {
        case specV1, draft23
        
        static func from(_ specVersion: SpecVersion) -> SpecVersionHandler {
            return specVersion == .v1 ? .specV1 : .draft23
        }
        
        func buildOpenID4VPHandover(authorizationRequest: AuthorizationRequest, mdocGeneratedNonce: String, responseUri: String, walletConfig: WalletConfig) throws -> CBOR {
            switch self {
            case .draft23:
                let clientIdToHash = CBOR.array([.utf8String(authorizationRequest.clientId), .utf8String(mdocGeneratedNonce)])
                let clientIdHash = CBOR.byteString(sha256Hash(from: clientIdToHash))
                
                let responseUriToHash = CBOR.array([.utf8String(responseUri), .utf8String(mdocGeneratedNonce)])
                let responseUriHash = CBOR.byteString(sha256Hash(from: responseUriToHash))
                return CBOR.array([clientIdHash, responseUriHash, .utf8String(authorizationRequest.nonce)])
            case .specV1:
                let responseHandler = try ResponseModeBasedHandlerFactory.get(responseMode: authorizationRequest.responseMode)
                let verifierPublicKey = try responseHandler.getVerifierPublicKeyForEncryption(
                    authorizationRequest: authorizationRequest, walletConfig: walletConfig
                )
                
                let thumbprintCBOR: CBOR = try verifierPublicKey?.toJWKThumbprintBstr() ?? .null
                
                let openId4VPHandoverInfo = CBOR.array([
                    .utf8String(authorizationRequest.clientId),
                    .utf8String(authorizationRequest.nonce),
                    thumbprintCBOR,
                    .utf8String(responseUri)
                ])
                
                let openId4VPHandoverInfoBytes: [UInt8] = openId4VPHandoverInfo.encode()
                let handoverInfoHash = CBOR.byteString([UInt8](Data(SHA256.hash(data: Data(openId4VPHandoverInfoBytes)))))
                
                return CBOR.array([.utf8String("OpenID4VPHandover"), handoverInfoHash])
            }
        }
    }
}
