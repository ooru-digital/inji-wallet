import Foundation

private let keyBindingJWT = "kb+jwt"

struct UnsignedSdJwtVPTokenBuilder : UnsignedVPTokenBuilder {
    let authorizationRequest: AuthorizationRequest
    let specVersion: SpecVersion
    let walletConfig: WalletConfig
    private let networkManager: any NetworkManaging
    
    private static let className = "UnsignedSdJwTVPTokenBuilder"
    
    init(authorizationRequest: AuthorizationRequest, specVersion: SpecVersion, networkManager: any NetworkManaging = NetworkManager(), walletConfig: WalletConfig = WalletConfig()) {
        self.authorizationRequest = authorizationRequest
        self.specVersion = specVersion
        self.networkManager = networkManager
        self.walletConfig = walletConfig
    }
    
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) {
        var identifierToUnsignedKBJWT = [String: String]()
        var unsignedVPTokens: [UnsignedVPToken] = []
        
        for index in 0..<credentialInputDescriptorMappings.count {
            let mapping = credentialInputDescriptorMappings[index]
            
            try await prepareUnsignedKeyBinding(
                setIdentifier: { id in credentialInputDescriptorMappings[index].identifier = id },
                credentialData: mapping.credential,
                format: mapping.format,
                clientId: authorizationRequest.clientId,
                nonce: authorizationRequest.nonce,
                shouldAddCryptographicHolderBinding: { cnf in cnf.isEmpty == false },
                identifierToUnsignedKBJWT: &identifierToUnsignedKBJWT,
                unsignedVPTokens: &unsignedVPTokens
            )
        }
        
        return (vpTokenSigningPayload: identifierToUnsignedKBJWT, unsignedVPTokens: unsignedVPTokens)
    }
    
    func build(credentialToCredentialQueryIdMappings: inout [CredentialToCredentialQueryIdMapping]) async throws -> (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) {
        guard let authorizationRequest = authorizationRequest as? AuthorizationDcqlRequest else {
            throw InvalidData(message: "Expected AuthorizationDcqlRequest for DCQL flow", className: Self.className)
        }
        
        var identifierToUnsignedKBJWT = [String: String]()
        var unsignedVPTokens: [UnsignedVPToken] = []
        
        for index in 0..<credentialToCredentialQueryIdMappings.count {
            let identifier = UUIDGenerator.generateUUID()
            credentialToCredentialQueryIdMappings[index].identifier = identifier
            let credentialToCredentialQueryIdMapping = credentialToCredentialQueryIdMappings[index]
            
            let matchedCredentialQuery = try authorizationRequest.dcqlQuery.credentials.first(where: { $0.id == credentialToCredentialQueryIdMapping.credentialQueryId }) ?? {
                throw InvalidData(message: "No matching credential query found for credential query id: \(credentialToCredentialQueryIdMapping.credentialQueryId)", className: Self.className)
            }()
            
            try await prepareUnsignedKeyBinding(
                setIdentifier: { id in credentialToCredentialQueryIdMappings[index].identifier = id },
                credentialData: credentialToCredentialQueryIdMapping.credential,
                format: credentialToCredentialQueryIdMapping.format,
                clientId: authorizationRequest.clientId,
                nonce: authorizationRequest.nonce,
                shouldAddCryptographicHolderBinding: { cnf in
                    if matchedCredentialQuery.requireCryptographicHolderBinding {
                        if cnf.isEmpty {
                            throw InvalidData(message: "Holder binding is required for presentation but no cnf claim was present", className: Self.className)
                        }
                        return true
                    }
                    return false
                },
                identifierToUnsignedKBJWT: &identifierToUnsignedKBJWT,
                unsignedVPTokens: &unsignedVPTokens
            )
        }
        
        return (vpTokenSigningPayload: identifierToUnsignedKBJWT, unsignedVPTokens: unsignedVPTokens)
    }
    
    private func prepareUnsignedKeyBinding(
        setIdentifier: (String) -> Void,
        credentialData: AnyCodable,
        format: FormatType,
        clientId: String,
        nonce: String,
        shouldAddCryptographicHolderBinding: ([String : Any]) throws -> Bool,
        identifierToUnsignedKBJWT: inout [String: String],
        unsignedVPTokens: inout [UnsignedVPToken]
    ) async throws  {
        let (credential, sdJWTPayload, _) = try extractSdJwtPayload(credentialData, className: Self.className)
        let confirmationKeyClaim = sdJWTPayload["cnf"] as? [String: Any] ?? [:]
        let identifier = UUIDGenerator.generateUUID()
        setIdentifier(identifier)
        
        guard try shouldAddCryptographicHolderBinding(confirmationKeyClaim) else {
            return
        }
        
        let signingAlgorithm: String
        let holderKeyReference: String
        
        if confirmationKeyClaim["jwk"] != nil && confirmationKeyClaim["kid"] != nil {
            throw InvalidData(message: "Invalid cnf: provide exactly one of 'jwk' or 'kid'", className: Self.className)
        }
        
        if let jwk = confirmationKeyClaim["jwk"] as? [String: Any] {
            signingAlgorithm = try resolveAlgFromJwk(jwk)
            holderKeyReference = try serializeJwkToJson(jwk)
        } else if let keyId = confirmationKeyClaim["kid"] as? String {
            let didResolver = DidPublicKeyResolver(networkManager: networkManager)
            signingAlgorithm = try await didResolver.getJWSAlgorithm(uri: keyId)
            holderKeyReference = keyId
        } else {
            throw UnsupportedOperationException(message: "Unsupported cnf format, must contain 'kid' or 'jwk'", className: Self.className)
        }
        
        let sdHashAlgorithm = sdJWTPayload["_sd_alg"] as? String ?? HashAlgorithm.sha256.rawValue
        let sdHash = try hashData(credential, hashAlgorithm: sdHashAlgorithm, className: Self.className).toBase64UrlEncoded()
        
        let jwtHeader = ["alg": signingAlgorithm, "typ": keyBindingJWT]
        let jwtPayload: [String: Any] = [
            "iat": Int(Date().timeIntervalSince1970),
            "aud": clientId,
            "nonce": nonce,
            "sd_hash": sdHash
        ]
        
        let unsignedJWT = try JWSHandler.createUnsignedJWS(header: jwtHeader, payload: jwtPayload)
        
        unsignedVPTokens.append(UnsignedVPToken(
            id: identifier,
            format: format,
            holderKeyReference: holderKeyReference,
            signatureAlgorithm: signingAlgorithm,
            dataToSign: Data(unsignedJWT.utf8)
        ))
        identifierToUnsignedKBJWT[identifier] = unsignedJWT
    }
}
