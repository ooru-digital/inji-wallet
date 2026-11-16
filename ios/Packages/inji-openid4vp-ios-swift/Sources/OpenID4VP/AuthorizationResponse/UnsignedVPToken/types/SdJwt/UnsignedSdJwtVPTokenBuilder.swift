import Foundation

private let keyBindingJWT = "kb+jwt"

struct UnsignedSdJwtVPTokenBuilder : UnsignedVPTokenBuilder {
    private let clientId: String
    private let nonce: String
    private let networkManager: any NetworkManaging
    
    private static let className = "UnsignedSdJwTVPTokenBuilder"
    
    init(clientId: String, authorizationRequestNonce: String, networkManager: any NetworkManaging = NetworkManager()) {
        self.clientId = clientId
        self.nonce = authorizationRequestNonce
        self.networkManager = networkManager
    }
    
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (vpTokenSigningPayload: VPTokenSigningPayload?, unsignedVPToken : UnsignedVPToken) {
        var uuidToUnsignedKBJWT = [String: String]()
        
        for index in 0..<credentialInputDescriptorMappings.count {
            let credentialInputDescriptorMapping = credentialInputDescriptorMappings[index]
            let uuid = UUIDGenerator.generateUUID()
            guard let credential = credentialInputDescriptorMapping.credential.value as? String else {
                throw InvalidData(
                    message: "SD-JWT credential is not a String",
                    className: Self.className)
            }
            
            let sdJWT = credential.split(separator: "~")[0]
            let sdJWTPayload = try JWSHandler.extractDataJsonFromJws(jws: String(sdJWT), jwsPart: .payload)
            
            credentialInputDescriptorMappings[index] = CredentialInputDescriptorMapping(
                format: credentialInputDescriptorMapping.format,
                credential: credentialInputDescriptorMapping.credential,
                inputDescriptorId: credentialInputDescriptorMapping.inputDescriptorId,
                identifier: uuid
                )
            
            guard let confirmationKeyClaim = sdJWTPayload["cnf"] as? [String: Any], !confirmationKeyClaim.isEmpty else {
                continue
            }
            
            var jwtSigningALgorithm: String = ""
            if let keyId = confirmationKeyClaim["kid"] as? String {
                let didResolver = DidPublicKeyResolver(networkManager: networkManager)
                let confirmationKey = try await didResolver.resolve(uri: keyId, keyId: nil)
                jwtSigningALgorithm = extractSigningAlgorithm(from: confirmationKey)
            } else {
                throw UnsupportedOperationException(message: "Unsupported cnf format, only 'kid' is supported", className: Self.className)
            }
            
            let jwtHeader = [
                "alg": jwtSigningALgorithm,
                "typ": keyBindingJWT
            ]
            
            let sdHashAlgorithm = sdJWTPayload["_sd_alg"] as? String ?? HashAlgorithm.sha256.rawValue
            let sdHash = try hashData(credential, hashAlgorithm: sdHashAlgorithm, className: Self.className).toBase64UrlEncoded()
            
            let jwtPayload : [String: Any] = [
                "iat": Int(Date().timeIntervalSince1970),
                "aud": clientId,
                "nonce": nonce,
                "sd_hash": sdHash
            ]
            
            let unsignedJWT = try JWSHandler.createUnsignedJWS(header: jwtHeader, payload: jwtPayload)
            
            uuidToUnsignedKBJWT[uuid] = unsignedJWT
        }
        
        return (
            vpTokenSigningPayload: nil,
            unsignedVPToken: UnsignedSdJwtVPToken(uuidToUnsignedKBT: uuidToUnsignedKBJWT)
        )
    }
}
