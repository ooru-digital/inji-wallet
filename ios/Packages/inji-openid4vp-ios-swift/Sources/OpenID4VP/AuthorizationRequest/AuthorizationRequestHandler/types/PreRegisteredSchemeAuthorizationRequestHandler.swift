import Foundation
import JSONWebKey

class PreRegisteredSchemeAuthorizationRequestHandler:  ClientIdSchemeBasedAuthorizationRequestHandler {
    let trustedVerifiers: [Verifier]
    let shouldValidateClient: Bool
    
    init(trustedVerifiers: [Verifier],
         authorizationRequestParameters: [String: Any],
         walletMetadata: WalletMetadata?,
         shouldValidateClient: Bool,
         setResponseUri: @escaping (String) -> Void,
         walletNonce: String,
         networkManager: NetworkManaging) {
        self.trustedVerifiers = trustedVerifiers
        self.shouldValidateClient = shouldValidateClient
        super.init(authorizationRequestParameters: authorizationRequestParameters,
                   walletMetadata: walletMetadata,
                   setResponseUri: setResponseUri,
                   walletNonce: walletNonce,
                   networkManager: networkManager)
        delegate = self
        super.className = String(describing: PreRegisteredSchemeAuthorizationRequestHandler.self)
    }
    
    func clientIdScheme() -> String {
        return ClientIdScheme.preRegistered.rawValue
    }
    
    override func validateClientId() throws {
        if shouldValidateClient {
            guard trustedVerifiers.contains(where: { $0.clientId == authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as? String }) else {
                throw InvalidVerifier(message: "Verifier is not trusted by the wallet", className: AuthorizationRequest.className)
            }
        }
    }
    
    func process(walletMetadata: WalletMetadata) -> WalletMetadata {
        var updatedWalletMetadata = walletMetadata
        updatedWalletMetadata.requestObjectSigningAlgValuesSupported = nil
        return updatedWalletMetadata
    }
    
    func isSignedRequestSupported() -> Bool {
        return true
    }
    
    
    func isUnsignedRequestSupported() throws -> Bool {
        if shouldValidateClient {
            let clientId = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue]) ?? ""
            let preRegisteredVerifier = try verifier(clientId: clientId)
            return preRegisteredVerifier.allowUnsignedRequest
        }
        return true
    }
    
    func extractPublicKey(keyId: String?, algorithm: String) async throws -> PublicKeyType {
        let clientId = authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as? String
        
        let preRegisteredClient = try verifier(clientId: clientId ?? "")
        if let jwksUri = preRegisteredClient.jwksUri {
            let jwkSet : JWKSet = try await resolveJwksFromUri(jwksUri, networkManager: self.networkManager, className: className)
            
            let publicKeyJwk =  try filterAndExtractKey(jwks: jwkSet, keyId: keyId, algorithm: algorithm)
            return try jwkToPublicKey(publicKeyJwk, className: className)
        } else {
            throw PublicKeyResolutionFailed(
                message: "Public key extraction failed - Public key information not available in pre-registered data to verify the signed Authorization Request",
                className: className,
                code: OpenID4VPErrorCodes.invalidRequestObject
            )
        }
    }
    
    override func validateAndParseRequestFields() async throws {
        if shouldValidateClient {
            let clientId = authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as! String
            let preRegisteredClient = try verifier(clientId: clientId)
            
            let responseUri = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri.rawValue]) ?? "null"
            guard preRegisteredClient.responseUris.contains(responseUri) else {
                throw InvalidVerifier(
                    message: "response_uri trust cannot be established",
                    className: AuthorizationRequest.className
                )
            }
            
        }
        try await super.validateAndParseRequestFields()
    }
    
    private func filterAndExtractKey(jwks publicKeys: JWKSet, keyId: String?, algorithm: String) throws -> JWK {
        if(keyId != nil) {
            if let matchingJWK = (publicKeys.keys as [JWK]).filter({ $0.keyID == keyId }).first {
                return matchingJWK
            } else {
                throw PublicKeyResolutionFailed(message: "Public key extraction failed for kid: \(String(describing: keyId))",
                                                className: className,
                                                code: OpenID4VPErrorCodes.invalidRequestObject)
            }
        }
        
        let matchingKeys = (publicKeys.keys as [JWK]).filter({ $0.algorithm == algorithm && $0.publicKeyUse == .signature })
        
        if(matchingKeys.isEmpty) {
            throw PublicKeyResolutionFailed(message: "No public key found for algorithm: \(algorithm) with key use: signature",
                                            className: className,
                                            code: OpenID4VPErrorCodes.invalidRequestObject)
        } else if(matchingKeys.count == 1) {
            return matchingKeys[0]
        } else  {
            throw PublicKeyResolutionFailed(message: "Public key extraction failed - Multiple ambiguous keys found for \(algorithm) with signature usage",
                                            className: className,
                                            code: OpenID4VPErrorCodes.invalidRequestObject)
        }
    }
    
    private func verifier(clientId: String) throws -> Verifier {
        if let found = trustedVerifiers.first(where: { $0.clientId == clientId }) {
            return found
        } else {
            throw InvalidVerifier(message: "Verifier is not trusted by the wallet", className: className)
        }
    }
}
