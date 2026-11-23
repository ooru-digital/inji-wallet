import Foundation
import JSONWebKey

class PreRegisteredSchemeAuthorizationRequestHandler:  ClientIdPrefixBasedAuthorizationRequestHandler {
    
    override init(clientId: String,
         specVersion: SpecVersion,
         authorizationRequestParameters: [String: Any],
         walletConfig: WalletConfig,
         setResponseDispatchInfo: @escaping (ResponseDispatchInfo) -> Void,
         walletNonce: String,
         networkManager: NetworkManaging) {
        super.init(clientId: clientId,
                   specVersion: specVersion,
                   authorizationRequestParameters: authorizationRequestParameters,
                   walletConfig: walletConfig,
                   setResponseDispatchInfo: setResponseDispatchInfo,
                   walletNonce: walletNonce,
                   networkManager: networkManager)
        delegate = self
        super.className = String(describing: PreRegisteredSchemeAuthorizationRequestHandler.self)
    }

    func clientIdPrefix() -> String {
        return ClientIdPrefix.preRegistered.rawValue
    }
    
    override func validateClientId() throws {
        if walletConfig.validateTrustedVerifier {
            guard walletConfig.trustedVerifiers.contains(where: { $0.clientId == super.clientId }) else {
                throw InvalidVerifier(message: "Verifier is not trusted by the wallet", className: className)
            }
        }
    }
    
    func getWalletMetadata(walletConfig: WalletConfig) throws -> [String: Any] {
        try validateRequestObjectSigningAlgSupported(walletConfig, className: className)
        
        return try walletConfig.toWalletMetadata(specVersion: specVersion)
    }
    
    func isSignedRequestSupported() -> Bool {
        return true
    }
    
    
    func isUnsignedRequestSupported() throws -> Bool {
        if walletConfig.validateTrustedVerifier {
            let preRegisteredVerifier = try verifier(clientId: super.clientId)
            return preRegisteredVerifier.allowUnsignedRequest
        }
        return true
    }
    
    func extractPublicKey(keyId: String?, algorithm: String) async throws -> PublicKeyType {
        let preRegisteredClient = try verifier(clientId: super.clientId)
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
    
    func validateClientAuthenticity() throws {
        if walletConfig.validateTrustedVerifier {
            let preRegisteredClient = try verifier(clientId: super.clientId)
            
            guard let responseUri = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri]) else {
                throw MissingInput(fieldPath: "response_uri", className: className, notifyVerifier: false)
            }
            guard preRegisteredClient.responseUris.contains(responseUri) else {
                throw InvalidVerifier(
                    message: "response_uri trust cannot be established",
                    className: className
                )
            }
            
        }
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
        if let found = walletConfig.trustedVerifiers.first(where: { $0.clientId == clientId }) {
            return found
        } else {
            throw InvalidVerifier(message: "Verifier is not trusted by the wallet", className: className)
        }
    }
}
