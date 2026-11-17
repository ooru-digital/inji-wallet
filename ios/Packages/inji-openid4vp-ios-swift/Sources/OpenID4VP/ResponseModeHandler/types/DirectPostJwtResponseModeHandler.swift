import Foundation
import JSONWebKey


struct DirectPostJwtResponseModeHandler : ResponseModeBasedHandler {

    let className = String(describing: DirectPostJwtResponseModeHandler.self)
    func validate(clientMetadata: ClientMetadata?,
                  walletMetadata: WalletMetadata?,
                  shouldValidateWithWalletMetadata: Bool) throws {

        guard clientMetadata != nil else {
            throw InvalidData(
                  message: "client_metadata must be present for given response mode",
                  className: className
              )
        }

        guard let alg = clientMetadata?.authorizationEncryptedResponseAlg else {
            throw MissingInput(fieldPath: ["client_metadata", "authorization_encrypted_response_alg"],
                               message: "",
                               className: className)
        }
        guard let enc = clientMetadata?.authorizationEncryptedResponseEnc else {
            throw MissingInput(fieldPath: ["client_metadata", "authorization_encrypted_response_enc"],
                                           message: "",
                                           className: className)
        }
        guard let jwks = clientMetadata?.jwks else {
            throw MissingInput(fieldPath: ["client_metadata", "jwks"],
                                 message: "",
                                 className: className)
        }

        if shouldValidateWithWalletMetadata {
            try validateWithWalletMetadata(clientAlg: alg,
                                           clientEnc: enc,
                                           walletMetadata: walletMetadata)
        }

        if !jwks.keys.contains(where: { $0.algorithm == alg && $0.publicKeyUse == .encryption}) {
            throw InvalidData(
                message: "No jwk matching the specified algorithm found for encryption",
                className: className
            )
        }
    }
    
    func getAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        walletNonce: String
    ) throws -> [String: String] {
        let responseParams = try authorizationResponse.toJsonEncodedMap()
        return try encryptResponse(
            authorizationRequest: authorizationRequest,
            responseParams: responseParams,
            walletNonce: walletNonce
        )
    }
    
    func getAuthorizationErrorResponse(
        authorizationRequest: AuthorizationRequest?,
        authorizationResponse: AuthorizationErrorResponse,
        walletNonce: String
    ) throws -> [String: String] {
        return authorizationResponse.toJsonEncodedMap()
    }

    private func encryptResponse(
        authorizationRequest: AuthorizationRequest,
        responseParams: [String: String],
        walletNonce: String
    ) throws -> [String: String] {
        let clientMetadata = authorizationRequest.clientMetadata!

        let verifierPublicKey = try getJwk(
            clientMetadata.jwks!,
            clientMetadata.authorizationEncryptedResponseAlg!
        )

        let jweHandler = JWEHandler(
            contentEncryptionAlgorithm: clientMetadata.authorizationEncryptedResponseEnc!,
            keyEncryptionAlgorithm: clientMetadata.authorizationEncryptedResponseAlg!,
            publicKey: verifierPublicKey,
            producerInfo: walletNonce,
            recipientInfo: authorizationRequest.nonce
        )

        let encryptedBody = try jweHandler.generateEncryptedResponse(payload: responseParams)
        return ["response": encryptedBody]
    }

    private func validateWithWalletMetadata(clientAlg: String,
                                            clientEnc: String,
                                            walletMetadata: WalletMetadata?) throws {
        guard let walletMetadata = walletMetadata else {
            throw InvalidData(message: "wallet_metadata must be present", className: className)
        }

        guard let supportedEncryptionAlgorithms = walletMetadata.authorizationEncryptionAlgValuesSupported?.compactMap({$0.rawValue}) else {
            throw InvalidData(message: "authorization_encryption_alg_values_supported must be present in wallet_metadata", className: className)
        }

        guard supportedEncryptionAlgorithms.contains(clientAlg) else {
            throw InvalidData(message: "authorization_encrypted_response_alg is not supported", className: className)
        }

        guard let supportedEncryptions = walletMetadata.authorizationEncryptionEncValuesSupported?.compactMap({$0.rawValue}) else {
            throw InvalidData(message: "authorization_encryption_enc_values_supported must be present in wallet_metadata", className: className)
        }

        guard supportedEncryptions.contains(clientEnc) else {
            throw InvalidData(message: "authorization_encrypted_response_enc is not supported", className: className)
        }
    }

    func sendAuthorizationResponse(authorizationRequest: AuthorizationRequest, authorizationResponse: AuthorizationResponse, url: String, networkManager: any NetworkManaging, producerInfo: String,
                                   recipientInfo: String) async throws -> NetworkResponse {
        let bodyParams = try authorizationResponse.toJsonEncodedMap()
        let clientMetadata = (authorizationRequest.clientMetadata)!
        let verifierPublicKey = try getJwk(clientMetadata.jwks!, clientMetadata.authorizationEncryptedResponseAlg!)

        let encryptedBody = try JWEHandler(contentEncryptionAlgorithm: clientMetadata.authorizationEncryptedResponseEnc!, keyEncryptionAlgorithm: clientMetadata.authorizationEncryptedResponseAlg!, publicKey: verifierPublicKey, producerInfo: producerInfo, recipientInfo: recipientInfo).generateEncryptedResponse(payload: bodyParams)

        let requestBody = ["response": encryptedBody]
        let response = try await networkManager.sendHTTPRequest(url: url, method: .post, bodyParams: requestBody, headers: [Header.contentType.rawValue : ContentTypes.applicationFormUrlEncoded.rawValue])

        return response
    }

    private func getJwk(_ jwks: JWKSet, _ alg: String) throws -> JWK {
        return jwks.keys.first(where: { $0.algorithm == alg && $0.publicKeyUse == .encryption})!
    }
}
