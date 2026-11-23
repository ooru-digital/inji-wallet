import Foundation
import JSONWebKey

struct DirectPostResponseModeHandler : ResponseModeBasedHandler {
    static let className = String(describing: DirectPostResponseModeHandler.self)
    
    func validate(clientMetadata: ClientMetadataDraft23?,
                  walletConfig: WalletConfig,
                  shouldValidateWithWalletMetadata: Bool) throws -> ResponseEncryptionSpecification? {
        if (clientMetadata?.authorizationEncryptedResponseEnc != nil || clientMetadata?.authorizationEncryptedResponseAlg != nil) {
            throw InvalidData(message: "authorization_encrypted_response_enc or authorization_encrypted_response_alg SHOULD not be present for response mode 'direct_post'", className: Self.className)
        }
        
        return nil
    }
    
    func validate(clientMetadata: ClientMetadata?,
                  walletConfig: WalletConfig,
                  shouldValidateWithWalletMetadata: Bool) throws -> ResponseEncryptionSpecification?{
        if clientMetadata?.encryptedResponseEncValuesSupported != nil {
            throw InvalidData(message: "encrypted_response_enc_values_supported SHOULD not be present for response mode 'direct_post'", className: Self.className)
        }
        
        return nil
    }

    func getVerifierPublicKeyForEncryption(
        authorizationRequest: AuthorizationRequest,
        walletConfig: WalletConfig
    ) throws -> JWK? {
        return nil
    }

    func getAuthorizationErrorResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationErrorResponse,
        authorizationRequest: AuthorizationRequest?
    ) throws -> [String: String] {
        return authorizationResponse.toJsonEncodedMap()
    }

    func sendAuthorizationError(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationErrorResponse,
        authorizationRequest: AuthorizationRequest?,
        networkManager: NetworkManaging
    ) async throws -> NetworkResponse {
        let requestBody = try getAuthorizationErrorResponse(dispatchInfo: dispatchInfo, authorizationResponse: authorizationResponse, authorizationRequest: authorizationRequest)
        return try await networkManager.sendHTTPRequest(
            url: dispatchInfo.responseUrl,
            method: .post,
            bodyParams: requestBody,
            headers: [Header.contentType.rawValue: ContentTypes.applicationFormUrlEncoded.rawValue]
        )
    }

    func getAuthorizationResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationResponse,
        authorizationRequest: AuthorizationRequest
    ) throws -> [String: String] {
        return try authorizationResponse.toJsonEncodedMap()
    }

    func sendAuthorizationResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationResponse,
        authorizationRequest: AuthorizationRequest,
        networkManager: NetworkManaging
    ) async throws -> NetworkResponse {
        let requestBody = try getAuthorizationResponse(dispatchInfo: dispatchInfo, authorizationResponse: authorizationResponse, authorizationRequest: authorizationRequest)
        return try await networkManager.sendHTTPRequest(
            url: dispatchInfo.responseUrl,
            method: .post,
            bodyParams: requestBody,
            headers: [Header.contentType.rawValue: ContentTypes.applicationFormUrlEncoded.rawValue]
        )
    }
}
