import CryptoKit
import Foundation
import JSONWebSignature

public struct AuthorizationRequest: Encodable {
    let clientId: String
    let clientIdScheme: String?
    var presentationDefinition: PresentationDefinition
    let responseType: String
    let responseMode: String?
    let nonce: String
    let state: String?
    let redirectUri: String?
    let responseUri: String?
    // As per spec, walletNonce is available if post call to request_uri is made with wallet_nonce (optional) in the request body. Library will add wallet_nonce to the request body in case of post call to request_uri.
    let walletNonce: String?
    var clientMetadata: ClientMetadata?
    static let className = String(describing: AuthorizationRequest.self)
    static var authorizationRequest: AuthorizationRequest?

    enum CodingKeys: String, CodingKey {
        case client_id
        case client_id_scheme
        case presentation_definition
        case response_type
        case response_mode
        case nonce
        case state
        case redirect_uri
        case response_uri
        case client_metadata
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(clientId, forKey: .client_id)
        try container.encodeIfPresent(clientIdScheme, forKey: .client_id_scheme)
        try container.encode(presentationDefinition, forKey: .presentation_definition)
        try container.encode(responseType, forKey: .response_type)
        try container.encode(responseMode, forKey: .response_mode)
        try container.encode(nonce, forKey: .nonce)
        try container.encode(state, forKey: .state)
        try container.encode(responseUri, forKey: .response_uri)
        try container.encode(redirectUri, forKey: .redirect_uri)
        try container.encode(clientMetadata, forKey: .client_metadata)
    }

    static func validateAndCreateAuthorizationRequest(urlEncodedAuthorizationRequest: String,
                                                      trustedVerifier: [Verifier],
                                                      walletMetadata: WalletMetadata?,
                                                      setResponseUri: @escaping (String) -> Void,
                                                      shouldValidateClient: Bool,
                                                      walletNonce: String,
                                                      networkManager: NetworkManaging
    ) async throws -> AuthorizationRequest {
        let extractedQueryParameters = try extractQueryParameters(urlEncodedAuthorizationRequest)

        return try await getAuthorizationRequest(authorizationRequestParameters: extractedQueryParameters,
                                                 trustedVerifiers: trustedVerifier,
                                                 walletMetadata: walletMetadata,
                                                 setResponseUri: setResponseUri,
                                                 shouldValidateClient: shouldValidateClient,
                                                 walletNonce: walletNonce,
                                                 networkManager: networkManager)
    }

    
    static func validateAndCreateAuthorizationRequest(
        authRequest: [String: Any],
        trustedVerifiers: [Verifier],
        walletMetadata: WalletMetadata?,
        setResponseUri: @escaping (String) -> Void,
        shouldValidateClient: Bool,
        walletNonce: String,
        networkManager: NetworkManaging
    ) async throws -> AuthorizationRequest {
        return try await getAuthorizationRequest(
            authorizationRequestParameters: authRequest,
            trustedVerifiers: trustedVerifiers,
            walletMetadata: walletMetadata,
            setResponseUri: setResponseUri,
            shouldValidateClient: shouldValidateClient,
            walletNonce: walletNonce,
            networkManager: networkManager
        )
    }

    private static func getAuthorizationRequest(authorizationRequestParameters: [String: Any],
                                                trustedVerifiers: [Verifier],
                                                walletMetadata: WalletMetadata?,
                                                setResponseUri: @escaping (String) -> Void,
                                                shouldValidateClient: Bool,
                                                walletNonce: String,
                                                networkManager: NetworkManaging
    ) async throws -> AuthorizationRequest {
        let authorizationRequestHandler = try getAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, trustedVerifiers: trustedVerifiers,
                                                                             walletMetadata: walletMetadata,
                                                                             shouldValidateClient: shouldValidateClient,
                                                                             setResponseUri: setResponseUri,
                                                                             walletNonce: walletNonce,
                                                                             networkManager: networkManager)

        try await processAndValidateAuthorizationRequestParameter(authorizationRequestHandler)

        return authorizationRequestHandler.createAuthorizationRequest()
    }

    private static func processAndValidateAuthorizationRequestParameter(_ authorizationRequestHandler: ClientIdSchemeBasedAuthorizationRequestHandler) async throws {
        try authorizationRequestHandler.validateClientId()
        try await authorizationRequestHandler.fetchAuthorizationRequest()
        try authorizationRequestHandler.setResponseUrl()
        try await authorizationRequestHandler.validateAndParseRequestFields()
    }
}
