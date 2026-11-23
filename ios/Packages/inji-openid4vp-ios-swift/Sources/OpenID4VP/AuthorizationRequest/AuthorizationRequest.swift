import Foundation

public class AuthorizationRequest: Encodable {
    public let clientId: String
    public let responseType: String
    public let responseMode: String?
    public let responseUri: String?
    public let redirectUri: String?
    public let nonce: String
    public let walletNonce: String?
    public let state: String?
    
    static let className: String = String(describing: AuthorizationRequest.self)
    
    enum CodingKeys: String, CodingKey {
        case clientId = "client_id"
        case responseType = "response_type"
        case responseMode = "response_mode"
        case responseUri = "response_uri"
        case redirectUri = "redirect_uri"
        case nonce
        case walletNonce = "wallet_nonce"
        case state
    }
    
    init(
        clientId: String,
        responseType: String,
        responseMode: String?,
        responseUri: String?,
        redirectUri: String?,
        nonce: String,
        walletNonce: String?,
        state: String?
    ) {
        self.clientId = clientId
        self.responseType = responseType
        self.responseMode = responseMode
        self.responseUri = responseUri
        self.redirectUri = redirectUri
        self.nonce = nonce
        self.walletNonce = walletNonce
        self.state = state
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(clientId, forKey: .clientId)
        try container.encode(responseType, forKey: .responseType)
        try container.encodeIfPresent(responseMode, forKey: .responseMode)
        try container.encodeIfPresent(responseUri, forKey: .responseUri)
        try container.encodeIfPresent(redirectUri, forKey: .redirectUri)
        try container.encode(nonce, forKey: .nonce)
        try container.encodeIfPresent(walletNonce, forKey: .walletNonce)
        try container.encodeIfPresent(state, forKey: .state)
    }
    
    
    static func validateAndCreateAuthorizationRequest(urlEncodedAuthorizationRequest: String,
                                                      walletConfig: WalletConfig,
                                                      setResponseDispatchInfo: @escaping (ResponseDispatchInfo) -> Void,
                                                      walletNonce: String,
                                                      networkManager: NetworkManaging
    ) async throws -> AuthorizationRequest {
        let extractedQueryParameters = try extractQueryParameters(urlEncodedAuthorizationRequest)
        
        return try await getAuthorizationRequest(authorizationRequestParameters: extractedQueryParameters,
                                                 walletConfig: walletConfig,
                                                 setResponseDispatchInfo: setResponseDispatchInfo,
                                                 walletNonce: walletNonce,
                                                 networkManager: networkManager)
    }
    
    
    static func validateAndCreateAuthorizationRequest(
        authRequest: [String: Any],
        walletConfig: WalletConfig,
        setResponseDispatchInfo: @escaping (ResponseDispatchInfo) -> Void,
        walletNonce: String,
        networkManager: NetworkManaging
    ) async throws -> AuthorizationRequest {
        return try await getAuthorizationRequest(
            authorizationRequestParameters: authRequest,
            walletConfig: walletConfig,
            setResponseDispatchInfo: setResponseDispatchInfo,
            walletNonce: walletNonce,
            networkManager: networkManager
        )
    }
    
    private static func getAuthorizationRequest(authorizationRequestParameters: [String: Any],
                                                walletConfig: WalletConfig,
                                                setResponseDispatchInfo: @escaping (ResponseDispatchInfo) -> Void,
                                                walletNonce: String,
                                                networkManager: NetworkManaging
    ) async throws -> AuthorizationRequest {
        let authorizationRequestHandler = try getAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters,
                                                                               walletConfig: walletConfig,
                                                                               setResponseDispatchInfo: setResponseDispatchInfo,
                                                                               walletNonce: walletNonce,
                                                                               networkManager: networkManager)
        
        return try await authorizationRequestHandler.handle()
    }
}

public final class AuthorizationPresentationExchangeRequest: AuthorizationRequest {
    public let presentationDefinition: PresentationDefinition
    public let clientMetadata: ClientMetadataDraft23?
    
    private enum SubCodingKeys: String, CodingKey {
        case presentationDefinition = "presentation_definition"
        case clientMetadata = "client_metadata"
    }
    
    init(
        clientId: String,
        responseType: String,
        responseMode: String?,
        responseUri: String?,
        redirectUri: String?,
        nonce: String,
        walletNonce: String?,
        state: String?,
        presentationDefinition: PresentationDefinition,
        clientMetadata: ClientMetadataDraft23?
    ) {
        self.presentationDefinition = presentationDefinition
        self.clientMetadata = clientMetadata
        super.init(
            clientId: clientId,
            responseType: responseType,
            responseMode: responseMode,
            responseUri: responseUri,
            redirectUri: redirectUri,
            nonce: nonce,
            walletNonce: walletNonce,
            state: state
        )
    }
    
    public override func encode(to encoder: Encoder) throws {
        try super.encode(to: encoder)
        var container = encoder.container(keyedBy: SubCodingKeys.self)
        try container.encode(presentationDefinition, forKey: .presentationDefinition)
        try container.encodeIfPresent(clientMetadata, forKey: .clientMetadata)
    }
}

public final class AuthorizationDcqlRequest: AuthorizationRequest {
    public let dcqlQuery: DCQLQuery
    public let clientMetadata: ClientMetadata?
    
    private enum SubCodingKeys: String, CodingKey {
        case dcqlQuery = "dcql_query"
        case clientMetadata = "client_metadata"
    }
    
    init(
        clientId: String,
        responseType: String,
        responseMode: String?,
        responseUri: String?,
        redirectUri: String?,
        nonce: String,
        walletNonce: String?,
        state: String?,
        dcqlQuery: DCQLQuery,
        clientMetadata: ClientMetadata?
    ) {
        self.dcqlQuery = dcqlQuery
        self.clientMetadata = clientMetadata
        super.init(
            clientId: clientId,
            responseType: responseType,
            responseMode: responseMode,
            responseUri: responseUri,
            redirectUri: redirectUri,
            nonce: nonce,
            walletNonce: walletNonce,
            state: state
        )
    }
    
    public override func encode(to encoder: Encoder) throws {
        try super.encode(to: encoder)
        var container = encoder.container(keyedBy: SubCodingKeys.self)
        try container.encode(dcqlQuery, forKey: .dcqlQuery)
        try container.encodeIfPresent(clientMetadata, forKey: .clientMetadata)
    }
}
