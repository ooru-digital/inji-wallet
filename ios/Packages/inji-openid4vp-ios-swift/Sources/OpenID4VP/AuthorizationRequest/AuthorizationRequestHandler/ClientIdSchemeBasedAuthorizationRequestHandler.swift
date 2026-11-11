import Foundation


protocol AbstractMethodsForClientIdSchemeBasedAuthorizationRequestHandler {
    func process(walletMetadata: WalletMetadata) throws -> WalletMetadata
    func isSignedRequestSupported() -> Bool
    func isUnsignedRequestSupported() throws -> Bool
    func extractPublicKey(keyId: String?, algorithm: String) async throws -> PublicKeyType
    func clientIdScheme() -> String
}

class ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass  {
    var delegate: AbstractMethodsForClientIdSchemeBasedAuthorizationRequestHandler!
    var authorizationRequestParameters: [String: Any]
    let walletMetadata: WalletMetadata?
    let setResponseUri: (String) -> Void
    let walletNonce: String
    let networkManager: NetworkManaging
    var shouldValidateWithWalletMetadata: Bool = false
    var className = String(describing: ClientIdSchemeBasedAuthorizationRequestHandler.self)
    
    let errorMessageForMismatchedAcceptableType: String = "does not match any acceptable types"
    
    init(authorizationRequestParameters: [String: Any],
         walletMetadata: WalletMetadata?,
         setResponseUri: @escaping (String) -> Void,
         walletNonce: String,
         networkManager: NetworkManaging) {
        self.authorizationRequestParameters = authorizationRequestParameters
        self.setResponseUri = setResponseUri
        self.networkManager = networkManager
        self.walletMetadata = walletMetadata
        self.walletNonce = walletNonce
    }
    
    func validateClientId() throws {
        return
    }
    
    func fetchAuthorizationRequest() async throws{
        let request = authorizationRequestParameters[AuthorizationRequestFieldConstants.request.rawValue] as? String
        let requestUri = authorizationRequestParameters[AuthorizationRequestFieldConstants.requestUri.rawValue] as? String
        
        if(request != nil && requestUri != nil){
            throw InvalidData(
                message: "Both 'request' and 'request_uri' cannot be present in same authorization request",
                className: className
            )
        }
        
        if let request = request {
            try await handleRequestObjectAsValue(request)
        }
        else if let requestUri = requestUri {
            try await handleRequestObjectByReference(requestUri)
        } else {
            try handleUrlEncodedRequest()
        }
    }
    
    private func handleRequestObjectAsValue(_ request: String) async throws {
        try validate(request, fieldPath: AuthorizationRequestFieldConstants.request.rawValue, className: className)
        guard (delegate.isSignedRequestSupported()) else {
            throw InvalidData(
                message: "Signed request (via request) is not supported for given client_id_scheme - \(delegate.clientIdScheme())",
                className: className
            )
        }
        
        try await validateJWTRequest(request)
        let authorizationRequestObject =  try JWSHandler.extractDataJsonFromJws(jws: request, jwsPart: .payload)
        
        try validateAuthorizationRequestObjectAndParameters(params: self.authorizationRequestParameters, requestObject: authorizationRequestObject)
        
        self.authorizationRequestParameters = authorizationRequestObject
    }
    
    private func handleRequestObjectByReference(_ requestUri: String) async throws {
        guard (delegate.isSignedRequestSupported()) else {
            throw InvalidData(
                message: "Signed request (via request_uri) is not supported for given client_id_scheme - \(delegate.clientIdScheme())",
                className: className
            )
        }
        
        try validate(requestUri, fieldPath: AuthorizationRequestFieldConstants.requestUri.rawValue, className: className)
        guard isValidUri(requestUri)
        else {
            throw InvalidData(
                message: "request_uri \(requestUri) data is not valid",
                className: className
            )
        }
        
        let httpMethod = try requestUriMethod()
        
        var body: [String: String]? = nil
        var headers: [String: String] = [Header.accept.rawValue: ContentTypes.applicationJwt.rawValue]
        
        if httpMethod == .post {
            body = [AuthorizationRequestFieldConstants.walletNonce.rawValue: walletNonce]
            headers[Header.contentType.rawValue] = ContentTypes.applicationFormUrlEncoded.rawValue
            
            if let walletMetadata = walletMetadata {
                try isClientIdSchemeSupported(walletMetadata: walletMetadata)
                let processedWalletMetadata = try delegate.process(walletMetadata: walletMetadata)
                let extractedExpr: String = try encode(processedWalletMetadata, fieldName:  "wallet_metadata", className: className)
                body?["wallet_metadata"] = extractedExpr
                shouldValidateWithWalletMetadata = true
            }
        }
        var response:  NetworkResponse
        do{
            response = try await networkManager.sendHTTPRequest(url: requestUri, method: httpMethod, bodyParams: body, headers: headers)
            if(!response.isOK){
                throw InvalidData(message: "Error while fetching request_uri: HTTP status code \(response.statusCode) & body: \(response.body)", className: className)
            }
        }
        catch let error as NetworkRequestException {
            let isMismatchedAcceptableType = error.localizedDescription.contains(errorMessageForMismatchedAcceptableType)
            if(isMismatchedAcceptableType){
                throw InvalidData(
                    message: "Authorization Request Object must have content type 'application/oauth-authz-req+jwt'", className: className)
            }
            throw GenericFailure(message: "Network error while fetching request_uri: \(error.localizedDescription)", className: className)
        } catch {
            throw GenericFailure(message: "Error while fetching request_uri: \(error.localizedDescription)", className: className)
        }
        self.authorizationRequestParameters = try await validateRequestUriResponse(response.body, httpMethod: httpMethod)
    }
    
    private func handleUrlEncodedRequest() throws {
        guard (try delegate.isUnsignedRequestSupported()) else {
            throw InvalidData(
                message: "unsigned request is not supported for given client_id_scheme - \(delegate.clientIdScheme())",
                className: className
            )
        }
    }
    
    private func validateRequestUriResponse(_ requestUriResponse: String, httpMethod: HttpMethod) async throws -> [String: Any] {
        guard isJWS(requestUriResponse) else {
            throw InvalidData(
                message: "Authorization Request Object must be a signed JWT", className: className)
        }
        
        try await validateJWTRequest(requestUriResponse)
        
        let authorizationRequestObject =  try JWSHandler.extractDataJsonFromJws(jws: requestUriResponse, jwsPart: .payload)
        if(httpMethod == .post){
            try validateWalletNonce(authorizationRequestObject, walletNonce)
        }
        
        try validateAuthorizationRequestObjectAndParameters(params: authorizationRequestParameters, requestObject: authorizationRequestObject)
        
        return authorizationRequestObject
    }
    
    // If the key is not associated with the client or if signature validation fails, error code = invalid_request_object
    private func validateJWTRequest(_ jwtRequest: String) async throws {
        do {
            let header:  [String : Any]
            do {
                header = try JWSHandler.extractDataJsonFromJws(jws: jwtRequest, jwsPart: .header)
            } catch {
                throw VerificationFailure(
                    message: "JWS header extraction failed: \(error.localizedDescription)",
                    className: String(describing: type(of: self))
                )
            }

            
            guard let algorithm = header["alg"] as? String else {
                throw InvalidData(message: "alg is not present in JWS header", className: className, code: OpenID4VPErrorCodes.invalidRequestObject)
            }
            
            try validateAuthorizationRequestSigningAlgorithm(algorithm)
            
            let publicKey = try await delegate.extractPublicKey(keyId: header["kid"] as? String, algorithm: algorithm)
            try await JWSHandler.verify(jws: jwtRequest , publicKey: publicKey)
        } catch {
            throw InvalidData(message: "Request URI response validation failed - \(error.localizedDescription)", className: className, code: OpenID4VPErrorCodes.invalidRequestObject)
        }
    }
    
    func validateAndParseRequestFields() async throws {
        if authorizationRequestParameters[AuthorizationRequestFieldConstants.transactionData.rawValue] != nil {
            throw InvalidTransactionData(message: "Invalid Request: transaction_data is not supported in the authorization request", className: className)
        }
        let mandatoryFields = [AuthorizationRequestFieldConstants.responseType.rawValue,AuthorizationRequestFieldConstants.nonce.rawValue]
        
        for field in mandatoryFields {
            try validateAttribute(field, values: authorizationRequestParameters)
        }
        
        try validateResponseTypeSupported((authorizationRequestParameters[AuthorizationRequestFieldConstants.responseType.rawValue] as? String)!)
        
        let optionalFields = [AuthorizationRequestFieldConstants.state.rawValue, AuthorizationRequestFieldConstants.responseMode.rawValue]
        for field in optionalFields {
            if (authorizationRequestParameters[field] != nil){
                try validateAttribute(field, values: authorizationRequestParameters)
            }
        }
        
        authorizationRequestParameters = try parseAndValidateClientMetadata(authorizationRequest: authorizationRequestParameters, shouldValidateWithWalletMetadata: shouldValidateWithWalletMetadata, walletMetadata: walletMetadata)
        
        let presentationDefinitionUriSupported = !shouldValidateWithWalletMetadata || walletMetadata?.presentationDefinitionURISupported ?? true
        
        authorizationRequestParameters = try await parseAndValidatePresentationDefinition(authorizationRequestParameters, presentationDefinitionUriSupported, networkManager)
    }
    
    final func setResponseUrl() throws {
        let responseMode = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode.rawValue])
        
        try ResponseModeBasedHandlerFactory.get(responseMode: responseMode).setResponseUrl(authorizationRequestParameters: authorizationRequestParameters,setResponseUri: setResponseUri)
    }
    
    private func isClientIdSchemeSupported(walletMetadata: WalletMetadata) throws {
        let clientIdScheme = delegate.clientIdScheme()
        let walletSupportedClientIdSchemes = walletMetadata.clientIdSchemesSupported.compactMap { $0.rawValue }
        if !walletSupportedClientIdSchemes.contains(clientIdScheme) {
            throw InvalidData(
                message: "client_id_scheme is not supported by wallet",
                className: className
            )
        }
    }
    
    private func validateAuthorizationRequestSigningAlgorithm(_ algorithm: String) throws {
        if shouldValidateWithWalletMetadata, let walletMetadata = walletMetadata {
            if let supportedAlgs = walletMetadata.requestObjectSigningAlgValuesSupported?.compactMap({$0.rawValue}) ,
               !supportedAlgs.contains(algorithm) {
                throw InvalidData(
                    message: "request_object_signing_alg is not supported by wallet",
                    className: className
                )
            }
        }
    }
    
    private func requestUriMethod() throws -> HttpMethod {
        let requestUriMethod = authorizationRequestParameters[AuthorizationRequestFieldConstants.requestUriMethod.rawValue] as? String ?? HttpMethod.get.rawValue
        let httpMethod = try determineHttpMethod(method: requestUriMethod)
        return httpMethod
    }
    
    private func validateWalletNonce(_ authorizationRequestObject: [String : Any], _ walletNonce: String) throws {
        let walletNonceFromAuthorizationRequest = authorizationRequestObject[AuthorizationRequestFieldConstants.walletNonce.rawValue] as? String
        if walletNonce != walletNonceFromAuthorizationRequest {
            throw InvalidData(message: "wallet_nonce provided in the authorization request is not the same as shared by wallet", className: AuthorizationRequest.className)
        }
    }
    
    final func createAuthorizationRequest() -> AuthorizationRequest {
        return AuthorizationRequest(
            clientId: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue])!,
            clientIdScheme: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.clientIdScheme.rawValue]),
            presentationDefinition: authorizationRequestParameters[AuthorizationRequestFieldConstants.presentationDefinition.rawValue]! as! PresentationDefinition,
            responseType: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseType.rawValue])!,
            responseMode: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode.rawValue]),
            nonce: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.nonce.rawValue])!,
            state: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.state.rawValue]),
            redirectUri: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.redirectUri.rawValue]),
            responseUri: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri.rawValue]),
            walletNonce: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.walletNonce.rawValue]),
            clientMetadata: authorizationRequestParameters[AuthorizationRequestFieldConstants.clientMetadata.rawValue] as? ClientMetadata
        )
    }
}

typealias ClientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass & AbstractMethodsForClientIdSchemeBasedAuthorizationRequestHandler
