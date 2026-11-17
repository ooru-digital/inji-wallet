import Foundation

public class OpenID4VP {
    public let traceabilityId: String
    let networkManager: NetworkManaging
    var authorizationRequest: AuthorizationRequest!
    private var responseUri: String?
    private var authorizationResponseHandler: AuthorizationResponseHandler
    private let walletMetadata: WalletMetadata?
    private var walletNonce: String = ""
    private let nonceProvider: NonceProvider

    private let className = String(describing: type(of: OpenID4VP.self))

    public init(traceabilityId: String, walletMetadata: WalletMetadata? = nil) {
        self.traceabilityId = traceabilityId
        networkManager = NetworkManager.shared
        authorizationResponseHandler = AuthorizationResponseHandler(networkManager: networkManager)
        self.walletMetadata = walletMetadata
        OpenID4VPException.setTraceabilityId(className: String(describing: type(of: self)), traceabilityId: traceabilityId)
        nonceProvider = NonceProvider()
        walletNonce = nonceProvider.generateNonce()
    }

    internal init(traceabilityId: String, networkManager: NetworkManaging? = nil, walletMetadata: WalletMetadata? = nil, nonceProvider: NonceProvider = NonceProvider(), authorizationResponseHandler: AuthorizationResponseHandler? = nil) {
        self.networkManager = networkManager ?? NetworkManager.shared
        self.nonceProvider = nonceProvider

        self.traceabilityId = traceabilityId
        self.authorizationResponseHandler = authorizationResponseHandler ?? AuthorizationResponseHandler(networkManager: networkManager ?? NetworkManager.shared)
        self.walletMetadata = walletMetadata
        OpenID4VPException.setTraceabilityId(className: String(describing: type(of: self)), traceabilityId: traceabilityId)
    }

    public func setResponseUri(_ responseUri: String) {
        self.responseUri = responseUri
    }

    public func authenticateVerifier(
        urlEncodedAuthorizationRequest: String,
        trustedVerifiers: [Verifier],
        shouldValidateClient: Bool = true
    ) async throws -> AuthorizationRequest {
        // Create a new wallet nonce for each request
        walletNonce = nonceProvider.generateNonce()
        authorizationRequest = nil
        responseUri = nil
        authorizationResponseHandler = AuthorizationResponseHandler(networkManager: networkManager)

        do {
            authorizationRequest = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest: urlEncodedAuthorizationRequest,
                trustedVerifier: trustedVerifiers,
                walletMetadata: walletMetadata,
                setResponseUri: setResponseUri,
                shouldValidateClient: shouldValidateClient,
                walletNonce: walletNonce,
                networkManager: networkManager
            )
            return authorizationRequest
        } catch let exception {
            await safeSendError(error: exception)
            throw exception
        }
    }

    public func authenticateVerifier(
        authorizationRequest: [String: Any],
        trustedVerifiers: [Verifier],
        shouldValidateClient: Bool = true
    ) async throws -> AuthorizationRequest {
        do {
            walletNonce = nonceProvider.generateNonce()
            self.authorizationRequest = nil
            responseUri = nil
            authorizationResponseHandler = AuthorizationResponseHandler(networkManager: networkManager)

            let validatedAuthorizationRequest = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
                authRequest: authorizationRequest,
                trustedVerifiers: trustedVerifiers,
                walletMetadata: walletMetadata,
                setResponseUri: setResponseUri,
                shouldValidateClient: shouldValidateClient,
                walletNonce: walletNonce,
                networkManager: networkManager
            )

            self.authorizationRequest = validatedAuthorizationRequest
            return validatedAuthorizationRequest
        } catch let error as OpenID4VPException {
            await safeSendError(error: error)
            throw error
        }
    }

    public func constructUnsignedVPToken(
        verifiableCredentials: [String: [FormatType: [AnyCodable]]],
        holderId: String? = nil,
        signatureSuite: String? = nil
    ) async throws -> [FormatType: UnsignedVPToken] {
        do {
            return try await authorizationResponseHandler.constructUnsignedVPToken(
                credentialsMap: verifiableCredentials,
                authorizationRequest: authorizationRequest,
                responseUri: responseUri!,
                holderId: holderId,
                signatureSuite: signatureSuite,
                walletNonce: walletNonce
            )
        } catch {
            await safeSendError(error: error)
            throw error
        }
    }

    public func constructUnsignedVPTokenV2(
        verifiableCredentials: [String: [FormatType: [AnyCodable]]],
        holderId: String? = nil,
        signatureSuite: String? = nil
    ) async throws -> [UnsignedVPTokenV2] {
        do {
            return try await authorizationResponseHandler.constructUnsignedVPTokenV2(
                credentialsMap: verifiableCredentials,
                authorizationRequest: authorizationRequest,
                responseUri: responseUri!,
                holderId: holderId,
                signatureSuite: signatureSuite,
                walletNonce: walletNonce
            )
        } catch {
            await safeSendError(error: error)
            throw error
        }
    }

    public func constructVPResponse(vpTokenSigningResults: [FormatType: VPTokenSigningResult]) -> [String: Any] {
        do {
            return try authorizationResponseHandler.constructAuthorizationResponse(
                authorizationRequest: authorizationRequest,
                vpTokenSigningResults: vpTokenSigningResults
            )
        } catch let exception {
            return constructErrorInfo(exception: exception)
        }
    }

    public func constructVPResponseV2(vpTokenSigningResults: [VPTokenSigningResultV2]) -> [String: Any] {
        do {
            return try authorizationResponseHandler.constructVPResponseV2(
                signingResults: vpTokenSigningResults, authorizationRequest: authorizationRequest
            )
        } catch let exception {
            return constructErrorInfo(exception: exception)
        }
    }

    public func constructErrorInfo(exception: Error) -> [String: Any] {
        return authorizationResponseHandler.constructAuthorizationErrorResponse(
            authorizationRequest: authorizationRequest,
            exception: exception,
            walletNonce: walletNonce
        )
    }

    public func sendVPResponseToVerifier(
        vpTokenSigningResults: [FormatType: VPTokenSigningResult]
    ) async throws -> VerifierResponse {
        do {
            return try await authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest: authorizationRequest,
                vpTokenSigningResults: vpTokenSigningResults,
                responseUri: responseUri!
            )
        } catch {
            await safeSendError(error: error)
            throw error
        }
    }

    public func sendErrorInfoToVerifier(error: Error) async throws -> VerifierResponse {
        return try await authorizationResponseHandler.sendAuthorizationError(responseUri: responseUri, authorizationRequest: authorizationRequest, error: error)
    }

    private func safeSendError(error: Error) async {
        do {
            let verifierResponse = try await sendErrorInfoToVerifier(error: error)
            (error as? OpenID4VPException)?.setVerifierResponse(verifierResponse)
        } catch {
            OpenID4VPException.error(error, className: className)
        }
    }

    @available(*, deprecated, renamed: "sendVPResponseToVerifier", message: "This method does not support listening to the status code sent from the verifier. Replace with sendVPResponseToVerifier(vpTokenSigningResults)")
    public func shareVerifiablePresentation(
        vpTokenSigningResults: [FormatType: VPTokenSigningResult]
    ) async throws -> String {
        return try await sendVPResponseToVerifier(vpTokenSigningResults: vpTokenSigningResults).body()
    }

    @available(*, deprecated, message: "Use authenticateVerifier without WalletMetadata instead. Reason: WalletMetadata is moved to OpenID4VP constructor instead of being passed as parameter")
    public func authenticateVerifier(
        urlEncodedAuthorizationRequest: String,
        trustedVerifierJSON: [Verifier],
        shouldValidateClient: Bool = false,
        walletMetadata: WalletMetadata? = nil
    ) async throws -> AuthorizationRequest {
        // Create a new wallet nonce for each request
        walletNonce = nonceProvider.generateNonce()
        do {
            authorizationRequest = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest: urlEncodedAuthorizationRequest,
                trustedVerifier: trustedVerifierJSON,
                walletMetadata: walletMetadata,
                setResponseUri: setResponseUri,
                shouldValidateClient: shouldValidateClient,
                walletNonce: walletNonce,
                networkManager: networkManager
            )
            return authorizationRequest
        } catch let exception {
            await sendErrorToVerifier(error: exception)
            throw exception
        }
    }

    @available(*, deprecated, message: "Use authenticateVerifier with trustedVerifiers parameter instead. Reason: Parameter trustedVerifierJSON has been renamed to trustedVerifiers")
    public func authenticateVerifier(
        urlEncodedAuthorizationRequest: String,
        trustedVerifierJSON: [Verifier],
        shouldValidateClient: Bool = true
    ) async throws -> AuthorizationRequest {
        // Create a new wallet nonce for each request
        walletNonce = nonceProvider.generateNonce()
        authorizationRequest = nil
        responseUri = nil
        authorizationResponseHandler = AuthorizationResponseHandler(networkManager: networkManager)

        do {
            authorizationRequest = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest: urlEncodedAuthorizationRequest,
                trustedVerifier: trustedVerifierJSON,
                walletMetadata: walletMetadata,
                setResponseUri: setResponseUri,
                shouldValidateClient: shouldValidateClient,
                walletNonce: walletNonce,
                networkManager: networkManager
            )
            return authorizationRequest
        } catch let exception {
            await safeSendError(error: exception)
            throw exception
        }
    }

    @available(*, deprecated, message: "Use constructUnsignedVPToken with [String: [FormatType: [Any]]] instead")
    public func constructVerifiablePresentationToken(
        verifiableCredentials: [String: [String]]
    ) async throws -> String {
        do {
            return try await authorizationResponseHandler.constructUnsignedVPTokenV1(
                verifiableCredentials: verifiableCredentials,
                authorizationRequest: authorizationRequest,
                responseUri: responseUri!,
                walletNonce: walletNonce
            )
        } catch {
            await sendErrorToVerifier(error: error)
            throw error
        }
    }

    @available(*, deprecated, message: "Supports only direct POST response mode for LDP VC. Use shareVerifiablePresentation with VPTokenSigningResults instead")
    public func shareVerifiablePresentation(
        vpResponseMetadata: VPResponseMetadata
    ) async throws -> String {
        do {
            return try await authorizationResponseHandler.shareVPV1(
                vpResponseMetadata: vpResponseMetadata,
                nonce: authorizationRequest.nonce,
                state: authorizationRequest.state,
                responseUri: responseUri!, presentationDefinitionId: authorizationRequest.presentationDefinition.id
            )
        } catch {
            await sendErrorToVerifier(error: error)
            throw error
        }
    }

    @available(*, deprecated, renamed: "sendErrorInfoToVerifier", message: "sendErrorToVerifier is now changed to sendErrorInfoToVerifier. Reason: This does not support listening the response from the verifier")
    public func sendErrorToVerifier(error: Error) async {
        await safeSendError(error: error)
    }
}
