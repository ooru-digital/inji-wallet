
import Foundation

public class AuthorizationResponseHandler {
    private let networkManager: NetworkManaging
    private var walletNonce: String = ""
    private var signatureSuite: String = SignatureAlgorithm.ed25519Signature2020.rawValue
    private var formatToCredentialInputDescriptorMapping: [FormatType: [CredentialInputDescriptorMapping]] = [:]
    private var unsignedVPTokenResults: [FormatType: (vpTokenSigningPayload: VPTokenSigningPayload?, unsignedVPToken: UnsignedVPToken)] = [:]

    public static let className = String(describing: AuthorizationResponseHandler.self)

    public init(networkManager: NetworkManaging) {
        self.networkManager = networkManager
    }

    func constructUnsignedVPToken(credentialsMap: [String: [FormatType: [AnyCodable]]],
                                  authorizationRequest: AuthorizationRequest,
                                  responseUri: String,
                                  holderId: String?,
                                  signatureSuite: String?,
                                  walletNonce: String
    ) async throws -> [FormatType: UnsignedVPToken] {
        let hasLdpVc = credentialsMap.values.contains { formatMap in
            formatMap.keys.contains(.ldp_vc)
        }
        if hasLdpVc {
            // In case of ldp_vc, the Verifiable presentation created will have the info of holder and signature suite
            if isNullOrEmpty(holderId) {
                throw InvalidData(
                    message: "Holder ID cannot be null or empty for LDP VC format",
                    className: AuthorizationResponseHandler.className
                )
            }
            if isNullOrEmpty(signatureSuite) {
                throw InvalidData(
                    message: "Signature Suite cannot be null or empty for LDP VC format",
                    className: AuthorizationResponseHandler.className
                )
            }
        }
        self.signatureSuite = signatureSuite ?? self.signatureSuite

        return try await createUnsignedVPToken(credentialsMap: credentialsMap, authorizationRequest: authorizationRequest, responseUri: responseUri, walletNonce: walletNonce, holderId: holderId, signatureSuite: signatureSuite)
    }

    private func createUnsignedVPToken(
        credentialsMap: [String: [FormatType: [AnyCodable]]],
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        walletNonce: String,
        holderId: String?,
        signatureSuite: String?
    ) async throws -> [FormatType: UnsignedVPToken] {
        if credentialsMap.isEmpty {
            throw InvalidData(
                message: "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
                className: AuthorizationResponseHandler.className
            )
        }

        self.walletNonce = walletNonce

        unsignedVPTokenResults = try await createUnsignedVPTokens(
            credentialsMap: credentialsMap,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite
        )

        let unsignedVPTokensExtracted: [FormatType: UnsignedVPToken] = unsignedVPTokenResults.mapValues { innerMap in
            innerMap.1
        }

        return unsignedVPTokensExtracted
    }
    
    func constructUnsignedVPTokenV2(
        credentialsMap: [String: [FormatType: [AnyCodable]]],
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        holderId: String?,
        signatureSuite: String?,
        walletNonce: String
    ) async throws -> [UnsignedVPTokenV2] {

        _ = try await constructUnsignedVPToken(
            credentialsMap: credentialsMap,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )

        return try await flattenUnsignedVPTokens(
            unsignedVPTokenResults: unsignedVPTokenResults,
            formatMappings: formatToCredentialInputDescriptorMapping,
            holderId: holderId,
            signatureSuite: signatureSuite
        )
    }

    func constructVPResponseV2(
        signingResults: [VPTokenSigningResultV2],
        authorizationRequest: AuthorizationRequest
    ) throws -> [String: String] {

        let reconstructed = try constructSigningResults(
            unsignedVPTokenResults: unsignedVPTokenResults,
            formatMappings: formatToCredentialInputDescriptorMapping,
            signingResults: signingResults,
            signatureSuite: self.signatureSuite
        )

        return try constructAuthorizationResponse(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: reconstructed
        )
    }


    func sendAuthorizationError(responseUri: String?, authorizationRequest: AuthorizationRequest?, error: Error) async throws -> VerifierResponse {
        guard let responseUri = responseUri, !responseUri.isEmpty else {
            throw ErrorDispatchFailure(message: "Response URI is not set. Cannot send error to verifier.", className: Self.className)
        }

        var errorPayload: [String: String] = [:]

        let resolvedError: OpenID4VPException
        if let openidError = error as? OpenID4VPException {
            resolvedError = openidError
        } else {
            resolvedError = GenericFailure(
                message: "\(error)",
                className: String(describing: OpenID4VP.self)
            )
        }

        errorPayload.merge(resolvedError.toErrorResponse()) { _, new in new }

        if let state = authorizationRequest?.state, !state.isEmpty {
            errorPayload["state"] = state
        }

        do {
            let dispatchResult = try await networkManager.sendHTTPRequest(
                url: responseUri,
                method: .post,
                bodyParams: errorPayload,
                headers: [Header.contentType.rawValue: ContentTypes.applicationFormUrlEncoded.rawValue]
            )
            let verifierResponse: VerifierResponse = toVerifierResponse(dispatchResult)

            (error as? OpenID4VPException)?.setVerifierResponse(verifierResponse)
            return verifierResponse
        } catch {
            throw ErrorDispatchFailure(
                message: "Failed to send error to verifier: \(error)",
                className: Self.className
            )
        }
    }

    func constructAndSendAuthorizationResponseToVerifier(
        authorizationRequest: AuthorizationRequest,
        vpTokenSigningResults: [FormatType: VPTokenSigningResult],
        responseUri: String
    ) async throws -> VerifierResponse {
        let authorizationResponse = try createAuthorizationResponse(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults
        )

        let response: NetworkResponse = try await sendAuthorizationResponse(
            authorizationRequest: authorizationRequest,
            authorizationResponse: authorizationResponse,
            responseUri: responseUri
        )
        return toVerifierResponse(response)
    }

    func constructAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        vpTokenSigningResults: [FormatType: VPTokenSigningResult]
    ) throws -> [String: String] {
        let authorizationResponse = try createAuthorizationResponse(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults
        )

        return try ResponseModeBasedHandlerFactory
            .get(responseMode: authorizationRequest.responseMode)
            .getAuthorizationResponse(
                authorizationRequest: authorizationRequest,
                authorizationResponse: authorizationResponse,
                walletNonce: walletNonce
            )
    }

    func constructAuthorizationErrorResponse(
        authorizationRequest: AuthorizationRequest?,
        exception: Error,
        walletNonce: String
    ) -> [String: Any] {
        self.walletNonce = walletNonce
        
        let authorizationResponse: AuthorizationErrorResponse

        if let openIDException = exception as? OpenID4VPException {
            authorizationResponse = openIDException.toAuthorizationErrorResponse(state: authorizationRequest?.state)
        } else {
            let genericException = GenericFailure(
                message: exception.localizedDescription.isEmpty ? "Unknown internal error" : exception.localizedDescription,
                className: String(describing: OpenID4VP.self)
            )
            authorizationResponse = genericException.toAuthorizationErrorResponse(state: authorizationRequest?.state)
        }
 
        do {
            return try ResponseModeBasedHandlerFactory
                .get(responseMode: authorizationRequest?.responseMode ?? ResponseMode.directPost.rawValue)
                .getAuthorizationErrorResponse(
                    authorizationRequest: authorizationRequest,
                    authorizationResponse: authorizationResponse,
                    walletNonce: self.walletNonce
                )
        } catch {
            OpenID4VPException.error(error, className: Self.className)
            return [
                "error": "invalid_request",
                "error_description": "Failed to construct error response: \(error.localizedDescription)"
            ]
        }
    }

    private func createAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        vpTokenSigningResults: [FormatType: VPTokenSigningResult]
    ) throws -> AuthorizationResponse {
        switch authorizationRequest.responseType {
        case ResponseType.vp_token.rawValue:
            let (vpToken, presentationSubmission) = try createVPTokenAndPresentationSubmission(
                vpTokenSigningResults: vpTokenSigningResults,
                authorizationRequest: authorizationRequest,
                unsignedVPTokenResults: unsignedVPTokenResults,
                formatToCredentialInputDescriptorMapping: formatToCredentialInputDescriptorMapping
            )
            return AuthorizationResponse(
                vpToken: vpToken,
                presentationSubmission: presentationSubmission,
                state: authorizationRequest.state
            )
        default:
            throw InvalidData(
                message: "Provided response_type - \(authorizationRequest.responseType) is not supported",
                className: AuthorizationResponseHandler.className
            )
        }
    }

    private func createVPTokenAndPresentationSubmission(
        vpTokenSigningResults: [FormatType: VPTokenSigningResult],
        authorizationRequest: AuthorizationRequest,
        unsignedVPTokenResults: [FormatType: (VPTokenSigningPayload?, UnsignedVPToken)],
        formatToCredentialInputDescriptorMapping: [FormatType: [CredentialInputDescriptorMapping]]
    ) throws -> (VPTokenType, PresentationSubmission) {
        if Set(unsignedVPTokenResults.keys) != Set(vpTokenSigningResults.keys) {
            throw InvalidData(
                message: "VPTokenSigningResult not provided for the required formats",
                className: Self.className
            )
        }

        var finalVpTokens: [VPToken] = []
        var finalDescriptorMappings: [DescriptorMap] = []
        var rootIndex = 0

        for (credentialFormat, credentialInputDescriptorMappings) in formatToCredentialInputDescriptorMapping {
            guard let vpTokenSigningResult = vpTokenSigningResults[credentialFormat] else {
                throw InvalidData(
                    message: "unable to find the related credential format - \(credentialFormat) in the vpTokenSigningResults map",
                    className: Self.className
                )
            }
            guard let unsignedVPTokenResult = unsignedVPTokenResults[credentialFormat] else {
                throw InvalidData(
                    message: "unable to find the related credential format - \(credentialFormat) in the unsignedVPTokenResults map",
                    className: Self.className
                )
            }

            let vpTokenBuilder = try VPTokenFactory.getVPTokenBuilder(credentialFormat: credentialFormat)

            let (vpTokens, descriptorMaps, nextRootIndex) = try vpTokenBuilder.build(
                credentialInputDescriptorMappings: credentialInputDescriptorMappings,
                unsignedVPTokenResult: unsignedVPTokenResult,
                vpTokenSigningResult: vpTokenSigningResult,
                rootIndex: rootIndex
            )
            finalVpTokens.append(contentsOf: vpTokens)
            finalDescriptorMappings.append(contentsOf: descriptorMaps)
            rootIndex = nextRootIndex
        }

        let vpToken: VPTokenType = (finalVpTokens.count == 1)
            ? .vpTokenElement(finalVpTokens[0])
            : .vpTokenArray(finalVpTokens)

        sanitizeDescriptorMap(&finalDescriptorMappings, isSingleVPToken: finalVpTokens.count == 1)
        let presentationSubmission = PresentationSubmission(
            definitionId: authorizationRequest.presentationDefinition.id,
            descriptorMap: finalDescriptorMappings
        )

        return (vpToken, presentationSubmission)
    }

    private func sanitizeDescriptorMap(
        _ descriptorMaps: inout [DescriptorMap],
        isSingleVPToken: Bool
    ) {
        // In case of only single VP, presentation_submission -> path = $, path_nest = $.<credentialPathIdentifier - internalPath>[n]
        // and in case of multiple VPs, presentation_submission -> path = $[i], path_nest = $[i].<credentialPathIdentifier - internalPath>[n]
        if isSingleVPToken {
            for i in 0 ..< descriptorMaps.count {
                let updatedRootPath = descriptorMaps[i].path.replacingOccurrences(of: #"\[\d+]"#, with: "", options: .regularExpression)
                descriptorMaps[i] = DescriptorMap(
                    id: descriptorMaps[i].id,
                    format: descriptorMaps[i].format,
                    path: updatedRootPath,
                    pathNested: descriptorMaps[i].pathNested
                )
            }
        }
    }

    private func sendAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        responseUri: String
    ) async throws -> NetworkResponse {
        return try await ResponseModeBasedHandlerFactory.get(responseMode: authorizationRequest.responseMode)
            .sendAuthorizationResponse(
                authorizationRequest: authorizationRequest,
                authorizationResponse: authorizationResponse,
                url: responseUri,
                networkManager: networkManager,
                producerInfo: walletNonce,
                recipientInfo: authorizationRequest.nonce
            )
    }

    private func createUnsignedVPTokens(
        credentialsMap: [String: [FormatType: [AnyCodable]]],
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        holderId: String?,
        signatureSuite: String?
    ) async throws -> [FormatType: (VPTokenSigningPayload?, UnsignedVPToken)] {
        createFormatToCredentialInputDescriptorMapping(matchingCredentials: credentialsMap)

        var unsignedVPTokenResults: [FormatType: (VPTokenSigningPayload?, UnsignedVPToken)] = [:]

        for format in formatToCredentialInputDescriptorMapping.keys {
            guard var credentialsArray = formatToCredentialInputDescriptorMapping[format] else {
                continue
            }
            switch format {
            case .ldp_vc:
                let token = try await UnsignedLdpVPTokenBuilder(
                    id: UUIDGenerator.generateUUID(),
                    holder: holderId ?? "",
                    challenge: authorizationRequest.nonce,
                    domain: authorizationRequest.clientId,
                    signatureSuite: signatureSuite ?? "Ed25519Signature2020"
                ).build(
                    credentialInputDescriptorMappings: &credentialsArray
                )
                unsignedVPTokenResults[format] = token
            case .mso_mdoc:
                let token = try await UnsignedMdocVPTokenBuilder(
                    clientId: authorizationRequest.clientId,
                    responseUri: responseUri,
                    verifierNonce: authorizationRequest.nonce,
                    mdocGeneratedNonce: walletNonce
                ).build(
                    credentialInputDescriptorMappings: &credentialsArray
                )
                unsignedVPTokenResults[format] = token

            case .dc_sd_jwt, .vc_sd_jwt:
                let token = try await UnsignedSdJwtVPTokenBuilder(
                    clientId: authorizationRequest.clientId, authorizationRequestNonce: authorizationRequest.nonce
                ).build(
                    credentialInputDescriptorMappings: &credentialsArray
                )
                unsignedVPTokenResults[format] = token
            }
            formatToCredentialInputDescriptorMapping[format] = credentialsArray
        }

        return unsignedVPTokenResults
    }

    @available(*, deprecated, message: "This method supports constructing VP token for LDP VC without canonicalization of the data sent for signing. use constructUnsignedVPToken instead")
    func constructUnsignedVPTokenV1(
        verifiableCredentials: [String: [String]],
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        walletNonce: String
    ) async throws -> String {
        let transformedCredentials: [String: [FormatType: [AnyCodable]]] = verifiableCredentials.mapValues { credentials in
            let wrapped = credentials.map { AnyCodable($0) }
            return [.ldp_vc: wrapped]
        }

        _ = try await createUnsignedVPToken(
            credentialsMap: transformedCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            walletNonce: walletNonce,
            holderId: nil,
            signatureSuite: nil
        )

        var ldpToken = unsignedVPTokenResults[.ldp_vc]?.0 as? LdpVPToken

        ldpToken?.proof = nil

        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            encoder.keyEncodingStrategy = .useDefaultKeys
            let encodedData = try encoder.encode(ldpToken)

            guard let jsonString = String(data: encodedData, encoding: .utf8) else {
                throw JsonEncodingFailed(
                    fieldPath: ["unsignedLdpVPToken"],
                    errorMessage: "Failed to convert encoded data to UTF-8 string",
                    className: "AuthorizationResponseHandler"
                )
            }

            return jsonString
        } catch {
            throw JsonEncodingFailed(
                fieldPath: ["unsignedLdpVPToken"],
                errorMessage: error.localizedDescription,
                className: "AuthorizationResponseHandler"
            )
        }
    }

    @available(*, deprecated, message: "Use shareVP instead")
    func shareVPV1(
        vpResponseMetadata: VPResponseMetadata,
        nonce: String,
        state: String?,
        responseUri: String,
        presentationDefinitionId: String
    ) async throws -> String {
        do {
            try vpResponseMetadata.validate()
            var pathIndex = 0

            // Flatten credentials
            let flattenedCredentials: [String: [Any]] = formatToCredentialInputDescriptorMapping[.ldp_vc]?.reduce(into: [String: [Any]]()) { partialResult, mapping in
                partialResult[mapping.inputDescriptorId, default: []].append(mapping.credential.value)
            } ?? [:]

            // Build descriptor map
            var descriptorMap: [DescriptorMap] = []
            for (inputDescriptorId, vcs) in flattenedCredentials {
                for _ in vcs {
                    descriptorMap.append(
                        DescriptorMap(
                            id: inputDescriptorId,
                            format: VPFormatType.ldp_vp,
                            path: "$.verifiableCredential[\(pathIndex)]",
                            pathNested: nil
                        )
                    )
                    pathIndex += 1
                }
            }

            let presentationSubmission = PresentationSubmission(
                definitionId: presentationDefinitionId,
                descriptorMap: descriptorMap
            )

            guard let unsignedLdpVPTokenMap = unsignedVPTokenResults[.ldp_vc],
                  var unsignedLdpVPToken = unsignedLdpVPTokenMap.0 as? LdpVPToken else {
                throw NSError(domain: "Missing unsignedLdpVPToken", code: 0)
            }

            // Construct final VP Token
            unsignedLdpVPToken.proof?.verificationMethod = vpResponseMetadata.publicKey
            unsignedLdpVPToken.proof?.proofValue = vpResponseMetadata.jws

            return try await constructHttpRequestBody(
                vpToken: unsignedLdpVPToken,
                presentationSubmission: presentationSubmission,
                responseUri: responseUri,
                state: state
            )

        } catch {
            throw error
        }
    }

    @available(*, deprecated, message: "This is a private method used by shareVPV1 and should not be used directly.")
    private func constructHttpRequestBody(
        vpToken: VPToken,
        presentationSubmission: PresentationSubmission,
        responseUri: String,
        state: String?
    ) async throws -> String {
        let encodedVPToken: String
        let encodedPresentationSubmission: String

        do {
            let jsonData = try JSONEncoder().encode(vpToken)
            encodedVPToken = String(data: jsonData, encoding: .utf8) ?? ""
        } catch {
            throw JsonEncodingFailed(
                fieldPath: ["vp_token"],
                errorMessage: error.localizedDescription,
                className: "AuthorizationResponseHandler"
            )
        }

        do {
            let jsonData = try JSONEncoder().encode(presentationSubmission)
            encodedPresentationSubmission = String(data: jsonData, encoding: .utf8) ?? ""
        } catch {
            throw JsonEncodingFailed(
                fieldPath: ["presentation_submission"],
                errorMessage: error.localizedDescription,
                className: "AuthorizationResponseHandler"
            )
        }

        do {
            var bodyParams: [String: String] = [
                "vp_token": encodedVPToken,
                "presentation_submission": encodedPresentationSubmission,
            ]

            if let state = state {
                bodyParams["state"] = state
            }

            let response = try await networkManager.sendHTTPRequest(
                url: responseUri,
                method: .post,
                bodyParams: bodyParams,
                headers: ["content-type": "application/x-www-form-urlencoded"]
            )

            return response.body
        } catch {
            throw error
        }
    }

    private func createFormatToCredentialInputDescriptorMapping(
        matchingCredentials: [String: [FormatType: [AnyCodable]]]
    ) {
        var formatToCredentialInputDescriptorMapping: [FormatType: [CredentialInputDescriptorMapping]] = [:]

        for (inputDescriptorId, formatCredentialMap) in matchingCredentials {
            for (format, credentialsArray) in formatCredentialMap {
                for credential in credentialsArray {
                    let mapping = CredentialInputDescriptorMapping(
                        format: format,
                        credential: credential,
                        inputDescriptorId: inputDescriptorId
                    )
                    formatToCredentialInputDescriptorMapping[format, default: []].append(mapping)
                }
            }
        }
        self.formatToCredentialInputDescriptorMapping = formatToCredentialInputDescriptorMapping
    }

    private func toVerifierResponse(_ networkResponse: NetworkResponse) -> VerifierResponse {
        let redirectUriKey = "redirect_uri"

        var redirectUri: String?
        var additionalParams: String? = networkResponse.body

        if let data = networkResponse.body.data(using: .utf8),
           var json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            redirectUri = json[redirectUriKey] as? String

            json.removeValue(forKey: redirectUriKey)
            if let cleanedData = try? JSONSerialization.data(withJSONObject: json, options: []),
               let cleanedString = String(data: cleanedData, encoding: .utf8) {
                additionalParams = cleanedString
            }
        }

        return VerifierResponse(
            statusCode: networkResponse.statusCode,
            responseBody: networkResponse.body,
            redirectUri: redirectUri,
            additionalParams: additionalParams,
            headers: networkResponse.headers
        )
    }
}
