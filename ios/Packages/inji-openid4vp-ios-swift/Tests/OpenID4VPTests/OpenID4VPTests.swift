@testable import OpenID4VP
import XCTest

class OpenID4VPTests: XCTestCase {
    var openID4VP: OpenID4VP!
    var mockNetworkManager: MockNetworkManager!
    var mockNonceProvider: NonceProvider!
    var authorizationRequest: AuthorizationRequest!

    let jws = "wemcn3234ns"
    let signatureAlgoType = "JsonWebSignature2020"
    let publicKey = "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBggvSPv73S\\nG5ToTt07NZPdKDrg9lSjetZup39oj12u0YoyRMlMhY0xYL6c8X1BexM7Wlp+c13o\\n1QIDAQAB\\n-----END PUBLIC KEY-----\\n"
    let domain = "https://example"
    let descriptorMap: [DescriptorMap] = [
        DescriptorMap(id: "bank_input", format: .ldp_vp, path: "$", pathNested: PathNested(id: "input_1", format: .ldp_vc, path: "$.verifiableCredential[0]")),
        DescriptorMap(id: "bank_input", format: .ldp_vp, path: "$", pathNested: PathNested(id: "input_1", format: .ldp_vc, path: "$.verifiableCredential[0]")),
    ]

    let decodedPresentationDefinition = "{\"id\":\"#2345333\",\"input_descriptors\":[{\"id\":\"banking_input_1\",\"name\":\"Bank Account Information\",\"purpose\":\"We can\",\"constraints\":{\"fields\":[{\"path\":[\"$.crede\"],\"purpose\":\"We can use for  # verification purpose # for anything\",\"filter\":{\"type\":\"string\",\"pattern\":\"^$\"}},{\"path\":[\"$.vc.credential\",\"$.vc.credentialSubject.account[*].route\",\"$.account[*].route\"],\"purpose\":\"We can use for verification purpose\",\"filter\":{\"type\":\"string\",\"pattern\":\"^\"}}]}}]}"

    let decodedClientMetadata =
        "{\"name\":\"dummyClient\"}"
    let processedSuccessfullyMessage = "{\"message\":\"Some additional info\"}"
    let responseUri = "https://mock-verifier.com"

    override func setUp() {
        super.setUp()
        mockNetworkManager = MockNetworkManager()
        mockNonceProvider = MockNonceProvider()

        openID4VP = OpenID4VP(traceabilityId: "AXESWSAW123", networkManager: mockNetworkManager, nonceProvider: MockNonceProvider())
        openID4VP.setResponseUri("https://mock-verifier.com")
        openID4VP.authorizationRequest = authorizationRequest
    }

    override func tearDown() {
        openID4VP = nil
        mockNetworkManager = nil
        mockNonceProvider = nil
        super.tearDown()
    }

    func testWalletNonceIsDifferentForEveryAuthenticateVerifierCall() async {
        let openID4VP = OpenID4VP(traceabilityId: "trace-id")
        _ = try! await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithRedirectUri, trustedVerifiers: preRegisteredVerifiers, shouldValidateClient: true)
        let firstMirror = Mirror(reflecting: openID4VP as Any)
        let firstNonce = firstMirror.children.first(where: { $0.label == "walletNonce" })?.value as? String

        _ = try! await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithRedirectUri, trustedVerifiers: preRegisteredVerifiers, shouldValidateClient: true)
        let secondMirror = Mirror(reflecting: openID4VP as Any)
        let secondNonce = secondMirror.children.first(where: { $0.label == "walletNonce" })?.value as? String

        XCTAssertNotEqual(firstNonce, secondNonce, "Wallet nonce should be different for every authenticateVerifier call")
    }

    // client_id_scheme = redirect_uri
    func testAuthorizationRequestJsonStringConversion() async {
        do {
            let decoded = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithRedirectUri, trustedVerifiers: preRegisteredVerifiers, shouldValidateClient: true)
            let jsonData = try JSONEncoder().encode(decoded)
            let authorizationRequestJsonString = String(decoding: jsonData, as: UTF8.self)

            assertJsonString(expected: "{\"redirect_uri\":null,\"client_id\":\"redirect_uri:https:\\/\\/mock-verifier.com\",\"response_uri\":\"https:\\/\\/mock-verifier.com\",\"nonce\":\"VbRRB\\/LTxLiXmVNZuyMO8A==\",\"response_type\":\"vp_token\",\"state\":\"+mRQe1d6pBoJqF6Ab28klg==\",\"response_mode\":\"direct_post\",\"presentation_definition\":{\"id\":\"vp_presentation_definition\",\"input_descriptors\":[{\"constraints\":{\"fields\":[{\"path\":[\"$.credentialSubject.email\"],\"filter\":{\"pattern\":\"@gmail.com\",\"type\":\"string\"}}]},\"name\":\"Verifiable Credential\",\"format\":{\"ldp_vc\":{\"proof_type\":[\"Ed25519Signature2018\",\"RsaSignature2018\"]}},\"id\":\"input_1\",\"purpose\":\"To verify identity using Linked Data Proofs\"}]},\"client_metadata\":{\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\"]}},\"jwks\":{\"keys\":[{\"kid\":\"ed-key1\",\"crv\":\"X25519\",\"kty\":\"OKP\",\"alg\":\"ECDH-ES\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"use\":\"enc\"},{\"kid\":\"ed-key2\",\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"alg\":\"EdDSA\",\"x\":\"5tvU4k_TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc\",\"use\":\"sig\"}]},\"client_name\":\"Requester name\",\"logo_uri\":\"https:\\/\\/mock-verifier.com\\/logo\",\"authorization_encrypted_response_alg\":\"ECDH-ES\"}}", actual: authorizationRequestJsonString)
        } catch {
            XCTFail("Should not get error but got error - \(error)")
        }
    }
    
    // client_id_scheme = redirect_uri, test with deprecated authenticateVerifier including trustedVerifierJSON parameter
    func testAuthorizationRequestJsonStringConversionDeprecatedMethod() async {
        do {
            let decoded = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithRedirectUri, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
            let jsonData = try JSONEncoder().encode(decoded)
            let authorizationRequestJsonString = String(decoding: jsonData, as: UTF8.self)

            assertJsonString(expected: "{\"redirect_uri\":null,\"client_id\":\"redirect_uri:https:\\/\\/mock-verifier.com\",\"response_uri\":\"https:\\/\\/mock-verifier.com\",\"nonce\":\"VbRRB\\/LTxLiXmVNZuyMO8A==\",\"response_type\":\"vp_token\",\"state\":\"+mRQe1d6pBoJqF6Ab28klg==\",\"response_mode\":\"direct_post\",\"presentation_definition\":{\"id\":\"vp_presentation_definition\",\"input_descriptors\":[{\"constraints\":{\"fields\":[{\"path\":[\"$.credentialSubject.email\"],\"filter\":{\"pattern\":\"@gmail.com\",\"type\":\"string\"}}]},\"name\":\"Verifiable Credential\",\"format\":{\"ldp_vc\":{\"proof_type\":[\"Ed25519Signature2018\",\"RsaSignature2018\"]}},\"id\":\"input_1\",\"purpose\":\"To verify identity using Linked Data Proofs\"}]},\"client_metadata\":{\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\"]}},\"jwks\":{\"keys\":[{\"kid\":\"ed-key1\",\"crv\":\"X25519\",\"kty\":\"OKP\",\"alg\":\"ECDH-ES\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"use\":\"enc\"},{\"kid\":\"ed-key2\",\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"alg\":\"EdDSA\",\"x\":\"5tvU4k_TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc\",\"use\":\"sig\"}]},\"client_name\":\"Requester name\",\"logo_uri\":\"https:\\/\\/mock-verifier.com\\/logo\",\"authorization_encrypted_response_alg\":\"ECDH-ES\"}}", actual: authorizationRequestJsonString)
        } catch {
            XCTFail("Should not get error but got error - \(error)")
        }
    }

    // client_id_scheme = redirect_uri, response_mode = fragment
    func testInvalidResponseModeWithRedirectUriScheme() async {
        let result = await Task {
            try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testVPRequestWithRedirectUriAndClientIdNotEqual, trustedVerifiers: preRegisteredVerifiers, shouldValidateClient: true)
        }.result

        switch result {
        case let .failure(error):
            assertOpenID4VPException(
                error,
                expectedMessage: "Given response_mode - fragment is not supported",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        case .success:
            XCTFail("Expected error for unsupported response_mode but got success")
        }
    }

    // client_id_scheme = pre-registered
    func testReturnDataForValidRequestWithResponseUri() async {
        let requestUriResponse = createAuthorizationRequestObject(clientIdScheme: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23), applicableFields: authRequestWithPreRegisteredByValueDraft23)
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, response: (requestUriResponse, httpUrlResponseForJWS))

        await XCTAssertNoThrowAndVerifyAsync(
            try await openID4VP.authenticateVerifier(
                urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithResponseUri,
                trustedVerifiers: preRegisteredVerifiers,
                shouldValidateClient: true
            )
        ) { authorizationRequest in
            XCTAssertEqual(authorizationRequest.clientId, "mock-client")
        }
    }

    // client_id_scheme = pre-registered, validation of client via shouldValidateClient

    func testAuthenticateVerifierWithShouldValidateClientFalse() async throws {
        await XCTAssertAsyncThrowsError(try await openID4VP.authenticateVerifier(
            urlEncodedAuthorizationRequest: testUrlEncodedAuthRequestOfUntrustedVerifier,
            trustedVerifiers: preRegisteredVerifiers,
            shouldValidateClient: false
        ), "should not throw even though the client ID isn't in the trusted list because shouldValidateClient is false") { error in
            assertOpenID4VPException(error, expectedMessage: "Authorization Request Object must be a signed JWT", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testAuthenticateVerifierWithShouldValidateClientTrue() async throws {
        await XCTAssertAsyncThrowsError(try await openID4VP.authenticateVerifier(
            urlEncodedAuthorizationRequest: testUrlEncodedAuthRequestOfUntrustedVerifier,
            trustedVerifiers: preRegisteredVerifiers,
            shouldValidateClient: true
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Verifier is not trusted by the wallet",
                expectedCode: OpenID4VPErrorCodes.invalidClient
            )
        }
    }

    func testAuthenticateVerifierWithoutShouldValidateClientParam() async throws {
        await XCTAssertAsyncThrowsError(try await openID4VP.authenticateVerifier(
            urlEncodedAuthorizationRequest: testUrlEncodedAuthRequestOfUntrustedVerifier,
            trustedVerifiers: preRegisteredVerifiers
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Verifier is not trusted by the wallet",
                expectedCode: OpenID4VPErrorCodes.invalidClient
            )
        }
    }

    // pre-registered client available with associated client metadata
    func testAuthenticateVerifierWithClientMetadataAlsoAvailableForVerifier() async throws {
        let clientMetadataString = """
            {
                "client_name": "Valid Client",
                "logo_uri": "https://example.com/logo.png",
                "authorization_encrypted_response_alg": "RSA-OAEP",
                "authorization_encrypted_response_enc": "A256GCM",
                "vp_formats": { "format1": { "type1": ["value1"] } },
                "jwks": { "keys": [{ "kty": "RSA", "crv": "P-256", "use": "sig", "alg": "RS256", "kid": "1", "x": "ur76ru" }] }
            }
        """.data(using: .utf8)!
        let clientMetadata = try ClientMetadata.deserializeAndValidate(clientMetadata: clientMetadataString)

        let trustedVerifiers = [Verifier(clientId: "mock-client-id", responseUris: ["https://example.com/callback"], jwksUri: "https://mock-verifier.com/.well-known/jwks.json")]
        await XCTAssertAsyncThrowsError(try await openID4VP.authenticateVerifier(
            urlEncodedAuthorizationRequest: testUrlEncodedAuthRequestOfUntrustedVerifier,
            trustedVerifiers: trustedVerifiers,
            shouldValidateClient: true
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Verifier is not trusted by the wallet",
                expectedCode: OpenID4VPErrorCodes.invalidClient
            )
        }
    }

    // client_id_scheme = pre-registered draft 21
    func testReturnDataForValidRequestWithResponseUriDraft21() async {
        let decoded: Any?

        do {
            decoded = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithResponseUriDraft21, trustedVerifiers: preRegisteredVerifiers, shouldValidateClient: true)
        } catch {
            decoded = nil
            XCTFail("Should not get error but got error - \(error)")
        }
        XCTAssertTrue(decoded is AuthorizationRequest, "decodedResponse should be an instance of AuthenticationResponse")
        XCTAssertTrue(decoded != nil, "decodedResponse should not be null")
    }

    // client_id_scheme = pre_registered, ClientMetadata mandatory values are not present
    func testMissingClientMetadataRequiredFieldsInRequest() async {
        let result = await Task {
            try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: urlEncodedAuthorizationRequestWithInvalidClientMetadata, trustedVerifiers: [Verifier(clientId: "mock-client-2", responseUris: ["https://mock-verifier.com"], jwksUri: "https://mock-client.com/jwks", allowUnsignedRequest: true)], shouldValidateClient: true)
        }.result

        switch result {
        case let .failure(error):
            assertOpenID4VPException(
                error,
                expectedMessage: "Error during client metadata decoding - Missing Input: client_metadata->vp_formats param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        case .success:
            XCTFail("Expected failure but got success")
        }
    }

    func testShouldConstructAuthorizationRequestSuccessfullyWhenPresentationDefinitionIsSentByReference() async {
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/presentation-definition", responseBody: convertToJsonString(presentationDefinition))
        do {
            let authorizationRequest = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: urlEncodedAuthRequestWithPresentationDefinitionUri, trustedVerifiers: preRegisteredVerifiers, shouldValidateClient: true)
            XCTAssertNotNil(authorizationRequest)
            XCTAssertEqual("mock-client", authorizationRequest.clientId)
        } catch {
            XCTFail("should not get error but got error \(error)")
        }
    }

    // client_id_scheme = did
    func testReturnDataForValidRequestWithDid() async {
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, response: (validJwtResponse, httpUrlResponseForJWS))
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)

        let decodedAuthorizationRequest: Any?
        do {
            decodedAuthorizationRequest = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidSignedVPRequestWithDid, trustedVerifiers: preRegisteredVerifiers, shouldValidateClient: true)
        } catch {
            decodedAuthorizationRequest = nil
            XCTFail("Should not get error but got error - \(error)")
        }

        XCTAssertTrue(decodedAuthorizationRequest is AuthorizationRequest, "decodedResponse should be an instance of AuthorizationRequest")
        XCTAssertTrue(decodedAuthorizationRequest != nil, "decodedResponse should not be null")
    }

    // jwt -> client_id_scheme = did, Invalid did
    func testThrowErrorForInValidSignatureInRequest() async {
        mockNetworkManager.setMockResponse(
            for: "https://mock-verifier.com/verifier/get-auth-request-obj",
            response: (invalidJwtResponse, httpUrlResponseForJWS)
        )
        mockNetworkManager.setMockResponse(
            for: didDocumentUrl,
            responseBody: didResponse
        )

        await XCTAssertAsyncThrowsError(try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidSignedVPRequestWithDid, trustedVerifiers: preRegisteredVerifiers, shouldValidateClient: true)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Request URI response validation failed - JWS proof verification failed",
                expectedCode: OpenID4VPErrorCodes.invalidRequestObject
            )
        }
    }

    // jwt -> client_id_scheme = did, Mismatching clientId's in QR data and Request Uri response
    func testThrowErrorIfClientIdIsMismatchingWithQrDataAndRequest() async {
        mockNetworkManager.setMockResponse(
            for: requestUri.absoluteString,
            response: (validJwtResponse, httpUrlResponseForJWS)
        )
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)

        await XCTAssertAsyncThrowsError(try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testInValidSignedVPRequestWithDidAndClientIdDifferent, trustedVerifiers: preRegisteredVerifiers, shouldValidateClient: true)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Client Id mismatch in Authorization Request parameter and the Request Object",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // jwt -> client_id_scheme = did, Kid is empty in the JWT header
    func testThrowErrorIfKidExtractionFailedFromJws() async {
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj", response: (invalidJwtResponseWithoutKid, httpUrlResponseForJWS))
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)

        await XCTAssertAsyncThrowsError(try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidSignedVPRequestWithDid, trustedVerifiers: preRegisteredVerifiers, shouldValidateClient: true)) {
            error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Request URI response validation failed - keyId is required to extract public key in did client_id_scheme",
                expectedCode: OpenID4VPErrorCodes.invalidRequestObject
            )
        }
    }

    // client_id_scheme = redirect_uri, Client id validation is false
    func testReturnDataForValidRequestWhenClientValidationIsFalse() async {
        let decoded: Any?

        do {
            decoded = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithRedirectUri, trustedVerifiers: preRegisteredVerifiers, shouldValidateClient: false)
        } catch {
            decoded = nil
            XCTFail("should not get error but got error \(error)")
        }
        XCTAssertTrue(decoded is AuthorizationRequest, "decodedResponse should be an instance of AuthenticationResponse")
        XCTAssertTrue(decoded != nil, "decodedResponse should not be null")
    }

    func testMissingPresentationDefinitionFields() async {
        let result = await Task {
            try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testInvalidPresentationDefinitionVPRequest, trustedVerifiers: preRegisteredVerifiers, shouldValidateClient: true)
        }.result

        switch result {
        case let .failure(error):
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing Input: presentation_definition->id param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        case .success:
            XCTFail("Expected OpenID4VPException but got success response")
        }
    }

    // Construct and return VP token for signing
    func testShareVerifiablePresentation() async {
        var received: [FormatType: UnsignedVPToken]?

        do {
            _ = try await openID4VP.authenticateVerifier(
                urlEncodedAuthorizationRequest: mockUrlEncodedVPRequestWithDirectPostJwt,
                trustedVerifiers: preRegisteredVerifiers,
                shouldValidateClient: true
            )

            let mockCredentials: [String: [FormatType: [AnyCodable]]] = [
                "input_1": [
                    .ldp_vc: [AnyCodable(ldpVC())],
                ],
            ]

            received = try await openID4VP.constructUnsignedVPToken(
                verifiableCredentials: mockCredentials,
                holderId: "did:example:123",
                signatureSuite: "JsonWebSignature2020"
            )
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        XCTAssertNotNil(received, "The response should not be nil for valid credentials map")
    }

    // NetworkManager Tests Success
    func testSendVPSuccess() async throws {
        mockNetworkManager.setMockResponse(
            for: "https://mock-verifier.com",
            responseBody: "{\"message\":\"Some additional info\"}"
        )

        _ = try await openID4VP.authenticateVerifier(
            urlEncodedAuthorizationRequest: mockUrlEncodedVPRequestWithDirectPostJwt,
            trustedVerifiers: preRegisteredVerifiers,
            shouldValidateClient: true
        )

        _ = try await openID4VP.constructUnsignedVPToken(
            verifiableCredentials: verifiableCredentialsList,
            holderId: "did:example:123",
            signatureSuite: "JsonWebSignature2020"
        )

        let vpTokenSigningResults: [FormatType: VPTokenSigningResult] = [
            .ldp_vc: LdpVPTokenSigningResult(
                jws: jws,
                proofValue: "test", signatureAlgorithm: signatureAlgoType
            ),
        ]

        let response = try await openID4VP.shareVerifiablePresentation(vpTokenSigningResults: vpTokenSigningResults)

        XCTAssertEqual(response, "{\"message\":\"Some additional info\"}")
    }

    // NetworkManager Tests Failure
    func testSendVPFailure() async {
        let errorMessage = "Network Request failed with error response: response"
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com", error: NetworkRequestException.networkRequestFailed(message: errorMessage))
        let vpTokenSigningResults = [FormatType.ldp_vc: LdpVPTokenSigningResult(jws: jws, proofValue: "test", signatureAlgorithm: signatureAlgoType)]

        do {
            authorizationRequest = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: mockUrlEncodedVPRequestWithDirectPostJwt, trustedVerifiers: preRegisteredVerifiers, shouldValidateClient: true)
            _ = try! await openID4VP.constructUnsignedVPToken(verifiableCredentials: verifiableCredentialsList, holderId: "wallet-holder-id", signatureSuite: "JsonWebSignature2020")

            let _ = try await openID4VP.shareVerifiablePresentation(vpTokenSigningResults: vpTokenSigningResults)
        } catch let error as NetworkRequestException {
            switch error {
            case let .networkRequestFailed(message):
                XCTAssertEqual(message, errorMessage, "Unexpected error message: \(message)")
            default:
                XCTFail("Expected NetworkRequestException.networkRequestFailed but got \(error)")
            }
        } catch {
            XCTFail("Expected NetworkRequestException.networkRequestFailed but got \(error)")
        }
    }

    func testShareVPSuccessWhenResponseModeIsDirectPostJwt() async throws {
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com", responseBody: "{\"message\":\"Some additional info\"}")

        authorizationRequest = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: mockUrlEncodedVPRequestWithDirectPostJwt, trustedVerifiers: preRegisteredVerifiers, shouldValidateClient: true)
        _ = try! await openID4VP.constructUnsignedVPToken(verifiableCredentials: verifiableCredentialsList, holderId: "wallet-holder-id", signatureSuite: "JsonWebSignature2020")
        let vpTokenSigningResults = [FormatType.ldp_vc: LdpVPTokenSigningResult(jws: "test-jws-valid", proofValue: "test", signatureAlgorithm: "JsonWebSignature2020")]

        let response = try await openID4VP.shareVerifiablePresentation(vpTokenSigningResults: vpTokenSigningResults)

        XCTAssertEqual(response, "{\"message\":\"Some additional info\"}")
    }

    func testSendErrorToVerifier_withoutState() async {
        openID4VP.setResponseUri("https://mock-verifier.com")

        let expectedError = InvalidData(message: "Some Error Message", className: "test")

        await openID4VP.sendErrorToVerifier(error: expectedError)

        guard let recorded = mockNetworkManager.recordedRequests["https://mock-verifier.com"] else {
            return XCTFail("No request recorded")
        }

        let requestBody = recorded.requestBody ?? [:]

        XCTAssertEqual(requestBody["error"], "invalid_request")
        XCTAssertEqual(requestBody["error_description"], "Some Error Message")
        XCTAssertNil(requestBody["state"], "State should not be present in the request body")
    }

    func testSendErrorToVerifier_withState() async throws {
        openID4VP.setResponseUri("https://mock-verifier.com")
        let authorizationRequest = try await openID4VP.authenticateVerifier(
            urlEncodedAuthorizationRequest: mockUrlEncodedVPRequestWithDirectPostJwt,
            trustedVerifiers: preRegisteredVerifiers,
            shouldValidateClient: true
        )
        mockNetworkManager.setMockResponse(for: jwksUri, responseBody: jwkSet)
        openID4VP.authorizationRequest = authorizationRequest

        let expectedError = InvalidData(message: "Some Error Message", className: "test")

        await openID4VP.sendErrorToVerifier(error: expectedError)

        guard let recorded = mockNetworkManager.recordedRequests["https://mock-verifier.com"] else {
            return XCTFail("No request recorded")
        }

        let requestBody = recorded.requestBody ?? [:]

        XCTAssertEqual(requestBody["error"], "invalid_request")
        XCTAssertEqual(requestBody["error_description"], "Some Error Message")
        XCTAssertNotNil(requestBody["state"], "Expected 'state' to be present in the request body")
        XCTAssertEqual(requestBody["state"], "+mRQe1d6pBoJqF6Ab28klg==")
    }

    func testResetOfOpenID4VPFields() async throws {
        let openID4VP = OpenID4VP(traceabilityId: "trace-id", networkManager: mockNetworkManager)
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, response: (validJwtResponse, httpUrlResponseForJWS))
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)

        // first call
        _ = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidSignedVPRequestWithDid, trustedVerifiers: preRegisteredVerifiers, shouldValidateClient: true)
        let firstMirror = Mirror(reflecting: openID4VP as Any)
        let firstResponseUri = firstMirror.children.first(where: { $0.label == "responseUri" })?.value as? String
        let firstAuthorizationRequest = firstMirror.children.first(where: { $0.label == "authorizationRequest" })?.value as? AuthorizationRequest
        XCTAssertNotNil(firstResponseUri, "responseUri should not be nil after first authenticateVerifier call")
        XCTAssertNotNil(firstAuthorizationRequest, "authorizedRequest should not be nil after first authenticateVerifier call")

        // second call
        // clear all mock responses and set only those required for the second call
        mockNetworkManager.clearResponses()
        mockNetworkManager.setMockResponse(
            for: "https://mock-verifier.com/verifier/get-auth-request-obj",
            response: (invalidJwtResponse, httpUrlResponseForJWS)
        )
        mockNetworkManager.setMockResponse(
            for: didDocumentUrl,
            responseBody: didResponse
        )

        await XCTAssertAsyncThrowsError(try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidSignedVPRequestWithDid, trustedVerifiers: preRegisteredVerifiers, shouldValidateClient: true)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Request URI response validation failed - JWS proof verification failed",
                expectedCode: OpenID4VPErrorCodes.invalidRequestObject
            )
        }
        let secondMirror = Mirror(reflecting: openID4VP as Any)
        let secondResponseUri = secondMirror.children.first(where: { $0.label == "responseUri" })?.value as? String
        let secondAuthorizationRequest = secondMirror.children.first(where: { $0.label == "authorizationRequest" })?.value as? AuthorizationRequest
        XCTAssertNil(secondResponseUri, "responseUri should be nil after second authenticateVerifier call which throws error")
        XCTAssertNil(secondAuthorizationRequest, "authorizedRequest should be nil after second authenticateVerifier call which throws error")
        // No error to verifier to be sent as no response uri is available
        XCTAssertTrue(mockNetworkManager.recordedRequests.count == 2, "No requests should be recorded as responseUri is nil")
    }

    func testThrowErrorWhenResponseUriNotAvailableDuringsendErrorInfoToVerifier
    () async throws {
        let error = AccessDenied(message: "Some error", className: "test")
        let openID4VP = OpenID4VP(traceabilityId: "trace-id", networkManager: mockNetworkManager)

        // directly call sendErrorInfoToVerifier
        await XCTAssertAsyncThrowsError(try await openID4VP.sendErrorInfoToVerifier(error: error)) { error in
            XCTAssertEqual(error.localizedDescription, "Failed to send error to verifier: Response URI is not set. Cannot send error to verifier.", "error_dispatch_failure")
        }
    }

    func testSuccessWhensendErrorInfoToVerifierCalled
    () async throws {
        let error = AccessDenied(message: "Some error", className: "test")
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: processedSuccessfullyMessage)

        let openID4VP = OpenID4VP(traceabilityId: "trace-id", networkManager: mockNetworkManager)
        openID4VP.setResponseUri(responseUri)

        await XCTAssertNoThrowAndVerifyAsync(try await openID4VP.sendErrorInfoToVerifier(error: error)) { result in
            XCTAssertEqual(result.body(), "{\"message\":\"Some additional info\"}")
            XCTAssertEqual(result.statusCode, 200)
            XCTAssertEqual(result.headers, ["Content-Type": "application/json"])
        }
    }

    func testNoThrowErrorWhenResponseUriNotAvailableDuringSendErrorToVerifier
    () async throws {
        let error = AccessDenied(message: "Some error", className: "test")
        let openID4VP = OpenID4VP(traceabilityId: "trace-id", networkManager: mockNetworkManager)

        // directly call sendErrorInfoToVerifier
        await XCTAssertNoThrowAndVerifyAsync(try await openID4VP.sendErrorToVerifier(error: error)) {
            print("No error thrown even when responseUri is not set")
        }
    }

    func testThrownExceptionHavingVerifierResponse() async {
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "{\"message\":\"Some additional info\",\"redirect_uri\":\"https://mock-verifier.com/redirect#response_code=200\"}")

        await XCTAssertAsyncThrowsError(try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testInvalidPresentationDefinitionVPRequest, trustedVerifiers: preRegisteredVerifiers, shouldValidateClient: true)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing Input: presentation_definition->id param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest,
                expectedVerifierResponse: VerifierResponse(statusCode: 200, responseBody: "{\"message\":\"Some additional info\",\"redirect_uri\":\"https://mock-verifier.com/redirect#response_code=200\"}", redirectUri: "https://mock-verifier.com/redirect#response_code=200", additionalParams: "{\"message\":\"Some additional info\"}", headers: ["Content-Type": "application/json"])
            )
        }
    }

    func testAuthenticateVerifierSuccess_WithRedirectUriClientIdScheme() async {
        let authorizationRequest = baseAuthRequest(
            clientId: "redirect_uri:https://example.com/iar/callback",
            responseUri: "https://example.com/iar/callback"
        )

        let trustedVerifiers = [
            Verifier(clientId: "redirect-uri:https://example.com/callback", responseUris: ["https://example.com/callback"]),
        ]

        do {
            _ = try await openID4VP.authenticateVerifier(
                authorizationRequest: authorizationRequest,
                trustedVerifiers: trustedVerifiers,
                shouldValidateClient: true
            )
        } catch let error {
            print(error)
            XCTFail("Should not throw error")
        }
    }

    func testConstructVPResponse_Success() {
        let signingResult: [FormatType: VPTokenSigningResult] = [FormatType.ldp_vc: LdpVPTokenSigningResult(jws: jws, proofValue: "test", signatureAlgorithm: signatureAlgoType)]
        let handler = MockAuthorizationResponseHandler(networkManager: MockNetworkManager())
        handler.expectedResponse = ["vp_token": "jwt-token"]
        
        let openIdVP  = OpenID4VP(traceabilityId: "AXESWSAW123", networkManager: mockNetworkManager, nonceProvider: MockNonceProvider(), authorizationResponseHandler: handler)
        openIdVP.authorizationRequest = mockAuthorizationRequestObjectWithDirectPostResponseMode
        let result = openIdVP.constructVPResponse(vpTokenSigningResults: signingResult)

        XCTAssertEqual(result["vp_token"] as! String, "jwt-token")
    }

    

        func testConstructErrorInfoSuccess() {
            let handler = MockAuthorizationResponseHandler(networkManager: mockNetworkManager)
            handler.expectedErrorResponse = ["error": "invalid_request"]

            let openIdVP  = OpenID4VP(traceabilityId: "AXESWSAW123", networkManager: mockNetworkManager, nonceProvider: MockNonceProvider(), authorizationResponseHandler: handler)
            openIdVP.authorizationRequest = mockAuthorizationRequestObjectWithDirectPostResponseMode
            let result = openIdVP.constructErrorInfo(exception: InvalidData(message: "mock error", className: ""))

            XCTAssertEqual(result["error"] as! String, "invalid_request")
        }
}



