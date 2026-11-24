@testable import OpenID4VP
import XCTest

final class DirectPostResponseModeHandlerTests: XCTestCase {
    let mockVPTokens = VPTokenType.vpTokenElement(LdpVPToken(context: ["context"], type: ["typ1"], verifiableCredential: [AnyCodable(ldpVC())], id: "identifier", holder: "holder", proof: Proof(type: "Ed25519Signature2018", created: "2021-03-19T15:30:15Z", challenge: "n-0S6_WzA2Mj", domain: "https://client.example.org/cb", jws: "eyJhbG...IAoDA", proofPurpose: .vpProofPurpose, verificationMethod: "did:example:holder#key-1")))

    let mockPresentationSubmission = PresentationSubmission(definitionId: "client-identifier", descriptorMap: [DescriptorMap(id: "input_1", format: .ldp_vp, path: "$", pathNested: PathNested(id: "input_1", format: .ldp_vc, path: "$.verifiableCredential[0]"))])

    private let mockNetworkManager = MockNetworkManager()
    private let responseUri = "https://mock-verifier.com"

    private var walletConfig: WalletConfig!

    override func setUpWithError() throws {
        walletConfig = createWalletConfig()
    }

    func testValidationClientMetadatadaNotThrowErrorForDirectPost() throws {
        let directPostAuthorizationResponseModeHandler = DirectPostResponseModeHandler()

        XCTAssertNoThrow(try directPostAuthorizationResponseModeHandler.validate(clientMetadata: mockClientMetadataSpecVersionDraft23[.directPost], walletConfig: walletConfig, shouldValidateWithWalletMetadata: true))
    }

    func testThrowErrorWhenEncryptionRelatedPropertiesAvailableInVerifierMetadata() throws {
        let handler = DirectPostResponseModeHandler()

        let baseFields = """
            "client_name": "Test",
            "logo_uri": "https://example.com/logo.png",
            "jwks": { "keys": [{ "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "ECDH-ES", "kid": "key1", "x": "5tvU4k_TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc" }] },
            "vp_formats": { "ldp_vc": { "proof_type": ["Ed25519Signature2020"] } }
        """

        let draft23EncryptionFields: [String] = [
            "\"authorization_encrypted_response_alg\": \"ECDH-ES\"",
            "\"authorization_encrypted_response_enc\": \"A256GCM\"",
            "\"authorization_encrypted_response_alg\": \"ECDH-ES\", \"authorization_encrypted_response_enc\": \"A256GCM\""
        ]

        for encryptionField in draft23EncryptionFields {
            let json = "{ \(baseFields), \(encryptionField) }"
            let draft23ClientMetadata = try JSONDecoder().decode(ClientMetadataDraft23.self, from: Data(json.utf8))
            XCTAssertThrowsError(
                try handler.validate(clientMetadata: draft23ClientMetadata, walletConfig: walletConfig, shouldValidateWithWalletMetadata: false)
            ) { error in
                assertOpenID4VPException(error, expectedMessage: "authorization_encrypted_response_enc or authorization_encrypted_response_alg SHOULD not be present for response mode 'direct_post'", expectedCode: OpenID4VPErrorCodes.invalidRequest)
            }
        }

        let v1ClientMetadataStr = """
        {
            "authorization_encrypted_response_alg": "ECDH-ES",
            "encrypted_response_enc_values_supported": ["A256GCM"],
            "jwks": { "keys": [{ "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "ECDH-ES", "kid": "key1", "x": "5tvU4k_TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc" }] },
            "vp_formats_supported": { "ldp_vc": { "proof_type_values": ["Ed25519Signature2020"] } }
        }
        """
        let v1ClientMetadata = try JSONDecoder().decode(ClientMetadata.self, from: Data(v1ClientMetadataStr.utf8))
        XCTAssertThrowsError(
            try handler.validate(clientMetadata: v1ClientMetadata, walletConfig: walletConfig, shouldValidateWithWalletMetadata: false)
        ) { error in
            assertOpenID4VPException(error, expectedMessage: "encrypted_response_enc_values_supported SHOULD not be present for response mode 'direct_post'", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }
    
    func testGetVerifierPublicKeyForEncryptionReturnsNilForBothSpecVersions() throws {
        let handler = DirectPostResponseModeHandler()

        for specVersion: SpecVersion in [.draft23, .v1] {
            let result = try handler.getVerifierPublicKeyForEncryption(
                authorizationRequest: getMockAuthorizationRequest(responseMode: .directPost, specVersion: specVersion),
                        walletConfig: walletConfig
            )
            XCTAssertNil(result)
        }
    }

    func testGetVerifierPublicKeyForEncryptionReturnsNilWithNilWalletMetadata() throws {
        let handler = DirectPostResponseModeHandler()
        let result = try handler.getVerifierPublicKeyForEncryption(
            authorizationRequest: getMockAuthorizationRequest(responseMode: .directPost, specVersion: .v1),
                    walletConfig: WalletConfig()
        )
        XCTAssertNil(result)
    }

    // MARK: - dispatchInfo-based method tests

    private func makeDirectPostDispatchInfo(state: String? = "test-state") -> ResponseDispatchInfo {
        ResponseDispatchInfo(
            responseMode: ResponseMode.directPost.rawValue,
            nonce: "auth-nonce",
            walletNonce: "wallet-nonce",
            state: state,
            clientId: "client_id",
            responseUrl: responseUri,
            responseEncryptionSpecification: nil
        )
    }

    func testGetAuthorizationErrorResponseWithDispatchInfoReturnsPlainMap() throws {
        let handler = DirectPostResponseModeHandler()
        let errorResponse = AuthorizationErrorResponse(
            error: "invalid_request",
            errorDescription: "Something went wrong",
            state: "err-state"
        )

        let result = try handler.getAuthorizationErrorResponse(
            dispatchInfo: makeDirectPostDispatchInfo(),
            authorizationResponse: errorResponse,
            authorizationRequest: nil
        )

        XCTAssertEqual(result["error"], "invalid_request")
        XCTAssertEqual(result["error_description"], "Something went wrong")
        XCTAssertEqual(result["state"], "err-state")
        XCTAssertEqual(result.keys.count, 3)
    }

    func testGetAuthorizationErrorResponseWithDispatchInfoOmitsStateWhenNil() throws {
        let handler = DirectPostResponseModeHandler()
        let errorResponse = AuthorizationErrorResponse(error: "access_denied", errorDescription: "User denied", state: nil)

        let result = try handler.getAuthorizationErrorResponse(
            dispatchInfo: makeDirectPostDispatchInfo(),
            authorizationResponse: errorResponse,
            authorizationRequest: nil
        )

        XCTAssertEqual(result["error"], "access_denied")
        XCTAssertEqual(result["error_description"], "User denied")
        XCTAssertNil(result["state"])
    }

    func testGetAuthorizationResponseWithDispatchInfoReturnsPlainMap() throws {
        let handler = DirectPostResponseModeHandler()
        let authorizationResponse = AuthorizationResponse.presentationExchange(
            vpToken: mockVPTokens,
            presentationSubmission: mockPresentationSubmission,
            state: "sample-state"
        )

        let result = try handler.getAuthorizationResponse(
            dispatchInfo: makeDirectPostDispatchInfo(),
            authorizationResponse: authorizationResponse,
            authorizationRequest: getMockAuthorizationRequest(responseMode: .directPost)
        )

        XCTAssertNotNil(result["vp_token"])
        XCTAssertNotNil(result["presentation_submission"])
        XCTAssertEqual(result["state"], "sample-state")
        XCTAssertEqual(result.keys.count, 3)
    }

    func testSendAuthorizationErrorWithDispatchInfoPostsToResponseUrl() async throws {
        let handler = DirectPostResponseModeHandler()
        mockNetworkManager.clearResponses()
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "error acknowledged")

        let errorResponse = AuthorizationErrorResponse(error: "invalid_scope", errorDescription: "Bad scope", state: "s1")
        let dispatchInfo = makeDirectPostDispatchInfo()

        let result = try await handler.sendAuthorizationError(
            dispatchInfo: dispatchInfo,
            authorizationResponse: errorResponse,
            authorizationRequest: nil,
            networkManager: mockNetworkManager
        )

        let recorded = mockNetworkManager.recordedRequests[responseUri]
        XCTAssertEqual(recorded?.requestMethod, .post)
        XCTAssertEqual(recorded?.requestBody?["error"], "invalid_scope")
        XCTAssertEqual(recorded?.requestBody?["error_description"], "Bad scope")
        XCTAssertEqual(recorded?.requestBody?["state"], "s1")
        assertDictionariesEqual(expected: ["Content-Type": ContentTypes.applicationFormUrlEncoded.rawValue], actual: recorded?.requestHeaders)
        XCTAssertEqual(result.body, "error acknowledged")
    }

    func testSendAuthorizationResponseWithDispatchInfoPostsToResponseUrl() async throws {
        let handler = DirectPostResponseModeHandler()
        mockNetworkManager.clearResponses()
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "response received")

        let authorizationResponse = AuthorizationResponse.presentationExchange(
            vpToken: mockVPTokens,
            presentationSubmission: mockPresentationSubmission,
            state: "my-state"
        )
        let dispatchInfo = makeDirectPostDispatchInfo()

        let result = try await handler.sendAuthorizationResponse(
            dispatchInfo: dispatchInfo,
            authorizationResponse: authorizationResponse,
            authorizationRequest: getMockAuthorizationRequest(responseMode: .directPost),
            networkManager: mockNetworkManager
        )

        let recorded = mockNetworkManager.recordedRequests[responseUri]
        XCTAssertEqual(recorded?.requestMethod, .post)
        XCTAssertNotNil(recorded?.requestBody?["vp_token"])
        XCTAssertNotNil(recorded?.requestBody?["presentation_submission"])
        XCTAssertEqual(recorded?.requestBody?["state"], "my-state")
        assertDictionariesEqual(expected: ["Content-Type": ContentTypes.applicationFormUrlEncoded.rawValue], actual: recorded?.requestHeaders)
        XCTAssertEqual(result.body, "response received")
    }

    func testGetResponseEndpointReturnsResponseUriForDirectPost() throws {
        let handler = DirectPostResponseModeHandler()
        let responseUrl = try handler.getResponseEndpoint(authorizationRequestParameters: [
            AuthorizationRequestFieldConstants.responseUri: "https://mock-verifier.com/callback"
        ])

        XCTAssertEqual(responseUrl, "https://mock-verifier.com/callback")
    }

    func testGetResponseEndpointThrowsForInvalidUriForDirectPost() throws {
        let handler = DirectPostResponseModeHandler()

        XCTAssertThrowsError(try handler.getResponseEndpoint(authorizationRequestParameters: [
            AuthorizationRequestFieldConstants.responseUri: "invalid-uri"
        ])) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "response_uri data is not valid",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
