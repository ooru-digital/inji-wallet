@testable import OpenID4VP
import XCTest

final class DirectPostResponseModeHandlerTests: XCTestCase {
    let mockVPTokens = VPTokenType.vpTokenElement(LdpVPToken(context: ["context"], type: ["typ1"], verifiableCredential: [AnyCodable(ldpVC())], id: "identifier", holder: "holder", proof: Proof(type: "Ed25519Signature2018", created: "2021-03-19T15:30:15Z", challenge: "n-0S6_WzA2Mj", domain: "https://client.example.org/cb", jws: "eyJhbG...IAoDA", proofPurpose: .vpProofPurpose, verificationMethod: "did:example:holder#key-1")))

    let mockPresentationSubmission = PresentationSubmission(definitionId: "client-identifier", descriptorMap: [DescriptorMap(id: "input_1", format: .ldp_vp, path: "$", pathNested: PathNested(id: "input_1", format: .ldp_vc, path: "$.verifiableCredential[0]"))])

    private let mockNetworkManager = MockNetworkManager()
    private let responseUri = "https://mock-verifier.com"

    private var walletMetadata: WalletMetadata!

    override func setUpWithError() throws {
        walletMetadata = try createWalletMetadataV2()
    }

    func testValidationClientMetadatadaNotThrowErrorForDirectPost() throws {
        let directPostAuthorizationResponseModeHandler = DirectPostResponseModeHandler()

        XCTAssertNoThrow(try directPostAuthorizationResponseModeHandler.validate(clientMetadata: mockClientMetadataObject, walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true))
    }

    func testSendAuthorizationResponseForDirectPostResponseMode() async throws {
        let directPostAuthorizationResponseModeHandler = DirectPostResponseModeHandler()
        let authorizationResponse: AuthorizationResponse = AuthorizationResponse(vpToken: mockVPTokens, presentationSubmission: mockPresentationSubmission, state: "state")
        mockNetworkManager.clearResponses()
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "Response has been shared successfully here.")

        do {
            let result = try await directPostAuthorizationResponseModeHandler.sendAuthorizationResponse(authorizationRequest: mockAuthorizationRequestObjectWithDirectPostResponseMode, authorizationResponse: authorizationResponse, url: mockAuthorizationRequestObjectWithDirectPostResponseMode.responseUri!, networkManager: mockNetworkManager,
                                                                                                        producerInfo: "mock-nonce",
                                                                                                        recipientInfo: "verifier-nonce")

            let recordedRequest = mockNetworkManager.recordedRequests[responseUri]
            XCTAssertEqual(HttpMethod.post, recordedRequest?.requestMethod)
            XCTAssertTrue(recordedRequest?.requestBody?.keys.count == 3)
            XCTAssertTrue((recordedRequest?.requestBody?.keys.allSatisfy(["vp_token", "presentation_submission", "state"].contains(_:))) != nil)
            assertDictionariesEqual(expected: ["Content-Type": ContentTypes.applicationFormUrlEncoded.rawValue], actual: recordedRequest?.requestHeaders)
            XCTAssertEqual("Response has been shared successfully here.", result.body)
        }
    }

    func testShouldThrowErrorIfNoJwkMatchingUseKeyIsFound() throws {
            
            let clientMetadataStr = """
            {
                "client_name": "Requestername",
                "logo_uri": "<logo_uri>",
                "authorization_encrypted_response_alg": "ECDH-ES",
                "authorization_encrypted_response_enc": "A256GCM",
                "jwks": {
                    "keys": [
                        {
                            "kty": "OKP",
                            "crv": "X25519",
                            "use": "sig",
                            "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                            "alg": "ECDH-ES",
                            "kid": "ed-key1"
                        }
                    ]
                },
                "vp_formats": {
                    "mso_mdoc": {
                        "alg": ["ES256"]
                    }
                }
            }
            """

            let clientMetadata = try JSONDecoder().decode(ClientMetadata.self, from: Data(clientMetadataStr.utf8))
            let handler = DirectPostJwtResponseModeHandler()

            
            let expectedMessage = "No jwk matching the specified algorithm found for encryption"

            XCTAssertThrowsError(
                try handler.validate(
                    clientMetadata: clientMetadata,
                    walletMetadata: walletMetadata,
                    shouldValidateWithWalletMetadata: false
                )
            ) { error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: expectedMessage,
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    
    func testShouldReturnGetAuthorizationSuccessResponseSuccesfully() throws {
        let handler = DirectPostResponseModeHandler()

        let authorizationResponse = AuthorizationResponse(
            vpToken: mockVPTokens,
            presentationSubmission: mockPresentationSubmission,
            state: "sample-state"
        )

        let result = try handler.getAuthorizationResponse(
            authorizationRequest: mockAuthorizationRequestObjectWithDirectPostResponseMode,
            authorizationResponse: authorizationResponse,
            walletNonce: "mock-nonce"
        )

        XCTAssertEqual(result["state"], "sample-state")
        XCTAssertNotNil(result["vp_token"])
        XCTAssertNotNil(result["presentation_submission"])
    }

    func testShouldReturnGetAuthorizationErrorResponseSuccesfully() throws {
        let handler = DirectPostResponseModeHandler()

        let errorResponse = AuthorizationErrorResponse(
            error: "invalid_request",
            errorDescription: "Something went wrong",
            state: "error-state"
        )

        let result = handler.getAuthorizationErrorResponse(
            authorizationRequest: mockAuthorizationRequestObjectWithDirectPostResponseMode,
            authorizationResponse: errorResponse,
            walletNonce: "mock-nonce"
        )

        XCTAssertEqual(result["error"], "invalid_request")
        XCTAssertEqual(result["error_description"], "Something went wrong")
        XCTAssertEqual(result["state"], "error-state")
    }


}
