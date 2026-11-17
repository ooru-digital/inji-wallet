import XCTest
@testable import OpenID4VP

final class DirectPostJwtResponseModeHandlerTests: XCTestCase {
    private let directPostJwtResponseModeHandler = DirectPostJwtResponseModeHandler()
    let mockVPTokens = VPTokenType.vpTokenElement(LdpVPToken(context: ["context"], type: ["typ1"], verifiableCredential: [AnyCodable(ldpVC())], id: "identifier", holder: "holder", proof: Proof(type: "Ed25519Signature2018", created: "2021-03-19T15:30:15Z", challenge: "n-0S6_WzA2Mj", domain: "https://client.example.org/cb", jws: "eyJhbG...IAoDA", proofPurpose: .vpProofPurpose, verificationMethod: "did:example:holder#key-1")))
    
    let mockPresentationSubmission = PresentationSubmission(definitionId: "client-identifier", descriptorMap: [DescriptorMap(id: "input_1", format: .ldp_vp, path: "$", pathNested: PathNested(id: "input_1", format: .ldp_vc, path: "$.verifiableCredential[0]"))])
    private let mockNetworkManager = MockNetworkManager()
    private let responseUri = "https://mock-verifier.com"
    
    private var walletMetadata: WalletMetadata!
    
    override func setUpWithError() throws {
        walletMetadata = try createWalletMetadataV2()
    }
    
    /// client metadata validation tests
    
    func testThrowErrorWhenClientMetadataIsNil() throws {
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: nil, walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("client_metadata must be present for given response mode", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenClientMetadataDoesNotHaveAuthorizationEncryptedResponseAlg() throws {
        let invalidClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_enc": "A256GCM",
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats": [
                "mso_mdoc": [
                    "alg": [
                        "ES256",
                        "EdDSA"
                    ]
                ],
                "ldp_vp": [
                    "proof_type": [
                        "Ed25519Signature2018",
                        "Ed25519Signature2020",
                        "RsaSignature2018"
                    ]
                ]
            ]
        ]
        
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadata.self),walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Missing Input: client_metadata->authorization_encrypted_response_alg param is required", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenClientMetadataDoesNotHaveAuthorizationEncryptedResponseEnc() throws {
        let invalidClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats": [
                "mso_mdoc": [
                    "alg": [
                        "ES256",
                        "EdDSA"
                    ]
                ],
                "ldp_vp": [
                    "proof_type": [
                        "Ed25519Signature2018",
                        "Ed25519Signature2020",
                        "RsaSignature2018"
                    ]
                ]
            ]
        ]
        
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadata.self),walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Missing Input: client_metadata->authorization_encrypted_response_enc param is required", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenClientMetadataDoesNotHaveJwks() throws {
        let invalidClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM",
            "vp_formats": [
                "mso_mdoc": [
                    "alg": [
                        "ES256",
                        "EdDSA"
                    ]
                ],
                "ldp_vp": [
                    "proof_type": [
                        "Ed25519Signature2018",
                        "Ed25519Signature2020",
                        "RsaSignature2018"
                    ]
                ]
            ]
        ]
        
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadata.self),walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Missing Input: client_metadata->jwks param is required", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenClientMetadataDoesNotHaveJwkWithAlgorithmMentioned() throws {
        let invalidClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM",
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats": [
                "mso_mdoc": [
                    "alg": [
                        "ES256",
                        "EdDSA"
                    ]
                ],
                "ldp_vp": [
                    "proof_type": [
                        "Ed25519Signature2018",
                        "Ed25519Signature2020",
                        "RsaSignature2018"
                    ]
                ]
            ]
        ]
        
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadata.self),walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("No jwk matching the specified algorithm found for encryption", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenClientMetadataResponseEncDoesNotMatchWithWalletMetadataResponseEnc() throws {
        let invalidClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "GCM",
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats": [
                "ldp_vp": [
                    "proof_type": [
                        "Ed25519Signature2018",
                        "Ed25519Signature2020",
                        "RsaSignature2018"
                    ]
                ]
            ]
        ]
        
        let mismatchingWalletMetadata = try createWalletMetadataV2()
        
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadata.self), walletMetadata: mismatchingWalletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("authorization_encrypted_response_enc is not supported", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenClientMetadataResponseAlgDoesNotMatchWithWalletMetadataResponseAlg() throws {
        let invalidClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_alg": "ECDH-AS",
            "authorization_encrypted_response_enc": "A256GCM",
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-AS",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats": [
                "ldp_vp": [
                    "proof_type": [
                        "Ed25519Signature2018",
                        "Ed25519Signature2020",
                        "RsaSignature2018"
                    ]
                ]
            ]
        ]
        
        let mismatchingWalletMetadata = try createWalletMetadataV2()
        
        
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadata.self), walletMetadata: mismatchingWalletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("authorization_encrypted_response_alg is not supported", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenWalletMetadataIsNilAndIfRequiredValuesAreNil() throws {
        let validClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM",
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats": [
                "ldp_vp": [
                    "proof_type": [
                        "Ed25519Signature2018",
                        "Ed25519Signature2020",
                        "RsaSignature2018"
                    ]
                ]
            ]
        ]
        
        // Wallet metadata is nil
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(validClientMetadataForDirectPostJwt, as: ClientMetadata.self), walletMetadata: nil, shouldValidateWithWalletMetadata: true)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "wallet_metadata must be present",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
        
        // Alg values are nil
        var invalidWalletMetadata = try createWalletMetadataV2(authorizationEncryptionAlgValuesSupported: nil)
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(validClientMetadataForDirectPostJwt, as: ClientMetadata.self), walletMetadata: invalidWalletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "authorization_encryption_alg_values_supported must be present in wallet_metadata",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
        
        // Enc values are nil
        invalidWalletMetadata = try createWalletMetadataV2(authorizationEncryptionEncValuesSupported: nil)
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(validClientMetadataForDirectPostJwt, as: ClientMetadata.self), walletMetadata: invalidWalletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "authorization_encryption_enc_values_supported must be present in wallet_metadata",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testShouldNotThrowErrorForValidClientMetadataOnValidation() {
        XCTAssertNoThrow(try directPostJwtResponseModeHandler.validate(clientMetadata: mockClientMetadataObject,walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true))
    }
    
    /// Send authorization response tests
    
    func testSendAuthorizationResponseForDirectPostJwtResponseMode()  async throws {
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "Response has been shared successfully here.")
        let authorizationResponse: AuthorizationResponse = AuthorizationResponse(vpToken: mockVPTokens, presentationSubmission: mockPresentationSubmission, state: "state")
        
        do {
            let result = try await directPostJwtResponseModeHandler.sendAuthorizationResponse(authorizationRequest: mockAuthorizationRequestObjectWithDirectPostJwtResponseMode, authorizationResponse: authorizationResponse, url: mockAuthorizationRequestObjectWithDirectPostJwtResponseMode.responseUri!, networkManager: mockNetworkManager,
                                                                                              producerInfo: "mock-nonce",
                                                                                              recipientInfo: "verifier-nonce"
            )
            
            let recordedRequest = mockNetworkManager.recordedRequests[responseUri]
            XCTAssertEqual(HttpMethod.post, recordedRequest?.requestMethod)
            XCTAssertTrue(recordedRequest?.requestBody?.keys.count == 1)
            XCTAssertTrue(((recordedRequest?.requestBody?.keys.allSatisfy(["request"].contains(_:))) != nil))
            assertDictionariesEqual(expected: ["Content-Type":ContentTypes.applicationFormUrlEncoded.rawValue], actual: recordedRequest?.requestHeaders)
            XCTAssertEqual("Response has been shared successfully here.", result.body)
        }
    }
    
    func testShouldReturnEncryptedResponseForSuccessAuthorizationResponse() throws {
        let handler = DirectPostJwtResponseModeHandler()

        let authorizationResponse = AuthorizationResponse(
            vpToken: mockVPTokens,
            presentationSubmission: mockPresentationSubmission,
            state: "test-state"
        )

        let result = try handler.getAuthorizationResponse(
            authorizationRequest: mockAuthorizationRequestObjectWithDirectPostJwtResponseMode,
            authorizationResponse: authorizationResponse,
            walletNonce: "mock-nonce"
        )

        XCTAssertEqual(result.keys.count, 1)
        XCTAssertNotNil(result["response"])
        XCTAssertFalse(result["response"]!.isEmpty)

        XCTAssertTrue(result["response"]!.contains("."),
                      "Expected encrypted JWE compact format result")
    }
    
    func testGetAuthorizationResponseShouldReturnPlainErrorMapWhenErrorResponseGiven() throws {
        let handler = DirectPostJwtResponseModeHandler()

        let errorResponse = AuthorizationErrorResponse(
            error: "invalid_request",
            errorDescription: "something went wrong",
            state: "error-state"
        )

        let result = try handler.getAuthorizationErrorResponse(
            authorizationRequest: mockAuthorizationRequestObjectWithDirectPostJwtResponseMode,
            authorizationResponse: errorResponse,
            walletNonce: "mock-nonce"
        )

        XCTAssertEqual(result["error"], "invalid_request")
        XCTAssertEqual(result["error_description"], "something went wrong")
        XCTAssertEqual(result["state"], "error-state" )
        XCTAssertNil(result["response"])
    }
    
    func testGetAuthorizationResponseShouldReturnPlainErrorMapWhenErrorResponseGivenAndStateIsNil() throws {
        let handler = DirectPostJwtResponseModeHandler()

        let errorResponse = AuthorizationErrorResponse(
            error: "invalid_request",
            errorDescription: "something went wrong",
            state: nil
        )

        let result = try handler.getAuthorizationErrorResponse(
            authorizationRequest: mockAuthorizationRequestObjectWithDirectPostJwtResponseMode,
            authorizationResponse: errorResponse,
            walletNonce: "mock-nonce"
        )

        XCTAssertEqual(result["error"], "invalid_request")
        XCTAssertEqual(result["error_description"], "something went wrong")
        XCTAssertEqual(result["state"], nil)
        XCTAssertNil(result["response"])
    }

}
