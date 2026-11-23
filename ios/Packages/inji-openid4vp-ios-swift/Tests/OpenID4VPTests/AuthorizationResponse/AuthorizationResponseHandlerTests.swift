@testable import OpenID4VP
import JSONWebKey
import XCTest

final class AuthorizationResponseHandlerTests: XCTestCase {
    let mockNetworkManager = MockNetworkManager()
    let state = "state"
    let responseUri = "https://mock-verifier.com"
    let walletNonce = "_G6UkKgcsUPFlHAbzUMerA"
    let signatureSuite = SignatureSuite.ed25519Signature2020.rawValue
    let walletConfig = WalletConfig()

    private func makeDispatchInfo(
        responseMode: ResponseMode = .directPost,
        responseUrl: String? = nil
    ) -> ResponseDispatchInfo {
        ResponseDispatchInfo(
            responseMode: responseMode.rawValue,
            nonce: "tHwahwI6M5_Cd_Sj5k2_Aw",
            walletNonce: walletNonce,
            state: "state",
            clientId: "client_id",
            responseUrl: responseUrl ?? responseUri,
            responseEncryptionSpecification: nil
        )
    }

    // makeJwtDispatchInfo is provided by the shared makeJwtDispatchInfo() free function in TestUtils.swift
    
    // MARK: - OVP Spec Version Draft 23
    // MARK: Credential format = ldp_vc
    
    override func setUp() {
        super.setUp()
        JsonLd.setCanonicalizer { _ in "Y2Fub25pY2FsaXplZA" }
    }

    override func tearDown() {
        super.tearDown()
    }
    
    func testConstructAndSendAuthorizationResponseToVerifierHasTheAuthorizationResponseAsExpected() async throws {
        let verifiableCredentials: [String: [Credential]] = [
            "input_descriptor1": [
                Credential(format: .ldp_vc, data: AnyCodable(ldpVC()), credentialId: "credential1"),
                Credential(format: .ldp_vc, data: AnyCodable(ldpVC(credentialType: "UniversityCredential")), credentialId: "credential2"),
            ],
            "input_descriptor2": [Credential(format: .ldp_vc, data: AnyCodable(ldpVC()), credentialId: "credential3")],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)
        
        let unsignedVPTokens = try await handler.constructUnsignedVPToken(
            selectedCredentials: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            walletNonce: walletNonce
        )
        
        let vpTokenSigningResults = unsignedVPTokens.enumerated().map { index, token in
            VPTokenSigningResult(id: token.id, signedData: Data("signed\(index + 1)".utf8))
        }
        
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        
        let result = try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults,
            dispatchInfo: makeDispatchInfo()
        )
        
        XCTAssertEqual(result.body(), "sending is success in AuthorizationResponseTests")
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        XCTAssertEqual(recordedRequest.requestBody?["state"] as? String, state)
        XCTAssertNotNil(recordedRequest.requestBody?["presentation_submission"])
        XCTAssertEqual(recordedRequest.requestBody?.keys.count, 3)
    }
    
    func testConstructAndSendAuthorizationResponseToVerifierSendingAuthorizationResponseWithMultipleVPFormatsSuccessfully() async throws {
        let verifiableCredentials: [String: [Credential]] = [
            "input_descriptor1": [Credential(format: .ldp_vc, data: AnyCodable(ldpVC()), credentialId: "credential1")],
            "org.iso.18013.5.1.mDL": [Credential(format: .mso_mdoc, data: AnyCodable(sampleMdoc), credentialId: "credential2")],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let mockAuthorizationRequest = getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .draft23)
        
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        
        let unsignedVPTokens = try await handler.constructUnsignedVPToken(
            selectedCredentials: verifiableCredentials,
            authorizationRequest: mockAuthorizationRequest,
            walletNonce: walletNonce
        )
        
        let vpTokenSigningResults = unsignedVPTokens.map {
            VPTokenSigningResult(id: $0.id, signedData: Data("testJWS".utf8))
        }
        
        let result = try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: mockAuthorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults,
            dispatchInfo: try makeJwtDispatchInfo()
        )
        
        XCTAssertEqual(result.body(), "sending is success in AuthorizationResponseTests")
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        XCTAssertEqual(recordedRequest.requestBody?.keys.count, 1)
        XCTAssertNotNil(recordedRequest.requestBody?["response"])
    }
    
    // Common: spec version agnostic
    func testConstructAndSendAuthorizationResponseToVerifierThrowErrorWhenResponseTypeIsNotSupportedByLibrary() async {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(responseType: "fragment")
        
        do {
            _ = try await handler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest: authorizationRequest,
                vpTokenSigningResults: [],
                dispatchInfo: makeDispatchInfo(responseUrl: "https://client.example.org/cb")
            )
            XCTFail("Expected error not thrown")
        } catch {
            assertOpenID4VPException(error,
                                     expectedMessage: "The wallet encountered an internal error while preparing the authorization response.",
                                     expectedCode: OpenID4VPErrorCodes.serverError,
                                     expectedUnderlyingErrorMessage: "Provided response_type - fragment is not supported"
            )
        }
    }
    
    func testConstructAndSendAuthorizationResponseToVerifierToSharePresentationSubmissionOfLdpVCInExpectedFormat() async throws {
        // Arrange
        let verifiableCredentials: [String: [Credential]] = [
            "input_descriptor1": [Credential(format: .ldp_vc, data: AnyCodable(ldpVC()), credentialId: "credential1")],
            "org.iso.18013.5.1.mDL": [Credential(format: .mso_mdoc, data: AnyCodable(sampleMdoc), credentialId: "credential2")],
        ]
        let presentationDefinition: [String: Any] = [
            "id": "vp_presentation_definition",
            "input_descriptors": [
                [
                    "id": "input_descriptor1",
                    "name": "Verifiable Credential",
                    "purpose": "To verify identity using Linked Data Proofs",
                    "format": [
                        "ldp_vc": [
                            "proof_type": ["Ed25519Signature2018", "RsaSignature2018"]
                        ]
                    ],
                    "constraints": [
                        "fields": [
                            [
                                "path": ["$.credentialSubject.email"],
                                "filter": [
                                    "type": "string",
                                    "pattern": "@gmail.com"
                                ]
                            ]
                        ]
                    ]
                ],
                [
                    "id": "org.iso.18013.5.1.mDL",
                    "name": "MSO MDOC",
                    "purpose": "To verify identity using MSO Mobile Driving License",
                    "format": [
                        "mso_mdoc": [
                            "alg": ["ES256"]
                        ]
                    ],
                    "constraints": [:]
                ]
            ]
        ]

        let mockPresentationDefinitionObject = createInstance(presentationDefinition, as: PresentationDefinition.self)
        
        let expectedPresentationSubmissionTemplateWithMdocFirst = """
        {
            "definition_id": "vp_presentation_definition",
            "descriptor_map": [
                {
                    "id": "org.iso.18013.5.1.mDL",
                    "format": "mso_mdoc",
                    "path": "$[0]"
                },
                {
                    "format": "ldp_vp",
                    "id": "input_descriptor1",
                    "path": "$[1]",
                    "path_nested": {
                        "id": "input_descriptor1",
                        "path": "$.verifiableCredential[0]",
                        "format": "ldp_vc"
                    }
                }
            ],
            "id": "<DYNAMIC_ID>"
        }
        """
        
        let expectedPresentationSubmissionTemplateWithLdpFirst = """
        {
            "definition_id": "vp_presentation_definition",
            "descriptor_map": [
                {
                    "format": "ldp_vp",
                    "id": "input_descriptor1",
                    "path": "$[0]",
                    "path_nested": {
                        "id": "input_descriptor1",
                        "path": "$.verifiableCredential[0]",
                        "format": "ldp_vc"
                    }
                },        
                {
                    "id": "org.iso.18013.5.1.mDL",
                    "format": "mso_mdoc",
                    "path": "$[1]"
                }
            ],
            "id": "<DYNAMIC_ID>"
        }
        """
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        
        let unsignedVPTokens = try await handler.constructUnsignedVPToken(
            selectedCredentials: verifiableCredentials,
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23, presentationDefinition: mockPresentationDefinitionObject),
            walletNonce: walletNonce
        )
        
        mockNetworkManager.setMockResponse(
            for: responseUri,
            responseBody: "sending is success in AuthorizationResponseTests"
        )
        
        let mockVPTokenSigningResults = unsignedVPTokens.map {
            VPTokenSigningResult(id: $0.id, signedData: Data("testJWS".utf8))
        }
        
        _ = try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            vpTokenSigningResults: mockVPTokenSigningResults,
            dispatchInfo: makeDispatchInfo()
        )
        
        // Extract actual response
        guard let recordedRequest = mockNetworkManager.recordedRequests[responseUri],
              let actualBody = recordedRequest.requestBody?["presentation_submission"] else {
            XCTFail("No recorded request found for \(responseUri)")
            return
        }
        
        // Get actual ID
        let actualJson = decodeQueryValue(actualBody)
        guard let actualData = actualJson.data(using: .utf8),
              let actualDict = try JSONSerialization.jsonObject(with: actualData) as? [String: Any],
              let actualId = actualDict["id"] as? String else {
            XCTFail("Could not parse or extract ID from actual body")
            return
        }
        
        let vpToken = recordedRequest.requestBody?["vp_token"] as? String
        // This check is made to avoid flakiness in tests as the order of credentials in vp_token is not guaranteed due to input mtaching credentials being a map
        let expectedPresentationSubmissionTemplate: String = vpToken?.starts(with: "[\"o") ?? false ? expectedPresentationSubmissionTemplateWithMdocFirst : expectedPresentationSubmissionTemplateWithLdpFirst
        
        // Replace the dynamic ID in expected string
        let expectedJsonString = expectedPresentationSubmissionTemplate.replacingOccurrences(of: "<DYNAMIC_ID>", with: actualId)
        
        assertJsonString(
            expected: expectedJsonString,
            actual: actualJson,
            strict: false
        )
    }
    
    // MARK: Credential format = SD-JWT, common spec version agnostic tests
    
    func testCreationOfUnsignedVPTokenWithSdJwtFormatSuccess() async throws {
        let verifiableCredentials: [String: [Credential]] = [
            "cred1": [Credential(format: .vc_sd_jwt, data: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialId: "credential1")],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest()
        
        await XCTAssertNoThrowAndVerifyAsync(try await handler.constructUnsignedVPToken(
            selectedCredentials: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            walletNonce: walletNonce
        )) { result in
            XCTAssertTrue(result.count == 1)
        }
    }
    
    func testSharingOfSdJwtWithHolderBindingSuccess() async throws {
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        let verifiableCredentials: [String: [Credential]] = [
            "input_descriptor2": [Credential(format: .vc_sd_jwt, data: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialId: "credential1")],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)
        let unsignedVPTokens = try await handler.constructUnsignedVPToken(
            selectedCredentials: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            walletNonce: walletNonce
        )
        
        let result = try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: unsignedVPTokens.map { VPTokenSigningResult(id: $0.id, signedData: Data("ayuht".utf8)) },
            dispatchInfo: makeDispatchInfo()
        )
        
        XCTAssertEqual(result.body(), "sending is success in AuthorizationResponseTests")
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        XCTAssertEqual(recordedRequest.requestBody?["state"] as? String, state)
        let presentationSubmission: String? = recordedRequest.requestBody?["presentation_submission"]
        XCTAssertNotNil(presentationSubmission)
        XCTAssertEqual(recordedRequest.requestBody?.keys.count, 3)
    }

    func testSharingOfSdJwtWithoutHolderBindingPreservesCredential() async throws {
        let verifiableCredentials: [String: [Credential]] = [
            "input_descriptor2": [Credential(format: .vc_sd_jwt, data: AnyCodable(sampleVcSdJwtWithNoHolderBinding), credentialId: "credential1")],
        ]

        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)

        let unsignedVPTokens = try await handler.constructUnsignedVPToken(
            selectedCredentials: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            walletNonce: walletNonce
        )

        XCTAssertTrue(unsignedVPTokens.isEmpty)

        let authorizationResponse = try handler.constructVPResponse(
            signingResults: [],
            authorizationRequest: authorizationRequest,
            dispatchInfo: makeDispatchInfo()
        )

        let encodedVpToken = try XCTUnwrap(authorizationResponse["vp_token"])
        let vpToken = try JSONDecoder().decode(String.self, from: Data(encodedVpToken.utf8))
        XCTAssertEqual(vpToken, sampleVcSdJwtWithNoHolderBinding)
    }
    
    // MARK: Credential format = All supported credential formats combination
    
    func testConstructUnsignedVPTokenSuccess() async throws {
        let verifiableCredentials: [String: [Credential]] = [
            "input_descriptor1": [Credential(format: .ldp_vc, data: AnyCodable(ldpVC()), credentialId: "credential1")],
            "org.iso.18013.5.1.mDL": [Credential(format: .mso_mdoc, data: AnyCodable(sampleMdoc), credentialId: "credential2")],
            "input_descriptor2": [Credential(format: .vc_sd_jwt, data: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialId: "credential3")],
            "input_descriptor3": [Credential(format: .dc_sd_jwt, data: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialId: "credential4")],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)
        
        await XCTAssertNoThrowAndVerifyAsync(try await handler.constructUnsignedVPToken(
            selectedCredentials: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            walletNonce: walletNonce
        )) { result in
            XCTAssertTrue(result.count == 4)
        }
    }
    
    func testShareAuthorizationResponseSuccess() async throws {
        mockNetworkManager.clearResponses()
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        let verifiableCredentials: [String: [Credential]] = [
            "input_descriptor1": [Credential(format: .ldp_vc, data: AnyCodable(ldpVC()), credentialId: "credential1")],
            "org.iso.18013.5.1.mDL": [Credential(format: .mso_mdoc, data: AnyCodable(sampleMdoc), credentialId: "credential2")],
            "input_descriptor2": [Credential(format: .vc_sd_jwt, data: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialId: "credential3")],
            "input_descriptor3": [Credential(format: .dc_sd_jwt, data: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialId: "credential4")],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)
        let unsignedVPTokens = try await handler.constructUnsignedVPToken(
            selectedCredentials: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            walletNonce: walletNonce
        )
        
        let vpTokenSigningResults = unsignedVPTokens.map {
            VPTokenSigningResult(id: $0.id, signedData: Data("ayuht".utf8))
        }
        
        _ = try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults,
            dispatchInfo: makeDispatchInfo()
        )
        
        let recordedRequest = (mockNetworkManager.recordedRequests[responseUri]!).requestBody
        XCTAssertEqual(recordedRequest?["state"] as? String, state)
        XCTAssertNotNil(recordedRequest?["presentation_submission"])
    }
    
    func testThrowExceptionWhenVPTokenSigningResultMissingForAFormat() async throws {
        mockNetworkManager.clearResponses()
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        let verifiableCredentials: [String: [Credential]] = [
            "input_descriptor1": [Credential(format: .ldp_vc, data: AnyCodable(ldpVC()), credentialId: "credential1")],
            "org.iso.18013.5.1.mDL": [Credential(format: .mso_mdoc, data: AnyCodable(sampleMdoc), credentialId: "credential2")],
            "input_descriptor2": [Credential(format: .vc_sd_jwt, data: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialId: "credential3")],
            "input_descriptor3": [Credential(format: .dc_sd_jwt, data: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialId: "credential4")],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)
        let unsignedVPTokens = try await handler.constructUnsignedVPToken(
            selectedCredentials: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            walletNonce: walletNonce
        )

        // Provide signing results for all but the last token — simulates a missing result
        let vpTokenSigningResults = unsignedVPTokens.dropLast().map {
            VPTokenSigningResult(id: $0.id, signedData: Data("testJWS".utf8))
        }
        
        do {
            _ = try await handler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest: authorizationRequest,
                vpTokenSigningResults: vpTokenSigningResults,
                dispatchInfo: makeDispatchInfo(responseUrl: "https://client.example.org/cb")
            )
            XCTFail("Expected error not thrown")
        } catch {
            assertOpenID4VPException(
                error,
                expectedMessage: "The wallet encountered an internal error while preparing the authorization response.",
                expectedCode: OpenID4VPErrorCodes.serverError
            )
            // the uuid is runtime-generated so we match the prefix only.
            if let causeMessage = (error as? OpenID4VPException)?.cause?.localizedDescription {
                XCTAssertTrue(
                    causeMessage.hasPrefix("Missing VP token signing result for credential identifier "),
                    "Expected cause about missing signing result, got: \(causeMessage)"
                )
            } else {
                XCTFail("Expected OpenID4VPException with an identifier-linked cause, got: \(error)")
            }
        }
    }
    
    func testConstructAuthorizationErrorResponseMapsErrorCorrectly() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)
        let error = InvalidData(message: "Invalid input data", className: "Test")

        let response = handler.constructAuthorizationErrorResponse(
            dispatchInfo: makeDispatchInfo(),
            error: error,
            walletNonce: "wallet-nonce",
            authorizationRequest: authorizationRequest
        )

        XCTAssertEqual(response["error"] as? String, "invalid_request")
        XCTAssertEqual(response["error_description"] as? String, "Invalid input data")
        XCTAssertEqual(response["state"] as? String, state)
    }
    
    
    func testConstructAuthorizationResponseSuccess() async throws {
        let verifiableCredentials: [String: [Credential]] = [
            "input_descriptor1": [Credential(format: .ldp_vc, data: AnyCodable(ldpVC()), credentialId: "credential1")],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(responseMode: .directPost, specVersion: .draft23)
        
        let unsignedVPTokens = try await handler.constructUnsignedVPToken(
            selectedCredentials: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            walletNonce: walletNonce
        )
        
        let vpTokenSigningResults = unsignedVPTokens.map {
            VPTokenSigningResult(id: $0.id, signedData: Data("testJWS".utf8))
        }
        
        let authorizationResponse = try handler.constructVPResponse(
            signingResults: vpTokenSigningResults, authorizationRequest: authorizationRequest,
            dispatchInfo: makeDispatchInfo()
        )
        
        XCTAssertNotNil(authorizationResponse["vp_token"])
        XCTAssertNotNil(authorizationResponse["presentation_submission"])
        XCTAssertEqual(authorizationResponse["state"], state)
    }
    
    func testConstructAuthorizationResponseThrowsErrorForUnsupportedResponseType() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(responseType: "fragment", specVersion: .draft23)
        
        XCTAssertThrowsError(
            try handler.constructVPResponse(
                signingResults: [],
                authorizationRequest: authorizationRequest,
                dispatchInfo: nil
            )
        ) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "The wallet encountered an internal error while preparing the authorization response.",
                                     expectedCode: OpenID4VPErrorCodes.serverError,
                                     expectedUnderlyingErrorMessage: "Provided response_type - fragment is not supported"
            )
        }
    }

    func testConstructVPResponseThrowsErrorDispatchFailureWhenDispatchInfoIsNil() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)

        XCTAssertThrowsError(
            try handler.constructVPResponse(
                signingResults: [],
                authorizationRequest: authorizationRequest,
                dispatchInfo: nil
            )
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "The wallet encountered an internal error while preparing the authorization response.",
                expectedCode: OpenID4VPErrorCodes.serverError,
                expectedUnderlyingErrorMessage: "Failed to send error to verifier: Response dispatch details are not set. Cannot construct VP response."
            )
        }
    }

    func testConstructAndSendThrowsErrorDispatchFailureWhenDispatchInfoIsNil() async {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)

        await XCTAssertAsyncThrowsError(
            try await handler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest: authorizationRequest,
                vpTokenSigningResults: [],
                dispatchInfo: nil
            )
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "The wallet encountered an internal error while preparing the authorization response.",
                expectedCode: OpenID4VPErrorCodes.serverError,
                expectedUnderlyingErrorMessage: "Failed to send error to verifier: Response dispatch details are not set. Cannot send authorization response to verifier."
            )
        }
    }
    
    func testConstructAuthorizationErrorResponseWithOpenIDException() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)

        let error = InvalidData(
            message: "Invalid input data",
            className: "TestClass"
        )

        let response = handler.constructAuthorizationErrorResponse(
            dispatchInfo: makeDispatchInfo(),
            error: error,
            walletNonce: "wallet-nonce",
            authorizationRequest: authorizationRequest
        )

        XCTAssertEqual(response["error"] as? String, "invalid_request")
        XCTAssertEqual(response["error_description"] as? String, "Invalid input data")
        XCTAssertEqual(response["state"] as? String, state)
    }

    func testConstructAuthorizationErrorResponseWithGenericError() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)

        let error = NSError(domain: "test", code: 500)

        let response = handler.constructAuthorizationErrorResponse(
            dispatchInfo: makeDispatchInfo(),
            error: error,
            walletNonce: "wallet-nonce",
            authorizationRequest: authorizationRequest
        )

        XCTAssertEqual(response["error"] as? String, "server_error")
        XCTAssertNotNil(response["error_description"])
        XCTAssertEqual(response["state"] as? String, state)
    }

    // common spec version agnostic tests
    func testConstructAuthorizationErrorResponseReturnMinimalErrorResponseIfConstructionOfErrorFails() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let dispatchInfo = ResponseDispatchInfo(
            responseMode: "fragment",
            nonce: nil,
            walletNonce: nil,
            state: nil,
            clientId: "mock-client",
            responseUrl: responseUri,
            responseEncryptionSpecification: nil
        )

        let error = NSError(domain: "test", code: 500)

        let response = handler.constructAuthorizationErrorResponse(
            dispatchInfo: dispatchInfo,
            error: error,
            walletNonce: "wallet-nonce"
        )

        XCTAssertEqual(response["error"] as? String, "invalid_request")
        XCTAssertNotNil(response["error_description"])
        XCTAssertTrue((response["error_description"] as? String)?.starts(with: "Failed to construct error response:") == true)
    }
    
    // MARK: - OVP Spec Version 1

    func testV1ConstructAndSendAuthorizationResponseHasExpectedBody() async throws {
        let verifiableCredentials: [String: [Credential]] = [
            "cred1": [Credential(format: .dc_sd_jwt, data: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialId: "credentialId1")],
            "cred2": [Credential(format: .mso_mdoc, data: AnyCodable(sampleMdoc), credentialId: "credentialId2")],
            "cred3": [Credential(format: .ldp_vc, data: AnyCodable(ldpVC()), credentialId: "credentialId2")]
        ]
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .v1)

        let unsignedVPTokens = try await handler.constructUnsignedVPToken(
            selectedCredentials: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            walletNonce: walletNonce
        )

        let vpTokenSigningResults = unsignedVPTokens.map {
            VPTokenSigningResult(id: $0.id, signedData: Data("testJWS".utf8))
        }

        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")

        let result = try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults,
            dispatchInfo: makeDispatchInfo()
        )

        XCTAssertEqual(result.body(), "sending is success in AuthorizationResponseTests")
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        XCTAssertEqual(recordedRequest.requestBody?["state"] as? String, state)
        XCTAssertNotNil(recordedRequest.requestBody?["vp_token"])
        XCTAssertEqual(recordedRequest.requestBody?.keys.count, 2)
    }

    func testV1ConstructAndSendAuthorizationResponseThrowsForUnsupportedResponseType() async {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(responseType: "fragment", specVersion: .v1)

        await XCTAssertAsyncThrowsError(try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: [],
            dispatchInfo: makeDispatchInfo(responseUrl: "https://client.example.org/cb")
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "The wallet encountered an internal error while preparing the authorization response.",
                expectedCode: OpenID4VPErrorCodes.serverError,
                expectedUnderlyingErrorMessage: "Provided response_type - fragment is not supported"
            )
        }
    }

    // MARK: - Spec Version 1 - Credential format = SD-JWT

    func testV1ConstructUnsignedVPTokenWithSdJwtSuccess() async throws {
        let verifiableCredentials: [String: [Credential]] = [
            "cred1": [Credential(format: .dc_sd_jwt, data: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialId: "cred1")],
        ]

        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .v1)

        await XCTAssertNoThrowAndVerifyAsync(try await handler.constructUnsignedVPToken(
            selectedCredentials: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            walletNonce: walletNonce
        )) { result in
            XCTAssertEqual(result.count, 1)
        }
    }

    // MARK: - Spec Version 1 - constructUnsignedVPToken

    func testV1ConstructUnsignedVPTokenWithAllFormatsSuccess() async throws {
        let verifiableCredentials: [String: [Credential]] = [
            "cred1": [Credential(format: .dc_sd_jwt, data: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialId: "credentialId1")],
            "cred2": [Credential(format: .mso_mdoc, data: AnyCodable(sampleMdoc), credentialId: "credentialId2")],
            "cred3": [Credential(format: .ldp_vc, data: AnyCodable(ldpVC()), credentialId: "credentialId2")]
        ]

        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .v1)

        await XCTAssertNoThrowAndVerifyAsync(try await handler.constructUnsignedVPToken(
            selectedCredentials: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            walletNonce: walletNonce
        )) { result in
            XCTAssertEqual(result.count, 3)
            let actualUnsignedVpTokenResultFormats = result.map({$0.format.rawValue})
            XCTAssertEqual([FormatType.ldp_vc.rawValue, FormatType.mso_mdoc.rawValue, FormatType.dc_sd_jwt.rawValue].sorted(), actualUnsignedVpTokenResultFormats.sorted())
        }
    }

    func testV1ShareAuthorizationResponseWithAllFormatsSuccess() async throws {
        mockNetworkManager.clearResponses()
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        let verifiableCredentials: [String: [Credential]] = [
            "cred3": [Credential(format: .ldp_vc, data: AnyCodable(ldpVC()), credentialId: "cred3")],
            "cred2": [Credential(format: .mso_mdoc, data: AnyCodable(sampleMdoc), credentialId: "cred2")],
            "cred1": [Credential(format: .dc_sd_jwt, data: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialId: "cred1")],
        ]

        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .v1)
        let unsignedVPTokens = try await handler.constructUnsignedVPToken(
            selectedCredentials: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            walletNonce: walletNonce
        )

        let vpTokenSigningResults = unsignedVPTokens.map {
            VPTokenSigningResult(id: $0.id, signedData: Data("testJWS".utf8))
        }

        _ = try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults,
            dispatchInfo: makeDispatchInfo()
        )

        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!.requestBody
        XCTAssertEqual(recordedRequest?["state"] as? String, state)
        XCTAssertNotNil(recordedRequest?["vp_token"])
    }

    // MARK: - Spec Version 1 - constructAuthorizationResponse

    func testV1ConstructAuthorizationResponseSuccess() async throws {
        let verifiableCredentials: [String: [Credential]] = [
            "cred3": [Credential(format: .ldp_vc, data: AnyCodable(ldpVC()), credentialId: "cred3")],
        ]

        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(responseMode: .directPost, specVersion: .v1)

        let unsignedVPTokens = try await handler.constructUnsignedVPToken(
            selectedCredentials: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            walletNonce: walletNonce
        )

        let vpTokenSigningResults = unsignedVPTokens.map {
            VPTokenSigningResult(id: $0.id, signedData: Data("testJWS".utf8))
        }

        let authorizationResponse = try handler.constructVPResponse(
            signingResults: vpTokenSigningResults, authorizationRequest: authorizationRequest,
            dispatchInfo: makeDispatchInfo()
        )

        XCTAssertNotNil(authorizationResponse["vp_token"])
        XCTAssertEqual(authorizationResponse["state"], state)
    }

    func testV1ConstructAuthorizationResponseThrowsForUnsupportedResponseType() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(responseType: "fragment", specVersion: .v1)

        XCTAssertThrowsError(try handler.constructVPResponse(
            signingResults: [], authorizationRequest: authorizationRequest, dispatchInfo: nil
        )) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "The wallet encountered an internal error while preparing the authorization response.",
                                     expectedCode: OpenID4VPErrorCodes.serverError,
                                     expectedUnderlyingErrorMessage: "Provided response_type - fragment is not supported"
            )
        }
    }

    // MARK: - Spec Version 1 - constructAuthorizationErrorResponse

    func testV1ConstructAuthorizationErrorResponseMapsErrorCorrectly() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .v1)
        let error = InvalidData(message: "Invalid input data", className: "Test")

        let response = handler.constructAuthorizationErrorResponse(
            dispatchInfo: makeDispatchInfo(),
            error: error,
            walletNonce: "wallet-nonce",
            authorizationRequest: authorizationRequest
        )

        XCTAssertEqual(response["error"] as? String, "invalid_request")
        XCTAssertEqual(response["error_description"] as? String, "Invalid input data")
        XCTAssertEqual(response["state"] as? String, state)
    }

    func testV1ConstructAuthorizationErrorResponseWithGenericError() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .v1)
        let error = NSError(domain: "test", code: 500)

        let response = handler.constructAuthorizationErrorResponse(
            dispatchInfo: makeDispatchInfo(),
            error: error,
            walletNonce: "wallet-nonce",
            authorizationRequest: authorizationRequest
        )

        XCTAssertEqual(response["error"] as? String, "server_error")
        XCTAssertNotNil(response["error_description"])
        XCTAssertEqual(response["state"] as? String, state)
    }

    func testSendAuthorizationErrorWithDispatchInfoSendsErrorViaResponseModeHandler() async throws {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(responseMode: .directPost, specVersion: .draft23)
        let error = AccessDenied(message: "User denied", className: "test")
        let dispatchInfo = ResponseDispatchInfo(
            responseMode: ResponseMode.directPost.rawValue,
            nonce: "nonce",
            walletNonce: "wallet-nonce",
            state: state,
            clientId: "mock-client",
            responseUrl: responseUri,
            responseEncryptionSpecification: nil
        )

        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "{\"message\":\"Some additional info\"}")

        let verifierResponse = try await handler.sendAuthorizationError(
            dispatchInfo: dispatchInfo,
            authorizationRequest: authorizationRequest,
            error: error
        )

        XCTAssertEqual(verifierResponse.statusCode, 200)
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]
        XCTAssertNotNil(recordedRequest)
        XCTAssertEqual(recordedRequest?.requestBody?["error"] as? String, "access_denied")
        XCTAssertEqual(recordedRequest?.requestBody?["error_description"] as? String, "User denied")
        XCTAssertEqual(recordedRequest?.requestBody?["state"] as? String, state)
    }

    func testSendAuthorizationErrorWithJwtDispatchInfoSendsEncryptedResponse() async throws {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let authorizationRequest = getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .draft23)
        let error = AccessDenied(message: "User denied", className: "test")
        let dispatchInfo = try makeJwtDispatchInfo(responseUrl: responseUri)

        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "{\"message\":\"Some additional info\"}")

        let verifierResponse = try await handler.sendAuthorizationError(
            dispatchInfo: dispatchInfo,
            authorizationRequest: authorizationRequest,
            error: error
        )

        XCTAssertEqual(verifierResponse.statusCode, 200)
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]
        XCTAssertNotNil(recordedRequest)
        XCTAssertNotNil(recordedRequest?.requestBody?["response"], "Error should be encrypted for direct_post.jwt")
        XCTAssertNil(recordedRequest?.requestBody?["error"])
        XCTAssertNil(recordedRequest?.requestBody?["error_description"])
        XCTAssertNil(recordedRequest?.requestBody?["state"])
    }

    func testSendAuthorizationErrorWithDispatchInfoThrowsWhenNetworkFails() async throws {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        let error = AccessDenied(message: "Denied", className: "test")
        let failingUrl = "https://failing-verifier.com"
        let dispatchInfo = ResponseDispatchInfo(
            responseMode: ResponseMode.directPost.rawValue,
            nonce: nil,
            walletNonce: nil,
            state: nil,
            clientId: "mock-client",
            responseUrl: failingUrl,
            responseEncryptionSpecification: nil
        )
        mockNetworkManager.setMockResponse(for: failingUrl, error: NSError(domain: "NetworkError", code: -1))

        await XCTAssertAsyncThrowsError(
            try await handler.sendAuthorizationError(
                dispatchInfo: dispatchInfo,
                authorizationRequest: nil,
                error: error
            )
        ) { thrownError in
            XCTAssertTrue(thrownError.localizedDescription.contains("Failed to send error to verifier"))
        }
    }
}
