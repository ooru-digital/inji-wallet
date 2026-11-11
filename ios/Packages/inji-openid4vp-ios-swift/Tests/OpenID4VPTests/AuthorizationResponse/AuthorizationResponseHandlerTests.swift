@testable import OpenID4VP
import XCTest

final class AuthorizationResponseHandlerTests: XCTestCase {
    let mockNetworkManager = MockNetworkManager()
    let state = "state"
    let responseUri = "https://mock-verifier.com"
    let holderId = "wallet-holder-id"
    let walletNonce = "mock-nonce"
    let signatureSuite = "JsonWebSignature2020"
    
    // MARK: Credential format = ldp_vc
    
    func testConstructUnsignedVPTokenThrowsErrorIncaseOfInvalidHoldersIdWithLdpVCAvailable() async throws {
        let invalidHolderIdTestCases = ["", " ", "  ", "null", nil]
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
        for holderId in invalidHolderIdTestCases {
            await XCTAssertAsyncThrowsError(try await handler.constructUnsignedVPToken(
                credentialsMap: verifiableCredentials,
                authorizationRequest: authorizationRequest,
                responseUri: responseUri,
                holderId: holderId,
                signatureSuite: "JsonWebSignature2020",
                walletNonce: "mock-nonce"
            )) { error in
                assertOpenID4VPException(error,
                                         expectedMessage: "Holder ID cannot be null or empty for LDP VC format",
                                         expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }
    
    func testConstructUnsignedVPTokenThrowsErrorIncaseOfInvalidSignatureSuitesWithLdpVCAvailable() async throws {
        let invalidsignatureSuiteTestCases = ["", " ", "  ", "null", nil]
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
        for invalidSignatureSuite in invalidsignatureSuiteTestCases {
            await XCTAssertAsyncThrowsError(try await handler.constructUnsignedVPToken(
                credentialsMap: verifiableCredentials,
                authorizationRequest: authorizationRequest,
                responseUri: responseUri,
                holderId: holderId,
                signatureSuite: invalidSignatureSuite,
                walletNonce: walletNonce
            )) { error in
                assertOpenID4VPException(error,
                                         expectedMessage: "Signature Suite cannot be null or empty for LDP VC format",
                                         expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }
    
    func testConstructUnsignedVPTokenV1Success() async throws {
        let verifiableCredentials: [String: [String]] = [
            "input_descriptor1": ["{\"credentialSubject\"...}"],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
        
        await XCTAssertNoThrowAndVerifyAsync(try await handler.constructUnsignedVPTokenV1(
            verifiableCredentials: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            walletNonce: walletNonce
        )) { result in
            XCTAssertTrue(result.contains("credentialSubject"))
        }
    }
    
    func testConstructAndSendAuthorizationResponseToVerifierHasTheAuthorizationResponseAsExpected() async throws {
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC()), AnyCodable(ldpVC(credentialType: "UniversityCredential"))]],
            "input_descriptor2": [.ldp_vc: [AnyCodable(ldpVC())]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
        
        _ = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )
        
        let vpTokenSigningResults = [FormatType.ldp_vc: LdpVPTokenSigningResult(
            jws: "testJWS",
            proofValue: "",
            signatureAlgorithm: "JsonWebSignature2020"
        )]
        
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        
        let result = try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults,
            responseUri: responseUri
        )
        
        XCTAssertEqual(result.body(), "sending is success in AuthorizationResponseTests")
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        XCTAssertEqual(recordedRequest.requestBody?["state"] as? String, state)
        XCTAssertNotNil(recordedRequest.requestBody?["presentation_submission"])
        XCTAssertEqual(recordedRequest.requestBody?.keys.count, 3)
    }
    
    func testConstructAndSendAuthorizationResponseToVerifierSendingAuthorizationResponseWithMultipleVPFormatsSuccessfully() async throws {
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let mockAuthorizationRequest = getMockAuthorizationRequest(responseMode: .directPostJwt)
        
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        
        let vpTokenSigningResults: [FormatType: VPTokenSigningResult] = [
            .ldp_vc: LdpVPTokenSigningResult(jws: "testJWS", proofValue: "", signatureAlgorithm: "JsonWebSignature2020"),
            .mso_mdoc: MdocVPTokenSigningResult(docTypeToDeviceAuthentication: ["org.iso.18013.5.1.mDL": DeviceAuthentication(signature: "aGVsbG8=", algorithm: "ES256")]),
        ]
        
        _ = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: mockAuthorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )
        
        let result = try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: mockAuthorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults,
            responseUri: responseUri
        )
        
        XCTAssertEqual(result.body(), "sending is success in AuthorizationResponseTests")
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        XCTAssertEqual(recordedRequest.requestBody?.keys.count, 1)
        XCTAssertNotNil(recordedRequest.requestBody?["response"])
    }
    
    func testConstructAndSendAuthorizationResponseToVerifierThrowErrorWhenResponseTypeIsNotSupportedByLibrary() async {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest(responseType: "fragment")
        
        do {
            _ = try await handler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest: authorizationRequest,
                vpTokenSigningResults: [:],
                responseUri: "https://client.example.org/cb"
            )
            XCTFail("Expected error not thrown")
        } catch {
            assertOpenID4VPException(error,
                                     expectedMessage: "Provided response_type - fragment is not supported",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testConstructAndSendAuthorizationResponseToVerifierThrowErrorWhenRespectiveCredentialFormatIsNotAvailableInUnsignedVPTokens() async {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
        _ = try? await handler.constructUnsignedVPToken(
            credentialsMap: [:],
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )
        
        do {
            _ = try await handler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest: authorizationRequest,
                vpTokenSigningResults: [FormatType.ldp_vc: LdpVPTokenSigningResult(jws: "", proofValue: "", signatureAlgorithm: "")],
                responseUri: "https://client.example.org/cb"
            )
            XCTFail("Expected error not thrown")
        } catch {
            assertOpenID4VPException(error,
                                     expectedMessage: "VPTokenSigningResult not provided for the required formats",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testConstructAndSendAuthorizationResponseToVerifierToSharePresentationSubmissionOfLdpVCInExpectedFormat() async throws {
        // Arrange
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
        ]
        
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
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        
        _ = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: mockAuthorizationRequestObjectWithDirectPostResponseMode,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )
        
        mockNetworkManager.setMockResponse(
            for: responseUri,
            responseBody: "sending is success in AuthorizationResponseTests"
        )
        
        let mockVPTokenSigningResults: [FormatType: VPTokenSigningResult] = [
            .ldp_vc: LdpVPTokenSigningResult(
                jws: "testJWS",
                proofValue: "test",
                signatureAlgorithm: "JsonWebSignature2020"
            ),
            .mso_mdoc: MdocVPTokenSigningResult(docTypeToDeviceAuthentication: ["org.iso.18013.5.1.mDL": DeviceAuthentication(signature: "sign", algorithm: "ES256")]),
        ]
        
        _ = try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: mockAuthorizationRequestObjectWithDirectPostResponseMode,
            vpTokenSigningResults: mockVPTokenSigningResults,
            responseUri: responseUri
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
    
    // MARK: Credential format = SD-JWT
    
    func testCreationOfUnsignedVPTokenWithSdJwtFormatSuccess() async throws {
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor2": [.vc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
        
        await XCTAssertNoThrowAndVerifyAsync(try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )) { result in
            XCTAssertTrue(result.keys.count == 1)
            XCTAssertTrue(result.keys.contains(.vc_sd_jwt))
            XCTAssertTrue((result.values.first as? UnsignedSdJwtVPToken)?.uuidToUnsignedKBT.count == 1)
        }
    }
    
    func testSharingOfSdJwtWithHolderBindingSuccess() async throws {
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor2": [.vc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
        let unsignedVpTokens = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )
        
        let sdJwtUUID = (unsignedVpTokens[.vc_sd_jwt] as! UnsignedSdJwtVPToken).uuidToUnsignedKBT.keys.first!
        let result = try await handler.constructAndSendAuthorizationResponseToVerifier(authorizationRequest: authorizationRequest, vpTokenSigningResults: [.vc_sd_jwt: SdJwtVpTokenSigningResult(uuidToKbJWTSignature: [sdJwtUUID: "ayuht"])], responseUri: responseUri)
        
        XCTAssertEqual(result.body(), "sending is success in AuthorizationResponseTests")
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        XCTAssertEqual(recordedRequest.requestBody?["state"] as? String, state)
        let presentationSubmission: String? = recordedRequest.requestBody?["presentation_submission"]
        XCTAssertNotNil(presentationSubmission)
        XCTAssertEqual(recordedRequest.requestBody?.keys.count, 3)
    }
    
    // MARK: Credential format = All supported credential formats combination
    
    func testConstructUnsignedVPTokenSuccess() async throws {
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
            "input_descriptor2": [.vc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
            "input_descriptor3": [.dc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
        
        await XCTAssertNoThrowAndVerifyAsync(try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )) { result in
            XCTAssertTrue(result.keys.contains(.ldp_vc))
            XCTAssertTrue(result.keys.contains(.mso_mdoc))
            XCTAssertTrue(result.keys.contains(.vc_sd_jwt))
            XCTAssertTrue(result.keys.contains(.dc_sd_jwt))
        }
    }
    
    func testShareAuthorizationResponseSuccess() async throws {
        mockNetworkManager.clearResponses()
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
            "input_descriptor2": [.vc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
            "input_descriptor3": [.dc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
        let unsignedVPTokens = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )
        let vcSdJwtUuids = Array((unsignedVPTokens[.vc_sd_jwt] as! UnsignedSdJwtVPToken).uuidToUnsignedKBT.keys)
        let dcSdJwtUuids = Array((unsignedVPTokens[.dc_sd_jwt] as! UnsignedSdJwtVPToken).uuidToUnsignedKBT.keys)
        
        let vpTokenSigningResults: [FormatType: VPTokenSigningResult] = [
            FormatType.ldp_vc: LdpVPTokenSigningResult(
                jws: "testJWS",
                proofValue: "",
                signatureAlgorithm: "JsonWebSignature2020"),
            .mso_mdoc: MdocVPTokenSigningResult(docTypeToDeviceAuthentication: ["org.iso.18013.5.1.mDL": DeviceAuthentication(signature: "aGVsbG8=", algorithm: "ES256")]),
            .vc_sd_jwt: SdJwtVpTokenSigningResult(uuidToKbJWTSignature: [vcSdJwtUuids[0]: "ayuht"]),
            .dc_sd_jwt: SdJwtVpTokenSigningResult(uuidToKbJWTSignature: [dcSdJwtUuids[0]: "ayuht"]),
        ]
        
        _ = try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults,
            responseUri: responseUri
        )
        
        let recordedRequest = (mockNetworkManager.recordedRequests[responseUri]!).requestBody
        XCTAssertEqual(recordedRequest?["state"] as? String, state)
        XCTAssertNotNil(recordedRequest?["presentation_submission"])
    }
    
    func testThrowExceptionWhenVPTokenSigningResultMissingForAFormat() async throws {
        mockNetworkManager.clearResponses()
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
            "input_descriptor2": [.vc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
            "input_descriptor3": [.dc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
        let unsignedVPTokens = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )
        let vcSdJwtUuids = Array((unsignedVPTokens[.vc_sd_jwt] as! UnsignedSdJwtVPToken).uuidToUnsignedKBT.keys)
        let dcSdJwtUuids = Array((unsignedVPTokens[.dc_sd_jwt] as! UnsignedSdJwtVPToken).uuidToUnsignedKBT.keys)
        
        let vpTokenSigningResults: [FormatType: VPTokenSigningResult] = [ // simulate missing credential format
            FormatType.ldp_vc: LdpVPTokenSigningResult(
                jws: "testJWS",
                proofValue: "",
                signatureAlgorithm: "JsonWebSignature2020"),
            .mso_mdoc: MdocVPTokenSigningResult(docTypeToDeviceAuthentication: ["org.iso.18013.5.1.mDL": DeviceAuthentication(signature: "aGVsbG8=", algorithm: "ES256")]),
            .dc_sd_jwt: SdJwtVpTokenSigningResult(uuidToKbJWTSignature: [dcSdJwtUuids[0]: "ayuht"]),
        ]
        
        do {
            _ = try await handler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest: authorizationRequest,
                vpTokenSigningResults: vpTokenSigningResults,
                responseUri: "https://client.example.org/cb"
            )
            XCTFail("Expected error not thrown")
        } catch {
            assertOpenID4VPException(error,
                                     expectedMessage: "VPTokenSigningResult not provided for the required formats",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testConstructAuthorizationErrorResponseMapsErrorCorrectly() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
        let error = InvalidData(message: "Invalid input data", className: "Test")
        
        
        let response = handler.constructAuthorizationErrorResponse(
            authorizationRequest: authorizationRequest,
            exception: error,
            walletNonce: "wallet-nonce"
        )
        
        XCTAssertEqual(response["error"] as? String, "invalid_request")
        XCTAssertEqual(response["error_description"] as? String, "Invalid input data")
        XCTAssertEqual(response["state"] as? String, state)
    }
    
    
    func testConstructAuthorizationResponseSuccess() async throws {
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest(responseMode: .directPost)
        
        _ = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )
        
        let vpTokenSigningResults: [FormatType: VPTokenSigningResult] = [
            .ldp_vc: LdpVPTokenSigningResult(
                jws: "testJWS",
                proofValue: "",
                signatureAlgorithm: "JsonWebSignature2020"
            )
        ]
        
        let authorizationResponse = try handler.constructAuthorizationResponse(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults
        )
        
        XCTAssertNotNil(authorizationResponse["vp_token"])
        XCTAssertNotNil(authorizationResponse["presentation_submission"])
        XCTAssertEqual(authorizationResponse["state"], state)
    }
    
    func testConstructAuthorizationResponseThrowsErrorForUnsupportedResponseType() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest(responseType: "fragment")
        
        XCTAssertThrowsError(
            try handler.constructAuthorizationResponse(
                authorizationRequest: authorizationRequest,
                vpTokenSigningResults: [:]
            )
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Provided response_type - fragment is not supported",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testConstructAuthorizationErrorResponseWithOpenIDException() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
        
        let error = InvalidData(
            message: "Invalid input data",
            className: "TestClass"
        )
        
        let response = handler.constructAuthorizationErrorResponse(
            authorizationRequest: authorizationRequest,
            exception: error,
            walletNonce: "wallet-nonce"
        )
        
        XCTAssertEqual(response["error"] as? String, "invalid_request")
        XCTAssertEqual(response["error_description"] as? String, "Invalid input data")
        XCTAssertEqual(response["state"] as? String, state)
    }
    
    func testConstructAuthorizationErrorResponseWithGenericError() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
        
        let error = NSError(domain: "test", code: 500)
        
        let response = handler.constructAuthorizationErrorResponse(
            authorizationRequest: authorizationRequest,
            exception: error,
            walletNonce: "wallet-nonce"
        )
        
        XCTAssertEqual(response["error"] as? String, "invalid_request")
        XCTAssertNotNil(response["error_description"])
        XCTAssertEqual(response["state"] as? String, state)
    }
    
    func testConstructAuthorizationErrorResponseReturnMinimalErrorResponseIfConstructionOfErrorFails() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest(responseModeValue: "fragment")
        
        let error = NSError(domain: "test", code: 500)
        
        let response = handler.constructAuthorizationErrorResponse(
            authorizationRequest: authorizationRequest,
            exception: error,
            walletNonce: "wallet-nonce"
        )
        
        XCTAssertEqual(response["error"] as? String, "invalid_request")
        XCTAssertNotNil(response["error_description"])
        XCTAssertTrue((response["error_description"] as? String)?.starts(with: "Failed to construct error response:") == true)
    }
    
    
}
