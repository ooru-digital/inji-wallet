import XCTest
@testable import OpenID4VP

final class UnsignedLdpVPTokenBuilderTests: XCTestCase {
    private let canonicalized = "Y2Fub25pY2FsaXplZA"

    override func setUp() {
        JsonLd.setCanonicalizer { _ in "Y2Fub25pY2FsaXplZA" }
    }

    // MARK: - build(credentialInputDescriptorMappings:) tests

    func testThrowsWhenAuthorizationRequestIsNotPresentationExchangeRequest() async throws {
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            id: "vp-id"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "cred-input-1")
        ]

        await XCTAssertAsyncThrowsError(
            try await builder.build(credentialInputDescriptorMappings: &mappings)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Expected AuthorizationPresentationExchangeRequest for Presentation Exchange flow",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testCreationOfUnsignedLdpVPToken() async throws {
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "ebc6f1c2"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "cred-input-1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        assertLdpVPTokenPayload(payload, expectedCredentialsInPresentation: convertToJsonString([ldpVC()]))

        assertUnsignedVPTokens(unsignedVPTokens, expected: [
            [
                "format": FormatType.ldp_vc,
                "signatureAlgorithm": SignatureAlgorithm.edDsa.rawValue,
                "holderKeyReference": didJwkKey,
                "dataToSign": [
                    "header": [
                        "alg": "EdDSA",
                        "crit" : ["b64"],
                        "b64": false
                    ],
                    "payload": "canonicalized"
                ]
            ]
        ])
    }

    func testContextIncludesJwsSuite() async throws {
        JsonLd.setCanonicalizer { _ in "Y2Fub25pY2FsaXplZA" }
        defer { JsonLd.setCanonicalizer(nil) }

        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "ebc6f1c2"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "cred-input-1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let ldpVPTokenPayload = try XCTUnwrap(payload as? [String: LdpVP])
        let ldpVP = ldpVPTokenPayload.values.first!
        guard case let .vp(ldpToken) = ldpVP else {
            XCTFail("Expected LdpVP.vp"); return
        }
        XCTAssertEqual(ldpToken.context, ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"])
        XCTAssertEqual(ldpToken.type, ["VerifiablePresentation"])
        XCTAssertEqual(ldpToken.id, "ebc6f1c2")
        XCTAssertEqual(ldpToken.holder, didJwkKey)
        XCTAssertEqual(ldpToken.proof?.type, SignatureSuite.jsonWebSignature2020.rawValue)
        XCTAssertEqual(ldpToken.proof?.verificationMethod, didJwkKey)
        XCTAssertNotNil(ldpToken.proof?.challenge)
        XCTAssertEqual(ldpToken.proof?.domain, "client_id")
        XCTAssertEqual(ldpToken.verifiableCredential.count, 1)
        // JsonWebSignature2020: dataToSign is "<base64url-JWS-header>.canonicalized"
        assertUnsignedVPTokens(unsignedVPTokens, expected: [
            [
                "format": FormatType.ldp_vc,
                "signatureAlgorithm": SignatureAlgorithm.edDsa.rawValue,
                "holderKeyReference": didJwkKey,
                "dataToSign": ["header": ["alg": "EdDSA", "crit": ["b64"], "b64": false] as [String: Any], "payload": "canonicalized"] as [String: Any]
            ]
        ])
    }
    
    // MARK: - build(credentialInputDescriptorMappings:) — PE flow: nil holder/signatureSuite

    func testExtractsHolderFromCredentialSubjectIdWhenBothNil() async throws {
        // holder=nil && signatureSuite=nil → extracts from credentialSubject.id
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "pe-flow-id"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "cred-input-1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let ldpVPTokenPayload = try XCTUnwrap(payload as? [String: LdpVP])
        let ldpVP = ldpVPTokenPayload.values.first!
        guard case let .vp(ldpToken) = ldpVP else { XCTFail("Expected LdpVP.vp"); return }

        // holderId must come from credentialSubject.id and be preserved as is by validateHolderId
        XCTAssertEqual(ldpToken.holder, didJwkKey)
        XCTAssertEqual(ldpToken.proof?.verificationMethod, didJwkKey)
        XCTAssertEqual(unsignedVPTokens.count, 1)
        XCTAssertEqual(unsignedVPTokens[0].holderKeyReference, didJwkKey)
    }

    func testSignatureSuiteContextInBuiltTokenPayload() async throws {
        // holder=nil && signatureSuite=nil → suite defaults to JsonWebSignature2020
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "pe-flow-id"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "cred-input-1")
        ]

        let (payload, _) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let ldpVPTokenPayload = try XCTUnwrap(payload as? [String: LdpVP])
        let ldpVP = ldpVPTokenPayload.values.first!
        guard case let .vp(ldpToken) = ldpVP else { XCTFail("Expected LdpVP.vp"); return }

        XCTAssertEqual(ldpToken.proof?.type, SignatureSuite.jsonWebSignature2020.rawValue)
        XCTAssertEqual(
            ldpToken.context,
            ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"]
        )
    }

    func testNestedPathWrittenToFormatToCredentialInputDescriptorMappingForEachCredential() async throws {
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "pe-flow-id"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "desc-1"),
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "desc-2"),
        ]

        _ = try await builder.build(credentialInputDescriptorMappings: &mappings)

        // Each mapping must carry the nested path $.verifiableCredential[n]
        XCTAssertEqual(mappings.count, 2)
        XCTAssertEqual(mappings[0].nestedPath, "$.verifiableCredential[0]")
        XCTAssertEqual(mappings[1].nestedPath, "$.verifiableCredential[0]")
    }

    func testThrowsWhenCredentialHasNoCredentialSubjectIdAndBothNil() async throws {
        let credentialWithoutSubjectId: [String: Any] = ["type": ["VerifiableCredential"]]
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "pe-flow-id"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(credentialWithoutSubjectId), inputDescriptorId: "cred-input-1")
        ]

        await XCTAssertAsyncThrowsError(
            try await builder.build(credentialInputDescriptorMappings: &mappings)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Holder ID not available in the credential",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - build(credentialToCredentialQueryIdMappings:) — error paths

    func testThrowsWhenAuthorizationRequestIsNotDcqlRequest() async throws {
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "vp-id"
        )
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), credentialQueryId: "q1")
        ]

        await XCTAssertAsyncThrowsError(
            try await builder.build(credentialToCredentialQueryIdMappings: &mappings)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Expected AuthorizationDcqlRequest for DCQL flow",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowsWhenCredentialQueryIdNotFoundInDcqlQuery() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc")
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), credentialQueryId: "nonexistent-id")
        ]

        await XCTAssertAsyncThrowsError(
            try await builder.build(credentialToCredentialQueryIdMappings: &mappings)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "No matching credential query found for credential query id: nonexistent-id",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowsWhenCredentialIsNotADictionary() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable("not-a-dict"), credentialQueryId: "q1")
        ]

        await XCTAssertAsyncThrowsError(
            try await builder.build(credentialToCredentialQueryIdMappings: &mappings)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Credential is not a valid JSON object",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowsWhenCredentialHasNoHolderId() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVCWithoutHolderBinding()), credentialQueryId: "q1")
        ]

        await XCTAssertAsyncThrowsError(
            try await builder.build(credentialToCredentialQueryIdMappings: &mappings)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Holder ID not available in the credential",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowsWhenJsonLdCanonicalizerIsNotSet() async throws {
        JsonLd.setCanonicalizer(nil)
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), credentialQueryId: "q1")
        ]

        await XCTAssertAsyncThrowsError(
            try await builder.build(credentialToCredentialQueryIdMappings: &mappings)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Failed to get JsonLd canonicalizer.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - build(credentialToCredentialQueryIdMappings:) — requireCryptographicHolderBinding = false

    func testBuildWithHolderBindingFalseProducesNoUnsignedTokens() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: false)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), credentialQueryId: "q1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)
        
        XCTAssertEqual(unsignedVPTokens.count, 0)
        assertLdpVPTokenPayload(payload, expectedCredentialsInPresentation: convertToJsonString([ldpVC()]), tokenType: .vc)
    }

    func testBuildWithHolderBindingFalseSetsIdentifierOnMapping() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: false)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), credentialQueryId: "q1")
        ]

        _ = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let identifier = try XCTUnwrap(mappings[0].identifier)
        XCTAssertFalse(identifier.isEmpty)
    }

    func testBuildWithHolderBindingFalseForMultipleMappings() async throws {
        let builder = builderWithDcqlRequest(
            credentials: [("q1", "ldp_vc"), ("q2", "ldp_vc")],
            requireCryptographicHolderBinding: false
        )
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), credentialQueryId: "q1"),
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), credentialQueryId: "q2")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        XCTAssertEqual(unsignedVPTokens.count, 0)
        let vpPayload = try XCTUnwrap(payload as? [String: LdpVP])
        XCTAssertEqual(vpPayload.count, 2)
        let id0 = try XCTUnwrap(mappings[0].identifier)
        let id1 = try XCTUnwrap(mappings[1].identifier)
        XCTAssertFalse(id0.isEmpty)
        XCTAssertFalse(id1.isEmpty)
        XCTAssertNotEqual(id0, id1)
    }

    // MARK: - build(credentialToCredentialQueryIdMappings:) — requireCryptographicHolderBinding = true

    func testBuildWithHolderBindingTrueProducesUnsignedToken() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVCWithJwkHolder()), credentialQueryId: "q1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        assertUnsignedVPTokens(unsignedVPTokens, expected: [
            [
                "format": FormatType.ldp_vc,
                "signatureAlgorithm": SignatureAlgorithm.edDsa.rawValue,
                "holderKeyReference": bareJwkDid,
                "dataToSign": ["header": ["alg": "EdDSA", "crit": ["b64"], "b64": false] as [String: Any], "payload": "canonicalized"] as [String: Any]
            ]
        ])

        let vpPayload = try XCTUnwrap(payload as? [String: LdpVP])
        XCTAssertEqual(vpPayload.count, 1)
        guard case let .vp(ldpToken) = vpPayload.values.first else {
            XCTFail("Expected LdpVP.vp entry in payload"); return
        }
        XCTAssertNotNil(ldpToken.proof)
        XCTAssertEqual(ldpToken.proof?.verificationMethod, bareJwkDid)
        XCTAssertEqual(ldpToken.proof?.challenge, "nonce")
        XCTAssertEqual(ldpToken.proof?.domain, "client_id")
        XCTAssertEqual(ldpToken.proof?.type, SignatureSuite.jsonWebSignature2020.rawValue)
        XCTAssertEqual(ldpToken.verifiableCredential.count, 1)
    }

    func testBuildWithHolderBindingTrueSetsIdentifierOnMapping() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVCWithJwkHolder()), credentialQueryId: "q1")
        ]

        _ = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let identifier = try XCTUnwrap(mappings[0].identifier)
        XCTAssertFalse(identifier.isEmpty)
    }

    func testBuildWithHolderBindingTrueVpTokenHasJws2020Context() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVCWithJwkHolder()), credentialQueryId: "q1")
        ]

        let (payload, _) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let ldpToken = try XCTUnwrap((payload as? [String: LdpVP])?.values.first.flatMap {
            if case let .vp(token) = $0 { return token } else { return nil }
        })
        XCTAssertEqual(ldpToken.context, ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"])
        XCTAssertEqual(ldpToken.type, ["VerifiablePresentation"])
        XCTAssertEqual(ldpToken.holder, bareJwkDid)
        XCTAssertEqual(ldpToken.verifiableCredential.count, 1)
        XCTAssertEqual(ldpToken.proof?.type, SignatureSuite.jsonWebSignature2020.rawValue)
        XCTAssertEqual(ldpToken.proof?.verificationMethod, bareJwkDid)
        XCTAssertEqual(ldpToken.proof?.challenge, "nonce")
        XCTAssertEqual(ldpToken.proof?.domain, "client_id")
    }

    func testBuildWithHolderBindingTrueDataToSignContainsJwsHeaderAndPayload() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVCWithJwkHolder()), credentialQueryId: "q1")
        ]

        let (_, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        assertUnsignedVPTokens(unsignedVPTokens, expected: [
            [
                "format": FormatType.ldp_vc,
                "signatureAlgorithm": SignatureAlgorithm.edDsa.rawValue,
                "holderKeyReference": bareJwkDid,
                "dataToSign": ["header": ["alg": "EdDSA", "crit": ["b64"], "b64": false] as [String: Any], "payload": "canonicalized"] as [String: Any]
            ]
        ])
    }

    // MARK: - Holder ID validation

    func testValidateHolderIdPreservesSupportedDidsWithOptionalFragments() throws {
        let holderIds = [
            "did:jwk:eyJrdHkiOiJFQyJ9",
            "did:jwk:eyJrdHkiOiJFQyJ9#0",
            "did:key:z6MkhWUE3JPyK6n4F6yA",
            "did:key:z6MkhWUE3JPyK6n4F6yA#z6MkhWUE3JPyK6n4F6yA",
            "did:web:example.com",
            "did:web:example.com:user:alice",
            "did:web:example.com#key-1"
        ]
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "vp-id"
        )

        for holderId in holderIds {
            XCTAssertEqual(try builder.validateHolderId(holderId), holderId)
        }
    }

    func testBuildThrowsForUnsupportedOrMalformedHolderDids() async throws {
        let holderIds = [
            "did:example:123",
            "did:key:z6MkhWUE3JPyK6n4F6yA#z6MkDifferentFingerprint",
            "did:jwk:eyJrdHkiOiJFQyJ9#1",
            "did:web:",
            "not-a-did",
            "did:jwk:eyJrdHkiOiJFQyJ9==#1"
        ]

        for holderId in holderIds {
            let builder = UnsignedLdpVPTokenBuilder(
                authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
                specVersion: .draft23,
                id: "vp-id"
            )
            var mappings = [
                CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC(holderId: holderId)), inputDescriptorId: "cred-input-1")
            ]

            await XCTAssertAsyncThrowsError(
                try await builder.build(credentialInputDescriptorMappings: &mappings)
            ) { error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: "Holder ID must be a valid did:jwk, did:key, or did:web identifier: \(holderId)",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }

    // MARK: - CredIssuer patch: fallback holder for non-DID subject ids

    private let urnUuidSubject = "urn:uuid:438c6110-95d2-4fd2-86f3-4722107aad2f"

    func testDcqlBuildUsesFallbackHolderWhenSubjectIdIsNotADid() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true, fallbackHolderId: bareJwkDid)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC(holderId: urnUuidSubject)), credentialQueryId: "q1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let ldpToken = try XCTUnwrap((payload as? [String: LdpVP])?.values.first.flatMap {
            if case let .vp(token) = $0 { return token } else { return nil }
        })
        XCTAssertEqual(ldpToken.holder, bareJwkDid)
        XCTAssertEqual(ldpToken.proof?.verificationMethod, bareJwkDid)
        XCTAssertEqual(unsignedVPTokens.first?.holderKeyReference, bareJwkDid)
        XCTAssertEqual(ldpToken.verifiableCredential.count, 1)
    }

    func testPresentationExchangeBuildUsesFallbackHolderWhenSubjectIdIsNotADid() async throws {
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "vp-id",
            fallbackHolderId: bareJwkDid
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC(holderId: urnUuidSubject)), inputDescriptorId: "cred-input-1")
        ]

        let (_, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        XCTAssertEqual(unsignedVPTokens.first?.holderKeyReference, bareJwkDid)
    }

    func testDcqlBuildKeepsSubjectDidWhenFallbackIsGiven() async throws {
        let subjectDid = didJwkKey
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true, fallbackHolderId: "did:jwk:eyJrdHkiOiJFQyJ9")
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC(holderId: subjectDid)), credentialQueryId: "q1")
        ]

        let (payload, _) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let ldpToken = try XCTUnwrap((payload as? [String: LdpVP])?.values.first.flatMap {
            if case let .vp(token) = $0 { return token } else { return nil }
        })
        XCTAssertEqual(ldpToken.holder, subjectDid)
    }

    func testDcqlBuildRejectsNonDidSubjectWithoutFallback() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC(holderId: urnUuidSubject)), credentialQueryId: "q1")
        ]

        await XCTAssertAsyncThrowsError(
            try await builder.build(credentialToCredentialQueryIdMappings: &mappings)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Holder ID must be a valid did:jwk, did:key, or did:web identifier: \(self.urnUuidSubject)",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testDcqlBuildRejectsFallbackThatIsNotADid() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true, fallbackHolderId: "urn:uuid:2")
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC(holderId: urnUuidSubject)), credentialQueryId: "q1")
        ]

        await XCTAssertAsyncThrowsError(
            try await builder.build(credentialToCredentialQueryIdMappings: &mappings)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Holder ID must be a valid did:jwk, did:key, or did:web identifier: urn:uuid:2",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - Holder ID with base64url padding

    private static let paddedP256JwkDid = "did:jwk:eyJrdHkiOiJFQyIsInVzZSI6InNpZyIsImNydiI6IlAtMjU2IiwieCI6IjFqNUtiM3JXNXRaMjBRYW5tZ1pYTkJNQzFGOExQNGRjS1VwWm5ZQ2tESEkiLCJ5IjoiaUR6MlpCOHZkS0Y1U05fSkRReHVFT29JMHpQNGV6ZXN5WS13NHo1bTdHdyIsImFsZyI6IkVTMjU2In0="

    func testValidateHolderIdAcceptsPaddedDidJwkAndReturnsOriginalHolderId() throws {
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "vp-id"
        )

        for paddedHolderId in ["did:jwk:eyJrdHkiOiJFQyJ9==", Self.paddedP256JwkDid] {
            XCTAssertEqual(try builder.validateHolderId(paddedHolderId), paddedHolderId)
        }
    }

    func testValidateHolderIdAcceptsPaddedDidJwkWithFragmentAndReturnsOriginalHolderId() throws {
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "vp-id"
        )
        let paddedHolderId = Self.paddedP256JwkDid + "#0"

        XCTAssertEqual(try builder.validateHolderId(paddedHolderId), paddedHolderId)
    }

    // MARK: - Holder ID pass-through

    func testBuildUsesHolderIdUnmodified() async throws {
        let testCases: [(holderId: String, signatureAlgorithm: String)] = [
            (bareJwkDid, SignatureAlgorithm.edDsa.rawValue),
            (didJwkKey, SignatureAlgorithm.edDsa.rawValue),
            (Self.p256JwkDid, SignatureAlgorithm.es256.rawValue),
            (Self.paddedP256JwkDid, SignatureAlgorithm.es256.rawValue),
            (Self.paddedP256JwkDid + "#0", SignatureAlgorithm.es256.rawValue)
        ]

        for testCase in testCases {
            let builder = UnsignedLdpVPTokenBuilder(
                authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
                specVersion: .draft23,
                id: "vp-id"
            )
            var mappings = [
                CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC(holderId: testCase.holderId)), inputDescriptorId: "cred-input-1")
            ]

            let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

            let ldpVPTokenPayload = try XCTUnwrap(payload as? [String: LdpVP])
            guard case let .vp(ldpToken) = ldpVPTokenPayload.values.first else {
                XCTFail("Expected LdpVP.vp for holder ID: \(testCase.holderId)"); continue
            }
            XCTAssertEqual(ldpToken.holder, testCase.holderId)
            XCTAssertEqual(ldpToken.proof?.verificationMethod, testCase.holderId)
            XCTAssertEqual(unsignedVPTokens.count, 1)
            XCTAssertEqual(unsignedVPTokens.first?.holderKeyReference, testCase.holderId)
            XCTAssertEqual(unsignedVPTokens.first?.signatureAlgorithm, testCase.signatureAlgorithm)
        }
    }

    func testDcqlBuildUsesHolderIdUnmodified() async throws {
        let holderId = Self.paddedP256JwkDid
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC(holderId: holderId)), credentialQueryId: "q1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let ldpVPTokenPayload = try XCTUnwrap(payload as? [String: LdpVP])
        guard case let .vp(ldpToken) = ldpVPTokenPayload.values.first else {
            return XCTFail("Expected LdpVP.vp")
        }
        XCTAssertEqual(ldpToken.holder, holderId)
        XCTAssertEqual(ldpToken.proof?.verificationMethod, holderId)
        XCTAssertEqual(unsignedVPTokens.count, 1)
        XCTAssertEqual(unsignedVPTokens.first?.holderKeyReference, holderId)
        XCTAssertEqual(unsignedVPTokens.first?.signatureAlgorithm, SignatureAlgorithm.es256.rawValue)
    }

    // MARK: - Helpers

    // MARK: - VC 2.0 Data Integrity

    private static let p256JwkDid = "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImY4M09KM0QyeEYxQmc4dnViOXRMZTFnSE16Vjc2ZThUdXM5dVBIdlJWRVUiLCJ5IjoieF9GRXpSdTltMzZITE5fdHVlNjU5TE5wWFc2cEN5U3Rpa1lqS0lXSTVhMCJ9#0"
    private static let rsaJwkDid = "did:jwk:eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsIm4iOiIwdng3YWdvZWJHY1FTdXVQaUxKWFpwdE45bm5kclFtYlhFcHMyYWlBRmJXaE03OExoV3g0Y2JiZkFBdFZUODZ6d3UxUks3YVBGRnh1aERSMUw2dFNvY19CSkVDUGViV0tSWGpCWkNpRlY0bjNva25qaE1zdG42NHRaXzJXLTVKc0dZNEhjNW45eUJYQXJ3bDkzbHF0N19STjV3NkNmMGg0UXlRNXYtNjVZR2pRUjBfRkRXMlF2enFZMzY4UVFNaWNBdGFTcXpzOEtKWmduWWI5YzdkMHpnZEFaSHp1NnFNUXZSTDVoYWpybjFuOTFDYk9wYklTRDA4cU5MeXJka3QtYkZUV2hBSTR2TVFGaDZXZVp1MGZNNGxGZDJOY1J3cjNYUGtzSU5IYVEtR194Qm5pSXFidzBMczFqRjQ0LWNzRkN1ci1rRWdVOGF3YXBKektucURLZ3cifQ#0"

    private func vcdm2Credential(holderId: String = didJwkKey) -> [String: Any] {
        return [
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": "did:example:issuer",
            "credentialSubject": ["id": holderId]
        ]
    }

    func testVcdm2CredentialBuildsEddsaDataIntegrityPresentation() async throws {
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "vp-id"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(vcdm2Credential()), inputDescriptorId: "vc2")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let parsedPayload = try XCTUnwrap(payload as? [String: LdpVP])
        guard case let .vp(vpToken) = parsedPayload.values.first else {
            return XCTFail("Expected an LdpVPToken payload")
        }

        XCTAssertEqual(vpToken.context, ["https://www.w3.org/ns/credentials/v2"])
        XCTAssertEqual(vpToken.proof?.type, "DataIntegrityProof")
        XCTAssertEqual(vpToken.proof?.cryptosuite, "eddsa-rdfc-2022")
        XCTAssertEqual(vpToken.proof?.proofPurpose, ProofPurpose.vpProofPurpose)
        XCTAssertEqual(vpToken.proof?.verificationMethod, didJwkKey)
        // Data Integrity signs the canonicalization output directly, with no JWS header prefix.
        XCTAssertEqual(unsignedVPTokens.first?.dataToSign, try Base64Decoder.decodeBase64ToData(canonicalized))
    }

    func testVcdm2CredentialBuildsEcdsaDataIntegrityPresentation() async throws {
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "vp-id"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(vcdm2Credential(holderId: Self.p256JwkDid)), inputDescriptorId: "vc2")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let parsedPayload = try XCTUnwrap(payload as? [String: LdpVP])
        guard case let .vp(vpToken) = parsedPayload.values.first else {
            return XCTFail("Expected an LdpVPToken payload")
        }

        XCTAssertEqual(vpToken.proof?.type, "DataIntegrityProof")
        XCTAssertEqual(vpToken.proof?.cryptosuite, "ecdsa-rdfc-2019")
        XCTAssertEqual(unsignedVPTokens.first?.signatureAlgorithm, SignatureAlgorithm.es256.rawValue)
    }

    func testVcdm2CredentialRejectsRsaHolderKey() async throws {
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "vp-id"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(vcdm2Credential(holderId: Self.rsaJwkDid)), inputDescriptorId: "vc2")
        ]

        await XCTAssertAsyncThrowsError(
            try await builder.build(credentialInputDescriptorMappings: &mappings)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "VC 2.0 presentation sharing supports only Ed25519 and P-256 holder keys; found RS256",
                expectedCode: OpenID4VPErrorCodes.accessDenied
            )
        }
    }

    func testVcdm2ContextMustBeTheFirstContextEntry() async throws {
        let credential: [String: Any] = [
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/ns/credentials/v2"
            ],
            "type": ["VerifiableCredential"],
            "credentialSubject": ["id": didJwkKey]
        ]
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "vp-id"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(credential), inputDescriptorId: "vc2")
        ]

        await XCTAssertAsyncThrowsError(
            try await builder.build(credentialInputDescriptorMappings: &mappings)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "VC 2.0 context must be the first @context entry",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    private func ldpVC(holderId: String = didJwkKey) -> [String: Any] {
        return [
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "issuer": "did:example:issuer",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": ["id": holderId]
        ]
    }

    private func ldpVCWithJwkHolder() -> [String: Any] {
        // Use the bare JWK DID without the fragment (#0); validateHolderId() preserves it as is
        return [
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "issuer": "did:example:issuer",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": ["id": bareJwkDid]
        ]
    }

    private func ldpVCWithoutHolderBinding() -> [String: Any] {
        return [
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "issuer": "did:example:issuer",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": ["given_name": "Bob"]
        ]
    }

    private func buildDcqlQuery(credentials: [(id: String, format: String)], requireCryptographicHolderBinding: Bool) -> DCQLQuery {
        let json: [String: Any] = [
            "credentials": credentials.map { cred in
                [
                    "id": cred.id,
                    "format": cred.format,
                    "meta": [:] as [String: Any],
                    "require_cryptographic_holder_binding": requireCryptographicHolderBinding
                ] as [String: Any]
            }
        ]
        return createInstance(json, as: DCQLQuery.self)
    }

    private func builderWithDcqlRequest(
        credentialQueryId: String,
        credentialQueryFormat: String,
        requireCryptographicHolderBinding: Bool = false,
        fallbackHolderId: String? = nil
    ) -> UnsignedLdpVPTokenBuilder {
        return builderWithDcqlRequest(
            credentials: [(credentialQueryId, credentialQueryFormat)],
            requireCryptographicHolderBinding: requireCryptographicHolderBinding,
            fallbackHolderId: fallbackHolderId
        )
    }

    private func builderWithDcqlRequest(
        credentials: [(id: String, format: String)],
        requireCryptographicHolderBinding: Bool = false,
        fallbackHolderId: String? = nil
    ) -> UnsignedLdpVPTokenBuilder {
        let dcqlQuery = buildDcqlQuery(credentials: credentials, requireCryptographicHolderBinding: requireCryptographicHolderBinding)
        let authorizationRequest = AuthorizationDcqlRequest(
            clientId: "client_id",
            responseType: ResponseType.vp_token.rawValue,
            responseMode: ResponseMode.directPost.rawValue,
            responseUri: "https://mock-verifier.com",
            redirectUri: nil,
            nonce: "nonce",
            walletNonce: nil,
            state: "state",
            dcqlQuery: dcqlQuery,
            clientMetadata: nil
        )
        return UnsignedLdpVPTokenBuilder(
            authorizationRequest: authorizationRequest,
            specVersion: .v1,
            id: "vp-id",
            fallbackHolderId: fallbackHolderId
        )
    }

    private func assertUnsignedVPTokens(
        _ actual: [UnsignedVPToken],
        expected: [[String: Any]],
        file: StaticString = #file,
        line: UInt = #line
    ) {
        XCTAssertEqual(actual.count, expected.count, "Token count mismatch", file: file, line: line)
        for (index, (token, expectedDict)) in zip(actual, expected).enumerated() {
            if let expectedFormat = expectedDict["format"] as? FormatType {
                XCTAssertEqual(token.format, expectedFormat, "Token[\(index)].format mismatch", file: file, line: line)
            }
            if let expectedAlg = expectedDict["signatureAlgorithm"] as? String {
                XCTAssertEqual(token.signatureAlgorithm, expectedAlg, "Token[\(index)].signatureAlgorithm mismatch", file: file, line: line)
            }
            if let expectedRef = expectedDict["holderKeyReference"] as? String {
                XCTAssertEqual(token.holderKeyReference, expectedRef, "Token[\(index)].holderKeyReference mismatch", file: file, line: line)
            }
            if let rawExpected = expectedDict["dataToSign"] as? String {
                let actual = String(decoding: token.dataToSign, as: UTF8.self)
                XCTAssertEqual(actual, rawExpected, "Token[\(index)].dataToSign mismatch", file: file, line: line)
            } else if let jwsExpected = expectedDict["dataToSign"] as? [String: Any],
                      let expectedHeader = jwsExpected["header"] as? [String: Any],
                      let expectedPayload = jwsExpected["payload"] as? String {
                assertJWSDataToSign(token.dataToSign, expectedHeader: expectedHeader, expectedPayload: expectedPayload, file: file, line: line)
            }
        }
    }

    private enum TokenPresentationType {
        case vp
        case vc
    }

    private func assertLdpVPTokenPayload(
        _ payload: Any?,
        holder: String = didJwkKey,
        expectedCredentialsInPresentation: String,
        tokenType: TokenPresentationType = .vp,
        file: StaticString = #file,
        line: UInt = #line
    ) {
        switch tokenType {
        case .vp:
            guard let parsedPayload = payload as? [String: LdpVP] else {
                XCTFail("Expected  string to LdpVP.vp payload", file: file, line: line)
                return
            }
            guard case let .vp(ldpToken) = parsedPayload.values.first else {
                XCTFail("Expected LdpVP.vp entry in payload", file: file, line: line)
                return
            }
            XCTAssertEqual(ldpToken.type, ["VerifiablePresentation"], file: file, line: line)
            XCTAssertEqual(ldpToken.id, "ebc6f1c2", file: file, line: line)
            XCTAssertEqual(ldpToken.holder, holder, file: file, line: line)
            XCTAssertEqual(ldpToken.proof?.type, SignatureSuite.jsonWebSignature2020.rawValue, file: file, line: line)
            XCTAssertEqual(ldpToken.proof?.verificationMethod, holder, file: file, line: line)
            XCTAssertNotNil(ldpToken.proof?.challenge)
            XCTAssertEqual(ldpToken.proof?.domain, "client_id", file: file, line: line)
            assertJsonString(expected: expectedCredentialsInPresentation, actual: convertToJsonString(ldpToken.verifiableCredential), file: file, line: line)

        case .vc:
            guard let dict = payload as? [String: LdpVP],
                  let firstEntry = dict.values.first,
                  case let .vc(ldpVCToken) = firstEntry else {
                XCTFail("Expected [String: LdpVP] payload with LdpVP.vc entries for VC type", file: file, line: line)
                return
            }
            assertJsonString(expected: expectedCredentialsInPresentation, actual: convertToJsonString([ldpVCToken.verifiableCredential.value]), file: file, line: line)
        }
    }

    private func assertJWSDataToSign(_ dataToSign: Data, expectedHeader: [String: Any], expectedPayload: String, file: StaticString = #file, line: UInt = #line) {
        let str = String(decoding: dataToSign, as: UTF8.self)
        let parts = str.components(separatedBy: ".")
        XCTAssertEqual(parts.count, 2, "dataToSign must be '<jwsHeader>.<payload>'", file: file, line: line)
        guard parts.count == 2 else { return }
        guard let headerData = Data(base64Encoded: parts[0].base64URLToBase64()),
              let actualHeader = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any] else {
            XCTFail("Failed to decode JWS header from base64url: \(parts[0])", file: file, line: line)
            return
        }
        assertDictionariesEqual(expected: expectedHeader, actual: actualHeader, file: file, line: line)
        XCTAssertEqual(parts[1], expectedPayload, file: file, line: line)
    }
}
