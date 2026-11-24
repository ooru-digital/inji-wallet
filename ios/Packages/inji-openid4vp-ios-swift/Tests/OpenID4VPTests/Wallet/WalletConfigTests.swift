import XCTest
@testable import OpenID4VP

final class WalletConfigTests: XCTestCase {

    // MARK: - Fixtures

    private let ldpVc = LdpVpFormatSupported(proofTypeValues: [.ed25519Signature2020], cryptoSuiteValues: nil)
    private let msoMdoc = MsoMdocVpFormatSupported(issuerAuthAlgValues: [-7], deviceAuthAlgValues: [-9])
    private let sdJwt = SdJwtVpFormatSupported(sdJwtAlgValues: ["ES256"], kbJwtAlgValues: ["ES256"])

    private func makeConfig(
        vpFormats: [VPFormatType: VPFormatSupported]? = nil,
        clientIdPrefixes: [ClientIdPrefix] = [.preRegistered],
        requestAlgs: [SignatureAlgorithm]? = [.edDsa],
        encAlgs: [EncryptionAlgorithm]? = [.ecdhES],
        encMethods: [EncryptionMethod]? = [.a256GCM],
        responseTypes: [ResponseType] = [.vp_token],
        presentationDefinitionUriSupported: Bool = true,
        trustedVerifiers: [Verifier] = [],
        validateTrustedVerifier: Bool = true
    ) -> WalletConfig {
        let formats = vpFormats ?? [.ldp_vc: ldpVc, .mso_mdoc: msoMdoc, .dc_sd_jwt: sdJwt]
        return WalletConfig(
            vpFormatsSupported: formats,
            clientIdPrefixesSupported: clientIdPrefixes,
            requestObjectSigningAlgValuesSupported: requestAlgs,
            authorizationEncryptionAlgValuesSupported: encAlgs,
            authorizationEncryptionEncValuesSupported: encMethods,
            responseTypesSupported: responseTypes,
            isPresentationDefinitionUriSupported: presentationDefinitionUriSupported,
            trustedVerifiers: trustedVerifiers,
            validateTrustedVerifier: validateTrustedVerifier
        )
    }

    private func encodeVpFormats(_ config: WalletConfig) throws -> [String: Any] {
        let data = try JSONEncoder().encode(config)
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        return try XCTUnwrap(json["vp_formats_supported"] as? [String: Any])
    }

    private func encodeToJson(_ config: WalletConfig) throws -> [String: Any] {
        let data = try JSONEncoder().encode(config)
        return try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    // MARK: - Memberwise init

    func testInitStoresAllFields() throws {
        let verifier = Verifier(clientId: "v1", responseUris: ["https://v.example.com"])
        let config = makeConfig(
            clientIdPrefixes: [.preRegistered, .redirectUri],
            requestAlgs: [.edDsa],
            encAlgs: [.ecdhES],
            encMethods: [.a256GCM],
            responseTypes: [.vp_token],
            presentationDefinitionUriSupported: false,
            trustedVerifiers: [verifier],
            validateTrustedVerifier: false
        )
        let formats = try encodeVpFormats(config)
        XCTAssertEqual(formats.keys.sorted(), ["dc+sd-jwt", "ldp_vc", "mso_mdoc"])
        XCTAssertEqual(config.clientIdPrefixesSupported, [.preRegistered, .redirectUri])
        XCTAssertEqual(config.requestObjectSigningAlgValuesSupported, [.edDsa])
        XCTAssertEqual(config.authorizationEncryptionAlgValuesSupported, [.ecdhES])
        XCTAssertEqual(config.authorizationEncryptionEncValuesSupported, [.a256GCM])
        XCTAssertEqual(config.responseTypesSupported, [.vp_token])
        XCTAssertEqual(config.isPresentationDefinitionUriSupported, false)
        XCTAssertEqual(config.trustedVerifiers.map { $0.clientId }, ["v1"])
        XCTAssertEqual(config.trustedVerifiers.map { $0.responseUris }, [["https://v.example.com"]])
        XCTAssertFalse(config.validateTrustedVerifier)
    }

    func testDefaultInitUsesWalletConfigDefaults() throws {
        let config = WalletConfig()
        let formats = try encodeVpFormats(config)
        XCTAssertEqual(formats.keys.sorted(), WalletConfigDefaults.vpFormatsSupported.keys.map { $0.rawValue }.sorted())
        XCTAssertEqual(config.clientIdPrefixesSupported, WalletConfigDefaults.clientIdPrefixesSupported)
        XCTAssertEqual(config.requestObjectSigningAlgValuesSupported, WalletConfigDefaults.requestObjectSigningAlgValuesSupported)
        XCTAssertEqual(config.authorizationEncryptionAlgValuesSupported, WalletConfigDefaults.authorizationEncryptionAlgValuesSupported)
        XCTAssertEqual(config.authorizationEncryptionEncValuesSupported, WalletConfigDefaults.authorizationEncryptionEncValuesSupported)
        XCTAssertEqual(config.responseTypesSupported, WalletConfigDefaults.responseTypesSupported)
        XCTAssertEqual(config.isPresentationDefinitionUriSupported, WalletConfigDefaults.presentationDefinitionUriSupported)
        XCTAssertEqual(config.trustedVerifiers.map { $0.clientId }, WalletConfigDefaults.trustedVerifiers.map { $0.clientId })
    }

    // MARK: - WalletConfigDefaults

    func testWalletConfigDefaultValues() {
        XCTAssertEqual(WalletConfigDefaults.clientIdPrefixesSupported, [.preRegistered, .redirectUri, .decentralizedIdentifier])
        XCTAssertEqual(WalletConfigDefaults.requestObjectSigningAlgValuesSupported, [.edDsa])
        XCTAssertEqual(WalletConfigDefaults.authorizationEncryptionAlgValuesSupported, [.ecdhES])
        XCTAssertEqual(WalletConfigDefaults.authorizationEncryptionEncValuesSupported, [.a256GCM])
        XCTAssertEqual(WalletConfigDefaults.responseTypesSupported, [.vp_token])
        XCTAssertEqual(WalletConfigDefaults.presentationDefinitionUriSupported, true)
        XCTAssertEqual(WalletConfigDefaults.trustedVerifiers.map { $0.clientId }, [])
        XCTAssertEqual(WalletConfigDefaults.vpFormatsSupported.keys.map { $0.rawValue }.sorted(), ["dc+sd-jwt", "ldp_vc", "mso_mdoc"])
    }

    // MARK: - Codable round-trip

    func testEncodeDecodeRoundTrip() throws {
        let original = makeConfig(
            clientIdPrefixes: [.preRegistered, .decentralizedIdentifier],
            requestAlgs: [.edDsa],
            encAlgs: [.ecdhES],
            encMethods: [.a256GCM],
            responseTypes: [.vp_token],
            presentationDefinitionUriSupported: true
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(WalletConfig.self, from: data)

        XCTAssertEqual(decoded.clientIdPrefixesSupported, original.clientIdPrefixesSupported)
        XCTAssertEqual(decoded.requestObjectSigningAlgValuesSupported, original.requestObjectSigningAlgValuesSupported)
        XCTAssertEqual(decoded.authorizationEncryptionAlgValuesSupported, original.authorizationEncryptionAlgValuesSupported)
        XCTAssertEqual(decoded.authorizationEncryptionEncValuesSupported, original.authorizationEncryptionEncValuesSupported)
        XCTAssertEqual(decoded.responseTypesSupported, original.responseTypesSupported)
        XCTAssertEqual(decoded.isPresentationDefinitionUriSupported, original.isPresentationDefinitionUriSupported)
        assertDictionariesEqual(expected: try encodeVpFormats(original), actual: try encodeVpFormats(decoded))
    }

    func testDecodeUsesDefaultsWhenOptionalFieldsAbsent() throws {
        let minimalJson = """
        {
          "vp_formats_supported": {
            "ldp_vc": { "proof_type_values": ["Ed25519Signature2020"] }
          },
          "trusted_verifiers": []
        }
        """.data(using: .utf8)!

        let decoded = try JSONDecoder().decode(WalletConfig.self, from: minimalJson)
        XCTAssertEqual(decoded.clientIdPrefixesSupported, WalletConfigDefaults.clientIdPrefixesSupported)
        XCTAssertEqual(decoded.requestObjectSigningAlgValuesSupported, WalletConfigDefaults.requestObjectSigningAlgValuesSupported)
        XCTAssertEqual(decoded.authorizationEncryptionAlgValuesSupported, WalletConfigDefaults.authorizationEncryptionAlgValuesSupported)
        XCTAssertEqual(decoded.authorizationEncryptionEncValuesSupported, WalletConfigDefaults.authorizationEncryptionEncValuesSupported)
        XCTAssertEqual(decoded.responseTypesSupported, WalletConfigDefaults.responseTypesSupported)
        XCTAssertEqual(decoded.isPresentationDefinitionUriSupported, WalletConfigDefaults.presentationDefinitionUriSupported)
    }

    func testDecodeWithNoTrustedVerifiers() throws {
        let json = """
        {
          "vp_formats_supported": {
            "ldp_vc": { "proof_type_values": ["Ed25519Signature2020"] }
          }
        }
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(WalletConfig.self, from: json)
        XCTAssertEqual(decoded.trustedVerifiers.map { $0.clientId }, [])
    }

    func testDecodeUsesDefaultVpFormatsWhenKeyAbsent() throws {
        let json = #"{ "trusted_verifiers": [] }"#.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(WalletConfig.self, from: json)
        let formats = try encodeVpFormats(decoded)
        XCTAssertEqual(formats.keys.sorted(), WalletConfigDefaults.vpFormatsSupported.keys.map { $0.rawValue }.sorted())
    }

    // MARK: - parseVPFormatsSupported — all format branches

    func testDecodeVpFormatsSupported() throws {
        struct FormatTestCase {
            let json: String
            let expectedKey: String
            let validate: ([String: Any]) throws -> Void
        }

        let cases: [FormatTestCase] = [
            FormatTestCase(
                json: #"{"vp_formats_supported":{"ldp_vc":{"proof_type_values":["Ed25519Signature2020"]}},"trusted_verifiers":[]}"#,
                expectedKey: "ldp_vc",
                validate: { fmt in
                    let inner = try XCTUnwrap(fmt["ldp_vc"] as? [String: Any])
                    XCTAssertEqual((inner["proof_type_values"] as? [String])?.sorted(), ["Ed25519Signature2020"])
                }
            ),
            FormatTestCase(
                json: #"{"vp_formats_supported":{"ldp_vp":{"proof_type_values":["Ed25519Signature2020"]}},"trusted_verifiers":[]}"#,
                expectedKey: "ldp_vp",
                validate: { fmt in
                    let inner = try XCTUnwrap(fmt["ldp_vp"] as? [String: Any])
                    XCTAssertEqual((inner["proof_type_values"] as? [String])?.sorted(), ["Ed25519Signature2020"])
                }
            ),
            FormatTestCase(
                json: #"{"vp_formats_supported":{"mso_mdoc":{"issuerauth_alg_values":[-7],"deviceauth_alg_values":[-9]}},"trusted_verifiers":[]}"#,
                expectedKey: "mso_mdoc",
                validate: { fmt in
                    let inner = try XCTUnwrap(fmt["mso_mdoc"] as? [String: Any])
                    XCTAssertEqual(inner["issuerauth_alg_values"] as? [Int], [-7])
                    XCTAssertEqual(inner["deviceauth_alg_values"] as? [Int], [-9])
                }
            ),
            FormatTestCase(
                json: #"{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"]}},"trusted_verifiers":[]}"#,
                expectedKey: "dc+sd-jwt",
                validate: { fmt in
                    let inner = try XCTUnwrap(fmt["dc+sd-jwt"] as? [String: Any])
                    XCTAssertEqual(inner["sd-jwt_alg_values"] as? [String], ["ES256"])
                }
            ),
            FormatTestCase(
                json: #"{"vp_formats_supported":{"vc+sd-jwt":{"sd-jwt_alg_values":["ES256"]}},"trusted_verifiers":[]}"#,
                expectedKey: "vc+sd-jwt",
                validate: { fmt in
                    let inner = try XCTUnwrap(fmt["vc+sd-jwt"] as? [String: Any])
                    XCTAssertEqual(inner["sd-jwt_alg_values"] as? [String], ["ES256"])
                }
            )
        ]

        for tc in cases {
            let decoded = try JSONDecoder().decode(WalletConfig.self, from: tc.json.data(using: .utf8)!)
            let formats = try encodeVpFormats(decoded)
            XCTAssertEqual(formats.keys.sorted(), [tc.expectedKey])
            try tc.validate(formats)
        }
    }

    func testDecodeVpFormatsSupportedAllFormats() throws {
        let json = """
        {
          "vp_formats_supported": {
            "ldp_vc": { "proof_type_values": ["Ed25519Signature2020"] },
            "mso_mdoc": {},
            "dc+sd-jwt": {}
          },
          "trusted_verifiers": []
        }
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(WalletConfig.self, from: json)
        let formats = try encodeVpFormats(decoded)
        XCTAssertEqual(formats.keys.sorted(), ["dc+sd-jwt", "ldp_vc", "mso_mdoc"])
        let ldpVcFormat = try XCTUnwrap(formats["ldp_vc"] as? [String: Any])
        XCTAssertEqual((ldpVcFormat["proof_type_values"] as? [String])?.sorted(), ["Ed25519Signature2020"])
        let mdocFormat = try XCTUnwrap(formats["mso_mdoc"] as? [String: Any])
        XCTAssertEqual(mdocFormat.count, 0)
        let sdJwtFormat = try XCTUnwrap(formats["dc+sd-jwt"] as? [String: Any])
        XCTAssertEqual(sdJwtFormat.count, 0)
    }

    // MARK: - encode(to:)

    func testEncodeContainsAllExpectedKeys() throws {
        let json = try encodeToJson(makeConfig())
        XCTAssertEqual(json.keys.sorted(), [
            "authorization_encryption_alg_values_supported",
            "authorization_encryption_enc_values_supported",
            "client_id_prefixes_supported",
            "presentation_definition_uri_supported",
            "request_object_signing_alg_values_supported",
            "response_types_supported",
            "trusted_verifiers",
            "vp_formats_supported",
            "validate_trusted_verifier"
        ].sorted())
    }

    func testEncodeSingleFields() throws {
        struct FieldTestCase {
            let label: String
            let config: WalletConfig
            let key: String
            let validate: ([String: Any]) throws -> Void
        }

        let cases: [FieldTestCase] = [
            FieldTestCase(label: "clientIdPrefixes",
                config: self.makeConfig(clientIdPrefixes: [.preRegistered, .redirectUri, .decentralizedIdentifier]),
                key: "client_id_prefixes_supported",
                validate: { json in
                    let encoded = try XCTUnwrap(json["client_id_prefixes_supported"] as? [String])
                    XCTAssertEqual(encoded, ["pre-registered", "redirect_uri", "decentralized_identifier"])
                }
            ),
            FieldTestCase(label: "requestAlgs",
                config: self.makeConfig(requestAlgs: [.edDsa]),
                key: "request_object_signing_alg_values_supported",
                validate: { json in
                    let encoded = try XCTUnwrap(json["request_object_signing_alg_values_supported"] as? [String])
                    XCTAssertEqual(encoded, ["EdDSA"])
                }
            ),
            FieldTestCase(label: "encAlgs",
                config: self.makeConfig(encAlgs: [.ecdhES]),
                key: "authorization_encryption_alg_values_supported",
                validate: { json in
                    let encoded = try XCTUnwrap(json["authorization_encryption_alg_values_supported"] as? [String])
                    XCTAssertEqual(encoded, ["ECDH-ES"])
                }
            ),
            FieldTestCase(label: "encMethods",
                config: self.makeConfig(encMethods: [.a256GCM]),
                key: "authorization_encryption_enc_values_supported",
                validate: { json in
                    let encoded = try XCTUnwrap(json["authorization_encryption_enc_values_supported"] as? [String])
                    XCTAssertEqual(encoded, ["A256GCM"])
                }
            ),
            FieldTestCase(label: "responseTypes",
                config: self.makeConfig(responseTypes: [.vp_token]),
                key: "response_types_supported",
                validate: { json in
                    let encoded = try XCTUnwrap(json["response_types_supported"] as? [String])
                    XCTAssertEqual(encoded, ["vp_token"])
                }
            ),
            FieldTestCase(label: "presentationDefinitionUri",
                config: self.makeConfig(presentationDefinitionUriSupported: false),
                key: "presentation_definition_uri_supported",
                validate: { json in
                    let encoded = try XCTUnwrap(json["presentation_definition_uri_supported"] as? Bool)
                    XCTAssertEqual(encoded, false)
                }
            )
        ]

        for tc in cases {
            let json = try encodeToJson(tc.config)
            try tc.validate(json)
        }
    }

    func testEncodeTrustedVerifiers() throws {
        struct VerifierTestCase {
            let label: String
            let verifier: Verifier
            let validate: (Verifier) -> Void
        }

        let cases: [VerifierTestCase] = [
            VerifierTestCase(
                label: "minimal — required fields only",
                verifier: Verifier(
                    clientId: "v1",
                    responseUris: ["https://v.example.com"]
                ),
                validate: { v in
                    XCTAssertEqual(v.clientId, "v1")
                    XCTAssertEqual(v.responseUris, ["https://v.example.com"])
                    XCTAssertNil(v.jwksUri)
                    XCTAssertFalse(v.allowUnsignedRequest)
                    XCTAssertEqual(v.specVersion, .v1)
                }
            ),
            VerifierTestCase(
                label: "full config — all fields set",
                verifier: Verifier(
                    clientId: "https://verifier.example.com",
                    responseUris: ["https://verifier.example.com/cb", "https://verifier.example.com/response"],
                    jwksUri: "https://verifier.example.com/.well-known/jwks.json",
                    allowUnsignedRequest: true,
                    specVersion: .draft23
                ),
                validate: { v in
                    XCTAssertEqual(v.clientId, "https://verifier.example.com")
                    XCTAssertEqual(v.responseUris, ["https://verifier.example.com/cb", "https://verifier.example.com/response"])
                    XCTAssertEqual(v.jwksUri, "https://verifier.example.com/.well-known/jwks.json")
                    XCTAssertTrue(v.allowUnsignedRequest)
                    XCTAssertEqual(v.specVersion, .draft23)
                }
            )
        ]

        for tc in cases {
            let data = try JSONEncoder().encode(makeConfig(trustedVerifiers: [tc.verifier]))
            let decoded = try JSONDecoder().decode(WalletConfig.self, from: data)
            let result = try XCTUnwrap(decoded.trustedVerifiers.first, "\(tc.label): expected one trusted verifier")
            tc.validate(result)
        }
    }

    func testEncodeVpFormatsSupported() throws {
        struct FormatTestCase {
            let formats: [VPFormatType: VPFormatSupported]
            let expectedKey: String
            let validate: ([String: Any]) throws -> Void
        }

        let cases: [FormatTestCase] = [
            FormatTestCase(formats: [.ldp_vc: ldpVc], expectedKey: "ldp_vc", validate: { fmt in
                let inner = try XCTUnwrap(fmt["ldp_vc"] as? [String: Any])
                XCTAssertEqual((inner["proof_type_values"] as? [String])?.sorted(), ["Ed25519Signature2020"])
            }),
            FormatTestCase(formats: [.mso_mdoc: msoMdoc], expectedKey: "mso_mdoc", validate: { fmt in
                let inner = try XCTUnwrap(fmt["mso_mdoc"] as? [String: Any])
                XCTAssertEqual(inner["issuerauth_alg_values"] as? [Int], [-7])
                XCTAssertEqual(inner["deviceauth_alg_values"] as? [Int], [-9])
            }),
            FormatTestCase(formats: [.dc_sd_jwt: sdJwt], expectedKey: "dc+sd-jwt", validate: { fmt in
                let inner = try XCTUnwrap(fmt["dc+sd-jwt"] as? [String: Any])
                XCTAssertEqual(inner["sd-jwt_alg_values"] as? [String], ["ES256"])
                XCTAssertEqual(inner["kb-jwt_alg_values"] as? [String], ["ES256"])
            })
        ]

        for tc in cases {
            let formats = try encodeVpFormats(makeConfig(vpFormats: tc.formats))
            XCTAssertEqual(formats.keys.sorted(), [tc.expectedKey])
            try tc.validate(formats)
        }
    }

    // MARK: - toWalletMetadata — spec version v1

    func testToWalletMetadataV1ContainsExpectedKeys() throws {
        let metadata = try makeConfig().toWalletMetadata(specVersion: .v1)
        XCTAssertEqual(metadata.keys.sorted(), [
            WalletMetadataConstants.authorizationEncryptionAlgValuesSupported,
            WalletMetadataConstants.authorizationEncryptionEncValuesSupported,
            WalletMetadataConstants.clientIdPrefixesSupported,
            WalletMetadataConstants.requestObjectSigningAlgValuesSupported,
            WalletMetadataConstants.responseTypesSupported,
            MetadataConstants.vpFormatsSupported
        ].sorted())
    }

    func testToWalletMetadataV1Fields() throws {
        struct FieldTestCase {
            let label: String
            let config: WalletConfig
            let key: String
            let validate: ([String: Any]) throws -> Void
        }

        let cases: [FieldTestCase] = [
            FieldTestCase(label: "vpFormats",
                config: makeConfig(vpFormats: [.ldp_vc: ldpVc]),
                key: MetadataConstants.vpFormatsSupported,
                validate: { metadata in
                    let vpFormats = try XCTUnwrap(metadata[MetadataConstants.vpFormatsSupported] as? [String: Any])
                    XCTAssertEqual(vpFormats.keys.sorted(), ["ldp_vc"])
                }
            ),
            FieldTestCase(label: "clientIdPrefixes",
                config: makeConfig(clientIdPrefixes: [.preRegistered, .decentralizedIdentifier]),
                key: WalletMetadataConstants.clientIdPrefixesSupported,
                validate: { metadata in
                    let prefixes = try XCTUnwrap(metadata[WalletMetadataConstants.clientIdPrefixesSupported] as? [String])
                    XCTAssertEqual(prefixes.sorted(), ["decentralized_identifier", "pre-registered"])
                }
            ),
            FieldTestCase(label: "requestAlgs",
                config: makeConfig(requestAlgs: [.edDsa]),
                key: WalletMetadataConstants.requestObjectSigningAlgValuesSupported,
                validate: { metadata in
                    let algs = try XCTUnwrap(metadata[WalletMetadataConstants.requestObjectSigningAlgValuesSupported] as? [String])
                    XCTAssertEqual(algs, ["EdDSA"])
                }
            ),
            FieldTestCase(label: "encAlgs",
                config: makeConfig(encAlgs: [.ecdhES]),
                key: WalletMetadataConstants.authorizationEncryptionAlgValuesSupported,
                validate: { metadata in
                    let algs = try XCTUnwrap(metadata[WalletMetadataConstants.authorizationEncryptionAlgValuesSupported] as? [String])
                    XCTAssertEqual(algs, ["ECDH-ES"])
                }
            ),
            FieldTestCase(label: "encMethods",
                config: makeConfig(encMethods: [.a256GCM]),
                key: WalletMetadataConstants.authorizationEncryptionEncValuesSupported,
                validate: { metadata in
                    let methods = try XCTUnwrap(metadata[WalletMetadataConstants.authorizationEncryptionEncValuesSupported] as? [String])
                    XCTAssertEqual(methods, ["A256GCM"])
                }
            ),
            FieldTestCase(label: "responseTypes",
                config: makeConfig(responseTypes: [.vp_token]),
                key: WalletMetadataConstants.responseTypesSupported,
                validate: { metadata in
                    let types = try XCTUnwrap(metadata[WalletMetadataConstants.responseTypesSupported] as? [String])
                    XCTAssertEqual(types, ["vp_token"])
                }
            )
        ]

        for tc in cases {
            let metadata = try tc.config.toWalletMetadata(specVersion: .v1)
            try tc.validate(metadata)
        }
    }

    // MARK: - toWalletMetadata — omits nil optional fields (both spec versions)

    func testToWalletMetadataOmitsNilOptionalFields() throws {
        struct OmitTestCase {
            let label: String
            let config: WalletConfig
            let key: String
        }

        let cases: [OmitTestCase] = [
            OmitTestCase(label: "v1 requestAlgs nil",    config: makeConfig(requestAlgs: nil),  key: WalletMetadataConstants.requestObjectSigningAlgValuesSupported),
            OmitTestCase(label: "v1 encAlgs nil",        config: makeConfig(encAlgs: nil),       key: WalletMetadataConstants.authorizationEncryptionAlgValuesSupported),
            OmitTestCase(label: "v1 encMethods nil",     config: makeConfig(encMethods: nil),    key: WalletMetadataConstants.authorizationEncryptionEncValuesSupported),
            OmitTestCase(label: "draft23 requestAlgs nil", config: makeConfig(requestAlgs: nil), key: WalletMetadataConstants.requestObjectSigningAlgValuesSupported),
            OmitTestCase(label: "draft23 encAlgs nil",     config: makeConfig(encAlgs: nil),     key: WalletMetadataConstants.authorizationEncryptionAlgValuesSupported),
            OmitTestCase(label: "draft23 encMethods nil",  config: makeConfig(encMethods: nil),  key: WalletMetadataConstants.authorizationEncryptionEncValuesSupported)
        ]

        for (i, tc) in cases.enumerated() {
            let specVersion: SpecVersion = i < 3 ? .v1 : .draft23
            let metadata = try tc.config.toWalletMetadata(specVersion: specVersion)
            XCTAssertNil(metadata[tc.key], "Expected \(tc.key) to be nil for \(tc.label)")
        }
    }

    // MARK: - toWalletMetadata — spec version draft23

    func testToWalletMetadataDraft23ContainsExpectedKeys() throws {
        let metadata = try makeConfig().toWalletMetadata(specVersion: .draft23)
        XCTAssertEqual(metadata.keys.sorted(), [
            WalletMetadataConstants.authorizationEncryptionAlgValuesSupported,
            WalletMetadataConstants.authorizationEncryptionEncValuesSupported,
            WalletMetadataConstants.clientIdSchemesSupported,
            WalletMetadataConstants.presentationDefinitionUriSupported,
            WalletMetadataConstants.requestObjectSigningAlgValuesSupported,
            WalletMetadataConstants.responseTypesSupported,
            MetadataConstants.vpFormatsSupported
        ].sorted())
    }

    func testToWalletMetadataDraft23PresentationDefinitionUriSupported() throws {
        let metadata = try makeConfig(presentationDefinitionUriSupported: true).toWalletMetadata(specVersion: .draft23)
        let value = try XCTUnwrap(metadata[WalletMetadataConstants.presentationDefinitionUriSupported] as? Bool)
        XCTAssertEqual(value, true)
    }

    func testToWalletMetadataDraft23ClientIdSchemesUsesToClientIdSchemeMapping() throws {
        let metadata = try makeConfig(clientIdPrefixes: [.preRegistered, .decentralizedIdentifier]).toWalletMetadata(specVersion: .draft23)
        let schemes = try XCTUnwrap(metadata[WalletMetadataConstants.clientIdSchemesSupported] as? [String])
        XCTAssertEqual(schemes.sorted(), ["did", "pre-registered"])
    }

    func testToWalletMetadataDraft23VpFormatsUsesAlgValuesSupported() throws {
        let metadata = try makeConfig(vpFormats: [.ldp_vc: ldpVc]).toWalletMetadata(specVersion: .draft23)
        let vpFormats = try XCTUnwrap(metadata[MetadataConstants.vpFormatsSupported] as? [String: Any])
        let ldpVcFormat = try XCTUnwrap(vpFormats["ldp_vc"] as? [String: Any])
        let algValues = try XCTUnwrap(ldpVcFormat[MetadataConstants.algValuesSupported] as? [String])
        XCTAssertEqual(algValues.sorted(), ["Ed25519Signature2020"])
    }

    func testToWalletMetadataDraft23VpFormatsEmptyDictWhenNoAlgValues() throws {
        let emptyMsoMdoc = MsoMdocVpFormatSupported(issuerAuthAlgValues: nil, deviceAuthAlgValues: nil)
        let metadata = try makeConfig(vpFormats: [.mso_mdoc: emptyMsoMdoc]).toWalletMetadata(specVersion: .draft23)
        let vpFormats = try XCTUnwrap(metadata[MetadataConstants.vpFormatsSupported] as? [String: Any])
        let msoFormat = try XCTUnwrap(vpFormats["mso_mdoc"] as? [String: Any])
        XCTAssertEqual(msoFormat.count, 0)
    }

    func testToWalletMetadataDraft23ResponseTypesEncoded() throws {
        let metadata = try makeConfig(responseTypes: [.vp_token]).toWalletMetadata(specVersion: .draft23)
        let types = try XCTUnwrap(metadata[WalletMetadataConstants.responseTypesSupported] as? [String])
        XCTAssertEqual(types, ["vp_token"])
    }

    // MARK: - toWalletMetadata — excludeSignedRequestConfig flag

    func testToWalletMetadataExcludeSignedRequestConfig() throws {
        struct FlagTestCase {
            let specVersion: SpecVersion
            let exclude: Bool
            let expectNil: Bool
        }

        let cases: [FlagTestCase] = [
            FlagTestCase(specVersion: .v1,     exclude: true,  expectNil: true),
            FlagTestCase(specVersion: .draft23, exclude: true,  expectNil: true),
            FlagTestCase(specVersion: .v1,     exclude: false, expectNil: false),
            FlagTestCase(specVersion: .draft23, exclude: false, expectNil: false)
        ]

        for tc in cases {
            let metadata = try makeConfig(requestAlgs: [.edDsa]).toWalletMetadata(specVersion: tc.specVersion, excludeSignedRequestConfig: tc.exclude)
            if tc.expectNil {
                XCTAssertNil(metadata[WalletMetadataConstants.requestObjectSigningAlgValuesSupported],
                    "Expected nil for specVersion=\(tc.specVersion) exclude=\(tc.exclude)")
            } else {
                let algs = try XCTUnwrap(metadata[WalletMetadataConstants.requestObjectSigningAlgValuesSupported] as? [String])
                XCTAssertEqual(algs, ["EdDSA"],
                    "Expected [EdDSA] for specVersion=\(tc.specVersion) exclude=\(tc.exclude)")
            }
        }
    }

    // MARK: - toWalletMetadata — encoding failure

    func testToWalletMetadataThrowsEncodingFailedWhenVpFormatEncodingFails() throws {
        struct ThrowingVPFormat: VPFormatSupported {
            func toAlgValuesSupported() -> [String]? { nil }
            func encode(to encoder: Encoder) throws {
                throw NSError(domain: "test", code: 0, userInfo: [NSLocalizedDescriptionKey: "forced encode failure"])
            }
            init() {}
            init(from decoder: Decoder) throws {}
        }
        let config = makeConfig(vpFormats: [.ldp_vc: ThrowingVPFormat()])
        XCTAssertThrowsError(try config.toWalletMetadata(specVersion: .v1)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Encoding failed for  due to this error: Error encoding wallet metadata",
                expectedCode: OpenID4VPErrorCodes.serverError
            )
        }
    }
}
