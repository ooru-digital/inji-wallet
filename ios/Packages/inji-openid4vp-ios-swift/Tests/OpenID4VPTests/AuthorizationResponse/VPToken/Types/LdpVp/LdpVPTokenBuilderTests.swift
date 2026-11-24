import XCTest
@testable import OpenID4VP

final class LdpVPTokenBuilderTests: XCTestCase {

    let builder = LdpVPTokenBuilder(authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23))

    private let credential = AnyCodable(["@context": ["https://www.w3.org/2018/credentials/v1"], "type": ["VerifiableCredential"]])
    private let unsignedVPToken = UnsignedVPToken(
        id: "uuid1",
        format: .ldp_vc,
        holderKeyReference: "did:example:holder",
        signatureAlgorithm: SignatureAlgorithm.edDsa.rawValue,
        // "<base64url-JWS-header>.<payload>" — header decodes to {"alg":"EdDSA","crit":["b64"],"b64":false}
        dataToSign: Data("eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9.payload".utf8)
    )

    private func makeLdpVPToken(
        proofType: String = SignatureSuite.jsonWebSignature2020.rawValue,
        jws: String? = nil,
        proofValue: String? = nil,
        signatureValue: String? = nil
    ) ->LdpVP {
        let proof = Proof(
            type: proofType,
            created: nil,
            challenge: "nonce",
            domain: "client_id",
            jws: jws,
            verificationMethod: "did:example:holder"
        )
        return .vp(
            LdpVPToken(
                verifiableCredential: [credential],
                id: "vp-id",
                holder: "did:example:holder",
                proof: proof
            )
        )
    }

    // MARK: - Data Integrity proofs (VC 2.0)

    private func buildDataIntegrity(signatureLength: Int) throws -> (vpTokens: [VPToken], DescriptorMaps: [DescriptorMap], nextIndex: Int) {
        let ldpToken = makeLdpVPToken(proofType: SignatureSuite.dataIntegrityProof.rawValue)
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1", identifier: "uuid1")
        ]
        let unsignedResult = (vpTokenSigningPayload: ["uuid1": ldpToken] as VPTokenSigningPayload, unsignedVPTokens: [unsignedVPToken])

        return try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [
                VPTokenSigningResult(id: "uuid1", signedData: Data(repeating: 0x01, count: signatureLength))
            ],
            rootIndex: 0
        )
    }

    func testDataIntegritySignatureEncodedAsMultibaseProofValue() throws {
        let result = try buildDataIntegrity(signatureLength: 64)

        let token = try XCTUnwrap(result.vpTokens[0] as? LdpVPToken)
        XCTAssertEqual(token.proof?.type, SignatureSuite.dataIntegrityProof.rawValue)
        XCTAssertEqual(
            token.proof?.proofValue,
            BaseEncoding.base58BtcEncode(Data(repeating: 0x01, count: 64))
        )
        XCTAssertNil(token.proof?.jws)
        XCTAssertNil(token.proof?.signatureValue)
    }

    func testDataIntegrityRejectsSignatureThatIsNot64Bytes() throws {
        for length in [63, 65] {
            XCTAssertThrowsError(try buildDataIntegrity(signatureLength: length)) { error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: "Data Integrity Ed25519 and P-256 signatures must be exactly 64 bytes",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }

    // MARK: - build(credentialInputDescriptorMappings:)

    func testBuildWithHolderBindingJsonWebSignature2020() throws {
        let signature = Data("mockSig".utf8)
        let ldpToken = makeLdpVPToken(proofType: SignatureSuite.jsonWebSignature2020.rawValue)
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1", identifier: "uuid1")
        ]
        let unsignedResult = (vpTokenSigningPayload: ["uuid1" : ldpToken] as VPTokenSigningPayload, unsignedVPTokens: [unsignedVPToken])

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: signature)],
            rootIndex: 0
        )

        XCTAssertEqual(result.vpTokens.count, 1)
        let token = try XCTUnwrap(result.vpTokens[0] as? LdpVPToken)
        let expectedJws = "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..\(signature.toBase64UrlEncoded())"
        XCTAssertEqual(token.proof?.jws, expectedJws)
        XCTAssertNil(token.proof?.proofValue)
        XCTAssertNil(token.proof?.signatureValue)
        XCTAssertEqual(result.DescriptorMaps.count, 1)
        XCTAssertEqual(result.DescriptorMaps[0].id, "desc-1")
        XCTAssertEqual(result.DescriptorMaps[0].format, .ldp_vp)
        XCTAssertEqual(result.DescriptorMaps[0].path, "$[0]")
        XCTAssertEqual(result.nextIndex, 1)
    }

    func testBuildWithHolderBindingEd25519Signature2018() throws {
        let signature = Data("mockSig".utf8)
        let ldpToken = makeLdpVPToken(proofType: SignatureSuite.ed25519Signature2018.rawValue)
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1", identifier: "uuid1")
        ]
        let unsignedResult = (vpTokenSigningPayload: ["uuid1" : ldpToken] as VPTokenSigningPayload, unsignedVPTokens: [unsignedVPToken])

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: signature)],
            rootIndex: 0
        )

        let token = try XCTUnwrap(result.vpTokens[0] as? LdpVPToken)
        let expectedJws = "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..\(signature.toBase64UrlEncoded())"
        XCTAssertEqual(token.proof?.jws, expectedJws)
        XCTAssertNil(token.proof?.proofValue)
        XCTAssertNil(token.proof?.signatureValue)
    }

    func testBuildWithHolderBindingRsaSignature2018() throws {
        let signature = Data("mockSig".utf8)
        let ldpToken = makeLdpVPToken(proofType: SignatureSuite.rsaSignature2018.rawValue)
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1", identifier: "uuid1")
        ]
        let unsignedResult = (vpTokenSigningPayload: ["uuid1" : ldpToken] as VPTokenSigningPayload, unsignedVPTokens: [unsignedVPToken])

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: signature)],
            rootIndex: 0
        )

        let token = try XCTUnwrap(result.vpTokens[0] as? LdpVPToken)
        XCTAssertEqual(token.proof?.signatureValue, signature.toBase64UrlEncoded())
        XCTAssertNil(token.proof?.jws)
        XCTAssertNil(token.proof?.proofValue)
    }

    func testBuildWithHolderBindingEd25519Signature2020() throws {
        let signature = Data("mockSig".utf8)
        let ldpToken = makeLdpVPToken(proofType: SignatureSuite.ed25519Signature2020.rawValue)
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1", identifier: "uuid1")
        ]
        let unsignedResult = (vpTokenSigningPayload: ["uuid1" : ldpToken] as VPTokenSigningPayload, unsignedVPTokens: [unsignedVPToken])

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: signature)],
            rootIndex: 0
        )

        let token = try XCTUnwrap(result.vpTokens[0] as? LdpVPToken)
        XCTAssertEqual(token.proof?.proofValue, BaseEncoding.base58BtcEncode(signature))
        XCTAssertNil(token.proof?.jws)
        XCTAssertNil(token.proof?.signatureValue)
    }

    func testBuildRespectsRootIndexOffset() throws {
        let signature = Data("mockSig".utf8)
        let ldpToken = makeLdpVPToken()
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1", identifier: "uuid1")
        ]
        let unsignedResult = (vpTokenSigningPayload: ["uuid1" : ldpToken] as VPTokenSigningPayload, unsignedVPTokens: [unsignedVPToken])

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: signature)],
            rootIndex: 3
        )

        XCTAssertEqual(result.DescriptorMaps[0].path, "$[3]")
        XCTAssertEqual(result.nextIndex, 4)
    }

    func testBuildDescriptorMapContainsAllMappings() throws {
        let ldpToken = makeLdpVPToken()
        let unsignedVPToken2 = UnsignedVPToken(
            id: "uuid2",
            format: .ldp_vc,
            holderKeyReference: "did:example:holder",
            signatureAlgorithm: SignatureAlgorithm.edDsa.rawValue,
            dataToSign: Data("eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9.payload".utf8)
        )
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1", identifier: "uuid1", nestedPath: "$.verifiableCredential[0]"),
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-2", identifier: "uuid2", nestedPath: "$.verifiableCredential[0]"),
        ]
        let unsignedResult = (vpTokenSigningPayload: ["uuid1" : ldpToken, "uuid2": ldpToken] as VPTokenSigningPayload, unsignedVPTokens: [unsignedVPToken, unsignedVPToken2])

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [
                VPTokenSigningResult(id: "uuid2", signedData: Data("mockSig2".utf8)),
                VPTokenSigningResult(id: "uuid1", signedData: Data("mockSig1".utf8))
            ],
            rootIndex: 0
        )

        // 1 VP per VC is constructed -> 2 VCs = 2 VPs
        XCTAssertEqual(result.vpTokens.count, 2)
        XCTAssertEqual(result.DescriptorMaps.count, 2)
        let descriptorMap1: DescriptorMap = result.DescriptorMaps[0]
        let descriptorMap2: DescriptorMap = result.DescriptorMaps[1]
        
        XCTAssertEqual(descriptorMap1.id, "desc-1")
        XCTAssertEqual(descriptorMap2.id, "desc-2")
        XCTAssertEqual(descriptorMap1.format, .ldp_vp)
        XCTAssertEqual(descriptorMap2.format, .ldp_vp)
        XCTAssertEqual(descriptorMap1.path, "$[0]")
        XCTAssertEqual(descriptorMap2.path, "$[1]")
        XCTAssertEqual(descriptorMap1.pathNested?.path, "$.verifiableCredential[0]")
        XCTAssertEqual(descriptorMap2.pathNested?.path, "$.verifiableCredential[0]")
    }

    func testBuildThrowsWhenPayloadIsNotLdpVPToken() {
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1", identifier: "uuid1")
        ]
        let unsignedResult = (vpTokenSigningPayload: ["uuid1" : "not-an-ldp-vp-token"] as VPTokenSigningPayload, unsignedVPTokens: [unsignedVPToken])

        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: Data("sig".utf8))],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Expected List<LdpVPToken> as payload", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testBuildThrowsWhenSigningResultIsMissing() {
        let ldpToken = makeLdpVPToken()
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1", identifier: "uuid1")
        ]
        let unsignedResult = (vpTokenSigningPayload: ["uuid1" : ldpToken] as VPTokenSigningPayload, unsignedVPTokens: [unsignedVPToken])

        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Missing LDP signature", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    // MARK: - build(credentialToCredentialQueryIdMappings:)

    func testDcqlBuildWithHolderBindingJsonWebSignature2020() throws {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        let signature = Data("mockSig".utf8)
        let ldpToken = makeLdpVPToken(proofType: SignatureSuite.jsonWebSignature2020.rawValue)
        var mapping = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping.identifier = "uuid1"
        let unsignedResult = (vpTokenSigningPayload: ["uuid1": ldpToken] as [String: LdpVP] as VPTokenSigningPayload, unsignedVPTokens: [unsignedVPToken])

        let result = try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: signature)]
        )

        XCTAssertEqual(result.keys.sorted(), ["q1"])
        XCTAssertEqual(result["q1"]?.count, 1)
        let token = try XCTUnwrap(result["q1"]?.first as? LdpVPToken)
        let expectedJws = "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..\(signature.toBase64UrlEncoded())"
        XCTAssertEqual(token.proof?.jws, expectedJws)
    }

    func testDcqlBuildWithoutHolderBinding() throws {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: false)
        var mapping = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping.identifier = "uuid1"
        let unsignedResult = (vpTokenSigningPayload: ["uuid1": LdpVP.vc(LdpVCToken(verifiableCredential: credential))] as [String: LdpVP] as VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]())
        
        let result = try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )
        
        XCTAssertEqual(result.keys.sorted(), ["q1"])
        XCTAssertEqual(result["q1"]?.count, 1)
        let token = try XCTUnwrap(result["q1"]?.first as? LdpVP)
        guard case .vc(let presentation) = token else {
            XCTFail("Expected VC here")
            return
        }
        let credentialDict = try XCTUnwrap(presentation.verifiableCredential.value as? [String: Any])
        XCTAssertEqual(credentialDict["type"] as? [String], ["VerifiableCredential"])
    }

    func testDcqlBuildMultipleCredentialsDifferentQueryIds() throws {
        let dcqlBuilder = builderWithDcqlRequest(credentials: [("q1", true), ("q2", false)])
        let signature = Data("mockSig".utf8)
        let ldpToken1 = makeLdpVPToken(proofType: SignatureSuite.jsonWebSignature2020.rawValue)

        var mapping1 = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping1.identifier = "uuid1"
        var mapping2 = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q2")
        mapping2.identifier = "uuid2"

        let payload: [String: LdpVP] = [
            "uuid1": ldpToken1,
            "uuid2": .vc(LdpVCToken(verifiableCredential: credential))
        ]
        let unsignedResult = (vpTokenSigningPayload: payload as VPTokenSigningPayload, unsignedVPTokens: [unsignedVPToken])

        let result = try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping1, mapping2],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: signature)]
        )

        XCTAssertEqual(result.keys.sorted(), ["q1", "q2"])
        XCTAssertEqual(result["q1"]?.count, 1)
        XCTAssertEqual(result["q2"]?.count, 1)

        let token1 = try XCTUnwrap(result["q1"]?.first as? LdpVPToken)
        XCTAssertNotNil(token1.proof?.jws)

        let tokenData = try XCTUnwrap(result["q2"]?.first as? LdpVP)
        guard case .vc(_) = tokenData else {
            XCTFail("Expected LdpVCToken for no-binding query")
            return
        }
    }

    func testDcqlBuildMultipleCredentialsSameQueryId() throws {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        let signature = Data("mockSig".utf8)
        let ldpToken1 = makeLdpVPToken(proofType: SignatureSuite.jsonWebSignature2020.rawValue)
        let ldpToken2 = makeLdpVPToken(proofType: SignatureSuite.jsonWebSignature2020.rawValue)
        let unsignedVPToken2 = UnsignedVPToken(
            id: "uuid2",
            format: .ldp_vc,
            holderKeyReference: "did:example:holder",
            signatureAlgorithm: SignatureAlgorithm.edDsa.rawValue,
            dataToSign: Data("eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9.payload".utf8)
        )

        var mapping1 = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping1.identifier = "uuid1"
        var mapping2 = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping2.identifier = "uuid2"

        let payload = ["uuid1": ldpToken1, "uuid2": ldpToken2] as [String: LdpVP]
        let unsignedResult = (vpTokenSigningPayload: payload as VPTokenSigningPayload, unsignedVPTokens: [unsignedVPToken, unsignedVPToken2])

        let result = try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping1, mapping2],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: signature), VPTokenSigningResult(id: "uuid2", signedData: signature)]
        )

        XCTAssertEqual(result.keys.sorted(), ["q1"])
        XCTAssertEqual(result["q1"]?.count, 2)
        XCTAssertTrue(result["q1"]?.first is LdpVPToken)
        XCTAssertTrue(result["q1"]?.last is LdpVPToken)
    }

    func testDcqlBuildThrowsWhenPayloadIsNotLdpVPTokenDictionary() {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: false)
        var mapping = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping.identifier = "uuid1"
        let unsignedResult = (vpTokenSigningPayload: ["uuid1":"invalid"] as VPTokenSigningPayload, unsignedVPTokens: [unsignedVPToken])

        XCTAssertThrowsError(try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Expected Map<String, Any> as payload for DCQL LDP flow", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildSucceedsEvenWhenCredentialQueryIdNotInDcqlQuery() throws {
        // The signed builder does not validate credentialQueryId against the DCQL definition;
        // it uses the mapping's credentialQueryId directly as the result key.
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: false)
        var mapping = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "nonexistent")
        mapping.identifier = "uuid1"
        let unsignedResult = (vpTokenSigningPayload: ["uuid1": LdpVP.vc(LdpVCToken(verifiableCredential: credential))] as [String: LdpVP] as VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]())

        let result = try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )

        XCTAssertEqual(result["nonexistent"]?.count, 1)
    }

    func testDcqlBuildThrowsWhenPayloadMissingForIdentifier() {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        let signature = Data("mockSig".utf8)
        var mapping = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping.identifier = "uuid-missing"
        let unsignedResult = (vpTokenSigningPayload: [String: LdpVP]() as VPTokenSigningPayload, unsignedVPTokens: [unsignedVPToken])

        XCTAssertThrowsError(try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: signature)]
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "No payload found for identifier: uuid-missing", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildThrowsWhenSigningResultMissing() {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        let ldpToken = makeLdpVPToken()
        var mapping = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping.identifier = "uuid1"
        let unsignedResult = (vpTokenSigningPayload: ["uuid1": ldpToken] as [String: LdpVP] as VPTokenSigningPayload, unsignedVPTokens: [unsignedVPToken])

        XCTAssertThrowsError(try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Missing VP token signing result for credential identifier uuid1", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildThrowsWhenSignedDataIsEmpty() throws {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        let ldpToken = makeLdpVPToken()
        var mapping = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping.identifier = "uuid1"
        let unsignedResult = (vpTokenSigningPayload: ["uuid1": ldpToken] as [String: LdpVP] as VPTokenSigningPayload, unsignedVPTokens: [unsignedVPToken])

        XCTAssertThrowsError(try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: Data())]
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Invalid signature for identifier uuid1", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildThrowsWhenUnsignedVPTokenMissing() {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        let ldpToken = makeLdpVPToken()
        var mapping = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping.identifier = "uuid1"
        let unsignedResult = (vpTokenSigningPayload: ["uuid1": ldpToken] as [String: LdpVP] as VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]())

        XCTAssertThrowsError(try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: Data("sig".utf8))]
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Missing unsigned VP token for identifier uuid1", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildWithUnsupportedSignatureSuiteSetsProofValue() throws {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        let ldpToken = makeLdpVPToken(proofType: "UnsupportedSuite2099")
        var mapping = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping.identifier = "uuid1"
        let unsignedResult = (vpTokenSigningPayload: ["uuid1": ldpToken] as [String: LdpVP] as VPTokenSigningPayload, unsignedVPTokens: [unsignedVPToken])

        // Default branch: unsupported suite falls through to proofValue (no throw, mirrors Kotlin)
        let result = try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: Data("sig".utf8))]
        )
        XCTAssertEqual(result["q1"]?.count, 1)
        let token = try XCTUnwrap(result["q1"]?.first as? LdpVPToken)
        XCTAssertNotNil(token.proof?.proofValue)
    }

    // MARK: - Helpers

    private func builderWithDcqlRequest(credentialQueryId: String, requireCryptographicHolderBinding: Bool) -> LdpVPTokenBuilder {
        builderWithDcqlRequest(credentials: [(credentialQueryId, requireCryptographicHolderBinding)])
    }

    private func builderWithDcqlRequest(credentials: [(id: String, requireCryptographicHolderBinding: Bool)]) -> LdpVPTokenBuilder {
        let dcqlJson: [String: Any] = [
            "credentials": credentials.map { cred in
                [
                    "id": cred.id,
                    "format": "ldp_vc",
                    "meta": [:] as [String: Any],
                    "require_cryptographic_holder_binding": cred.requireCryptographicHolderBinding
                ] as [String: Any]
            }
        ]
        let dcqlQuery = createInstance(dcqlJson, as: DCQLQuery.self)
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
        return LdpVPTokenBuilder(authorizationRequest: authorizationRequest)
    }
}
