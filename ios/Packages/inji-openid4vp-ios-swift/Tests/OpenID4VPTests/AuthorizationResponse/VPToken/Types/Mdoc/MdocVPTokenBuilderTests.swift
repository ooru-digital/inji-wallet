import XCTest
@testable import OpenID4VP

final class MdocVPTokenBuilderTests: XCTestCase {

    let builder = MdocVPTokenBuilder(authorizationRequest: getMockAuthorizationRequest())
    let docType = "org.iso.18013.5.1.mDL"
    let deviceAuthBytes = "d818587e847444657669636541757468656e7469636174696f6e"

    // MARK: - build(credentialInputDescriptorMappings:)

    func testBuildSuccess() throws {
        let signature = Data("mock-signature".utf8)
        let mappings = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-1", identifier: "uuid1")
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: ["uuid1": deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )
        let signingResults = [VPTokenSigningResult(id: "uuid1", signedData: signature)]

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: signingResults,
            rootIndex: 0
        )

        XCTAssertEqual(result.vpTokens.count, 1)
        let mdocToken = try XCTUnwrap(result.vpTokens.first as? MdocVPToken)
        XCTAssertFalse(mdocToken.base64EncodedDeviceResponse.isEmpty)
        XCTAssertEqual(result.DescriptorMaps.count, 1)
        XCTAssertEqual(result.DescriptorMaps[0].id, "id-1")
        XCTAssertEqual(result.DescriptorMaps[0].format, .mso_mdoc)
        XCTAssertEqual(result.DescriptorMaps[0].path, "$[0]")
        XCTAssertEqual(result.nextIndex, 1)
    }

    func testBuildThrowsWhenPayloadMissing() {
        let mappings = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-1", identifier: "uuid1")
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [:],
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Missing payload for identifier: uuid1", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testBuildThrowsWhenSigningResultMissing() {
        let mappings = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-1", identifier: "uuid1")
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: ["uuid1": deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Missing VP token signing result for credential identifier uuid1", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testBuildThrowsWhenExtraSigningResults() {
        let signature = Data("mock-signature".utf8)
        let mappings = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-1", identifier: "uuid1")
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: ["uuid1": deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )
        let signingResults = [
            VPTokenSigningResult(id: "uuid2", signedData: signature)
        ]

        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: signingResults,
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Missing VP token signing result for credential identifier uuid1", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    // MARK: - build(credentialToCredentialQueryIdMappings:)

    func testDcqlBuildSuccess() throws {
        let signature = Data("mock-signature".utf8)
        var mapping = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        mapping.identifier = "uuid1"
        let mappings = [mapping]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: ["uuid1": deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )

        let result = try builder.build(
            credentialToCredentialQueryIdMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: signature)]
        )

        XCTAssertEqual(result.keys.sorted(), ["q1"])
        XCTAssertEqual(result["q1"]?.count, 1)
        let mdocToken = try XCTUnwrap(result["q1"]?.first as? MdocVPToken)
        XCTAssertFalse(mdocToken.base64EncodedDeviceResponse.isEmpty)
    }

    func testDcqlBuildMultipleCredentialsDifferentQueryIds() throws {
        let sig1 = Data("sig1".utf8)
        let sig2 = Data("sig2".utf8)

        var mapping1 = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        mapping1.identifier = "uuid1"
        var mapping2 = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q2")
        mapping2.identifier = "uuid2"
        let mappings = [mapping1, mapping2]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: ["uuid1": deviceAuthBytes, "uuid2": deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )

        let result = try builder.build(
            credentialToCredentialQueryIdMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: sig1), VPTokenSigningResult(id: "uuid2", signedData: sig2)]
        )

        XCTAssertEqual(result.keys.sorted(), ["q1", "q2"])
        XCTAssertEqual(result["q1"]?.count, 1)
        XCTAssertEqual(result["q2"]?.count, 1)
        XCTAssertNotNil(result["q1"]?.first as? MdocVPToken)
        XCTAssertNotNil(result["q2"]?.first as? MdocVPToken)
    }

    func testDcqlBuildMultipleCredentialsSameQueryId() throws {
        let sig1 = Data("sig1".utf8)
        let sig2 = Data("sig2".utf8)

        var mapping1 = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        mapping1.identifier = "uuid1"
        var mapping2 = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        mapping2.identifier = "uuid2"
        let mappings = [mapping1, mapping2]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: ["uuid1": deviceAuthBytes, "uuid2": deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )

        let result = try builder.build(
            credentialToCredentialQueryIdMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: sig1), VPTokenSigningResult(id: "uuid2", signedData: sig2)]
        )

        XCTAssertEqual(result.keys.sorted(), ["q1"])
        XCTAssertEqual(result["q1"]?.count, 2)
        XCTAssertNotNil(result["q1"]?.first as? MdocVPToken)
        XCTAssertNotNil(result["q1"]?[1] as? MdocVPToken)
    }

    func testDcqlBuildThrowsWhenPayloadMissing() {
        var mapping = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        mapping.identifier = "uuid1"
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [:],
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Missing payload for identifier: uuid1", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildThrowsWhenSigningResultMissing() {
        var mapping = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        mapping.identifier = "uuid1"
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: ["uuid1": deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Missing VP token signing result for credential identifier uuid1", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    // With identifier-based lookup we iterate over mappings, so empty mappings
    // produces an empty result rather than throwing.
    func testDcqlBuildWithEmptyMappingsReturnsEmptyResult() throws {
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: ["uuid1": deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )

        let result = try builder.build(
            credentialToCredentialQueryIdMappings: [],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: Data("sig".utf8))]
        )
        XCTAssertTrue(result.isEmpty)
    }

    func testDcqlBuildThrowsWhenCredentialIsNotString() {
        var mapping = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(12345), credentialQueryId: "q1")
        mapping.identifier = "uuid1"
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: ["uuid1": deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: Data("sig".utf8))]
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Invalid MSO-MDOC token: expected String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildThrowsWhenCredentialIsInvalidCBOR() {
        var mapping = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable("invalidCBOR"), credentialQueryId: "q1")
        mapping.identifier = "uuid1"
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: ["uuid1": deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: Data("sig".utf8))]
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Invalid Verifiable Credential: Error while decoding credential", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildEmptyMappingsReturnsEmptyResult() throws {
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String]() as [String: String],
            unsignedVPTokens: []
        )

        let result = try builder.build(
            credentialToCredentialQueryIdMappings: [],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )

        XCTAssertEqual(result.count, 0)
    }

    // MARK: - // VCI 1.0 compliant mDoc - DeviceSigned structure

    func testBuildSuccessWithFormat1Mdoc() throws {
        let signature = Data("mock-signature".utf8)
        let mappings = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdocFormat1), inputDescriptorId: "id-1", identifier: "uuid1")
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: ["uuid1": deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )
        let signingResults = [VPTokenSigningResult(id: "uuid1", signedData: signature)]

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: signingResults,
            rootIndex: 0
        )

        XCTAssertEqual(result.vpTokens.count, 1)
        let mdocToken = try XCTUnwrap(result.vpTokens.first as? MdocVPToken)
        XCTAssertFalse(mdocToken.base64EncodedDeviceResponse.isEmpty)
        XCTAssertEqual(result.DescriptorMaps.count, 1)
        XCTAssertEqual(result.DescriptorMaps[0].id, "id-1")
        XCTAssertEqual(result.DescriptorMaps[0].format, .mso_mdoc)
        XCTAssertEqual(result.nextIndex, 1)
    }

    func testDcqlBuildSuccessWithFormat1Mdoc() throws {
        let signature = Data("mock-signature".utf8)
        var mapping = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdocFormat1), credentialQueryId: "q1")
        mapping.identifier = "uuid1"
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: ["uuid1": deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )

        let result = try builder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: signature)]
        )

        XCTAssertEqual(result.keys.sorted(), ["q1"])
        XCTAssertEqual(result["q1"]?.count, 1)
        let mdocToken = try XCTUnwrap(result["q1"]?.first as? MdocVPToken)
        XCTAssertFalse(mdocToken.base64EncodedDeviceResponse.isEmpty)
    }
}
