import XCTest
@testable import OpenID4VP

final class UnsignedMdocVPTokenBuilderTests: XCTestCase {

    private let expectedDocType = "org.iso.18013.5.1.mDL"

    // MARK: - build(credentialInputDescriptorMappings:)

    func testCreationOfUnsignedMdocVPToken() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let payloadMap = try XCTUnwrap(payload as? [String: String])

        // Identifier is now a generated UUID
        let identifier = try XCTUnwrap(mappings[0].identifier)
        XCTAssertTrue(identifier.hasPrefix("urn:uuid:"), "Expected UUID identifier, got: \(identifier)")

        // Payload map is keyed by the UUID identifier (one entry per credential)
        XCTAssertEqual(payloadMap.count, 1)
        let bytes = try XCTUnwrap(payloadMap[identifier])
        XCTAssertTrue(bytes.hasPrefix("846a"), "Expected CBOR-tagged hex starting with '846a', got: \(bytes.prefix(4))")

        XCTAssertEqual(unsignedVPTokens.count, 1)
        XCTAssertEqual(unsignedVPTokens[0].format, .mso_mdoc)
        // The unsigned token id must match the mapping identifier
        XCTAssertEqual(unsignedVPTokens[0].id, identifier)
    }

    func testCreationOfUnsignedMdocVPTokenForDraft23() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let payloadMap = try XCTUnwrap(payload as? [String: String])
        let identifier = try XCTUnwrap(mappings[0].identifier)
        XCTAssertTrue(identifier.hasPrefix("urn:uuid:"), "Expected UUID identifier, got: \(identifier)")

        XCTAssertEqual(payloadMap.count, 1)
        let bytes = try XCTUnwrap(payloadMap[identifier])
        XCTAssertTrue(bytes.hasPrefix("846a"), "Expected CBOR-tagged hex starting with '846a', got: \(bytes.prefix(4))")

        XCTAssertEqual(unsignedVPTokens.count, 1)
        XCTAssertEqual(unsignedVPTokens[0].format, .mso_mdoc)
        XCTAssertEqual(unsignedVPTokens[0].id, identifier)
    }

    func testDeviceAuthenticationBytesAreDifferentBetweenSpecVersions() async throws {
        var mappingsDraft23 = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-1")
        ]
        var mappingsV1 = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-1")
        ]

        let (draft23Payload, _) = try await UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            mdocGeneratedNonce: "mock-nonce"
        ).build(credentialInputDescriptorMappings: &mappingsDraft23)

        let (v1Payload, _) = try await UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        ).build(credentialInputDescriptorMappings: &mappingsV1)

        // Each payload map has exactly one UUID-keyed entry; compare the byte values
        let draft23Map = try XCTUnwrap(draft23Payload as? [String: String])
        let v1Map = try XCTUnwrap(v1Payload as? [String: String])
        XCTAssertEqual(draft23Map.count, 1)
        XCTAssertEqual(v1Map.count, 1)
        let draft23Bytes = try XCTUnwrap(draft23Map.values.first)
        let v1Bytes = try XCTUnwrap(v1Map.values.first)
        XCTAssertNotEqual(draft23Bytes, v1Bytes)
    }

    func testThrowErrorWhenUnableToDecodeCredential() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable("invalidCBOR"), inputDescriptorId: "id-1")
        ]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialInputDescriptorMappings: &mappings)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid Verifiable Credential: Error while decoding credential",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorWhenMdocIsNotString() async {
        do {
            let builder = try UnsignedMdocVPTokenBuilder(
                authorizationRequest: getMockAuthorizationRequest(),
                specVersion: .v1,
                mdocGeneratedNonce: "mock-nonce"
            )
            var mappings = [
                CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(12345), inputDescriptorId: "id-1")
            ]

            await XCTAssertAsyncThrowsError(try await builder.build(credentialInputDescriptorMappings: &mappings)) { error in
                assertOpenID4VPException(error,
                    expectedMessage: "MDOC credential is not a String",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        } catch {
            XCTFail("Builder init should not throw: \(error)")
        }
    }

    func testThrowErrorWhenDuplicateDocTypes() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-1"),
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-2"),
        ]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialInputDescriptorMappings: &mappings)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Duplicate Mdoc Credentials with same doctype found",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - build(credentialToCredentialQueryIdMappings:)

    func testDcqlBuildReturnsCorrectPayloadAndUnsignedTokensForV1() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let payloadMap = try XCTUnwrap(payload as? [String: String])
        let identifier = try XCTUnwrap(mappings[0].identifier)
        XCTAssertTrue(identifier.hasPrefix("urn:uuid:"), "Expected UUID identifier, got: \(identifier)")

        XCTAssertEqual(payloadMap.count, 1)
        let bytes = try XCTUnwrap(payloadMap[identifier])
        XCTAssertTrue(bytes.hasPrefix("846a"), "Expected CBOR-tagged hex starting with '846a', got: \(bytes.prefix(4))")

        XCTAssertEqual(unsignedVPTokens.count, 1)
        XCTAssertEqual(unsignedVPTokens[0].format, .mso_mdoc)
        XCTAssertEqual(unsignedVPTokens[0].dataToSign.map { String(format: "%02x", $0) }.joined(), bytes)
        XCTAssertEqual(unsignedVPTokens[0].id, identifier)
    }

    func testDcqlBuildReturnsCorrectPayloadAndUnsignedTokensForDraft23() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let payloadMap = try XCTUnwrap(payload as? [String: String])
        let identifier = try XCTUnwrap(mappings[0].identifier)
        XCTAssertTrue(identifier.hasPrefix("urn:uuid:"), "Expected UUID identifier, got: \(identifier)")

        XCTAssertEqual(payloadMap.count, 1)
        let bytes = try XCTUnwrap(payloadMap[identifier])
        XCTAssertTrue(bytes.hasPrefix("846a"), "Expected CBOR-tagged hex starting with '846a', got: \(bytes.prefix(4))")

        XCTAssertEqual(unsignedVPTokens.count, 1)
        XCTAssertEqual(unsignedVPTokens[0].format, .mso_mdoc)
        XCTAssertEqual(unsignedVPTokens[0].dataToSign.map { String(format: "%02x", $0) }.joined(), bytes)
        XCTAssertEqual(unsignedVPTokens[0].id, identifier)
    }

    func testDcqlBuildDeviceAuthBytesAreDifferentBetweenSpecVersions() async throws {
        var mappingsDraft23 = [CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")]
        var mappingsV1 = [CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")]

        let (draft23Payload, _) = try await UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            mdocGeneratedNonce: "mock-nonce"
        ).build(credentialToCredentialQueryIdMappings: &mappingsDraft23)

        let (v1Payload, _) = try await UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        ).build(credentialToCredentialQueryIdMappings: &mappingsV1)

        // Each payload map has exactly one UUID-keyed entry; compare the byte values
        let draft23Map = try XCTUnwrap(draft23Payload as? [String: String])
        let v1Map = try XCTUnwrap(v1Payload as? [String: String])
        XCTAssertEqual(draft23Map.count, 1)
        XCTAssertEqual(v1Map.count, 1)
        let draft23Bytes = try XCTUnwrap(draft23Map.values.first)
        let v1Bytes = try XCTUnwrap(v1Map.values.first)
        XCTAssertNotEqual(draft23Bytes, v1Bytes)
    }

    func testDcqlBuildThrowsWhenCredentialIsNotString() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(12345), credentialQueryId: "q1")]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialToCredentialQueryIdMappings: &mappings)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "MDOC credential is not a String",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testDcqlBuildThrowsWhenCredentialIsInvalidCBOR() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable("invalidCBOR"), credentialQueryId: "q1")]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialToCredentialQueryIdMappings: &mappings)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid Verifiable Credential: Error while decoding credential",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testDcqlBuildThrowsWhenDuplicateDocTypes() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1"),
            CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q2")
        ]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialToCredentialQueryIdMappings: &mappings)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Duplicate Mdoc Credentials with same doctype found",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testDcqlBuildSetsIdentifierToUUIDOnMapping() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        ]

        _ = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let identifier = mappings[0].identifier
        XCTAssertNotNil(identifier)
        XCTAssertTrue(identifier?.hasPrefix("urn:uuid:") == true, "Expected UUID identifier, got: \(identifier ?? "nil")")
    }

    func testDcqlBuildUnsignedTokenDataToSignMatchesPayloadBytes() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let payloadMap = try XCTUnwrap(payload as? [String: String])
        let identifier = try XCTUnwrap(mappings[0].identifier)
        let expectedBytes = try XCTUnwrap(payloadMap[identifier])
        // The unsigned token's dataToSign must match the payload bytes for its identifier
        XCTAssertEqual(unsignedVPTokens[0].dataToSign.map { String(format: "%02x", $0) }.joined(), expectedBytes)
        XCTAssertEqual(unsignedVPTokens[0].id, identifier)
    }

    // MARK: - // VCI 1.0 compliant mDoc - DeviceSigned structure

    func testCreationOfUnsignedMdocVPTokenWithFormat1Mdoc() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdocFormat1), inputDescriptorId: "id-1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let payloadMap = try XCTUnwrap(payload as? [String: String])
        let identifier = try XCTUnwrap(mappings[0].identifier)
        XCTAssertTrue(identifier.hasPrefix("urn:uuid:"), "Expected UUID identifier, got: \(identifier)")

        XCTAssertEqual(payloadMap.count, 1)
        XCTAssertNotNil(payloadMap[identifier])
        XCTAssertFalse(payloadMap[identifier]!.isEmpty)

        XCTAssertEqual(unsignedVPTokens.count, 1)
        XCTAssertEqual(unsignedVPTokens[0].format, .mso_mdoc)
        XCTAssertEqual(unsignedVPTokens[0].id, identifier)
    }

    func testDcqlBuildWithFormat1Mdoc() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdocFormat1), credentialQueryId: "q1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let payloadMap = try XCTUnwrap(payload as? [String: String])
        let identifier = try XCTUnwrap(mappings[0].identifier)
        XCTAssertTrue(identifier.hasPrefix("urn:uuid:"), "Expected UUID identifier, got: \(identifier)")

        XCTAssertEqual(payloadMap.count, 1)
        XCTAssertNotNil(payloadMap[identifier])
        XCTAssertFalse(payloadMap[identifier]!.isEmpty)

        XCTAssertEqual(unsignedVPTokens.count, 1)
        XCTAssertEqual(unsignedVPTokens[0].format, .mso_mdoc)
        XCTAssertEqual(unsignedVPTokens[0].id, identifier)
    }
}
