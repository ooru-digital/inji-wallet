import XCTest
@testable import OpenID4VP

final class UnsignedSdJwtVPTokenBuilderTests: XCTestCase {

    // MARK: - Constants

    private let expectedCnfKid = "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Ii1pa2lOemRxV1BDMWlYSW9KNDJvV0M4cU16VHdvWjA4ejY5RjVZZWNaOWsiLCJ5IjoiUUlQcGRPREx4X1hxdVhLaUZhV3oyWW84MmRWelUzNWpFSjRNc2NVR0Z5OCIsInVzZSI6InNpZyJ9#0"
    private let expectedSignatureAlgorithm = "ES256"
    private let expectedKBJwtHeader: [String: Any] = ["alg": "ES256", "typ": "kb+jwt"]

    // MARK: - build(credentialInputDescriptorMappings:) — success paths

    func testBuildReturnsExpectedStructure() async throws {
        let builder = UnsignedSdJwtVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(),
            specVersion: .v1,
            networkManager: MockNetworkManager()
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .vc_sd_jwt, credential: AnyCodable(sampeVcSdJwtWithHolderBinding), inputDescriptorId: "input1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let uuidToKB = try XCTUnwrap(payload as? [String: String])
        XCTAssertEqual(uuidToKB.count, 1)

        let identifier = try XCTUnwrap(mappings[0].identifier)
        let kbJwt = try XCTUnwrap(uuidToKB[identifier])
        assertKBJwtHeader(kbJwt, expectedHeader: expectedKBJwtHeader)

        XCTAssertEqual(unsignedVPTokens.count, 1)
        let token = unsignedVPTokens[0]
        XCTAssertEqual(token.format, .vc_sd_jwt)
        XCTAssertEqual(token.holderKeyReference, expectedCnfKid)
        XCTAssertEqual(token.signatureAlgorithm, expectedSignatureAlgorithm)
        XCTAssertEqual(String(decoding: token.dataToSign, as: UTF8.self), kbJwt)
    }

    func testBuildReturnsExpectedStructureForDraft23() async throws {
        let builder = UnsignedSdJwtVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            networkManager: MockNetworkManager()
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .vc_sd_jwt, credential: AnyCodable(sampeVcSdJwtWithHolderBinding), inputDescriptorId: "input1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let uuidToKB = try XCTUnwrap(payload as? [String: String])
        XCTAssertEqual(uuidToKB.count, 1)

        let identifier = try XCTUnwrap(mappings[0].identifier)
        let kbJwt = try XCTUnwrap(uuidToKB[identifier])
        assertKBJwtHeader(kbJwt, expectedHeader: expectedKBJwtHeader)

        XCTAssertEqual(unsignedVPTokens.count, 1)
        let token = unsignedVPTokens[0]
        XCTAssertEqual(token.format, .vc_sd_jwt)
        XCTAssertEqual(token.holderKeyReference, expectedCnfKid)
        XCTAssertEqual(token.signatureAlgorithm, expectedSignatureAlgorithm)
        XCTAssertEqual(String(decoding: token.dataToSign, as: UTF8.self), kbJwt)
    }

    func testBuildPreservesOriginalMappingOrder() async throws {
        let builder = UnsignedSdJwtVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(),
            specVersion: .v1,
            networkManager: MockNetworkManager()
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .vc_sd_jwt, credential: AnyCodable(sampeVcSdJwtWithHolderBinding), inputDescriptorId: "input1"),
            CredentialInputDescriptorMapping(format: .vc_sd_jwt, credential: AnyCodable(sampeVcSdJwtWithHolderBinding), inputDescriptorId: "input2")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let uuidToKB = try XCTUnwrap(payload as? [String: String])
        XCTAssertEqual(uuidToKB.count, 2)
        XCTAssertEqual(unsignedVPTokens.count, 2)

        let id0 = try XCTUnwrap(mappings[0].identifier)
        let id1 = try XCTUnwrap(mappings[1].identifier)
        XCTAssertNotEqual(id0, id1)
        XCTAssertEqual(String(decoding: unsignedVPTokens[0].dataToSign, as: UTF8.self), uuidToKB[id0])
        XCTAssertEqual(String(decoding: unsignedVPTokens[1].dataToSign, as: UTF8.self), uuidToKB[id1])
        XCTAssertEqual(unsignedVPTokens[0].format, .vc_sd_jwt)
        XCTAssertEqual(unsignedVPTokens[1].format, .vc_sd_jwt)
        XCTAssertEqual(unsignedVPTokens[0].holderKeyReference, expectedCnfKid)
        XCTAssertEqual(unsignedVPTokens[1].holderKeyReference, expectedCnfKid)
        XCTAssertEqual(unsignedVPTokens[0].signatureAlgorithm, expectedSignatureAlgorithm)
        XCTAssertEqual(unsignedVPTokens[1].signatureAlgorithm, expectedSignatureAlgorithm)
    }

    func testBuildReturnsNoEntryForNonHolderBoundCredential() async throws {
        let builder = UnsignedSdJwtVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(),
            specVersion: .v1,
            networkManager: MockNetworkManager()
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .vc_sd_jwt, credential: AnyCodable(sampleVcSdJwtWithNoHolderBinding), inputDescriptorId: "input1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let uuidToKB = try XCTUnwrap(payload as? [String: String])
        XCTAssertEqual(uuidToKB, [:])
        XCTAssertEqual(unsignedVPTokens.count, 0)
        let identifier = try XCTUnwrap(mappings[0].identifier)
        XCTAssertFalse(identifier.isEmpty)
    }

    // MARK: - build(credentialInputDescriptorMappings:) — error paths

    func testBuildThrowsWhenCredentialIsNotString() async {
        let builder = UnsignedSdJwtVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(),
            specVersion: .v1,
            networkManager: MockNetworkManager()
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .vc_sd_jwt, credential: AnyCodable(12345), inputDescriptorId: "input1")
        ]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialInputDescriptorMappings: &mappings)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is not a String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testBuildSucceedsWhenCnfContainsJwk() async throws {
        let sdJwtWithJwkCnf = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlCNVRDQ0FZdWdBd0lCQWdJUUdVZEYwa0JpUUdEYXdwKzBkQlNTNWpBS0JnZ3Foa2pPUFFRREFqQWRNUTR3REFZRFZRUURFd1ZCYm1sdGJ6RUxNQWtHQTFVRUJoTUNUa3d3SGhjTk1qVXdOREV5TVRReU16TXdXaGNOTWpZd05UQXlNVFF5TXpNd1dqQWhNUkl3RUFZRFZRUURFd2xqY21Wa2J5QmtZM014Q3pBSkJnTlZCQVlUQWs1TU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUZYVk5BMGxhYSs1UDJuazVQSkZvdjh4aEJGTno1VU9KQklWc3lrMFNLU2ZxVGZLTUI2UitjRkROaWpkbUJZeXVFYVVnTWd1VWM4aE9Wbm5yZVc5dGhLT0JxRENCcFRBZEJnTlZIUTRFRmdRVVlSOHZGUVRsa2pmMS9ObktlWnh2WTBaejNhQXdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1CVUdBMVVkSlFFQi93UUxNQWtHQnlpQmpGMEZBUUl3SHdZRFZSMGpCQmd3Rm9BVUw5OHdhTll2OVFueElIYjVDRmd4anZaVXRVc3dJUVlEVlIwU0JCb3dHSVlXYUhSMGNITTZMeTltZFc1clpTNWhibWx0Ynk1cFpEQVpCZ05WSFJFRUVqQVFnZzVtZFc1clpTNWhibWx0Ynk1cFpEQUtCZ2dxaGtqT1BRUURBZ05JQURCRkFpQkJ3ZFMvY0ZCczNhd3RmUDlHRlZrZ1NPSVRRZFBCTUxoc0pCeWpnN2wyTFFJaEFQUUpXeTdxUXNmcTJHcmRwY0dYSHJEVkswdy9YblBGMlhBVDZyVFg4dUNQIiwiTUlJQnp6Q0NBWFdnQXdJQkFnSVFWd0FGb2xXUWltOTRnbXlDaWMzYkNUQUtCZ2dxaGtqT1BRUURBakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d0hoY05NalF3TlRBeU1UUXlNek13V2hjTk1qZ3dOVEF5TVRReU16TXdXakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFRQy9ZeUJwY1JRWDhaWHBIZnJhMVROZFNiUzdxemdIWUhKM21zYklyOFRKTFBOWkk0VWw0ekpsRmRRVklWbHM1KzVDbENiTitKOUZVdmhQR3M0QXpBK280R1dNSUdUTUIwR0ExVWREZ1FXQkJRdjN6Qm8xaS8xQ2ZFZ2R2a0lXREdPOWxTMVN6QU9CZ05WSFE4QkFmOEVCQU1DQVFZd0lRWURWUjBUQkJvd0dJWVdhSFIwY0hNNkx5OW1kVzVyWlM1aGJtbHRieTVwWkRBU0JnTlZIUk1CQWY0RUNEQUdBUUgvQWdFQU1Dc0dBMVVkSHdRa01DSXdJS0Flb0J5R0dtaDBkSEJ6T2k4dlpuVnVhMlV1WVc1cGJXOHVhV1F2WTNKc01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRQ1RnODBBbXFWSEpMYVp0MnV1aEF0UHFLSVhhZlAyZ2h0ZDlPQ21kRDUxWndJZ0t2VmtyZ1RZbHhTUkFibUtZNk1sa0g4bU0zU05jbkVKazlmR1Z3SkcrKzA9Il19.ewogICJpc3N1YW5jZV9kYXRlIjogIjIwMjUtMDgtMTgiLAogICJleHBpcnlfZGF0ZSI6ICIyMDI2LTA4LTI4IiwKICAiaXNzdWluZ19jb3VudHJ5IjogIkRFIiwKICAibmJmIjogMTc1NTQ3NTIwMCwKICAiZXhwIjogMTc4Nzg3NTIwMCwKICAidmN0IjogImh0dHBzOi8vZXhhbXBsZS5ldWRpLmVjLmV1cm9wYS5ldS9jb3IvMSIsCiAgImNuZiI6IHsKICAgICJqd2siOiB7CiAgICAgICAgICJrdHkiOiAiRUMiLAogICAgICAgICAiY3J2IjogIlAtMjU2IiwKICAgICAgICAgIngiOiAiVENBRVIxOVp2dTNPSEY0ajRXNHZmU1ZvSElQMUlMaWxEbHM3dkNlR2VtYyIsCiAgICAgICAgICJ5IjogIlp4amlXV2JaTVFHSFZXS1ZRNGhiU0lpcnNWZnVlY0NFNnQ0alQ5RjJIWlEiCiAgICAgICB9CiAgfSwKICAiaXNzIjogImh0dHBzOi8vZnVua2UuYW5pbW8uaWQiLAogICJpYXQiOiAxNzU2ODk2NjUzLAogICJfc2QiOiBbCiAgICAiQzJQX3FvcTBQdlRvMVlZcnYzXzVGV2k0aUVhWlVHS1lhQ2t6YWtnTUlIYyIsCiAgICAiRjRaZEJQSXgwclFiaG5pZG5TcDFITDctVFJfT0NGcWhXSVZKWjdtQjNGVSIsCiAgICAiVXR2LXRHaElnb0tJS05UYjlndGJyN2JZOUVtUUFNS053dFhqY01zUXBMTSIsCiAgICAiZ3dfRmotNExRRkpDZ3JkVUpwRUJtbTRuemEzMVhSdGFnNVNoX0VQOER6VSIsCiAgICAia2F0NFVBbUs5eG5OR3o1LXhFdkNUdWZlbkFHOVJ1RW94eWtySy1sTktlZyIsCiAgICAib0VCTEtXNFFEOWdjSm5IQkYtWEdla2xBM3g4TDE1dWxDdzVVcXBleWhJcyIsCiAgICAicXRpVUp6bFNMOU0ybjd5eGdoa0lOSnhVSnQ2S2ZaZFBjRGtxaHRWcTR6USIsCiAgICAieTRMeXIyejZBSWRIaHA4ZXQ1VnE5cmhTYjY1c0dpTVgwNkVWWjEtX2k2USIKICBdLAogICJfc2RfYWxnIjogInNoYS0yNTYiCn0.F0gYaWKFzPXoI4pO4mixg6WgN1gM3hfqiJLIgxEAjfQb5yrQEU3G2CCYwJtg7d9bcs9-4lu4ZVS6aWpUJ70UNw~WyI1Njg2Njc5MzY5MTc4MDgxMDA5Nzc0MTQiLCJmYW1pbHlfbmFtZSIsIk11c3Rlcm1hbm4iXQ~WyIxMTc2MjI4NDI0Mzk4MTY4Mzc4NTQ1NTg0IiwiZ2l2ZW5fbmFtZSIsIkVyaWthIl0~WyI1MTI2Mzc4NDkyMDcxOTExMjczMTQwNjAiLCJiaXJ0aF9kYXRlIiwiMTk2NC0wOC0xMiJd~WyIxMTI0MjE5NzQ2NzM0MDA1ODYzMjU3NTAiLCJyZXNpZGVudF9hZGRyZXNzIiwiSGVpZGVzdHJhc3NlIDE3LCA1MTE0NyBLb2xuIl0~WyI1MzcxMzg4MzMyNjMxMDc3MjY5MjQ4NDkiLCJnZW5kZXIiLDJd~WyI5MjcxODEyMjgxOTIyMDY1MDcxOTQyMTMiLCJiaXJ0aF9wbGFjZSIsIkvDtmxuIl0~WyI1MTE2NDk3MzQxMDM5NTU1MTIwMzc0MDQiLCJhcnJpdmFsX2RhdGUiLCIyMDI0LTAzLTAxIl0~WyI5MTQ0NDg4OTMwNzAwNzQ5Mjc3NjMwODkiLCJuYXRpb25hbGl0eSIsIkRFIl0~"
        let builder = UnsignedSdJwtVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(),
            specVersion: .v1,
            networkManager: MockNetworkManager()
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .vc_sd_jwt, credential: AnyCodable(sdJwtWithJwkCnf), inputDescriptorId: "input1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let uuidToKB = try XCTUnwrap(payload as? [String: String])
        XCTAssertEqual(uuidToKB.count, 1)
        XCTAssertEqual(unsignedVPTokens.count, 1)

        let token = unsignedVPTokens[0]
        XCTAssertEqual(token.signatureAlgorithm, "ES256")
        XCTAssertEqual(token.format, .vc_sd_jwt)

        // holderKeyReference should be the serialized JWK JSON
        let holderKeyData = try XCTUnwrap(token.holderKeyReference.data(using: .utf8))
        let holderKeyJson = try XCTUnwrap(try JSONSerialization.jsonObject(with: holderKeyData) as? [String: Any])
        XCTAssertEqual(holderKeyJson["kty"] as? String, "EC")
        XCTAssertEqual(holderKeyJson["crv"] as? String, "P-256")

        let identifier = try XCTUnwrap(mappings[0].identifier)
        let kbJwt = try XCTUnwrap(uuidToKB[identifier])
        assertKBJwtHeader(kbJwt, expectedHeader: ["alg": "ES256", "typ": "kb+jwt"])
    }

    func testBuildThrowsWhenJwkContainsUnsupportedAlgorithm() async throws {
        let credential = try makeSdJwt(cnf: [
            "jwk": [
                "kty": "EC",
                "crv": "P-256",
                "alg": "none"
            ]
        ])
        let builder = UnsignedSdJwtVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(),
            specVersion: .v1,
            networkManager: MockNetworkManager()
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .vc_sd_jwt, credential: AnyCodable(credential), inputDescriptorId: "input1")
        ]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialInputDescriptorMappings: &mappings)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Unsupported JWK alg 'none'",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testBuildThrowsWhenCnfContainsBothJwkAndKid() async throws {
        let credential = try makeSdJwt(cnf: [
            "jwk": [
                "kty": "EC",
                "crv": "P-256"
            ],
            "kid": expectedCnfKid
        ])
        let builder = UnsignedSdJwtVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(),
            specVersion: .v1,
            networkManager: MockNetworkManager()
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .vc_sd_jwt, credential: AnyCodable(credential), inputDescriptorId: "input1")
        ]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialInputDescriptorMappings: &mappings)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid cnf: provide exactly one of 'jwk' or 'kid'",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testBuildThrowsWhenCnfContainsNeitherJwkNorKid() async throws {
        let credential = try makeSdJwt(cnf: [
            "unsupported": "value"
        ])
        let builder = UnsignedSdJwtVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(),
            specVersion: .v1,
            networkManager: MockNetworkManager()
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .vc_sd_jwt, credential: AnyCodable(credential), inputDescriptorId: "input1")
        ]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialInputDescriptorMappings: &mappings)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Unsupported cnf format, must contain 'kid' or 'jwk'",
                expectedCode: "unsupported_operation"
            )
        }
    }

    // MARK: - build(credentialToCredentialQueryIdMappings:) — error paths

    func testDcqlThrowsWhenAuthorizationRequestIsNotDcqlRequest() async {
        let builder = UnsignedSdJwtVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            networkManager: MockNetworkManager()
        )
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .dc_sd_jwt, credential: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialQueryId: "q1")
        ]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialToCredentialQueryIdMappings: &mappings)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Expected AuthorizationDcqlRequest for DCQL flow",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testDcqlThrowsWhenCredentialQueryIdNotFound() async {
        let builder = sdJwtBuilderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .dc_sd_jwt, credential: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialQueryId: "nonexistent-id")
        ]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialToCredentialQueryIdMappings: &mappings)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "No matching credential query found for credential query id: nonexistent-id",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testDcqlThrowsWhenCredentialIsNotString() async {
        let builder = sdJwtBuilderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .dc_sd_jwt, credential: AnyCodable(12345), credentialQueryId: "q1")
        ]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialToCredentialQueryIdMappings: &mappings)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "SD-JWT credential is not a String",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testDcqlThrowsWhenHolderBindingRequiredButNoCnfClaim() async {
        let builder = sdJwtBuilderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .dc_sd_jwt, credential: AnyCodable(sampleVcSdJwtWithNoHolderBinding), credentialQueryId: "q1")
        ]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialToCredentialQueryIdMappings: &mappings)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Holder binding is required for presentation but no cnf claim was present",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testDcqlSucceedsWhenCnfContainsJwk() async throws {
        let sdJwtWithJwkCnf = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlCNVRDQ0FZdWdBd0lCQWdJUUdVZEYwa0JpUUdEYXdwKzBkQlNTNWpBS0JnZ3Foa2pPUFFRREFqQWRNUTR3REFZRFZRUURFd1ZCYm1sdGJ6RUxNQWtHQTFVRUJoTUNUa3d3SGhjTk1qVXdOREV5TVRReU16TXdXaGNOTWpZd05UQXlNVFF5TXpNd1dqQWhNUkl3RUFZRFZRUURFd2xqY21Wa2J5QmtZM014Q3pBSkJnTlZCQVlUQWs1TU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUZYVk5BMGxhYSs1UDJuazVQSkZvdjh4aEJGTno1VU9KQklWc3lrMFNLU2ZxVGZLTUI2UitjRkROaWpkbUJZeXVFYVVnTWd1VWM4aE9Wbm5yZVc5dGhLT0JxRENCcFRBZEJnTlZIUTRFRmdRVVlSOHZGUVRsa2pmMS9ObktlWnh2WTBaejNhQXdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1CVUdBMVVkSlFFQi93UUxNQWtHQnlpQmpGMEZBUUl3SHdZRFZSMGpCQmd3Rm9BVUw5OHdhTll2OVFueElIYjVDRmd4anZaVXRVc3dJUVlEVlIwU0JCb3dHSVlXYUhSMGNITTZMeTltZFc1clpTNWhibWx0Ynk1cFpEQVpCZ05WSFJFRUVqQVFnZzVtZFc1clpTNWhibWx0Ynk1cFpEQUtCZ2dxaGtqT1BRUURBZ05JQURCRkFpQkJ3ZFMvY0ZCczNhd3RmUDlHRlZrZ1NPSVRRZFBCTUxoc0pCeWpnN2wyTFFJaEFQUUpXeTdxUXNmcTJHcmRwY0dYSHJEVkswdy9YblBGMlhBVDZyVFg4dUNQIiwiTUlJQnp6Q0NBWFdnQXdJQkFnSVFWd0FGb2xXUWltOTRnbXlDaWMzYkNUQUtCZ2dxaGtqT1BRUURBakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d0hoY05NalF3TlRBeU1UUXlNek13V2hjTk1qZ3dOVEF5TVRReU16TXdXakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFRQy9ZeUJwY1JRWDhaWHBIZnJhMVROZFNiUzdxemdIWUhKM21zYklyOFRKTFBOWkk0VWw0ekpsRmRRVklWbHM1KzVDbENiTitKOUZVdmhQR3M0QXpBK280R1dNSUdUTUIwR0ExVWREZ1FXQkJRdjN6Qm8xaS8xQ2ZFZ2R2a0lXREdPOWxTMVN6QU9CZ05WSFE4QkFmOEVCQU1DQVFZd0lRWURWUjBUQkJvd0dJWVdhSFIwY0hNNkx5OW1kVzVyWlM1aGJtbHRieTVwWkRBU0JnTlZIUk1CQWY0RUNEQUdBUUgvQWdFQU1Dc0dBMVVkSHdRa01DSXdJS0Flb0J5R0dtaDBkSEJ6T2k4dlpuVnVhMlV1WVc1cGJXOHVhV1F2WTNKc01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRQ1RnODBBbXFWSEpMYVp0MnV1aEF0UHFLSVhhZlAyZ2h0ZDlPQ21kRDUxWndJZ0t2VmtyZ1RZbHhTUkFibUtZNk1sa0g4bU0zU05jbkVKazlmR1Z3SkcrKzA9Il19.ewogICJpc3N1YW5jZV9kYXRlIjogIjIwMjUtMDgtMTgiLAogICJleHBpcnlfZGF0ZSI6ICIyMDI2LTA4LTI4IiwKICAiaXNzdWluZ19jb3VudHJ5IjogIkRFIiwKICAibmJmIjogMTc1NTQ3NTIwMCwKICAiZXhwIjogMTc4Nzg3NTIwMCwKICAidmN0IjogImh0dHBzOi8vZXhhbXBsZS5ldWRpLmVjLmV1cm9wYS5ldS9jb3IvMSIsCiAgImNuZiI6IHsKICAgICJqd2siOiB7CiAgICAgICAgICJrdHkiOiAiRUMiLAogICAgICAgICAiY3J2IjogIlAtMjU2IiwKICAgICAgICAgIngiOiAiVENBRVIxOVp2dTNPSEY0ajRXNHZmU1ZvSElQMUlMaWxEbHM3dkNlR2VtYyIsCiAgICAgICAgICJ5IjogIlp4amlXV2JaTVFHSFZXS1ZRNGhiU0lpcnNWZnVlY0NFNnQ0alQ5RjJIWlEiCiAgICAgICB9CiAgfSwKICAiaXNzIjogImh0dHBzOi8vZnVua2UuYW5pbW8uaWQiLAogICJpYXQiOiAxNzU2ODk2NjUzLAogICJfc2QiOiBbCiAgICAiQzJQX3FvcTBQdlRvMVlZcnYzXzVGV2k0aUVhWlVHS1lhQ2t6YWtnTUlIYyIsCiAgICAiRjRaZEJQSXgwclFiaG5pZG5TcDFITDctVFJfT0NGcWhXSVZKWjdtQjNGVSIsCiAgICAiVXR2LXRHaElnb0tJS05UYjlndGJyN2JZOUVtUUFNS053dFhqY01zUXBMTSIsCiAgICAiZ3dfRmotNExRRkpDZ3JkVUpwRUJtbTRuemEzMVhSdGFnNVNoX0VQOER6VSIsCiAgICAia2F0NFVBbUs5eG5OR3o1LXhFdkNUdWZlbkFHOVJ1RW94eWtySy1sTktlZyIsCiAgICAib0VCTEtXNFFEOWdjSm5IQkYtWEdla2xBM3g4TDE1dWxDdzVVcXBleWhJcyIsCiAgICAicXRpVUp6bFNMOU0ybjd5eGdoa0lOSnhVSnQ2S2ZaZFBjRGtxaHRWcTR6USIsCiAgICAieTRMeXIyejZBSWRIaHA4ZXQ1VnE5cmhTYjY1c0dpTVgwNkVWWjEtX2k2USIKICBdLAogICJfc2RfYWxnIjogInNoYS0yNTYiCn0.F0gYaWKFzPXoI4pO4mixg6WgN1gM3hfqiJLIgxEAjfQb5yrQEU3G2CCYwJtg7d9bcs9-4lu4ZVS6aWpUJ70UNw~WyI1Njg2Njc5MzY5MTc4MDgxMDA5Nzc0MTQiLCJmYW1pbHlfbmFtZSIsIk11c3Rlcm1hbm4iXQ~WyIxMTc2MjI4NDI0Mzk4MTY4Mzc4NTQ1NTg0IiwiZ2l2ZW5fbmFtZSIsIkVyaWthIl0~WyI1MTI2Mzc4NDkyMDcxOTExMjczMTQwNjAiLCJiaXJ0aF9kYXRlIiwiMTk2NC0wOC0xMiJd~WyIxMTI0MjE5NzQ2NzM0MDA1ODYzMjU3NTAiLCJyZXNpZGVudF9hZGRyZXNzIiwiSGVpZGVzdHJhc3NlIDE3LCA1MTE0NyBLb2xuIl0~WyI1MzcxMzg4MzMyNjMxMDc3MjY5MjQ4NDkiLCJnZW5kZXIiLDJd~WyI5MjcxODEyMjgxOTIyMDY1MDcxOTQyMTMiLCJiaXJ0aF9wbGFjZSIsIkvDtmxuIl0~WyI1MTE2NDk3MzQxMDM5NTU1MTIwMzc0MDQiLCJhcnJpdmFsX2RhdGUiLCIyMDI0LTAzLTAxIl0~WyI5MTQ0NDg4OTMwNzAwNzQ5Mjc3NjMwODkiLCJuYXRpb25hbGl0eSIsIkRFIl0~"
        let builder = sdJwtBuilderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .dc_sd_jwt, credential: AnyCodable(sdJwtWithJwkCnf), credentialQueryId: "q1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let uuidToKB = try XCTUnwrap(payload as? [String: String])
        XCTAssertEqual(uuidToKB.count, 1)
        XCTAssertEqual(unsignedVPTokens.count, 1)

        let token = unsignedVPTokens[0]
        XCTAssertEqual(token.signatureAlgorithm, "ES256")
        XCTAssertEqual(token.format, .dc_sd_jwt)

        let holderKeyData = try XCTUnwrap(token.holderKeyReference.data(using: .utf8))
        let holderKeyJson = try XCTUnwrap(try JSONSerialization.jsonObject(with: holderKeyData) as? [String: Any])
        XCTAssertEqual(holderKeyJson["kty"] as? String, "EC")
        XCTAssertEqual(holderKeyJson["crv"] as? String, "P-256")
    }

    func testDcqlThrowsWhenJwkContainsUnsupportedAlgorithm() async throws {
        let credential = try makeSdJwt(cnf: [
            "jwk": [
                "kty": "EC",
                "crv": "P-256",
                "alg": "none"
            ]
        ])
        let builder = sdJwtBuilderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .dc_sd_jwt, credential: AnyCodable(credential), credentialQueryId: "q1")
        ]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialToCredentialQueryIdMappings: &mappings)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Unsupported JWK alg 'none'",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testDcqlThrowsWhenCnfContainsBothJwkAndKid() async throws {
        let credential = try makeSdJwt(cnf: [
            "jwk": [
                "kty": "EC",
                "crv": "P-256"
            ],
            "kid": expectedCnfKid
        ])
        let builder = sdJwtBuilderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .dc_sd_jwt, credential: AnyCodable(credential), credentialQueryId: "q1")
        ]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialToCredentialQueryIdMappings: &mappings)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid cnf: provide exactly one of 'jwk' or 'kid'",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testDcqlThrowsWhenCnfContainsNeitherJwkNorKid() async throws {
        let credential = try makeSdJwt(cnf: [
            "unsupported": "value"
        ])
        let builder = sdJwtBuilderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .dc_sd_jwt, credential: AnyCodable(credential), credentialQueryId: "q1")
        ]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialToCredentialQueryIdMappings: &mappings)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Unsupported cnf format, must contain 'kid' or 'jwk'",
                expectedCode: "unsupported_operation"
            )
        }
    }

    // MARK: - build(credentialToCredentialQueryIdMappings:) — requireCryptographicHolderBinding = false

    func testDcqlHolderBindingFalseProducesNoUnsignedTokens() async throws {
        let builder = sdJwtBuilderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: false)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .dc_sd_jwt, credential: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialQueryId: "q1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let uuidToKB = try XCTUnwrap(payload as? [String: String])
        XCTAssertEqual(uuidToKB, [:])
        XCTAssertEqual(unsignedVPTokens.count, 0)
        let identifier = try XCTUnwrap(mappings[0].identifier)
        XCTAssertFalse(identifier.isEmpty)
    }

    func testDcqlHolderBindingFalseForMultipleMappingsSetsAllIdentifiers() async throws {
        let builder = sdJwtBuilderWithDcqlRequest(
            credentials: [("q1", "dc+sd-jwt"), ("q2", "dc+sd-jwt")],
            requireCryptographicHolderBinding: false
        )
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .dc_sd_jwt, credential: AnyCodable(sampleVcSdJwtWithNoHolderBinding), credentialQueryId: "q1"),
            CredentialToCredentialQueryIdMapping(format: .dc_sd_jwt, credential: AnyCodable(sampleVcSdJwtWithNoHolderBinding), credentialQueryId: "q2")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let uuidToKB = try XCTUnwrap(payload as? [String: String])
        XCTAssertEqual(uuidToKB, [:])
        XCTAssertEqual(unsignedVPTokens.count, 0)
        let id0 = try XCTUnwrap(mappings[0].identifier)
        let id1 = try XCTUnwrap(mappings[1].identifier)
        XCTAssertFalse(id0.isEmpty)
        XCTAssertFalse(id1.isEmpty)
        XCTAssertNotEqual(id0, id1)
    }

    // MARK: - build(credentialToCredentialQueryIdMappings:) — requireCryptographicHolderBinding = true

    func testDcqlHolderBindingTrueProducesUnsignedToken() async throws {
        let builder = sdJwtBuilderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .dc_sd_jwt, credential: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialQueryId: "q1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let uuidToKB = try XCTUnwrap(payload as? [String: String])
        XCTAssertEqual(uuidToKB.count, 1)
        XCTAssertEqual(unsignedVPTokens.count, 1)

        let identifier = try XCTUnwrap(mappings[0].identifier)
        let kbJwt = try XCTUnwrap(uuidToKB[identifier])
        let token = unsignedVPTokens[0]

        XCTAssertEqual(token.format, .dc_sd_jwt)
        XCTAssertEqual(token.holderKeyReference, expectedCnfKid)
        XCTAssertEqual(token.signatureAlgorithm, expectedSignatureAlgorithm)
        XCTAssertEqual(String(decoding: token.dataToSign, as: UTF8.self), kbJwt)
        assertKBJwtHeader(kbJwt, expectedHeader: expectedKBJwtHeader)
    }

    func testDcqlHolderBindingTrueUnsignedTokenHolderKeyReferenceMatchesCnfKid() async throws {
        let builder = sdJwtBuilderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .dc_sd_jwt, credential: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialQueryId: "q1")
        ]

        let (_, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        XCTAssertEqual(unsignedVPTokens[0].holderKeyReference, expectedCnfKid)
        XCTAssertEqual(unsignedVPTokens[0].signatureAlgorithm, expectedSignatureAlgorithm)
        XCTAssertEqual(unsignedVPTokens[0].format, .dc_sd_jwt)
    }

    func testDcqlHolderBindingTrueUnsignedJwtPayloadContainsRequiredClaims() async throws {
        let builder = sdJwtBuilderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .dc_sd_jwt, credential: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialQueryId: "q1")
        ]

        let (_, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let dataToSignString = String(decoding: unsignedVPTokens[0].dataToSign, as: UTF8.self)
        let jwtParts = dataToSignString.split(separator: ".")
        XCTAssertEqual(jwtParts.count, 2)
        assertKBJwtHeader(dataToSignString, expectedHeader: expectedKBJwtHeader)

        let payloadData = try XCTUnwrap(Data(base64Encoded: String(jwtParts[1]).base64URLToBase64()))
        let jwtPayload = try XCTUnwrap(try JSONSerialization.jsonObject(with: payloadData) as? [String: Any])

        XCTAssertEqual(jwtPayload["aud"] as? String, "client_id")
        XCTAssertEqual(jwtPayload["nonce"] as? String, "nonce")
        XCTAssertEqual(jwtPayload.keys.sorted(), ["aud", "iat", "nonce", "sd_hash"])
        let sdHash = try XCTUnwrap(jwtPayload["sd_hash"] as? String)
        XCTAssertFalse(sdHash.isEmpty)
        XCTAssertNotNil(jwtPayload["iat"] as? Int)
    }

    func testDcqlHolderBindingTruePreservesPayloadOrderAcrossMultipleMappings() async throws {
        let builder = sdJwtBuilderWithDcqlRequest(
            credentials: [("q1", "dc+sd-jwt"), ("q2", "dc+sd-jwt")],
            requireCryptographicHolderBinding: true
        )
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .dc_sd_jwt, credential: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialQueryId: "q1"),
            CredentialToCredentialQueryIdMapping(format: .dc_sd_jwt, credential: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialQueryId: "q2")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let uuidToKB = try XCTUnwrap(payload as? [String: String])
        XCTAssertEqual(uuidToKB.count, 2)
        XCTAssertEqual(unsignedVPTokens.count, 2)

        let id0 = try XCTUnwrap(mappings[0].identifier)
        let id1 = try XCTUnwrap(mappings[1].identifier)
        XCTAssertNotEqual(id0, id1)
        XCTAssertEqual(String(decoding: unsignedVPTokens[0].dataToSign, as: UTF8.self), uuidToKB[id0])
        XCTAssertEqual(String(decoding: unsignedVPTokens[1].dataToSign, as: UTF8.self), uuidToKB[id1])
        XCTAssertEqual(unsignedVPTokens[0].format, .dc_sd_jwt)
        XCTAssertEqual(unsignedVPTokens[1].format, .dc_sd_jwt)
        XCTAssertEqual(unsignedVPTokens[0].holderKeyReference, expectedCnfKid)
        XCTAssertEqual(unsignedVPTokens[1].holderKeyReference, expectedCnfKid)
        XCTAssertEqual(unsignedVPTokens[0].signatureAlgorithm, expectedSignatureAlgorithm)
        XCTAssertEqual(unsignedVPTokens[1].signatureAlgorithm, expectedSignatureAlgorithm)
    }

    // MARK: - Helpers

    private func makeSdJwt(cnf: [String: Any]) throws -> String {
        let header = try JSONSerialization.data(withJSONObject: ["alg": "ES256"]).toBase64UrlEncoded()
        let payload = try JSONSerialization.data(withJSONObject: [
            "cnf": cnf,
            "_sd_alg": HashAlgorithm.sha256.rawValue
        ]).toBase64UrlEncoded()
        return "\(header).\(payload).signature"
    }

    private func assertKBJwtHeader(_ kbJwt: String, expectedHeader: [String: Any], file: StaticString = #file, line: UInt = #line) {
        let parts = kbJwt.split(separator: ".")
        guard parts.count >= 1,
              let headerData = Data(base64Encoded: String(parts[0]).base64URLToBase64()),
              let actualHeader = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any] else {
            XCTFail("Failed to decode KB-JWT header from: \(kbJwt)", file: file, line: line)
            return
        }
        assertDictionariesEqual(expected: expectedHeader, actual: actualHeader, file: file, line: line)
    }

    private func sdJwtBuilderWithDcqlRequest(
        credentialQueryId: String,
        requireCryptographicHolderBinding: Bool
    ) -> UnsignedSdJwtVPTokenBuilder {
        sdJwtBuilderWithDcqlRequest(
            credentials: [(credentialQueryId, "dc+sd-jwt")],
            requireCryptographicHolderBinding: requireCryptographicHolderBinding
        )
    }

    private func sdJwtBuilderWithDcqlRequest(
        credentials: [(id: String, format: String)],
        requireCryptographicHolderBinding: Bool
    ) -> UnsignedSdJwtVPTokenBuilder {
        let dcqlJson: [String: Any] = [
            "credentials": credentials.map { cred in
                [
                    "id": cred.id,
                    "format": cred.format,
                    "meta": [:] as [String: Any],
                    "require_cryptographic_holder_binding": requireCryptographicHolderBinding
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
        return UnsignedSdJwtVPTokenBuilder(
            authorizationRequest: authorizationRequest,
            specVersion: .v1,
            networkManager: MockNetworkManager()
        )
    }
}
