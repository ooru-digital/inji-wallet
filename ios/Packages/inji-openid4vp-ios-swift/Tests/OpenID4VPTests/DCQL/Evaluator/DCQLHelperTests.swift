import XCTest
@testable import OpenID4VP

fileprivate func mockJsonLdExpanderForHelper(data: [String: Any]) async throws -> [String: Any] {
    return ["@type": data["type"] ?? []]
}

fileprivate func throwingJsonLdExpander(data: [String: Any]) async throws -> [String: Any] {
    throw NSError(domain: "test", code: 1, userInfo: [NSLocalizedDescriptionKey: "expander failed"])
}

final class DCQLHelperTests: XCTestCase {

    // MARK: - Fixtures

    private func dcqlQuery(_ json: String) throws -> DCQLQuery {
        try JSONDecoder().decode(DCQLQuery.self, from: Data(json.utf8))
    }

    private func sdJwtCredential(id: String = "c1", holderBinding: Bool = true) -> Credential {
        let raw = holderBinding ? sampeVcSdJwtWithHolderBinding : sampleVcSdJwtWithNoHolderBinding
        return Credential(format: .dc_sd_jwt, data: AnyCodable(raw), credentialId: id)
    }

    private func mdocCredential(id: String = "c1") -> Credential {
        Credential(format: .mso_mdoc, data: AnyCodable(sampleMdoc), credentialId: id)
    }

    private func ldpVcCredential(id: String = "c1") -> Credential {
        var credential = ldpVC()
        if var subject = credential["credentialSubject"] as? [String: Any] {
            subject["id"] = "did:example:holder"
            credential["credentialSubject"] = subject
        }
        return Credential(format: .ldp_vc, data: AnyCodable(credential), credentialId: id)
    }

    private static let p256JwkDid = "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImY4M09KM0QyeEYxQmc4dnViOXRMZTFnSE16Vjc2ZThUdXM5dVBIdlJWRVUiLCJ5IjoieF9GRXpSdTltMzZITE5fdHVlNjU5TE5wWFc2cEN5U3Rpa1lqS0lXSTVhMCJ9#0"
    private static let p384JwkDid = "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMzg0IiwieCI6ImxJblR4bDhmakxLcF9VQ3J4STBXRGtsYWhpLTctXzZKYnRpSGppUnZNdmhlZGhLVmRIQmZpMkhDWTh0X1FKeWMiLCJ5IjoieTZOMUlDLTJta0JhU3Q2QWctVU5PYjVoWS0yQi1hLUpidGlIamlSdk12aGVkaEtWZEhCZmkySENZOHRfUUp5YyJ9#0"
    private static let rsaJwkDid = "did:jwk:eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsIm4iOiIwdng3YWdvZWJHY1FTdXVQaUxKWFpwdE45bm5kclFtYlhFcHMyYWlBRmJXaE03OExoV3g0Y2JiZkFBdFZUODZ6d3UxUks3YVBGRnh1aERSMUw2dFNvY19CSkVDUGViV0tSWGpCWkNpRlY0bjNva25qaE1zdG42NHRaXzJXLTVKc0dZNEhjNW45eUJYQXJ3bDkzbHF0N19STjV3NkNmMGg0UXlRNXYtNjVZR2pRUjBfRkRXMlF2enFZMzY4UVFNaWNBdGFTcXpzOEtKWmduWWI5YzdkMHpnZEFaSHp1NnFNUXZSTDVoYWpybjFuOTFDYk9wYklTRDA4cU5MeXJka3QtYkZUV2hBSTR2TVFGaDZXZVp1MGZNNGxGZDJOY1J3cjNYUGtzSU5IYVEtR194Qm5pSXFidzBMczFqRjQ0LWNzRkN1ci1rRWdVOGF3YXBKektucURLZ3cifQ#0"

    private func vcdm2Credential(
        id: String,
        holderId: String = didJwkKey,
        context: [Any] = ["https://www.w3.org/ns/credentials/v2"]
    ) -> Credential {
        let credential: [String: Any] = [
            "@context": context,
            "type": ["VerifiableCredential", "IDCardCredential"],
            "credentialSubject": ["id": holderId]
        ]
        return Credential(format: .ldp_vc, data: AnyCodable(credential), credentialId: id)
    }

    private func ldpQuery(requireCryptographicHolderBinding: Bool = true) throws -> DCQLQuery {
        let binding = requireCryptographicHolderBinding ? "true" : "false"
        return try dcqlQuery(#"{"credentials":[{"id":"ldp","format":"ldp_vc","meta":{},"require_cryptographic_holder_binding":\#(binding)}]}"#)
    }

    private func matchedIds(_ result: MatchingCredentialsResult) -> [String]? {
        result.queryMatches["ldp"]?.matchingCredentials?.map { $0.credentialId }
    }

    // MARK: - VC 2.0 presentation readiness filtering

    func testMatchesVcdm2CredentialWithEddsaHolderKey() async throws {
        let helper = DCQLHelper(jsonLdExpander: mockJsonLdExpanderForHelper)

        let result = try await helper.getMatchingCredentials(
            inputCredentials: [vcdm2Credential(id: "ldp-1")],
            dcqlQuery: try ldpQuery()
        )

        XCTAssertTrue(result.success)
        XCTAssertEqual(matchedIds(result), ["ldp-1"])
    }

    func testMatchesVcdm2CredentialWithEs256HolderKey() async throws {
        let helper = DCQLHelper(jsonLdExpander: mockJsonLdExpanderForHelper)

        let result = try await helper.getMatchingCredentials(
            inputCredentials: [vcdm2Credential(id: "ldp-1", holderId: Self.p256JwkDid)],
            dcqlQuery: try ldpQuery()
        )

        XCTAssertTrue(result.success)
        XCTAssertEqual(matchedIds(result), ["ldp-1"])
    }

    func testFiltersOutVcdm2CredentialWithRsaHolderKey() async throws {
        let helper = DCQLHelper(jsonLdExpander: mockJsonLdExpanderForHelper)

        let result = try await helper.getMatchingCredentials(
            inputCredentials: [vcdm2Credential(id: "ldp-1", holderId: Self.rsaJwkDid)],
            dcqlQuery: try ldpQuery()
        )

        XCTAssertFalse(result.success)
        XCTAssertNil(matchedIds(result))
        XCTAssertEqual(
            result.queryMatches["ldp"]?.failureReason,
            DCQLEvaluationErrorCodes.cryptographicHolderBindingOrMetaFilterMismatch.rawValue
        )
    }

    func testFiltersOutVcdm2CredentialWithEs384HolderKey() async throws {
        let helper = DCQLHelper(jsonLdExpander: mockJsonLdExpanderForHelper)

        let result = try await helper.getMatchingCredentials(
            inputCredentials: [vcdm2Credential(id: "ldp-1", holderId: Self.p384JwkDid)],
            dcqlQuery: try ldpQuery()
        )

        XCTAssertNil(matchedIds(result))
    }

    func testFiltersOutOnlyTheUnsupportedCredential() async throws {
        let helper = DCQLHelper(jsonLdExpander: mockJsonLdExpanderForHelper)

        let result = try await helper.getMatchingCredentials(
            inputCredentials: [
                vcdm2Credential(id: "ldp-eddsa"),
                vcdm2Credential(id: "ldp-rsa", holderId: Self.rsaJwkDid)
            ],
            dcqlQuery: try ldpQuery()
        )

        XCTAssertTrue(result.success)
        XCTAssertEqual(matchedIds(result), ["ldp-eddsa"])
    }

    func testKeepsVcdm1CredentialWithRsaHolderKey() async throws {
        let helper = DCQLHelper(jsonLdExpander: mockJsonLdExpanderForHelper)

        let result = try await helper.getMatchingCredentials(
            inputCredentials: [
                vcdm2Credential(
                    id: "ldp-1",
                    holderId: Self.rsaJwkDid,
                    context: ["https://www.w3.org/2018/credentials/v1"]
                )
            ],
            dcqlQuery: try ldpQuery()
        )

        XCTAssertTrue(result.success)
        XCTAssertEqual(matchedIds(result), ["ldp-1"])
    }

    func testKeepsVcdm2CredentialWhenHolderBindingIsNotRequired() async throws {
        let helper = DCQLHelper(jsonLdExpander: mockJsonLdExpanderForHelper)

        let result = try await helper.getMatchingCredentials(
            inputCredentials: [vcdm2Credential(id: "ldp-1", holderId: Self.rsaJwkDid)],
            dcqlQuery: try ldpQuery(requireCryptographicHolderBinding: false)
        )

        XCTAssertTrue(result.success)
        XCTAssertEqual(matchedIds(result), ["ldp-1"])
    }

    func testKeepsCredentialWhoseDataModelCannotBeDetermined() async throws {
        let helper = DCQLHelper(jsonLdExpander: mockJsonLdExpanderForHelper)

        let result = try await helper.getMatchingCredentials(
            inputCredentials: [
                vcdm2Credential(id: "ldp-unknown", holderId: Self.rsaJwkDid, context: ["https://example.com/v9"])
            ],
            dcqlQuery: try ldpQuery()
        )

        XCTAssertEqual(matchedIds(result), ["ldp-unknown"])
    }

    func testKeepsCredentialWhoseHolderKeyCannotBeResolved() async throws {
        let helper = DCQLHelper(jsonLdExpander: mockJsonLdExpanderForHelper)

        let result = try await helper.getMatchingCredentials(
            inputCredentials: [vcdm2Credential(id: "ldp-1", holderId: "did:example:holder")],
            dcqlQuery: try ldpQuery()
        )

        XCTAssertTrue(result.success)
        XCTAssertEqual(matchedIds(result), ["ldp-1"])
    }

    // MARK: - init

    func testInitWithNilJsonLdExpander() {
        let helper = DCQLHelper(jsonLdExpander: nil)
        XCTAssertNotNil(helper)
    }

    func testInitWithJsonLdExpander() {
        let helper = DCQLHelper(jsonLdExpander: mockJsonLdExpanderForHelper)
        XCTAssertNotNil(helper)
    }

    // MARK: - getMatchingCredentials — success

    func testGetMatchingCredentialsReturnsSuccessForMatchingFormat() async throws {
        let helper = DCQLHelper(jsonLdExpander: mockJsonLdExpanderForHelper)
        let query = try dcqlQuery(#"{"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{}}]}"#)

        let result = try await helper.getMatchingCredentials(
            inputCredentials: [sdJwtCredential()],
            dcqlQuery: query
        )

        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches.keys.sorted(), ["q1"])
        XCTAssertEqual(result.queryMatches["q1"]?.matchingCredentials?.map { $0.credentialId }, ["c1"])
        XCTAssertNil(result.queryMatches["q1"]?.failureReason)
    }

    func testGetMatchingCredentialsReturnsSuccessForMsoMdoc() async throws {
        let helper = DCQLHelper()
        let query = try dcqlQuery(#"{"credentials":[{"id":"mdoc","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}]}"#)

        let result = try await helper.getMatchingCredentials(
            inputCredentials: [mdocCredential()],
            dcqlQuery: query
        )

        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["mdoc"]?.matchingCredentials?.map { $0.credentialId }, ["c1"])
        XCTAssertNil(result.queryMatches["mdoc"]?.failureReason)
    }

    func testGetMatchingCredentialsReturnsSuccessForLdpVc() async throws {
        let helper = DCQLHelper(jsonLdExpander: mockJsonLdExpanderForHelper)
        let query = try dcqlQuery(#"{"credentials":[{"id":"ldp","format":"ldp_vc","meta":{}}]}"#)

        let result = try await helper.getMatchingCredentials(
            inputCredentials: [ldpVcCredential()],
            dcqlQuery: query
        )

        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["ldp"]?.matchingCredentials?.map { $0.credentialId }, ["c1"])
        XCTAssertNil(result.queryMatches["ldp"]?.failureReason)
    }

    func testGetMatchingCredentialsReturnsSuccessForMultipleQueries() async throws {
        let helper = DCQLHelper(jsonLdExpander: mockJsonLdExpanderForHelper)
        let query = try dcqlQuery("""
        {
          "credentials": [
            {"id":"q1","format":"dc+sd-jwt","meta":{}},
            {"id":"q2","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}
          ]
        }
        """)

        let result = try await helper.getMatchingCredentials(
            inputCredentials: [sdJwtCredential(id: "sd1"), mdocCredential(id: "md1")],
            dcqlQuery: query
        )

        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.matchingCredentials?.map { $0.credentialId }, ["sd1"])
        XCTAssertEqual(result.queryMatches["q2"]?.matchingCredentials?.map { $0.credentialId }, ["md1"])
        XCTAssertEqual(result.queryMatches.keys.sorted(), ["q1", "q2"])
    }

    // MARK: - getMatchingCredentials — failure

    func testGetMatchingCredentialsReturnsFailureWhenNoFormatMatches() async throws {
        let helper = DCQLHelper()
        let query = try dcqlQuery(#"{"credentials":[{"id":"q1","format":"mso_mdoc","meta":{}}]}"#)

        let result = try await helper.getMatchingCredentials(
            inputCredentials: [sdJwtCredential()],
            dcqlQuery: query
        )

        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failureReason, DCQLEvaluationErrorCodes.noMatchingFormatsFound.rawValue)
        XCTAssertNil(result.queryMatches["q1"]?.matchingCredentials)
    }

    func testGetMatchingCredentialsReturnsFailureForEmptyCredentials() async throws {
        let helper = DCQLHelper()
        let query = try dcqlQuery(#"{"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{}}]}"#)

        let result = try await helper.getMatchingCredentials(
            inputCredentials: [],
            dcqlQuery: query
        )

        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failureReason, DCQLEvaluationErrorCodes.noMatchingFormatsFound.rawValue)
    }

    func testGetMatchingCredentialsReturnsFailureWhenClaimMissing() async throws {
        let helper = DCQLHelper()
        let query = try dcqlQuery("""
        {
          "credentials": [{
            "id": "q1",
            "format": "dc+sd-jwt",
            "meta": {},
            "claims": [{"path": ["nonexistent_claim"]}]
          }]
        }
        """)

        let result = try await helper.getMatchingCredentials(
            inputCredentials: [sdJwtCredential()],
            dcqlQuery: query
        )

        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failureReason, DCQLEvaluationErrorCodes.requiredClaimsNotSatisfied.rawValue)
        XCTAssertEqual(result.queryMatches["q1"]?.failedClaims?.count, 1)
    }

    // MARK: - getMatchingCredentials — credential_sets

    func testGetMatchingCredentialsWithCredentialSetsAllRequired() async throws {
        let helper = DCQLHelper(jsonLdExpander: mockJsonLdExpanderForHelper)
        let query = try dcqlQuery("""
        {
          "credentials": [
            {"id":"q1","format":"dc+sd-jwt","meta":{}},
            {"id":"q2","format":"ldp_vc","meta":{}}
          ],
          "credential_sets": [
            {"options":[["q1","q2"]],"required":true}
          ]
        }
        """)

        let result = try await helper.getMatchingCredentials(
            inputCredentials: [sdJwtCredential(id: "sd1"), ldpVcCredential(id: "ldp1")],
            dcqlQuery: query
        )

        XCTAssertTrue(result.success)
        XCTAssertEqual(result.credentialSets.count, 1)
        XCTAssertTrue(result.credentialSets[0].required)
        XCTAssertEqual(result.credentialSets[0].options, [["q1", "q2"]])
    }

    func testGetMatchingCredentialsWithCredentialSetsNotSatisfied() async throws {
        let helper = DCQLHelper()
        let query = try dcqlQuery("""
        {
          "credentials": [
            {"id":"q1","format":"dc+sd-jwt","meta":{}},
            {"id":"q2","format":"mso_mdoc","meta":{}}
          ],
          "credential_sets": [
            {"options":[["q1","q2"]],"required":true}
          ]
        }
        """)

        let result = try await helper.getMatchingCredentials(
            inputCredentials: [sdJwtCredential()],
            dcqlQuery: query
        )

        XCTAssertFalse(result.success)
    }

    // MARK: - jsonLdExpander propagation

    func testJsonLdExpanderIsPropagatedToEvaluator() async throws {
        var expanderCalled = false
        let capturingExpander: JsonLdExpanderCallback = { data in
            expanderCalled = true
            return ["@type": data["type"] ?? []]
        }
        let helper = DCQLHelper(jsonLdExpander: capturingExpander)
        let query = try dcqlQuery(#"{"credentials":[{"id":"q1","format":"ldp_vc","meta":{}}]}"#)

        _ = try await helper.getMatchingCredentials(
            inputCredentials: [ldpVcCredential()],
            dcqlQuery: query
        )

        XCTAssertTrue(expanderCalled)
    }
}
