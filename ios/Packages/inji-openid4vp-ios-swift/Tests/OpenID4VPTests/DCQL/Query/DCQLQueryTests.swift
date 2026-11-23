import XCTest
@testable import OpenID4VP

final class DCQLQueryTests: XCTestCase {

    private func decode<T: Decodable>(_ type: T.Type, from json: String) throws -> T {
        try JSONDecoder().decode(type, from: Data(json.utf8))
    }

    // MARK: - DCQLQuery: valid

    func testValidDCQLQueryWithCredentialsOnly() throws {
        let json = """
        {
            "credentials": [
                { 
                    "id": "cred1", 
                    "format": "dc+sd-jwt", 
                    "meta": {
                        "vct_values": [ "https://credentials.example.com/identity_credential" ]
                    }, 
                    "claims" : [
                        {"path": ["last_name"], "values": ["Doe"]}
                    ]
                },
                { 
                    "id": "cred2", 
                    "format": "dc+sd-jwt", 
                    "meta": {}, 
                    "claims" : [
                        {"path": ["last_name"]}
                    ]
                },
                { 
                    "id": "cred3", 
                    "format": "dc+sd-jwt", 
                    "meta": {}, 
                    "claims" : [
                        {"id": "last_name", "path": ["last_name"]},
                        {"id": "first_name", "path": ["first_name"]},
                        {"id": "date_of_birth", "path": ["date_of_birth"]}
                    ],
                    "claim_sets": [
                        ["last_name", "first_name"],
                        ["first_name", "date_of_birth"]
                    ]
                }
            ]
        }
        """
        let dcqlQuery = try decode(DCQLQuery.self, from: json)
        XCTAssertEqual(dcqlQuery.credentials.count, 3)
        XCTAssertNil(dcqlQuery.credentialSets)
    }

    func testValidDCQLQueryWithCredentialSets() throws {
        let json = """
        {
            "credentials": [
                { "id": "cred1", "format": "dc+sd-jwt", "meta": {} },
                { "id": "cred2", "format": "mso_mdoc", "meta": {} }
            ],
            "credential_sets": [
                { "options": [["cred1"], ["cred2"]] }
            ]
        }
        """
        let dcqlQuery = try decode(DCQLQuery.self, from: json)
        XCTAssertEqual(dcqlQuery.credentials.count, 2)
        XCTAssertEqual(dcqlQuery.credentialSets?.count, 1)
    }

    // MARK: - DCQLQuery: validation of credentials

    func testThrowErrorWhenCredentialsIsEmpty() {
        let json = """
        { "credentials": [] }
        """
        XCTAssertThrowsError(try decode(DCQLQuery.self, from: json)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid Input: dcql_query->credentials value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorWhenCredentialsIsMissing() {
        let json = "{}"
        XCTAssertThrowsError(try decode(DCQLQuery.self, from: json)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing Input: dcql_query->credentials param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorWhenCredentialQueryIdsAreNotUnique() {
        let json = """
        {
            "credentials": [
                { "id": "cred1", "format": "dc+sd-jwt", "meta": {} },
                { "id": "cred1", "format": "mso_mdoc", "meta": {} }
            ]
        }
        """
        XCTAssertThrowsError(try decode(DCQLQuery.self, from: json)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Credential Query ids must be unique within dcql_query",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - DCQLQuery: validation of credential sets

    func testThrowErrorWhenCredentialSetsIsEmpty() {
        let json = """
        {
            "credentials": [
                { "id": "cred1", "format": "dc+sd-jwt", "meta": {} }
            ],
            "credential_sets": []
        }
        """
        XCTAssertThrowsError(try decode(DCQLQuery.self, from: json)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid Input: dcql_query->credential_sets value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorWhenCredentialSetsReferencesUnknownCredentialId() {
        let json = """
        {
            "credentials": [
                { "id": "cred1", "format": "dc+sd-jwt", "meta": {} }
            ],
            "credential_sets": [
                { "options": [["unknown_id"]] }
            ]
        }
        """
        XCTAssertThrowsError(try decode(DCQLQuery.self, from: json)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "credential_sets references unknown credential id 'unknown_id'",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - CredentialQuery: valid

    func testValidCredentialQueryWithAllFields() throws {
        let json = """
        {
            "id": "my-cred_1",
            "format": "dc+sd-jwt",
            "multiple": true,
            "meta": { "vct_values": ["https://example.com/id"] },
            "require_cryptographic_holder_binding": false,
            "claims": [
                { "id": "given_name", "path": ["given_name"] }
            ],
            "claim_sets": [["given_name"]]
        }
        """
        let credentialQuery = try decode(CredentialQuery.self, from: json)
        XCTAssertEqual(credentialQuery.id, "my-cred_1")
        XCTAssertEqual(credentialQuery.format, "dc+sd-jwt")
        XCTAssertTrue(credentialQuery.multiple)
        XCTAssertFalse(credentialQuery.requireCryptographicHolderBinding)
        XCTAssertEqual(credentialQuery.claims?.count, 1)
        XCTAssertEqual(credentialQuery.claimSets?.count, 1)
    }

    func testCredentialQueryMultipleDefaultsToFalse() throws {
        let json = """
        { "id": "cred1", "format": "dc+sd-jwt", "meta": {} }
        """
        let credentialQuery = try decode(CredentialQuery.self, from: json)
        XCTAssertFalse(credentialQuery.multiple)
    }

    func testCredentialQueryRequireCryptographicHolderBindingDefaultsToTrue() throws {
        let json = """
        { "id": "cred1", "format": "dc+sd-jwt", "meta": {} }
        """
        let credentialQuery = try decode(CredentialQuery.self, from: json)
        XCTAssertTrue(credentialQuery.requireCryptographicHolderBinding)
    }

    // MARK: - CredentialQuery: validation of id

    func testThrowErrorWhenRequiredCredentialQueryPropertyIsMissing() {
        let testCases: [(input: String, expectedMessage: String)] = [
            (
                input: """
                { "format": "dc+sd-jwt", "meta": {} }
                """,
                expectedMessage: "Missing Input: credential_query->id param is required"
            ),
            (
                input: """
                { "id": "cred1", "meta": {} }
                """,
                expectedMessage: "Missing Input: credential_query->format param is required"
            ),
            (
                input: """
                { "id": "cred1", "format": "dc+sd-jwt" }
                """,
                expectedMessage: "Missing Input: credential_query->meta param is required"
            ),
        ]

        for testCase in testCases {
            XCTAssertThrowsError(try decode(CredentialQuery.self, from: testCase.input), testCase.expectedMessage) { error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: testCase.expectedMessage,
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }

    func testThrowErrorWhenCredentialQueryIdContainsInvalidCharacters() throws {
        let json = """
        { "id": "invalid id!", "format": "dc+sd-jwt", "meta": {} }
        """
        let credentialQuery = try decode(CredentialQuery.self, from: json)
        XCTAssertThrowsError(try credentialQuery.validate()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Credential Query id must consist of alphanumeric, underscore or hyphen characters",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - CredentialQuery: validation of format

    func testThrowErrorWhenCredentialQueryFormatIsMissing() {
        let json = """
        { "id": "cred1", "meta": {} }
        """
        
        XCTAssertThrowsError(try decode(CredentialQuery.self, from: json)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing Input: credential_query->format param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorWhenCredentialQueryFormatIsEmpty() throws {
        let json = """
        { "id": "cred1", "format": "", "meta": {} }
        """
        let credentialQuery = try decode(CredentialQuery.self, from: json)
        XCTAssertThrowsError(try credentialQuery.validate()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid Input: credential_query->format value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - CredentialQuery: validation of claims

    func testThrowErrorWhenClaimsIsEmptyArray() throws {
        let json = """
        { "id": "cred1", "format": "dc+sd-jwt", "meta": {}, "claims": [] }
        """
        let credentialQuery = try decode(CredentialQuery.self, from: json)
        
        XCTAssertThrowsError(try credentialQuery.validate()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid Input: credential_query->claims value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorWhenClaimIdsAreNotUnique() throws {
        let json = """
        {
            "id": "cred1",
            "format": "dc+sd-jwt",
            "meta": {},
            "claims": [
                { "id": "name", "path": ["given_name"] },
                { "id": "name", "path": ["family_name"] }
            ]
        }
        """
        let credentialQuery = try decode(CredentialQuery.self, from: json)
        
        XCTAssertThrowsError(try credentialQuery.validate()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Claim ids must be unique within a Credential Query",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - CredentialQuery: validation of claim_sets

    func testThrowErrorWhenClaimSetsIsPresentWithoutClaims() throws {
        let json = """
        {
            "id": "cred1",
            "format": "dc+sd-jwt",
            "meta": {},
            "claim_sets": [["name"]]
        }
        """
        let credentialQuery = try decode(CredentialQuery.self, from: json)
        
        XCTAssertThrowsError(try credentialQuery.validate()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "claim_sets must not be present when claims is absent",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorWhenClaimSetsIsEmptyArray() throws {
        let json = """
        {
            "id": "cred1",
            "format": "dc+sd-jwt",
            "meta": {},
            "claims": [{ "id": "name", "path": ["given_name"] }],
            "claim_sets": []
        }
        """
        let credentialQuery = try decode(CredentialQuery.self, from: json)
        
        XCTAssertThrowsError(try credentialQuery.validate()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid Input: credential_query->claim_sets value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorWhenClaimSetsContainsEmptyOption() throws {
        let json = """
        {
            "id": "cred1",
            "format": "dc+sd-jwt",
            "meta": {},
            "claims": [{ "id": "name", "path": ["given_name"] }],
            "claim_sets": [[]]
        }
        """
        let credentialQuery = try decode(CredentialQuery.self, from: json)
        
        XCTAssertThrowsError(try credentialQuery.validate()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid Input: credential_query->claim_sets value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorWhenClaimSetsReferencesUnknownClaimId() throws {
        let json = """
        {
            "id": "cred1",
            "format": "dc+sd-jwt",
            "meta": {},
            "claims": [{ "id": "name", "path": ["given_name"] }],
            "claim_sets": [["unknown_claim"]]
        }
        """
        let credentialQuery = try decode(CredentialQuery.self, from: json)
        
        XCTAssertThrowsError(try credentialQuery.validate()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "claim_sets references unknown claim id 'unknown_claim'",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - CredentialSetQuery: valid

    func testValidCredentialSetQueryWithRequiredTrue() throws {
        let json = """
        { "options": [["cred1", "cred2"]], "required": true }
        """
        let credentialSetQuery = try decode(CredentialSetQuery.self, from: json)
        XCTAssertTrue(credentialSetQuery.required)
        XCTAssertEqual(credentialSetQuery.options.count, 1)
    }

    func testCredentialSetQueryRequiredDefaultsToTrue() throws {
        let json = """
        { "options": [["cred1"]] }
        """
        let credentialSetQuery = try decode(CredentialSetQuery.self, from: json)
        XCTAssertTrue(credentialSetQuery.required)
    }

    func testCredentialSetQueryRequiredFalseWhenExplicitlySet() throws {
        let json = """
        { "options": [["cred1"]], "required": false }
        """
        let credentialSetQuery = try decode(CredentialSetQuery.self, from: json)
        XCTAssertFalse(credentialSetQuery.required)
    }

    // MARK: - CredentialSetQuery: validation of options

    func testThrowErrorWhenCredentialSetQueryOptionsIsEmpty() {
        let json = """
        { "options": [] }
        """
        XCTAssertThrowsError(try decode(CredentialSetQuery.self, from: json)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid Input: credential_set_query->options value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorWhenCredentialSetQueryOptionsContainsEmptyOption() {
        let json = """
        { "options": [[]] }
        """
        XCTAssertThrowsError(try decode(CredentialSetQuery.self, from: json)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid Input: credential_set_query->options value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorWhenCredentialSetQueryOptionsMissing() {
        let json = "{}"
        XCTAssertThrowsError(try decode(CredentialSetQuery.self, from: json)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing Input: credential_set_query->options param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - ClaimsQuery: valid

    func testValidClaimsQueryWithAllFields() throws {
        let json = """
        {
            "id": "given_name",
            "path": ["given_name"],
            "values": ["John", 42, true]
        }
        """
        let claimsQuery = try decode(ClaimsQuery.self, from: json)
        XCTAssertEqual(claimsQuery.id, "given_name")
        XCTAssertEqual(claimsQuery.path.count, 1)
        XCTAssertEqual(claimsQuery.values?.count, 3)
    }

    func testValidClaimsQueryWithoutOptionalFields() throws {
        let json = """
        { "path": ["given_name"] }
        """
        let claimsQuery = try decode(ClaimsQuery.self, from: json)
        XCTAssertNil(claimsQuery.id)
        XCTAssertNil(claimsQuery.values)
    }

    func testValidClaimsQueryPathWithNullAndIntegerElements() throws {
        let json = """
        { "path": ["degrees", null, 0] }
        """
        
        let claimsQuery = try decode(ClaimsQuery.self, from: json)
        XCTAssertEqual(claimsQuery.path.count, 3)
    }

    // MARK: - ClaimsQuery: validation of id

    func testThrowErrorWhenClaimsQueryIdContainsInvalidCharacters() {
        let json = """
        { "id": "invalid id!", "path": ["given_name"] }
        """
        XCTAssertThrowsError(try decode(ClaimsQuery.self, from: json).validate(isCredentialSetsAvailable: true)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Claims Query id must consist of alphanumeric, underscore or hyphen characters",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorWhenClaimsQueryIdIsMissingWithClaimSets() {
        let json = """
        {
            "id": "cred1",
            "format": "dc+sd-jwt",
            "meta": {},
            "claims": [{ "path": ["given_name"] }],
            "claim_sets": [["given_name"]]
        }
        """
        XCTAssertThrowsError(try decode(CredentialQuery.self, from: json).validate()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Claims with claim_sets must have an id",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - ClaimsQuery: validation of path

    func testThrowErrorWhenClaimsQueryPathIsMissing() {
        let json = """
        { "id": "name" }
        """
        XCTAssertThrowsError(try decode(ClaimsQuery.self, from: json)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing Input: claims_query->path param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorWhenClaimsQueryPathIsEmpty() {
        let json = """
        { "id": "name", "path": [] }
        """
        XCTAssertThrowsError(try decode(ClaimsQuery.self, from: json).validate(isCredentialSetsAvailable: true)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid Input: claims_query->path value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - ClaimsQuery: validation of values

    func testThrowErrorWhenClaimsQueryValuesIsEmpty() {
        let json = """
        { "path": ["given_name"], "values": [] }
        """
        XCTAssertThrowsError(try decode(ClaimsQuery.self, from: json).validate(isCredentialSetsAvailable: false)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid Input: claims_query->values value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorWhenClaimsQueryValuesContainsObject() {
        let json = """
        { "path": ["given_name"], "values": [{"key": "value"}] }
        """
        XCTAssertThrowsError(try decode(ClaimsQuery.self, from: json)) { error in
            XCTAssertTrue(error is DecodingError, "Expected DecodingError for object in values")
        }
    }

    func testThrowErrorWhenClaimsQueryValuesContainsArray() {
        let json = """
        { "path": ["given_name"], "values": [["nested"]] }
        """
        XCTAssertThrowsError(try decode(ClaimsQuery.self, from: json)) { error in
            XCTAssertTrue(error is DecodingError, "Expected DecodingError for array in values")
        }
    }

    // MARK: - Encoding round-trips

    func testDCQLQueryEncodesCredentialsKey() throws {
        let json = """
        {
            "credentials": [
                { "id": "cred1", "format": "dc+sd-jwt", "meta": {} },
                { "id": "cred2", "format": "mso_mdoc", "meta": {} }
            ]
        }
        """
        let dcqlQuery = try decode(DCQLQuery.self, from: json)
        let encoded = try JSONEncoder().encode(dcqlQuery)
        let decoded = try decode(DCQLQuery.self, from: String(data: encoded, encoding: .utf8)!)

        XCTAssertEqual(decoded.credentials.count, 2)
        XCTAssertEqual(decoded.credentials[0].id, "cred1")
        XCTAssertEqual(decoded.credentials[1].id, "cred2")
        XCTAssertNil(decoded.credentialSets)
    }

    func testDCQLQueryEncodesCredentialSetsKey() throws {
        let json = """
        {
            "credentials": [
                { "id": "cred1", "format": "dc+sd-jwt", "meta": {} }
            ],
            "credential_sets": [
                { "options": [["cred1"]], "required": false }
            ]
        }
        """
        let dcqlQuery = try decode(DCQLQuery.self, from: json)
        let encoded = try JSONEncoder().encode(dcqlQuery)
        let decoded = try decode(DCQLQuery.self, from: String(data: encoded, encoding: .utf8)!)

        XCTAssertEqual(decoded.credentialSets?.count, 1)
        XCTAssertEqual(decoded.credentialSets?.first?.required, false)
    }

    func testCredentialQueryEncodesAllFields() throws {
        let json = """
        {
            "id": "cred1",
            "format": "dc+sd-jwt",
            "multiple": true,
            "meta": { "vct_values": ["https://example.com"] },
            "require_cryptographic_holder_binding": false,
            "claims": [{ "id": "given_name", "path": ["given_name"] }],
            "claim_sets": [["given_name"]]
        }
        """
        let credentialQuery = try decode(CredentialQuery.self, from: json)
        let encoded = try JSONEncoder().encode(credentialQuery)
        let decoded = try decode(CredentialQuery.self, from: String(data: encoded, encoding: .utf8)!)

        XCTAssertEqual(decoded.id, "cred1")
        XCTAssertEqual(decoded.format, "dc+sd-jwt")
        XCTAssertTrue(decoded.multiple)
        XCTAssertFalse(decoded.requireCryptographicHolderBinding)
        XCTAssertEqual(decoded.claims?.count, 1)
        XCTAssertEqual(decoded.claimSets?.count, 1)
    }

    func testCredentialQueryEncodesDefaultValues() throws {
        let json = """
        { "id": "cred1", "format": "mso_mdoc", "meta": {} }
        """
        let credentialQuery = try decode(CredentialQuery.self, from: json)
        let encoded = try JSONEncoder().encode(credentialQuery)
        let encodedJson = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]

        XCTAssertEqual(encodedJson["multiple"] as? Bool, false)
        XCTAssertEqual(encodedJson["require_cryptographic_holder_binding"] as? Bool, true)
        XCTAssertNil(encodedJson["claims"])
        XCTAssertNil(encodedJson["claim_sets"])
    }

    func testCredentialSetQueryEncodesAllFields() throws {
        let json = """
        { "options": [["cred1", "cred2"], ["cred3"]], "required": false }
        """
        let credentialSetQuery = try decode(CredentialSetQuery.self, from: json)
        let encoded = try JSONEncoder().encode(credentialSetQuery)
        let decoded = try decode(CredentialSetQuery.self, from: String(data: encoded, encoding: .utf8)!)

        XCTAssertEqual(decoded.options.count, 2)
        XCTAssertEqual(decoded.options[0], ["cred1", "cred2"])
        XCTAssertEqual(decoded.options[1], ["cred3"])
        XCTAssertFalse(decoded.required)
    }

    func testCredentialSetQueryEncodesDefaultRequired() throws {
        let json = """
        { "options": [["cred1"]] }
        """
        let credentialSetQuery = try decode(CredentialSetQuery.self, from: json)
        let encoded = try JSONEncoder().encode(credentialSetQuery)
        let encodedJson = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]

        XCTAssertEqual(encodedJson["required"] as? Bool, true)
    }

    func testClaimsQueryEncodesAllFields() throws {
        let json = """
        { "id": "given_name", "path": ["given_name"], "values": ["John", 42, true] }
        """
        let claimsQuery = try decode(ClaimsQuery.self, from: json)
        let encoded = try JSONEncoder().encode(claimsQuery)
        let decoded = try decode(ClaimsQuery.self, from: String(data: encoded, encoding: .utf8)!)

        XCTAssertEqual(decoded.id, "given_name")
        XCTAssertEqual(decoded.path.count, 1)
        XCTAssertEqual(decoded.values?.count, 3)
        XCTAssertEqual(decoded.values?[0], .string("John"))
        XCTAssertEqual(decoded.values?[1], .int(42))
        XCTAssertEqual(decoded.values?[2], .bool(true))
    }

    func testClaimsQueryOmitsNilFieldsWhenEncoded() throws {
        let json = """
        { "path": ["family_name"] }
        """
        let claimsQuery = try decode(ClaimsQuery.self, from: json)
        let encoded = try JSONEncoder().encode(claimsQuery)
        let encodedJson = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]

        XCTAssertNil(encodedJson["id"])
        XCTAssertNil(encodedJson["values"])
        XCTAssertNotNil(encodedJson["path"])
    }

    // MARK: - ClaimValue: encoding

    func testClaimValueEncodesString() throws {
        let claimValue = ClaimValue.string("hello")
        let encodedData = try JSONEncoder().encode(claimValue)
        XCTAssertEqual(String(data: encodedData, encoding: .utf8), "\"hello\"")
    }

    func testClaimValueEncodesInt() throws {
        let claimValue = ClaimValue.int(42)
        let encodedData = try JSONEncoder().encode(claimValue)
        XCTAssertEqual(String(data: encodedData, encoding: .utf8), "42")
    }

    func testClaimValueEncodesBool() throws {
        let claimValue = ClaimValue.bool(true)
        let encodedData = try JSONEncoder().encode(claimValue)
        XCTAssertEqual(String(data: encodedData, encoding: .utf8), "true")
    }
}
