import XCTest
@testable import OpenID4VP

final class DCQLUtilTests: XCTestCase {

    private let validDcqlQuery: [String: Any] = [
        "credentials": [
            ["id": "cred1", "format": "dc+sd-jwt", "meta": [:]]
        ]
    ]

    // MARK: - Success

    func testSuccessfullyParsesValidDcqlQuery() throws {
        let authorizationRequest: [String: Any] = ["dcql_query": validDcqlQuery]

        let result = try parseAndValidateDcqlQuery(authorizationRequest)

        XCTAssertTrue(result["dcql_query"] is DCQLQuery)
    }

    // MARK: - Missing dcql_query

    func testThrowErrorWhenDcqlQueryIsMissing() {
        let authorizationRequest: [String: Any] = ["response_type": "vp_token"]

        XCTAssertThrowsError(try parseAndValidateDcqlQuery(authorizationRequest)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid Input: authorizationRequest->dcql_query value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - Both dcql_query and scope present

    func testThrowErrorWhenBothDcqlQueryAndScopeArePresent() {
        let authorizationRequest: [String: Any] = [
            "dcql_query": validDcqlQuery,
            "scope": "openid"
        ]

        XCTAssertThrowsError(try parseAndValidateDcqlQuery(authorizationRequest)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "The request contains both a dcql_query parameter and a scope parameter",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - String input

    func testSuccessfullyParsesValidDcqlQueryPassedAsString() throws {
        let dcqlQueryString = """
        {"credentials": [{"id": "cred1", "format": "dc+sd-jwt", "meta": {}}]}
        """
        let authorizationRequest: [String: Any] = ["dcql_query": dcqlQueryString]

        let result = try parseAndValidateDcqlQuery(authorizationRequest)

        XCTAssertTrue(result["dcql_query"] is DCQLQuery)
    }

    // MARK: - Invalid dcql_query type

    func testThrowErrorWhenDcqlQueryIsNeitherStringNorDictionary() {
        let authorizationRequest: [String: Any] = ["dcql_query": 12345]

        XCTAssertThrowsError(try parseAndValidateDcqlQuery(authorizationRequest)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "The dcql_query parameter must be a string or a JSON object",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - Invalid DCQL content

    func testThrowErrorWhenCredentialQueryIdIsInvalid() {
        let authorizationRequest: [String: Any] = [
            "dcql_query": [
                "credentials": [
                    ["id": "invalid id!", "format": "dc+sd-jwt", "meta": [:]]
                ]
            ]
        ]

        XCTAssertThrowsError(try parseAndValidateDcqlQuery(authorizationRequest)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Credential Query id must consist of alphanumeric, underscore or hyphen characters",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
