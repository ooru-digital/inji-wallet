import XCTest
@testable import OpenID4VP

final class VerifierTests: XCTestCase {

    // MARK: - Memberwise init

    func testInitStoresAllFields() {
        let verifier = Verifier(
            clientId: "https://example.com",
            responseUris: ["https://example.com/response"],
            jwksUri: "https://example.com/.well-known/jwks.json",
            allowUnsignedRequest: true,
            specVersion: .draft23
        )

        XCTAssertEqual(verifier.clientId, "https://example.com")
        XCTAssertEqual(verifier.responseUris, ["https://example.com/response"])
        XCTAssertEqual(verifier.jwksUri, "https://example.com/.well-known/jwks.json")
        XCTAssertTrue(verifier.allowUnsignedRequest)
        XCTAssertEqual(verifier.specVersion, .draft23)
    }

    func testInitUsesDefaultValues() {
        let verifier = Verifier(
            clientId: "https://example.com",
            responseUris: ["https://example.com/response"]
        )

        XCTAssertNil(verifier.jwksUri)
        XCTAssertFalse(verifier.allowUnsignedRequest)
        XCTAssertEqual(verifier.specVersion, .v1)
    }

    func testEncodeDecodeRoundTrip() throws {
        // Covers both spec versions — previously two separate tests
        let specVersions: [SpecVersion] = [.v1, .draft23]

        for specVersion in specVersions {
            let original = Verifier(
                clientId: "https://example.com",
                responseUris: ["https://example.com/response", "https://example.com/callback"],
                jwksUri: "https://example.com/.well-known/jwks.json",
                allowUnsignedRequest: true,
                specVersion: specVersion
            )
            let data = try JSONEncoder().encode(original)
            let decoded = try JSONDecoder().decode(Verifier.self, from: data)

            XCTAssertEqual(decoded.clientId, original.clientId, "clientId mismatch for specVersion \(specVersion)")
            XCTAssertEqual(decoded.responseUris, original.responseUris, "responseUris mismatch for specVersion \(specVersion)")
            XCTAssertEqual(decoded.jwksUri, original.jwksUri, "jwksUri mismatch for specVersion \(specVersion)")
            XCTAssertEqual(decoded.allowUnsignedRequest, original.allowUnsignedRequest, "allowUnsignedRequest mismatch for specVersion \(specVersion)")
            XCTAssertEqual(decoded.specVersion, original.specVersion, "specVersion mismatch for specVersion \(specVersion)")
        }
    }


    func testEncodeKeyNamesMatchApiSpec() throws {
        let verifier = Verifier(
            clientId: "https://example.com",
            responseUris: ["https://example.com/response"],
            jwksUri: "https://example.com/.well-known/jwks.json",
            allowUnsignedRequest: true
        )
        let data = try JSONEncoder().encode(verifier)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertNotNil(json["client_id"])
        XCTAssertNotNil(json["response_uris"])
        XCTAssertNotNil(json["jwks_uri"])
        XCTAssertNotNil(json["allow_unsigned_request"])
        XCTAssertNotNil(json["spec_version"])

        XCTAssertEqual(json["client_id"] as? String, "https://example.com")
        XCTAssertEqual(json["response_uris"] as? [String], ["https://example.com/response"])
        XCTAssertEqual(json["jwks_uri"] as? String, "https://example.com/.well-known/jwks.json")
        XCTAssertEqual(json["allow_unsigned_request"] as? Bool, true)
    }

    func testEncodeOmitsJwksUriWhenNil() throws {
        let verifier = Verifier(
            clientId: "https://example.com",
            responseUris: ["https://example.com/response"]
        )
        let data = try JSONEncoder().encode(verifier)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertNil(json["jwks_uri"])
    }

    func testDecodeUsesDefaultsWhenOptionalFieldsAbsent() throws {
        let json = """
        {
            "client_id": "https://example.com",
            "response_uris": ["https://example.com/response"]
        }
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(Verifier.self, from: json)

        XCTAssertEqual(decoded.clientId, "https://example.com")
        XCTAssertEqual(decoded.responseUris, ["https://example.com/response"])
        XCTAssertNil(decoded.jwksUri)
        XCTAssertFalse(decoded.allowUnsignedRequest)
        XCTAssertEqual(decoded.specVersion, .v1)
    }

    func testDecodeOptionalFieldsFromJson() throws {
        struct Case {
            let label: String
            let json: String
            let validate: (Verifier) -> Void
        }

        let cases: [Case] = [
            Case(
                label: "jwks_uri",
                json: """
                {
                    "client_id": "https://example.com",
                    "response_uris": ["https://example.com/response"],
                    "jwks_uri": "https://example.com/.well-known/jwks.json"
                }
                """,
                validate: { XCTAssertEqual($0.jwksUri, "https://example.com/.well-known/jwks.json") }
            ),
            Case(
                label: "allow_unsigned_request true",
                json: """
                {
                    "client_id": "https://example.com",
                    "response_uris": ["https://example.com/response"],
                    "allow_unsigned_request": true
                }
                """,
                validate: { XCTAssertTrue($0.allowUnsignedRequest) }
            ),
            Case(
                label: "allow_unsigned_request false",
                json: """
                {
                    "client_id": "https://example.com",
                    "response_uris": ["https://example.com/response"],
                    "allow_unsigned_request": false
                }
                """,
                validate: { XCTAssertFalse($0.allowUnsignedRequest) }
            ),
            Case(
                label: "multiple response_uris",
                json: """
                {
                    "client_id": "https://example.com",
                    "response_uris": [
                        "https://example.com/response1",
                        "https://example.com/response2",
                        "https://example.com/response3"
                    ]
                }
                """,
                validate: {
                    XCTAssertEqual($0.responseUris, [
                        "https://example.com/response1",
                        "https://example.com/response2",
                        "https://example.com/response3"
                    ])
                }
            )
        ]

        for tc in cases {
            let data = try XCTUnwrap(tc.json.data(using: .utf8), "\(tc.label): invalid UTF-8")
            let decoded = try JSONDecoder().decode(Verifier.self, from: data)
            tc.validate(decoded)
        }
    }

    func testDecodeThrowsWhenRequiredFieldMissing() {
        let cases: [TestCase<String, Void>] = [
            TestCase(input: """
            {
                "response_uris": ["https://example.com/response"]
            }
            """),
            TestCase(input: """
            {
                "client_id": "https://example.com"
            }
            """)
        ]

        for tc in cases {
            let data = tc.input.data(using: .utf8)!
            XCTAssertThrowsError(try JSONDecoder().decode(Verifier.self, from: data))
        }
    }
}
