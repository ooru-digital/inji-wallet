import XCTest
@testable import OpenID4VP

final class AuthorizationResponseTests: XCTestCase {

    let mdocVPToken = MdocVPToken(base64EncodedDeviceResponse: "mdoc")

    let ldpVPToken = LdpVPToken(
        context: ["context"],
        type: ["typ1"],
        verifiableCredential: [AnyCodable(AuthorizationResponseTests.ldpVC())],
        id: "identifier",
        holder: "holder",
        proof: Proof(
            type: "Ed25519Signature2018",
            created: "2021-03-19T15:30:15Z",
            challenge: "n-0S6_WzA2Mj",
            domain: "https://client.example.org/cb",
            jws: "eyJhbG...IAoDA",
            proofPurpose: .vpProofPurpose,
            verificationMethod: "did:example:holder#key-1",
            proofValue: "test"
        )
    )

    let presentationSubmissionWithMdoc = PresentationSubmission(
        definitionId: "client-identifier",
        descriptorMap: [
            DescriptorMap(id: "input_1", format: .ldp_vp, path: "$",pathNested: nil)
        ]
    )

    let presentationSubmissionWithLdpVPAndMdoc = PresentationSubmission(
        definitionId: "client-identifier",
        descriptorMap: [
            DescriptorMap(id: "input_1", format: .ldp_vp, path: "$[0]", pathNested: PathNested(id: "input_1", format: .ldp_vc, path: "$.verifiableCredential[0]")),
            DescriptorMap(id: "input_2", format: .mso_mdoc, path: "$[1]", pathNested: nil)
        ]
    )

    func testToJsonEncodedMapWithSingleToken() throws {
        let expectedPresentationSubmission: [String: Any] = [
            "descriptor_map": [
                ["path": "$", "id": "input_1", "format": "ldp_vp"]
            ],
            "definition_id": "client-identifier"
        ]

        let authorizationResponse = AuthorizationResponse(
            vpToken: .vpTokenElement(mdocVPToken),
            presentationSubmission: presentationSubmissionWithMdoc,
            state: "test-state"
        )

        let result = try authorizationResponse.toJsonEncodedMap()

        XCTAssertEqual(result["state"], "test-state")

        let decodedPresentation = decodeJsonDict(result["presentation_submission"])
        assertDictionariesEqual(expected: expectedPresentationSubmission, actual: decodedPresentation, strict: false)

        let decodedVPToken = decodeJsonString(result["vp_token"])
        XCTAssertEqual(decodedVPToken, "mdoc")
    }

    func testToJsonEncodedMapWithTokenArray() throws {
        let expectedVPToken: [Any] = [
            "mdoc",
            [
                "type": ["typ1"],
                "proof": [
                    "proofPurpose": "authentication",
                    "type": "Ed25519Signature2018",
                    "domain": "https://client.example.org/cb",
                    "verificationMethod": "did:example:holder#key-1",
                    "created": "2021-03-19T15:30:15Z",
                    "jws": "eyJhbG...IAoDA",
                    "challenge": "n-0S6_WzA2Mj",
                    "proofValue": "test"
                ],
                "id": "identifier",
                "verifiableCredential": [
                    AuthorizationResponseTests.ldpVC()
                ],
                "holder": "holder",
                "@context": ["context"]
            ]
        ]

        let authorizationResponse = AuthorizationResponse(
            vpToken: .vpTokenArray([mdocVPToken, ldpVPToken]),
            presentationSubmission: presentationSubmissionWithLdpVPAndMdoc,
            state: "test-state"
        )

        let result = try authorizationResponse.toJsonEncodedMap()

        XCTAssertEqual(result["state"], "test-state")

        let decodedPresentation = decodeJsonDict(result["presentation_submission"])
        assertDictionariesEqual(expected: [
            "descriptor_map": [
                [
                    "format": "ldp_vp",
                    "id": "input_1",
                    "path_nested": [
                        "path": "$.verifiableCredential[0]",
                        "id": "input_1",
                        "format": "ldp_vc"
                    ],
                    "path": "$[0]"
                ],
                [
                    "path": "$[1]",
                    "id": "input_2",
                    "format": "mso_mdoc"
                ]
            ],
            "definition_id": "client-identifier"
        ], actual: decodedPresentation, strict: false)

        let decodedVPToken = decodeJsonArray(result["vp_token"])
        assertJsonString(expected: convertToJsonString(expectedVPToken), actual: convertToJsonString(decodedVPToken))
    }

    func testToJsonEncodedMapWithoutState() throws {
        let expectedPresentationSubmission: [String: Any] = [
            "descriptor_map": [
                ["path": "$", "id": "input_1", "format": "ldp_vp"]
            ],
            "definition_id": "client-identifier"
        ]

        let authorizationResponse = AuthorizationResponse(
            vpToken: .vpTokenElement(mdocVPToken),
            presentationSubmission: presentationSubmissionWithMdoc,
            state: nil
        )

        let result = try authorizationResponse.toJsonEncodedMap()
        XCTAssertNil(result["state"])

        let decodedPresentation = decodeJsonDict(result["presentation_submission"])
        assertDictionariesEqual(expected: expectedPresentationSubmission, actual: decodedPresentation, strict: false)

        let decodedVPToken = decodeJsonString(result["vp_token"])
        XCTAssertEqual(decodedVPToken, "mdoc")
    }

    // MARK: - Mock Verifiable Credential

    static func ldpVC() -> [String: Any] {
        return [
            "type": ["VerifiableCredential", "IDCardCredential"],
            "proof": [
                "jws": "eyJhb...JQdBw",
                "type": "Ed25519Signature2018",
                "created": "2021-03-19T15:30:15Z",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "did:example:issuer#keys-1"
            ],
            "credentialSubject": [
                "family_name": "Mockister",
                "given_name": "MockUser",
                "birthdate": "1949-01-22"
            ],
            "id": "https://example.com/credentials/1872",
            "issuer": ["id": "did:example:issuer"],
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
                ["sec": "https://w3id.org/security#"]
            ],
            "issuanceDate": "2010-01-01T19:23:24Z"
        ]
    }

    // MARK: - Helpers

    func decodeJsonDict(_ json: String?) -> [String: Any] {
        guard let json else { return [:] }
        let data = Data(json.utf8)
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
    }

    func decodeJsonArray(_ json: String?) -> [Any] {
        guard let json else { return [] }
        let data = Data(json.utf8)
        return (try? JSONSerialization.jsonObject(with: data)) as? [Any] ?? []
    }

    func decodeJsonString(_ json: String?) -> String {
        guard let json else { return "" }
        let data = Data(json.utf8)
        return (try? JSONDecoder().decode(String.self, from: data)) ?? ""
    }

    func convertToJsonString(_ object: Any) -> String {
        guard JSONSerialization.isValidJSONObject(object) else {
            return "⚠️ Invalid top-level JSON object"
        }

        do {
            let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
            return String(data: data, encoding: .utf8) ?? ""
        } catch {
            return "⚠️ JSON serialization failed: \(error.localizedDescription)"
        }
    }



    func assertJsonString(expected: String, actual: String) {
        XCTAssertEqual(expected, actual, "JSON strings don't match.\nExpected:\n\(expected)\n\nActual:\n\(actual)")
    }

    func assertDictionariesEqual(expected: [String: Any], actual: [String: Any], strict: Bool = true) {
        for (key, expectedValue) in expected {
            guard let actualValue = actual[key] else {
                XCTFail("Missing key: \(key)")
                continue
            }

            let expectedJson = convertToJsonString(expectedValue)
            let actualJson = convertToJsonString(actualValue)
            XCTAssertEqual(expectedJson, actualJson, "Mismatch at key: \(key)")
        }

        if strict {
            for key in actual.keys where expected[key] == nil {
                XCTFail("Unexpected extra key: \(key)")
            }
        }
    }
}
