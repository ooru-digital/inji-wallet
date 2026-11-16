import XCTest
@testable import OpenID4VP

final class PresentationDefinitionUtilTests: XCTestCase {
    private let isPresentationDefinitionUriSupported = true
    private let networkManager = MockNetworkManager()

    // in case of presentation definition with format having mso_mdoc, response_mode should not be any other than direct_post.jwt or iar-post.jwt
    func testParseAndValidatePresentationDefinitionWithMdocFormatAndInvalidResponseMode() async throws {
        let testCases = [
            TestCase(input: [
                "presentation_definition": [
                    "id": "id card credential",
                    "input_descriptors": [
                        [
                            "id": "input descriptor id",
                            "format": [
                                "mso_mdoc": [
                                    "alg": ["ES256"]
                                ]
                            ],
                            "constraints": [
                                "fields": [
                                    [
                                        "path": ["$['org.iso.18013.5.1:mosip']['document_number']"],
                                        "intent_to_retain": true
                                    ]
                                ]
                            ]
                        ]
                    ],
                    "format": [
                        "mso_mdoc": [
                            "alg": ["ES256"]
                        ]
                    ]
                ],
                "response_mode": "direct_post"
            ]
                    ),
            TestCase(input:
                        [
                            "presentation_definition": [
                                "id": "id card credential",
                                "input_descriptors": [
                                    [
                                        "id": "input descriptor id",
                                        "constraints": [
                                            "fields": [
                                                [
                                                    "path": ["$['org.iso.18013.5.1:mosip']['document_number']"],
                                                    "intent_to_retain": true
                                                ]
                                            ]
                                        ]
                                    ]
                                ],
                                "format": [
                                    "mso_mdoc": [
                                        "alg": ["ES256"]
                                    ]
                                ]
                            ],
                            "response_mode": "direct_post"
                        ]
                    ),
            TestCase(input: [
                "presentation_definition": [
                    "id": "id card credential",
                    "input_descriptors": [
                        [
                            "id": "input descriptor id",
                            "format": [
                                "mso_mdoc": [
                                    "alg": ["ES256"]
                                ]
                            ],
                            "constraints": [
                                "fields": [
                                    [
                                        "path": ["$['org.iso.18013.5.1:mosip']['document_number']"],
                                        "intent_to_retain": true
                                    ]
                                ]
                            ]
                        ]
                    ]
                ],
                "response_mode": "direct_post"
            ])
        ]

        for testCase in testCases {
            await XCTAssertAsyncThrowsError(try await parseAndValidatePresentationDefinition(testCase.input, isPresentationDefinitionUriSupported, networkManager)) { error in
                assertOpenID4VPException(error,
                    expectedMessage: "When mso_mdoc format is present in presentation definition, response_mode must be direct_post.jwt or iar_post.jwt",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }

        }
    }
    
    func testShouldThrowErrorWhenBothPresenentationDefinitionAndPresenentationDefinitionUriArePresent() async throws {
        let testCase =
            TestCase(input: [
                "presentation_definition": [
                    "id": "id card credential",
                    "input_descriptors": [
                        [
                            "id": "input descriptor id",
                            "format": [
                                "mso_mdoc": [
                                    "alg": ["ES256"]
                                ]
                            ],
                            "constraints": [
                                "fields": [
                                    [
                                        "path": ["$['org.iso.18013.5.1:mosip']['document_number']"],
                                        "intent_to_retain": true
                                    ]
                                ]
                            ]
                        ]
                    ],
                    "format": [
                        "mso_mdoc": [
                            "alg": ["ES256"]
                        ]
                    ]
                ],
                "response_mode": "direct_post",
                "presentation_definition_uri": "mock-url"
            ]
        )
            await XCTAssertAsyncThrowsError(try await parseAndValidatePresentationDefinition(testCase.input, isPresentationDefinitionUriSupported, networkManager)) { error in
                assertOpenID4VPException(error,
                    expectedMessage: "Either presentation_definition or presentation_definition_uri request param can be provided but not both",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
    }
    
    func testShouldThrowErrorWhenBothPresenentationDefinitionAndPresenentationDefinitionUriAreNotPresent() async throws {
        let testCase =
            TestCase(input: [
                "definition": [
                    "id": "id card credential",
                    "input_descriptors": [
                        [
                            "id": "input descriptor id",
                            "format": [
                                "mso_mdoc": [
                                    "alg": ["ES256"]
                                ]
                            ],
                            "constraints": [
                                "fields": [
                                    [
                                        "path": ["$['org.iso.18013.5.1:mosip']['document_number']"],
                                        "intent_to_retain": true
                                    ]
                                ]
                            ]
                        ]
                    ],
                    "format": [
                        "mso_mdoc": [
                            "alg": ["ES256"]
                        ]
                    ]
                ],
                "response_mode": "direct_post"
            ]
        )
            await XCTAssertAsyncThrowsError(try await parseAndValidatePresentationDefinition(testCase.input, isPresentationDefinitionUriSupported, networkManager)) { error in
                assertOpenID4VPException(error,
                    expectedMessage: "Either presentation_definition or presentation_definition_uri request param must be present",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
    }
    
    func testThrowErrorWhenPresentationDefinitionUriRespondsWithNon2xxResponse() async {
        let presentationDefinitionUri = "https://mock-verifier.com/verifier/presentation-definition"
        let authorizationRequest = [
            "presentation_definition_uri": presentationDefinitionUri,
            // other request params
        ]
        let requestUriResponse = createRequestUriResponse("{\"message\" : \"Invalid request\"}", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 400, httpVersion: "", headerFields: ["Content-Type": "application/json"])!)
        networkManager.setMockResponse(for: presentationDefinitionUri,response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
            
        
        
        await XCTAssertAsyncThrowsError(try await parseAndValidatePresentationDefinition(authorizationRequest, isPresentationDefinitionUriSupported, networkManager)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "presentation_definition_uri could not be reached: https://mock-verifier.com/verifier/presentation-definition",
                expectedCode: OpenID4VPErrorCodes.invalidPresentationDefinitionUri
            )
        }
        
    }
}
