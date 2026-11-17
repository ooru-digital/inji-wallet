import XCTest
@testable import OpenID4VP

final class ConstraintsTests: XCTestCase {
    
    /// success test with valid constraints
    func testConstraintsDecoding_Success() throws {
        let constraints = try createConstraints("""
        {
            "fields": [
                {
                    "path": ["$.name"],
                    "filter": {
                        "type": "string",
                        "pattern": "^[a-zA-Z]+$"
                    }
                }
            ],
            "limit_disclosure": "preferred"
        }
        """)
        
        XCTAssertNotNil(constraints.fields)
        XCTAssertEqual(constraints.fields?.count, 1)
        XCTAssertEqual(constraints.fields?.first?.path, ["$.name"])
        XCTAssertEqual(constraints.limitDisclosure, .preferred)
    }
    
    func testConstraintsDecoding_SuccessWithEmptyFields() throws {
        let constraints = try createConstraints("""
                        {
                            "fields": [],
                            "limit_disclosure": "preferred"
                        }
                        """)
        
        
        XCTAssertNotNil(constraints.fields)
        XCTAssertEqual(constraints.fields?.count, 0)
        XCTAssertEqual(constraints.limitDisclosure, .preferred)
    }
    
    /// Fields Validation Tests
    
    func testConstraintsDecoding_FieldsValidation() throws {
        let testCases: [TestCase<String, Void>] = [
            TestCase(
                input: """
                {
                    "fields": [
                        {
                            "path": ["$.name"],
                            "filter": {
                                "type": "string"
                            }
                        }
                    ],
                    "limit_disclosure": ""
                }
                """,
                expectedError: "Missing Input: filter->pattern param is required"
            ),
            TestCase(
                input: """
                {
                    "fields": [
                        {
                            "filter": {
                                "type": "string"
                            }
                        }
                    ],
                    "limit_disclosure": "preferred"
                }
                """,
                expectedError: "Missing Input: fields->path param is required"
            )
        ]
        
        for testCase in testCases {
            XCTAssertThrowsError(try createConstraints(testCase.input)) { error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: testCase.expectedError ?? "",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }

    func testConstraintsDecoding_LimitDisclosureValidation() throws {
        let testCases: [TestCase<String, Void>] = [
            TestCase(
                input: """
                {
                    "fields": [
                        {
                            "path": ["$.name"],
                            "filter": {
                                "type": "string",
                                "pattern": "^[a-zA-Z]+$"
                            }
                        }
                    ],
                    "limit_disclosure": ""
                }
                """,
                expectedError: "Invalid Input: constraints->limit_disclosure value cannot be empty or null"
            ),
            TestCase(
                input: """
                {
                    "fields": [
                        {
                            "path": ["$.name"],
                            "filter": {
                                "type": "string",
                                "pattern": "^[a-zA-Z]+$"
                            }
                        }
                    ],
                    "limit_disclosure": "optional"
                }
                """,
                expectedError: "Invalid Input: constraints->limit_disclosure value should be preferred"
            )
        ]

        for testCase in testCases {
            XCTAssertThrowsError(try createConstraints(testCase.input)) { error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: testCase.expectedError ?? "",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }



    
    private func createConstraints(_ json: String) throws -> Constraints {
        let jsonData = json.data(using: .utf8)!
        
        return try JSONDecoder().decode(Constraints.self, from: jsonData)
    }
}
