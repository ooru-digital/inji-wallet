import XCTest
@testable import OpenID4VP

final class FieldValidatorTests: XCTestCase {
    func testIsValidStringSuccess() {
        let validString = "validValue"
        XCTAssertTrue(isValidString(validString))
    }
    
    func testIsValidStringFailure() {
        let testCases: [TestCase<String, Void>] = [
            TestCase(input: "nil", expectedError: nil),
            TestCase(input: "", expectedError: nil),
            TestCase(input: "null", expectedError: nil)
        ]
        
        for testCase in testCases {
            XCTAssertFalse(isValidString(testCase.input))
        }
    }
    
    func testIsNeitherNullNorEmptySuccess() {
        let validField = "validValue"
        XCTAssertTrue(isNeitherNullNorEmpty(field: validField))
    }
    
    func testIsNeitherNullNorEmptyFailure() {
        let testCases: [TestCase<String, Void>] = [
            TestCase(input: "nil", expectedError: nil),
            TestCase(input: "", expectedError: nil)
        ]
        
        for testCase in testCases {
            XCTAssertFalse(isNeitherNullNorEmpty(field: testCase.input))
        }
    }
    
    func testValidateFieldSuccess() throws {
        let validField = "validValue"
        XCTAssertNoThrow(try validateField(field: validField, fieldPath: ["field"], className: "TestClass"))
    }
    
    func testValidateFieldFailure() {
        let testCases: [TestCase<String, String>] = [
            TestCase(input: "nil", expectedError: "Invalid Input: field value cannot be empty or null"),
            TestCase(input: "", expectedError: "Invalid Input: field value cannot be empty or null"),
            TestCase(input: "null", expectedError: "Invalid Input: field value cannot be empty or null")
        ]
        
        
        for testCase in testCases {
            XCTAssertThrowsError(try validateField(field: testCase.input, fieldPath: ["field"], className: "TestClass")) { error in
                assertOpenID4VPException(error,
                                         expectedMessage: testCase.expectedError!,
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }
}
