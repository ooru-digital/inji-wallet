import XCTest
@testable import OpenID4VP

final class DeviceAuthenticationTests: XCTestCase {
    
    func testDeviceAuthenticationSuccess() {
        let validSignature = "validSignature123"
        let validAlgorithm = "ES256"
        
        let deviceAuth = DeviceAuthentication(signature: validSignature, algorithm: validAlgorithm)
        
        XCTAssertEqual(deviceAuth.signature, validSignature)
        XCTAssertEqual(deviceAuth.algorithm, validAlgorithm)
        XCTAssertNoThrow(try deviceAuth.validate())
    }
    
    func testDeviceAuthenticationInvalidSignature() {
        let testCases: [TestCase<String, String>] = [
            TestCase(input: "null", expectedError: "Invalid Input: DeviceAuthentication->signature value cannot be empty or null"),
            TestCase(input: "nil", expectedError: "Invalid Input: DeviceAuthentication->signature value cannot be empty or null"),
            TestCase(input: "", expectedError: "Invalid Input: DeviceAuthentication->signature value cannot be empty or null")
        ]
        
        let validAlgorithm = "ES256"
        
        for testCase in testCases {
            let deviceAuth = DeviceAuthentication(signature: testCase.input, algorithm: validAlgorithm)
            
            XCTAssertThrowsError(try deviceAuth.validate()) { error in
                assertOpenID4VPException(error,
                     expectedMessage: testCase.expectedError!,
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }
    
    func testDeviceAuthenticationInvalidAlgorithm() {
        let testCases: [TestCase<String, String>] = [
            TestCase(input: "null", expectedError: "Invalid Input: DeviceAuthentication->algorithm value cannot be empty or null"),
            TestCase(input: "nil", expectedError: "Invalid Input: DeviceAuthentication->algorithm value cannot be empty or null"),
            TestCase(input: "", expectedError: "Invalid Input: DeviceAuthentication->algorithm value cannot be empty or null")
        ]
        
        let validSignature = "validSignature123"
        
        for testCase in testCases {
            let deviceAuth = DeviceAuthentication(signature: validSignature, algorithm: testCase.input)
            
            XCTAssertThrowsError(try deviceAuth.validate()) { error in
                assertOpenID4VPException(error,
                     expectedMessage: testCase.expectedError!,
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }
}
