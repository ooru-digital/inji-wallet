import XCTest
@testable import OpenID4VP

import Foundation

final class NetworkManagerTests: XCTestCase {
    func testThrowErrorWhenInvalidUrlIsPassedAsInput() async throws {
        let networkManager = NetworkManager()
        let testCases: [TestCase<String, Void>] = [
            TestCase(input: "", expectedError: "Network request failed with error response - URL is not valid: "),
            TestCase(input: "invalid-url", expectedError: "Network request failed with error response - URLSessionTask failed with error: unsupported URL"),
            TestCase(input: "http://exa<mpl>e.com", expectedError: "Network request failed with error response - URL is not valid: http://exa<mpl>e.com"),
        ]
        
        for testCase in testCases {
            do {
                _ = try await networkManager.sendHTTPRequest(url: testCase.input, method: .get)
                XCTFail("Invalid URL error should have been captured but no error was thrown")
            } catch {
                XCTAssertEqual(testCase.expectedError, error.localizedDescription, "Error - \(testCase.expectedError!) should be thrown but got \(error.localizedDescription)")
            }
        }
    }
    
    func testReturnFalseForNon2xxStatusCode() async throws {
        let response = NetworkResponse(statusCode: 400, body: "", headers: [:])
        
        XCTAssertFalse(response.isOK)
    }
}
