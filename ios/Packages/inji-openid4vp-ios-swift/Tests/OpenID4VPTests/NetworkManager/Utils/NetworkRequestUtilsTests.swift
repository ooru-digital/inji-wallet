import XCTest
@testable import OpenID4VP

class NetworkRequestUtilsTests: XCTestCase {
    func testIsHeaderContentType() {
        let testCases: [(headerValue: String?, expectedValue: String, expectedResult: Bool)] = [
            ("application/json", "application/json", true),
            ("application/json; charset=UTF-8", "application/json", true),
            (" application/json ; charset=UTF-8 ", "application/json", true),
            ("APPLICATION/JSON", "application/json", false),
            ("application/json; version=1.0; charset=UTF-8", "application/json", true),
            ("multipart/form-data; boundary=xyz", "application/json", false),
            ("application/xml", "application/json", false),
            ("text/plain", "application/json", false),
            (nil, "application/json", false),
            ("application/", "application/json", false),
            ("some-random/type", "application/json", false)
        ]

        for testCase in testCases {
            let mockResponse = HTTPURLResponse(url: URL(string: "https://example.com")!,
                                               statusCode: 200,
                                               httpVersion: "HTTP/1.1",
                                               headerFields: testCase.headerValue != nil ? ["Content-Type": testCase.headerValue!] : nil)!

            let result = mockResponse.isHeaderContentType(equalTo: testCase.expectedValue)
            XCTAssertEqual(result, testCase.expectedResult, "Failed for input: \(testCase.headerValue ?? "nil")")
        }
        
    }
}
