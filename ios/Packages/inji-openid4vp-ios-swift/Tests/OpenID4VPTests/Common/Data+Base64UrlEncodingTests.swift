import Foundation

import XCTest
@testable import OpenID4VP

class Base64UrlEncodingTests: XCTestCase {
    
    func testBase64UrlEncodingSuccess() throws {
        let input = "Hello world!".data(using: .utf8)
        
        let base64UrlEncodedResult = input?.toBase64UrlEncoded()
        
        XCTAssertEqual("SGVsbG8gd29ybGQh", base64UrlEncodedResult)
    }
}
