import Foundation
import XCTest
@testable import OpenID4VP

struct MockDataClass: Codable {
    let key: String
    let keyWithMoreThanOneWord: String
    let nullableField: String?
    let number: Int
    
    enum CodingKeys: String, CodingKey {
        case key
        case keyWithMoreThanOneWord = "key_with_more_than_one_word"
        case nullableField = "nullable_field"
        case number
    }
}

class UtilsTest : XCTestCase {
    private let testClassName = String(describing: UtilsTest.self)
    
    /// Validate url tests
    
    func testInvalidUrl() {
        let testCases: [TestCase] = [
            TestCase(input: "www.example.com"),
            TestCase(input: "http://example.com/space here"),
            TestCase(input: "http://"),
            TestCase(input: "https://example"),
            TestCase(input: "http://example.com/file%/name"),
            TestCase(input: "http://example.com:99999"),
            TestCase(input: "http:///example.com"),
            TestCase(input: "http://example.com/search?q=hello%20world#@fragment"),
            TestCase(input: "http://:8080"),
            TestCase(input: ""),
            TestCase(input: "https://example.com/invalid|character")
        ]
        
        for testCase in testCases {
            XCTAssertFalse(isValidUri(testCase.input))
        }
    }
    
    func testValidUrl(){
        XCTAssertTrue(isValidUri("https://example.com"))
    }
    
    /// Check if input is JWT tests
    
    func testIsStringIsJWT() {
        let invalidJwt = isJWS("eeeee")
        let validJwt = isJWS("ec.exx.ef")
        
        XCTAssertFalse(invalidJwt)
        XCTAssertTrue(validJwt)
    }
    
    /// Test for string to HTTP method conversion
    
    func testDetermineHttpMethodToReturnHttpMethodIfInputIsValid(){
        let getMethod1 = try? determineHttpMethod(method: "get")
        let getMethod2 = try? determineHttpMethod(method: "GET")
        let getMethod3 = try? determineHttpMethod(method: "Get")
        let postMethod1 = try? determineHttpMethod(method: "post")
        let postMethod2 = try? determineHttpMethod(method: "POST")
        let postMethod3 = try? determineHttpMethod(method: "Post")
        
        XCTAssertEqual(getMethod1, .get)
        XCTAssertEqual(getMethod2, .get)
        XCTAssertEqual(getMethod3, .get)
        XCTAssertEqual(postMethod1, .post)
        XCTAssertEqual(postMethod2, .post)
        XCTAssertEqual(postMethod3, .post)
    }
    
    func testDetermineHttpMethodToThrowErrorIfInputIsNotValid(){
        XCTAssertThrowsError(try determineHttpMethod(method: "head")) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Unsupported HTTP method: head",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequestUriMethod
            )
        }
    }
    
    /// Test for dictionary of [String: Any] to data conversion
    
    func testToDataConversionSuccess() throws {
        
        let mockEncodable = MockDataClass(key: "value", keyWithMoreThanOneWord: "value1", nullableField: "value3", number: 1)
        
        let bodyParams: [String: Any] = [
            "key1": "value1",
            "key2": 123,
            "key3": mockEncodable
        ]
        
        let payloadData = try toData(bodyParams)
        
        let decoded = try JSONSerialization.jsonObject(with: payloadData, options: []) as? [String: Any]
        
        XCTAssertNotNil(decoded)
        XCTAssertEqual(decoded?["key1"] as? String, "value1")
        XCTAssertEqual(decoded?["key2"] as? Int, 123)
        
        let encodedMock = decoded?["key3"] as? [String: Any]
        XCTAssertNotNil(encodedMock)
        XCTAssertEqual(encodedMock?["key"] as? String, "value")
        XCTAssertEqual(encodedMock?["key_with_more_than_one_word"] as? String, "value1")
        XCTAssertEqual(encodedMock?["nullable_field"] as? String, "value3")
        XCTAssertEqual(encodedMock?["number"] as? Int, 1)
    }
    
    func testToDataConversionFailure() throws {
        let input: [String: Any] = ["timestamp": Date()]
        
        XCTAssertThrowsError(try toData(input), "Expected error for invalid JSON input") { error in
            assertOpenID4VPException(error,
                expectedMessage: "Json encoding failed for processedInput due to this error: Invalid JSON object",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    /// Encoding of classes to JSON test

    struct MockFailingEncodable: Encodable {
        func encode(to encoder: Encoder) throws {
            throw NSError(domain: "EncodingError", code: 0, userInfo: nil)
        }
    }
    
    func testEncodeWithAllProperties() throws {
        let mockDataClass = MockDataClass(
            key: "id_credential",
            keyWithMoreThanOneWord: "ldp_vp",
            nullableField: "value",
            number: 1
        )

        let encodedJson = try encode(mockDataClass, fieldName: "mockDataClass", className: testClassName)
        let expectedJson = "{\"key\":\"id_credential\",\"key_with_more_than_one_word\":\"ldp_vp\",\"nullable_field\":\"value\",\"number\":1}"
        
        assertJsonString(expected: expectedJson, actual: encodedJson)
    }

    func testEncodeWithoutNullableField() throws {
        let mockDataClass = MockDataClass(
            key: "id_credential",
            keyWithMoreThanOneWord: "ldp_vp",
            nullableField: nil,
            number: 1
        )

        let encodedJson = try encode(mockDataClass, fieldName: "mockDataClass", className: testClassName)
        let expectedJson = "{\"key\":\"id_credential\",\"number\":1,\"key_with_more_than_one_word\":\"ldp_vp\"}"
        
        assertJsonString(expected: expectedJson, actual: encodedJson)
    }

    
    func testEncodeFailure() {
        let failingObject = MockFailingEncodable()
        
        XCTAssertThrowsError(try encode(failingObject, fieldName: "failingObject", className: testClassName)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Json encoding failed for [\"failingObject\"] due to this error: The operation couldn’t be completed. (EncodingError error 0.)",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testBase64UrlToBase64Conversion() {
        let input = "U29t-_"
        let expected = "U29t+/=="
        
        let output = input.base64URLToBase64()
        
        XCTAssertEqual(output, expected, "URL-safe characters should be converted and padding should be added")
    }
    
    func testHashDataSHA256() throws {
        let input = "hello"
        let expectedHex = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        let result = try hashData(input, hashAlgorithm: "sha-256", className: "Utils")
        XCTAssertEqual(result.map { String(format: "%02x", $0) }.joined(), expectedHex)
    }
    
    func testHashDataDefaultingSHA256() throws {
        let input = "hello"
        let expectedHex = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        let result = try hashData(input, className: "Utils")
        XCTAssertEqual(result.map { String(format: "%02x", $0) }.joined(), expectedHex)
    }
    
    func testHashDataSHA384() throws {
        let input = "hello"
        let expectedHex = "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f"
        let result = try hashData(input, hashAlgorithm: "sha-384", className: "Utils")
        XCTAssertEqual(result.map { String(format: "%02x", $0) }.joined(), expectedHex)
    }
    
    func testHashDataSHA512() throws {
        let input = "hello"
        let expectedHex = "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
        let result = try hashData(input, hashAlgorithm: "sha-512", className: "Utils")
        XCTAssertEqual(result.map { String(format: "%02x", $0) }.joined(), expectedHex)
    }
    
    func testHashDataUnsupportedAlgorithm() {
        XCTAssertThrowsError(try hashData("hello", hashAlgorithm: "md5", className: "Utils")) { error in
            XCTAssertTrue(error is UnsupportedOperationException)
        }
    }
    
    // MARK: - resolveJwksFromUri Tests
    
    let mockNetworkManager = MockNetworkManager()
    let jwksUri = "https://example.com/jwks"
    
    func testResolveJwksFromUriSuccess() async throws {
        let validJwksJson = """
        {"keys":[{"kty":"RSA","kid":"1","n":"abc","e":"AQAB"}]}
        """
        mockNetworkManager.setMockResponse(for: jwksUri, responseBody: validJwksJson)
        
        let jwks = try await resolveJwksFromUri(jwksUri, networkManager: mockNetworkManager, className: testClassName)
        
        XCTAssertEqual(jwks.keys.count, 1)
        XCTAssertEqual(jwks.keys[0].keyType, .rsa)
        XCTAssertEqual(jwks.keys[0].keyID, "1")
    }
    
    func testResolveJwksFromUriNon200StatusCode() async {
        mockNetworkManager.setMockResponse(for: jwksUri, responseBody: "Not found", statusCode: 404)
        
        await XCTAssertAsyncThrowsError(try await resolveJwksFromUri(self.jwksUri, networkManager: self.mockNetworkManager, className: self.testClassName)) { error in
            assertOpenID4VPException(error, expectedMessage: "Public key extraction failed - Unable to fetch/parse jwks from https://example.com/jwks due to Error while fetching jwks information, status code: 404 with body: Not found", expectedCode: OpenID4VPErrorCodes.invalidRequestObject)
        }
    }
    
    func testResolveJwksFromUriInvalidJwksParsing() async {
        let invalidJwksJson = "{not a jwks}" // invalid JSON
        mockNetworkManager.setMockResponse(for: jwksUri, responseBody: invalidJwksJson)
        
        await XCTAssertAsyncThrowsError(try await resolveJwksFromUri(self.jwksUri, networkManager: self.mockNetworkManager, className: self.testClassName)) { error in
            assertOpenID4VPException(error, expectedMessage: "Public key extraction failed - Unable to fetch/parse jwks from https://example.com/jwks due to The data couldn’t be read because it isn’t in the correct format.", expectedCode: OpenID4VPErrorCodes.invalidRequestObject)
        }
    }
    
    func testResolveJwksFromUriNetworkError() async {
        mockNetworkManager.setMockResponse(for: jwksUri, error: NetworkRequestException.networkRequestFailed(message: "Simulated network error"))
        
        await XCTAssertAsyncThrowsError(try await resolveJwksFromUri(self.jwksUri, networkManager: self.mockNetworkManager, className: self.testClassName)) { error in
            assertOpenID4VPException(error, expectedMessage: "Public key extraction failed - Unable to fetch/parse jwks from https://example.com/jwks due to Network request failed with error response - Simulated network error", expectedCode: OpenID4VPErrorCodes.invalidRequestObject)
        }
    }
}
