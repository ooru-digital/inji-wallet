import Foundation
import XCTest
import JSONWebKey
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
        let invalidUrls: [String] = [
            "www.example.com",
            "http://example.com/space here",
            "http://",
            "https://example",
            "http://example.com/file%/name",
            "http://example.com:99999",
            "http:///example.com",
            "http://example.com/search?q=hello%20world#@fragment",
            "http://:8080",
            "",
            "https://example.com/invalid|character",
            "foo://example.com:8042/over/there?name=ferret#nose",
            "https://example.com/file%/name",
            "https://example.com/space here",
            "https://example.com/path\n"
        ]

        for url in invalidUrls {
            XCTAssertFalse(isValidUri(url), "expected invalid: \(url)")
        }
    }

    func testValidUrl(){
        let validUrls: [String] = [
            "https://609e-122-178-244-112.ngrok-free.app/verifier/get-auth-request-obj/did?draft=version-1.0&response_mode=direct_post",
            "https://example.com:8042/over/there?name=ferret#nose",
            "https://example.com/a%20b?q=hello%20world",
            "https://example.com//empty/seg",
            "https://example.com/p?a=1/2&b=x?y#f/g?h"
        ]
        for url in validUrls {
            XCTAssertTrue(isValidUri(url), "expected valid: \(url)")
        }
    }
    
    /// Check if input is JWT tests
    
    func testIsStringIsJWT() {
        let invalidJwt = isJWS("eeeee")
        let validJwt = isJWS("ec.exx.ef")
        
        XCTAssertFalse(invalidJwt)
        XCTAssertTrue(validJwt)
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

    // MARK: - getEncryptionKey Tests

    private func makeJWK(alg: String, use: String = "enc", kid: String = "key1") throws -> JWK {
        let dict: [String: Any] = ["kty": "OKP", "crv": "X25519", "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4", "alg": alg, "use": use, "kid": kid]
        return try JSONDecoder().decode(JWK.self, from: JSONSerialization.data(withJSONObject: dict))
    }

    private func makeJWKSet(_ jwks: [JWK]) -> JWKSet {
        JWKSet(keys: jwks)
    }

    func testGetEncryptionKeyReturnsSingleMatchingKey() throws {
        let encKey = try makeJWK(alg: "ECDH-ES", use: "enc", kid: "enc1")
        let jwks = makeJWKSet([encKey])

        let result = try getEncryptionKey(jwks, ["ECDH-ES"])

        XCTAssertEqual(result.keyID, "enc1")
        XCTAssertEqual(result.algorithm, "ECDH-ES")
    }

    func testGetEncryptionKeyThrowsWhenNoKeyMatchesAlgorithm() throws {
        let sigKey = try makeJWK(alg: "EdDSA", use: "sig", kid: "sig1")
        let jwks = makeJWKSet([sigKey])

        XCTAssertThrowsError(try getEncryptionKey(jwks, ["ECDH-ES"])) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "No jwk matching the specified algorithm found for encryption",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testGetEncryptionKeyThrowsWhenJwksIsEmpty() throws {
        let jwks = makeJWKSet([])

        XCTAssertThrowsError(try getEncryptionKey(jwks, ["ECDH-ES"])) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "No jwk matching the specified algorithm found for encryption",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testGetEncryptionKeyReturnsEncKeyWhenMultipleMatchingKeysExist() throws {
        let sigKey = try makeJWK(alg: "ECDH-ES", use: "sig", kid: "sig1")
        let encKey = try makeJWK(alg: "ECDH-ES", use: "enc", kid: "enc1")
        let jwks = makeJWKSet([sigKey, encKey])

        let result = try getEncryptionKey(jwks, ["ECDH-ES"])

        XCTAssertEqual(result.keyID, "enc1")
        XCTAssertEqual(result.publicKeyUse, .encryption)
    }

    func testGetEncryptionKeyThrowsWhenMultipleEncKeysMatchAlgorithm() throws {
        let encKey1 = try makeJWK(alg: "ECDH-ES", use: "enc", kid: "enc1")
        let encKey2 = try makeJWK(alg: "ECDH-ES", use: "enc", kid: "enc2")
        let jwks = makeJWKSet([encKey1, encKey2])

        XCTAssertThrowsError(try getEncryptionKey(jwks, ["ECDH-ES"])) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Multiple jwks matching the specified algorithm found for encryption",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testGetEncryptionKeyPicksFirstMatchingAlgorithmInPreferenceOrder() throws {
        let ecdhKey = try makeJWK(alg: "ECDH-ES", use: "enc", kid: "ecdh1")
        let jwks = makeJWKSet([ecdhKey])

        let result = try getEncryptionKey(jwks, ["ECDH-ES+A256KW", "ECDH-ES"])

        XCTAssertEqual(result.keyID, "ecdh1")
        XCTAssertEqual(result.algorithm, "ECDH-ES")
    }

    func testGetEncryptionKeyThrowsWhenNoAlgorithmsProvided() throws {
        let encKey = try makeJWK(alg: "ECDH-ES", use: "enc", kid: "enc1")
        let jwks = makeJWKSet([encKey])

        XCTAssertThrowsError(try getEncryptionKey(jwks, [])) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "No jwk matching the specified algorithm found for encryption",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - constructSigningResults Tests

    private func makeUnsignedVPToken(id: String, format: FormatType) -> UnsignedVPToken {
        UnsignedVPToken(id: id, format: format, holderKeyReference: "key-ref", signatureAlgorithm: "ES256", dataToSign: Data())
    }

    private func makeSigningResult(id: String) -> VPTokenSigningResult {
        VPTokenSigningResult(id: id, signedData: Data("signed".utf8))
    }

    func testConstructSigningResultsSingleFormatSingleCredentialReturnsMatchedResult() throws {
        let unsignedToken = makeUnsignedVPToken(id: "id-1", format: .ldp_vc)
        let signingResult = makeSigningResult(id: "id-1")

        let unsignedVPTokenResults: [FormatType: (VPTokenSigningPayload, [UnsignedVPToken])] = [
            .ldp_vc: (["id-1": "payload"], [unsignedToken])
        ]

        let result = try constructSigningResults(
            unsignedVPTokenResults: unsignedVPTokenResults,
            signingResults: [signingResult]
        )

        XCTAssertEqual(result.count, 1)
        XCTAssertEqual(result[.ldp_vc]?.count, 1)
        XCTAssertEqual(result[.ldp_vc]?.first?.id, "id-1")
    }

    func testConstructSigningResultsMultipleCredentialsSameFormatReturnsAllMatched() throws {
        let token1 = makeUnsignedVPToken(id: "id-1", format: .ldp_vc)
        let token2 = makeUnsignedVPToken(id: "id-2", format: .ldp_vc)
        let sr1 = makeSigningResult(id: "id-1")
        let sr2 = makeSigningResult(id: "id-2")

        let unsignedVPTokenResults: [FormatType: (VPTokenSigningPayload, [UnsignedVPToken])] = [
            .ldp_vc: (["id-1": "p1", "id-2": "p2"], [token1, token2])
        ]

        let result = try constructSigningResults(
            unsignedVPTokenResults: unsignedVPTokenResults,
            signingResults: [sr1, sr2]
        )

        XCTAssertEqual(result.count, 1)
        XCTAssertEqual(result[.ldp_vc]?.count, 2)
        XCTAssertEqual(Set(result[.ldp_vc]!.map { $0.id }), ["id-1", "id-2"])
    }

    func testConstructSigningResultsMultipleFormatsReturnsResultsSplitByFormat() throws {
        let ldpToken = makeUnsignedVPToken(id: "id-ldp", format: .ldp_vc)
        let mdocToken = makeUnsignedVPToken(id: "id-mdoc", format: .mso_mdoc)
        let ldpSR = makeSigningResult(id: "id-ldp")
        let mdocSR = makeSigningResult(id: "id-mdoc")

        let unsignedVPTokenResults: [FormatType: (VPTokenSigningPayload, [UnsignedVPToken])] = [
            .ldp_vc: (["id-ldp": "p1"], [ldpToken]),
            .mso_mdoc: (["id-mdoc": "p2"], [mdocToken])
        ]

        let result = try constructSigningResults(
            unsignedVPTokenResults: unsignedVPTokenResults,
            signingResults: [ldpSR, mdocSR]
        )

        XCTAssertEqual(result.count, 2)
        XCTAssertEqual(result[.ldp_vc]?.first?.id, "id-ldp")
        XCTAssertEqual(result[.mso_mdoc]?.first?.id, "id-mdoc")
    }

    func testConstructSigningResultsEmptyInputsReturnsEmptyResult() throws {
        let result = try constructSigningResults(
            unsignedVPTokenResults: [:],
            signingResults: []
        )
        XCTAssertTrue(result.isEmpty)
    }

    func testConstructSigningResultsThrowsWhenSigningResultIdHasNoMatchingUnsignedToken() {
        let unsignedToken = makeUnsignedVPToken(id: "id-1", format: .ldp_vc)

        let unsignedVPTokenResults: [FormatType: (VPTokenSigningPayload, [UnsignedVPToken])] = [
            .ldp_vc: (["id-1": "payload"], [unsignedToken])
        ]

        XCTAssertThrowsError(try constructSigningResults(
            unsignedVPTokenResults: unsignedVPTokenResults,
            signingResults: [makeSigningResult(id: "id-1"), makeSigningResult(id: "unknown-id")]
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Unexpected VP token signing result for credential identifier(s): unknown-id",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testConstructSigningResultsThrowsAndListsAllUnexpectedIdentifiers() {
        let unsignedToken = makeUnsignedVPToken(id: "id-1", format: .ldp_vc)

        let unsignedVPTokenResults: [FormatType: (VPTokenSigningPayload, [UnsignedVPToken])] = [
            .ldp_vc: (["id-1": "payload"], [unsignedToken])
        ]

        XCTAssertThrowsError(try constructSigningResults(
            unsignedVPTokenResults: unsignedVPTokenResults,
            signingResults: [makeSigningResult(id: "id-1"), makeSigningResult(id: "extra-1"), makeSigningResult(id: "extra-2")]
        )) { error in
            guard let ovpException = error as? OpenID4VPException else {
                XCTFail("Expected OpenID4VPException but got \(error)")
                return
            }
            XCTAssertEqual(ovpException.errorCode, OpenID4VPErrorCodes.invalidRequest)
            XCTAssertTrue(
                ovpException.message.hasPrefix("Unexpected VP token signing result for credential identifier(s):"),
                "Unexpected message prefix: \(ovpException.message)"
            )
            XCTAssertTrue(ovpException.message.contains("extra-1"), "Expected 'extra-1' in: \(ovpException.message)")
            XCTAssertTrue(ovpException.message.contains("extra-2"), "Expected 'extra-2' in: \(ovpException.message)")
        }
    }

    func testConstructSigningResultsThrowsWhenSigningResultMissingForIdentifier() {
        let unsignedToken = makeUnsignedVPToken(id: "id-1", format: .ldp_vc)

        let unsignedVPTokenResults: [FormatType: (VPTokenSigningPayload, [UnsignedVPToken])] = [
            .ldp_vc: (["id-1": "payload"], [unsignedToken])
        ]

        XCTAssertThrowsError(try constructSigningResults(
            unsignedVPTokenResults: unsignedVPTokenResults,
            signingResults: []
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing VP token signing result for credential identifier id-1",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testConstructSigningResultsThrowsWhenSigningResultMissingInOneOfMultipleFormats() {
        let ldpToken = makeUnsignedVPToken(id: "id-ldp", format: .ldp_vc)
        let mdocToken = makeUnsignedVPToken(id: "id-mdoc", format: .mso_mdoc)

        let unsignedVPTokenResults: [FormatType: (VPTokenSigningPayload, [UnsignedVPToken])] = [
            .ldp_vc: (["id-ldp": "p1"], [ldpToken]),
            .mso_mdoc: (["id-mdoc": "p2"], [mdocToken])
        ]

        // Only ldp SR provided — mdoc SR is missing
        XCTAssertThrowsError(try constructSigningResults(
            unsignedVPTokenResults: unsignedVPTokenResults,
            signingResults: [makeSigningResult(id: "id-ldp")]
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing VP token signing result for credential identifier id-mdoc",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
