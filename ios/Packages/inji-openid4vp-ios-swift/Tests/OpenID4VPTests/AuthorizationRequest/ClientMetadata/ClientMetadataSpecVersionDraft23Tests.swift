import XCTest
@testable import OpenID4VP

final class ClientMetadataSpecVersionDraft23Tests: XCTestCase {

    private let mixedJwks = """
    {
        "keys": [
            {
                "kty": "EC",
                "use": "enc",
                "alg": "ECDH-ES",
                "kid": "valid-enc-key",
                "crv": "P-256",
                "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
                "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
            },
            {
                "kty": "AKP",
                "alg": "ML-KEM-9999",
                "use": "enc",
                "kid": "post-quantum-key"
            },
            {
                "kty": "OIDF-CONFORMANCE-UNSUPPORTED",
                "use": "enc",
                "kid": "unsupported-key"
            }
        ]
    }
    """

    func testThrowErrorOnValidationOfInvalidClientMetadataNew() {
            let testCases: [TestCase] = [
                TestCase(
                    input: """
                    {
                        "client_name": null,
                        "logo_uri": "https://example.com/logo.png",
                        "authorization_encrypted_response_alg": "RSA-OAEP",
                        "authorization_encrypted_response_enc": "A256GCM",
                        "vp_formats": { "format1": { "type1": ["value1"] } },
                        "jwks": null
                    }
                    """.data(using: .utf8)!,
                    expectedError: "Error during client metadata decoding - Invalid Input: client_metadata->client_name value cannot be empty or null",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                ),
                TestCase(
                    input: """
                    {
                        "client_name": "Test Client",
                        "logo_uri": null,
                        "authorization_encrypted_response_alg": "RSA-OAEP",
                        "authorization_encrypted_response_enc": "A256GCM",
                        "vp_formats": { "format1": { "type1": ["value1"] } },
                        "jwks": null
                    }
                    """.data(using: .utf8)!,
                    expectedError: "Error during client metadata decoding - Invalid Input: client_metadata->logo_uri value cannot be empty or null",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                ),
                TestCase(
                    input: """
                    {
                        "client_name": "Test Client",
                        "logo_uri": "https://example.com/logo.png",
                        "authorization_encrypted_response_alg": null,
                        "authorization_encrypted_response_enc": "A256GCM",
                        "vp_formats": { "format1": { "type1": ["value1"] } },
                        "jwks": null
                    }
                    """.data(using: .utf8)!,
                    expectedError: "Error during client metadata decoding - Invalid Input: client_metadata->authorization_encrypted_response_alg value cannot be empty or null",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                ),
                TestCase(
                    input: """
                    {
                        "client_name": "Test Client",
                        "logo_uri": "https://example.com/logo.png",
                        "authorization_encrypted_response_alg": "RSA-OAEP",
                        "authorization_encrypted_response_enc": null,
                        "vp_formats": { "format1": { "type1": ["value1"] } },
                        "jwks": null
                    }
                    """.data(using: .utf8)!,
                expectedError: "Error during client metadata decoding - Invalid Input: client_metadata->authorization_encrypted_response_enc value cannot be empty or null",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                ),
                TestCase(
                    input: """
                    {
                        "client_name": "Test Client",
                        "logo_uri": "https://example.com/logo.png",
                        "authorization_encrypted_response_alg": "RSA-OAEP",
                        "authorization_encrypted_response_enc": "A256GCM",
                        "vp_formats": {},
                        "jwks": {
                            "keys": [
                                {
                                    "kty": "EC",
                                    "use": "sig",
                                    "alg": "RS256",
                                    "kid": "abc123",
                                    "x": "xqr0QcHyPyuhIzsPhchZ0QXrDI1pLx9kz0B3SAYLw1vTOpUd9qnQRgGnFoLPaKqxvX8OZlQ6DLgQ7eEK9gHe9cqB7_EYOZxJYmEKC4Gmxds2ExF3PXmtvCQRtAQ29Lv8OUU5BWfMrx6CwQwM0yiJdhWw4BMKzFUInMMWLz6-U0ky5PFeoqNNi3X9bEJmQMGb54Mp5T8JQWm3nB41Nq5G-LWdaV-NLYbdvYwYbX_tYw2kOTK_1hfu2GH0fVlOVbeCKpK5-lJXJGLhCQ7RbvZz2wGmOcUJoTGP1davTNv4B5Xww4Gh_NZRTVzLepJxai1ZkHcAFNT3n4S889p5BQ",
                                    "crv": "P-256"
                                }
                            ]
                        }
                    }
                    """.data(using: .utf8)!,
                    expectedError: "Error during client metadata decoding - Invalid Input: client_metadata->vp_formats value cannot be empty or null",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                ),
                TestCase(
                    input: """
                    {
                        "client_name": "Test Client",
                        "logo_uri": "https://example.com/logo.png",
                        "authorization_encrypted_response_alg": "RSA-OAEP",
                        "authorization_encrypted_response_enc": "A256GCM",
                        "vp_formats": { "format1": { "type1": ["value1"] } },
                        "jwks": null
                    }
                    """.data(using: .utf8)!,
                expectedError: "Error during client metadata decoding - Invalid Input: client_metadata->jwks value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            ]
        
            for testCase in testCases {
                XCTAssertThrowsError(try ClientMetadataDraft23.deserializeAndValidate(clientMetadata: testCase.input)) { error in
                    assertOpenID4VPException(
                        error,
                        expectedMessage: testCase.expectedError ?? "Missing expected error",
                        expectedCode: testCase.expectedCode ?? "Missing expected code"
                    )
                }
            }
        }

    func testValidationOfvalidClientMetadataBeingSuccessful() {
        let testCases: [TestCase] = [
            TestCase(input: """
                {
                    "client_name": "Valid Client",
                    "logo_uri": "https://example.com/logo.png",
                    "authorization_encrypted_response_alg": "RSA-OAEP",
                    "authorization_encrypted_response_enc": "A256GCM",
                    "vp_formats": { "format1": { "type1": ["value1"] } },
                    "jwks": { "keys": [{ "kty": "RSA", "crv": "P-256", "use": "sig", "alg": "RS256", "kid": "1", "x": "ur76rg" }] }
                }
            """.data(using: .utf8)!),
            TestCase(input: """
                {
                    "client_name": "Valid Client",
                    "logo_uri": "https://example.com/logo.png",
                    "authorization_encrypted_response_alg": "RSA-OAEP",
                    "authorization_encrypted_response_enc": "A256GCM",
                    "vp_formats": { "format1": { "type1": ["value1"] } },
                    "jwks": { "keys": [] }
                }
            """.data(using: .utf8)!)
        ]

        for testCase in testCases {
            XCTAssertNoThrow(try ClientMetadataDraft23.deserializeAndValidate(clientMetadata: testCase.input))
        }
    }

    func testDraft23IgnoresUnusableEncryptionKeys() throws {
        let input = """
        {
            "client_name": "Test Client",
            "logo_uri": "https://example.com/logo.png",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM",
            "vp_formats": { "ldp_vp": { "proof_type_values": ["Ed25519Signature2020"] } },
            "jwks": \(mixedJwks)
        }
        """.data(using: .utf8)!

        let metadata = try ClientMetadataDraft23.deserializeAndValidate(clientMetadata: input)

        XCTAssertEqual(metadata.jwks?.keys.count, 1)
        XCTAssertEqual(metadata.jwks?.keys.first?.keyID, "valid-enc-key")
    }
}
