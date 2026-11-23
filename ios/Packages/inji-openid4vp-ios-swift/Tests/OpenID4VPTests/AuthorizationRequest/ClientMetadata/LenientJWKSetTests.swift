import XCTest
@testable import OpenID4VP

final class LenientJWKSetTests: XCTestCase {

    private let validJwks = """
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
            }
        ]
    }
    """

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

    func testParsesValidJwks() throws {
        let decoded = try JSONDecoder().decode(LenientJWKSet.self, from: validJwks.data(using: .utf8)!)

        XCTAssertEqual(decoded.keys.count, 1)
        XCTAssertEqual(decoded.jwkSet.keys.first?.keyID, "valid-enc-key")
    }

    func testIgnoresUnusableKeysAndKeepsValidOnes() throws {
        let decoded = try JSONDecoder().decode(LenientJWKSet.self, from: mixedJwks.data(using: .utf8)!)

        XCTAssertEqual(decoded.keys.count, 1)
        XCTAssertEqual(decoded.jwkSet.keys.first?.keyID, "valid-enc-key")
    }

    func testDefaultsToEmptyKeysWhenKeysArrayMissing() throws {
        let decoded = try JSONDecoder().decode(LenientJWKSet.self, from: "{}".data(using: .utf8)!)

        XCTAssertTrue(decoded.keys.isEmpty)
    }
}
