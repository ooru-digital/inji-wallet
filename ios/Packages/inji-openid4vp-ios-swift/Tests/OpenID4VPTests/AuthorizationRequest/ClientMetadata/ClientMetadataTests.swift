import XCTest
@testable import OpenID4VP

final class ClientMetadataTests: XCTestCase {

    private let validJwks = """
    {"keys": [{"kty": "EC", "use": "enc", "alg": "ECDH-ES", "kid": "1", "crv": "P-256", "x": "ur76rg", "y": "ur76rg"}]}
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

    // MARK: - init (memberwise)

    func testInitStoresAllFields() {
        let ldp = LdpVpFormatSupported(proofTypeValues: [.ed25519Signature2020])
        let metadata = ClientMetadata(
            clientName: "Client",
            logoUri: "https://example.com/logo.png",
            vpFormatsSupported: ["ldp_vc": ldp],
            authorizationEncryptedResponseAlg: "ECDH-ES",
            encryptedResponseEncValuesSupported: ["A256GCM"],
            jwks: nil
        )
        XCTAssertEqual(metadata.clientName, "Client")
        XCTAssertEqual(metadata.logoUri, "https://example.com/logo.png")
        XCTAssertEqual(metadata.vpFormatsSupported.count, 1)
        XCTAssertEqual(metadata.encryptedResponseEncValuesSupported, ["A256GCM"])
        XCTAssertNil(metadata.jwks)
    }

    func testInitAllOptionalFieldsNil() {
        let metadata = ClientMetadata(
            vpFormatsSupported: [:]
        )
        XCTAssertNil(metadata.clientName)
        XCTAssertNil(metadata.logoUri)
        XCTAssertNil(metadata.encryptedResponseEncValuesSupported)
        XCTAssertNil(metadata.jwks)
    }

    // MARK: - init(from decoder)

    func testDecodeAllFields() throws {
        let data = json(jwks: validJwks)
        let decoded = try JSONDecoder().decode(ClientMetadata.self, from: data)
        XCTAssertEqual(decoded.clientName, "Test Client")
        XCTAssertEqual(decoded.logoUri, "https://example.com/logo.png")
        XCTAssertEqual(decoded.encryptedResponseEncValuesSupported, ["A256GCM"])
        XCTAssertNotNil(decoded.jwks)
        XCTAssertEqual(decoded.vpFormatsSupported.count, 1)
        XCTAssertNotNil(decoded.vpFormatsSupported["ldp_vc"] as? LdpVpFormatSupported)
    }

    func testDecodeOptionalFieldsAbsent() throws {
        let data = "{ \"vp_formats_supported\": {\"ldp_vc\": {}} }".data(using: .utf8)!
        let decoded = try JSONDecoder().decode(ClientMetadata.self, from: data)
        XCTAssertNil(decoded.clientName)
        XCTAssertNil(decoded.logoUri)
        XCTAssertNil(decoded.encryptedResponseEncValuesSupported)
        XCTAssertNil(decoded.jwks)
    }

    func testDecodeVpFormatsSupportedLdpVc() throws {
        let data = json()
        let decoded = try JSONDecoder().decode(ClientMetadata.self, from: data)
        let ldp = decoded.vpFormatsSupported["ldp_vc"] as? LdpVpFormatSupported
        XCTAssertNotNil(ldp)
        XCTAssertEqual(ldp?.proofTypeValues, [.ed25519Signature2020])
    }

    func testDecodeVpFormatsSupportedLdpVp() throws {
        let data = json(vpFormatsSupported: """
        {"ldp_vp": {"proof_type_values": ["JsonWebSignature2020"]}}
        """)
        let decoded = try JSONDecoder().decode(ClientMetadata.self, from: data)
        XCTAssertNotNil(decoded.vpFormatsSupported["ldp_vp"] as? LdpVpFormatSupported)
    }

    func testDecodeVpFormatsSupportedMsoMdoc() throws {
        let data = json(vpFormatsSupported: """
        {"mso_mdoc": {"issuerauth_alg_values": [-7], "deviceauth_alg_values": [-9]}}
        """)
        let decoded = try JSONDecoder().decode(ClientMetadata.self, from: data)
        let mdoc = decoded.vpFormatsSupported["mso_mdoc"] as? MsoMdocVpFormatSupported
        XCTAssertNotNil(mdoc)
        XCTAssertEqual(mdoc?.issuerAuthAlgValues, [-7])
        XCTAssertEqual(mdoc?.deviceAuthAlgValues, [-9])
    }

    func testDecodeVpFormatsSupportedDcSdJwt() throws {
        let data = json(vpFormatsSupported: """
        {"dc+sd-jwt": {"sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["EdDSA"]}}
        """)
        let decoded = try JSONDecoder().decode(ClientMetadata.self, from: data)
        let sdJwt = decoded.vpFormatsSupported["dc+sd-jwt"] as? SdJwtVpFormatSupported
        XCTAssertNotNil(sdJwt)
        XCTAssertEqual(sdJwt?.sdJwtAlgValues, ["ES256"])
        XCTAssertEqual(sdJwt?.kbJwtAlgValues, ["EdDSA"])
    }

    func testDecodeVpFormatsSupportedVcSdJwt() throws {
        let data = json(vpFormatsSupported: """
        {"vc+sd-jwt": {"sd-jwt_alg_values": ["ES256"]}}
        """)
        let decoded = try JSONDecoder().decode(ClientMetadata.self, from: data)
        XCTAssertNotNil(decoded.vpFormatsSupported["vc+sd-jwt"] as? SdJwtVpFormatSupported)
    }

    // MARK: - encode(to encoder)

    func testEncodeAndDecode() throws {
        let ldp = LdpVpFormatSupported(proofTypeValues: [.ed25519Signature2020])
        let original = ClientMetadata(
            clientName: "Client",
            logoUri: "https://example.com/logo.png",
            vpFormatsSupported: ["ldp_vc": ldp],
            encryptedResponseEncValuesSupported: ["A256GCM"],
            jwks: nil
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(ClientMetadata.self, from: data)
        XCTAssertEqual(decoded.clientName, original.clientName)
        XCTAssertEqual(decoded.logoUri, original.logoUri)
        XCTAssertEqual(decoded.encryptedResponseEncValuesSupported, original.encryptedResponseEncValuesSupported)
        XCTAssertEqual(decoded.vpFormatsSupported.count, original.vpFormatsSupported.count)
    }

    func testEncodeOmitsNilOptionalFields() throws {
        let metadata = ClientMetadata(
            vpFormatsSupported: ["ldp_vc": LdpVpFormatSupported()]
        )
        let data = try JSONEncoder().encode(metadata)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertNil(json["client_name"])
        XCTAssertNil(json["logo_uri"])
        XCTAssertNil(json["authorization_encrypted_response_alg"])
        XCTAssertNil(json["encrypted_response_enc_values_supported"])
        XCTAssertNil(json["jwks"])
    }

    func testEncodeVpFormatsSupportedSkipsUnknownFormatType() throws {
        let metadata = ClientMetadata(
            vpFormatsSupported: ["unknown_format": LdpVpFormatSupported()]
        )
        let data = try JSONEncoder().encode(metadata)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let vpFormats = json["vp_formats_supported"] as! [String: Any]
        XCTAssertTrue(vpFormats.isEmpty)
    }

    func testEncodeVpFormatsSupportedMsoMdoc() throws {
        let mdoc = MsoMdocVpFormatSupported(issuerAuthAlgValues: [-7], deviceAuthAlgValues: [-9])
        let metadata = ClientMetadata(
            vpFormatsSupported: ["mso_mdoc": mdoc]
        )
        let data = try JSONEncoder().encode(metadata)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let vpFormats = json["vp_formats_supported"] as! [String: Any]
        XCTAssertNotNil(vpFormats["mso_mdoc"])
    }

    func testEncodeVpFormatsSupportedSdJwt() throws {
        let sdJwt = SdJwtVpFormatSupported(sdJwtAlgValues: ["ES256"], kbJwtAlgValues: ["EdDSA"])
        let metadata = ClientMetadata(
            vpFormatsSupported: ["dc+sd-jwt": sdJwt]
        )
        let data = try JSONEncoder().encode(metadata)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let vpFormats = json["vp_formats_supported"] as! [String: Any]
        XCTAssertNotNil(vpFormats["dc+sd-jwt"])
    }

    // MARK: - deserializeAndValidate(clientMetadata: Data)

    func testDeserializeAndValidateWithData() throws {
        let data = json()
        let result = try ClientMetadata.deserializeAndValidate(clientMetadata: data)
        XCTAssertEqual(result.clientName, "Test Client")
    }

    // MARK: - deserializeAndValidate(clientMetadata: String)

    func testDeserializeAndValidateWithString() throws {
        let jsonString = String(data: json(), encoding: .utf8)!
        let result = try ClientMetadata.deserializeAndValidate(clientMetadata: jsonString)
        XCTAssertEqual(result.clientName, "Test Client")
    }

    func testDeserializeAndValidateWithStringThrowsOnInvalidUTF8() {
        XCTAssertThrowsError(
            try ClientMetadata.deserializeAndValidate(clientMetadata: 12345)
        )
    }

    func testDeserializeAndValidateThrowsForInvalidType() {
        XCTAssertThrowsError(
            try ClientMetadata.deserializeAndValidate(clientMetadata: 12345)
        )
    }
    
    
    // MARK: - vp_formats_supported empty validation

    func testDecodeThrowsWhenVpFormatsSupportedIsEmpty() {
        let data = json(vpFormatsSupported: "{}")
        XCTAssertThrowsError(try JSONDecoder().decode(ClientMetadata.self, from: data)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Error during client metadata decoding - vp_formats_supported cannot be empty in client metadata",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testDeserializeAndValidateWithDataThrowsWhenVpFormatsSupportedIsEmpty() {
        let data = json(vpFormatsSupported: "{}")
        XCTAssertThrowsError(try ClientMetadata.deserializeAndValidate(clientMetadata: data)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Error during client metadata decoding - vp_formats_supported cannot be empty in client metadata",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testDeserializeAndValidateWithStringThrowsWhenVpFormatsSupportedIsEmpty() {
        let jsonString = String(data: json(vpFormatsSupported: "{}"), encoding: .utf8)!
        XCTAssertThrowsError(try ClientMetadata.deserializeAndValidate(clientMetadata: jsonString)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Error during client metadata decoding - vp_formats_supported cannot be empty in client metadata",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - jwks decoding

    func testV1IgnoresUnusableEncryptionKeys() throws {
        let data = json(jwks: mixedJwks)

        let decoded = try JSONDecoder().decode(ClientMetadata.self, from: data)

        XCTAssertEqual(decoded.jwks?.keys.count, 1)
        XCTAssertEqual(decoded.jwks?.keys.first?.keyID, "valid-enc-key")
    }

    func testV1RejectsExplicitNullJwks() {
        let data = json(jwks: "null")

        XCTAssertThrowsError(try JSONDecoder().decode(ClientMetadata.self, from: data))
    }

    // MARK: - Helper methods

    private func json(
        clientName: String? = "\"Test Client\"",
        logoUri: String? = "\"https://example.com/logo.png\"",
        vpFormatsSupported: String = """
        {"ldp_vc": {"proof_type_values": ["Ed25519Signature2020"]}}
        """,
        authorizationEncryptedResponseEncValues: String? = "[\"A256GCM\"]",
        jwks: String? = nil
    ) -> Data {
        let jwksField = jwks.map { "\"jwks\": \($0)" } ?? "\"jwks\": {\"keys\": []}"
        let fields: [String] = [
            clientName.map { "\"client_name\": \($0)" },
            logoUri.map { "\"logo_uri\": \($0)" },
            "\"vp_formats_supported\": \(vpFormatsSupported)",
            authorizationEncryptedResponseEncValues.map { "\"encrypted_response_enc_values_supported\": \($0)" },
            jwksField
        ].compactMap { $0 }
        return "{\(fields.joined(separator: ", "))}".data(using: .utf8)!
    }
}
