import XCTest
@testable import OpenID4VP

final class VPFormatSupportedTests: XCTestCase {

    // MARK: - LdpVcFormatSupported init

    func testLdpVcFormatSupportedDefaultInit() {
        let ldp = LdpVpFormatSupported()
        XCTAssertEqual(ldp.proofTypeValues, [.ed25519Signature2020, .jsonWebSignature2020])
        XCTAssertNil(ldp.cryptoSuiteValues)
    }

    func testLdpVcFormatSupportedCustomInit() {
        let ldp = LdpVpFormatSupported(proofTypeValues: [.ed25519Signature2020], cryptoSuiteValues: ["suite1"])
        XCTAssertEqual(ldp.proofTypeValues, [.ed25519Signature2020])
        XCTAssertEqual(ldp.cryptoSuiteValues, ["suite1"])
    }

    // MARK: - LdpVcFormatSupported decode

    func testLdpVcFormatSupportedDecodesValidProofTypes() throws {
        let json = """
        {"proof_type_values": ["Ed25519Signature2020", "JsonWebSignature2020"]}
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(LdpVpFormatSupported.self, from: json)
        XCTAssertEqual(decoded.proofTypeValues, [.ed25519Signature2020, .jsonWebSignature2020])
    }

    func testLdpVcFormatSupportedFiltersUnknownProofTypes() throws {
        let json = """
        {"proof_type_values": ["Ed25519Signature2020", "UnknownType", "JsonWebSignature2020"]}
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(LdpVpFormatSupported.self, from: json)
        XCTAssertEqual(decoded.proofTypeValues, [.ed25519Signature2020, .jsonWebSignature2020])
    }

    func testLdpVcFormatSupportedSetsNilWhenAllProofTypesUnknown() throws {
        let json = """
        {"proof_type_values": ["UnknownType1", "UnknownType2"]}
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(LdpVpFormatSupported.self, from: json)
        XCTAssertNil(decoded.proofTypeValues)
    }

    func testLdpVcFormatSupportedSetsNilWhenProofTypesKeyAbsent() throws {
        let json = """
        {}
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(LdpVpFormatSupported.self, from: json)
        XCTAssertNil(decoded.proofTypeValues)
    }

    func testLdpVcFormatSupportedDecodesCryptoSuiteValues() throws {
        let json = """
        {"proof_type_values": ["Ed25519Signature2020"], "cryptosuite_values": ["suite1", "suite2"]}
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(LdpVpFormatSupported.self, from: json)
        XCTAssertEqual(decoded.cryptoSuiteValues, ["suite1", "suite2"])
    }

    func testLdpVcFormatSupportedDecodesNilCryptoSuiteValuesWhenAbsent() throws {
        let json = """
        {"proof_type_values": ["Ed25519Signature2020"]}
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(LdpVpFormatSupported.self, from: json)
        XCTAssertNil(decoded.cryptoSuiteValues)
    }

    // MARK: - LdpVcFormatSupported encode

    func testLdpVcFormatSupportedEncodesProofTypeValues() throws {
        let ldp = LdpVpFormatSupported(proofTypeValues: [.ed25519Signature2020])
        let data = try JSONEncoder().encode(ldp)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let proofTypes = json["proof_type_values"] as! [String]
        XCTAssertEqual(proofTypes, ["Ed25519Signature2020"])
    }

    func testLdpVcFormatSupportedEncodesCryptoSuiteValues() throws {
        let ldp = LdpVpFormatSupported(proofTypeValues: [.ed25519Signature2020], cryptoSuiteValues: ["suite1"])
        let data = try JSONEncoder().encode(ldp)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertEqual(json["cryptosuite_values"] as! [String], ["suite1"])
    }

    func testLdpVcFormatSupportedOmitsCryptoSuiteValuesWhenNil() throws {
        let ldp = LdpVpFormatSupported(proofTypeValues: [.ed25519Signature2020], cryptoSuiteValues: nil)
        let data = try JSONEncoder().encode(ldp)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertNil(json["cryptosuite_values"])
    }

    // MARK: - LdpVcFormatSupported toAlgValuesSupported

    func testLdpVcFormatSupportedToAlgValuesSupportedReturnsRawValues() {
        let ldp = LdpVpFormatSupported(proofTypeValues: [.ed25519Signature2020, .jsonWebSignature2020])
        XCTAssertEqual(ldp.toAlgValuesSupported(), ["Ed25519Signature2020", "JsonWebSignature2020"])
    }

    func testLdpVcFormatSupportedToAlgValuesSupportedReturnsNilWhenProofTypesNil() {
        let ldp = LdpVpFormatSupported(proofTypeValues: [], cryptoSuiteValues: nil)
        let ldpWithNilProofTypes = LdpVpFormatSupported(proofTypeValues: nil)
        XCTAssertNil(ldpWithNilProofTypes.toAlgValuesSupported())
        _ = ldp
    }

    // MARK: - MsoMdocVcFormatSupported init

    func testMsoMdocVcFormatSupportedDefaultInit() {
        let mdoc = MsoMdocVpFormatSupported()
        XCTAssertNil(mdoc.issuerAuthAlgValues)
        XCTAssertNil(mdoc.deviceAuthAlgValues)
    }

    func testMsoMdocVcFormatSupportedCustomInit() {
        let mdoc = MsoMdocVpFormatSupported(issuerAuthAlgValues: [-7], deviceAuthAlgValues: [-9])
        XCTAssertEqual(mdoc.issuerAuthAlgValues, [-7])
        XCTAssertEqual(mdoc.deviceAuthAlgValues, [-9])
    }

    // MARK: - MsoMdocVcFormatSupported toAlgValuesSupported

    func testMsoMdocVcFormatSupportedToAlgValuesSupportedMapsKnownCoseAlgs() {
        let mdoc = MsoMdocVpFormatSupported(issuerAuthAlgValues: [-7], deviceAuthAlgValues: [-7, -9])
        XCTAssertEqual(mdoc.toAlgValuesSupported(), ["ES256", "ESP256"])
    }

    func testMsoMdocVcFormatSupportedToAlgValuesSupportedMapsUnknownCoseAlgToLabel() {
        let mdoc = MsoMdocVpFormatSupported(deviceAuthAlgValues: [-99])
        XCTAssertEqual(mdoc.toAlgValuesSupported(), ["Unknown(-99)"])
    }

    func testMsoMdocVcFormatSupportedToAlgValuesSupportedReturnsNilWhenDeviceAuthNil() {
        let mdoc = MsoMdocVpFormatSupported(issuerAuthAlgValues: [-7], deviceAuthAlgValues: nil)
        XCTAssertNil(mdoc.toAlgValuesSupported())
    }

    func testMsoMdocVcFormatSupportedToAlgValuesSupportedReturnsNilWhenBothNil() {
        let mdoc = MsoMdocVpFormatSupported()
        XCTAssertNil(mdoc.toAlgValuesSupported())
    }

    // MARK: - MsoMdocVcFormatSupported encode / decode

    func testMsoMdocVcFormatSupportedEncodesAndDecodes() throws {
        let mdoc = MsoMdocVpFormatSupported(issuerAuthAlgValues: [-7], deviceAuthAlgValues: [-9])
        let data = try JSONEncoder().encode(mdoc)
        let decoded = try JSONDecoder().decode(MsoMdocVpFormatSupported.self, from: data)
        XCTAssertEqual(decoded.issuerAuthAlgValues, [-7])
        XCTAssertEqual(decoded.deviceAuthAlgValues, [-9])
    }

    func testMsoMdocVcFormatSupportedDecodesNilsWhenKeysAbsent() throws {
        let json = "{}".data(using: .utf8)!
        let decoded = try JSONDecoder().decode(MsoMdocVpFormatSupported.self, from: json)
        XCTAssertNil(decoded.issuerAuthAlgValues)
        XCTAssertNil(decoded.deviceAuthAlgValues)
    }

    // MARK: - SdJwtVcFormatSupported init

    func testSdJwtVcFormatSupportedDefaultInit() {
        let sdJwt = SdJwtVpFormatSupported()
        XCTAssertNil(sdJwt.sdJwtAlgValues)
        XCTAssertNil(sdJwt.kbJwtAlgValues)
    }

    func testSdJwtVcFormatSupportedCustomInit() {
        let sdJwt = SdJwtVpFormatSupported(sdJwtAlgValues: ["ES256"], kbJwtAlgValues: ["EdDSA"])
        XCTAssertEqual(sdJwt.sdJwtAlgValues, ["ES256"])
        XCTAssertEqual(sdJwt.kbJwtAlgValues, ["EdDSA"])
    }

    // MARK: - SdJwtVcFormatSupported toAlgValuesSupported

    func testSdJwtVcFormatSupportedToAlgValuesSupportedReturnsKbJwtAlgValues() {
        let sdJwt = SdJwtVpFormatSupported(sdJwtAlgValues: ["ES256"], kbJwtAlgValues: ["EdDSA"])
        XCTAssertEqual(sdJwt.toAlgValuesSupported(), ["EdDSA"])
    }

    func testSdJwtVcFormatSupportedToAlgValuesSupportedReturnsNilWhenKbJwtNil() {
        let sdJwt = SdJwtVpFormatSupported(sdJwtAlgValues: ["ES256"], kbJwtAlgValues: nil)
        XCTAssertNil(sdJwt.toAlgValuesSupported())
    }

    func testSdJwtVcFormatSupportedToAlgValuesSupportedIgnoresSdJwtAlgValues() {
        let sdJwt = SdJwtVpFormatSupported(sdJwtAlgValues: ["ES256"], kbJwtAlgValues: nil)
        XCTAssertNil(sdJwt.toAlgValuesSupported())
    }

    // MARK: - SdJwtVcFormatSupported encode / decode

    func testSdJwtVcFormatSupportedEncodesAndDecodes() throws {
        let sdJwt = SdJwtVpFormatSupported(sdJwtAlgValues: ["ES256"], kbJwtAlgValues: ["EdDSA"])
        let data = try JSONEncoder().encode(sdJwt)
        let decoded = try JSONDecoder().decode(SdJwtVpFormatSupported.self, from: data)
        XCTAssertEqual(decoded.sdJwtAlgValues, ["ES256"])
        XCTAssertEqual(decoded.kbJwtAlgValues, ["EdDSA"])
    }

    func testSdJwtVcFormatSupportedDecodesNilsWhenKeysAbsent() throws {
        let json = "{}".data(using: .utf8)!
        let decoded = try JSONDecoder().decode(SdJwtVpFormatSupported.self, from: json)
        XCTAssertNil(decoded.sdJwtAlgValues)
        XCTAssertNil(decoded.kbJwtAlgValues)
    }

    func testSdJwtVcFormatSupportedUsesCorrectCodingKeys() throws {
        let json = """
        {"sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["EdDSA"]}
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(SdJwtVpFormatSupported.self, from: json)
        XCTAssertEqual(decoded.sdJwtAlgValues, ["ES256"])
        XCTAssertEqual(decoded.kbJwtAlgValues, ["EdDSA"])
    }
}
