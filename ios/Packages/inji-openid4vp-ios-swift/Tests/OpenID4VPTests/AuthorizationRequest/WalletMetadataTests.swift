import XCTest
@testable import OpenID4VP

final class WalletMetadataTests: XCTestCase {
    let vpFormatsRaw: [String: VPFormatSupported] = [
        "ldp_vc": VPFormatSupported(algValuesSupported: ["Ed25519Signature2018"])
    ]
    let vpFormats: [VPFormatType: VPFormatSupported] = [
        .ldp_vc : VPFormatSupported(algValuesSupported: ["Ed25519Signature2018"])
    ]
    let clientIdSchemesSupportedRaw: [String] = [
        "pre-registered",
        "redirect_uri",
        "did"
    ]
    let requestObjectSigningAlgValuesSupportedRaw: [String] = ["EdDSA"]
    let authorizationEncryptionAlgValuesSupportedRaw: [String] = ["ECDH-ES"]
    let authorizationEncryptionEncValuesSupportedRaw: [String] = ["A256GCM"]
    
    func testValidWalletMetadataInitialization() throws {
        do{
            let metadata = try WalletMetadata(
                presentationDefinitionURISupported: true,
                vpFormatsSupported: vpFormatsRaw,
                clientIdSchemesSupported: clientIdSchemesSupportedRaw,
                requestObjectSigningAlgValuesSupported: requestObjectSigningAlgValuesSupportedRaw,
                authorizationEncryptionAlgValuesSupported: authorizationEncryptionAlgValuesSupportedRaw,
                authorizationEncryptionEncValuesSupported: authorizationEncryptionEncValuesSupportedRaw
            )
            
            XCTAssertTrue(metadata.presentationDefinitionURISupported)
            XCTAssertEqual(metadata.vpFormatsSupported.count, 1)

        } catch {
            XCTFail("WalletMetadata initialization failed with error: \(error)")
        }
    }
    
    func testWalletMetadataThrowsForEmptyVPFormatsSupported() {
        XCTAssertThrowsError(try WalletMetadata(
            presentationDefinitionURISupported: nil,
            vpFormatsSupported: [:],
            clientIdSchemesSupported: nil
        )) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "vp_formats_supported should at least have one supported vp_format",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testWalletMetadataThrowsErrorForVPFOrmatsSupportedWithEmptyKey() {
        XCTAssertThrowsError(try WalletMetadata(
            presentationDefinitionURISupported: nil,
            vpFormatsSupported: ["": VPFormatSupported(algValuesSupported: ["Ed25519Signature2018"])],
            clientIdSchemesSupported: nil
        )) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "vp_formats_supported cannot have empty keys.",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testWalletMetadataThrowsErrorForVPFormatsSupportedPassingWithNotSupportedLibraryVPFormat() {
        XCTAssertThrowsError(try WalletMetadata(
            presentationDefinitionURISupported: nil,
            vpFormatsSupported: ["sd-jwt": VPFormatSupported(algValuesSupported: ["Ed25519Signature2018"])],
            clientIdSchemesSupported: nil
        )) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Invalid VPFormatType value: sd-jwt. Its is not supported by the library.",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testWalletMetadataThrowsErrorForClientIdSchemesWithUnsupportedValue() {
        XCTAssertThrowsError(try WalletMetadata(
            presentationDefinitionURISupported: nil,
            vpFormatsSupported: vpFormatsRaw,
            clientIdSchemesSupported: ["https"]
        )) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Invalid ClientIdScheme value: https. Its is not supported by the library.",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testWalletMetadataThrowsErrorForRequestObjectSigningAlgWithUnsupportedValue() {
        XCTAssertThrowsError(try WalletMetadata(
            presentationDefinitionURISupported: nil,
            vpFormatsSupported: vpFormatsRaw,
            clientIdSchemesSupported: nil,
            requestObjectSigningAlgValuesSupported: ["EdDSA", "ES256"]
        )) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Invalid RequestSigningAlgorithm value: ES256. Its is not supported by the library.",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testWalletMetadataThrowsErrorForAuthorizationEncryptionAlgWithUnsupportedValue() {
        XCTAssertThrowsError(try WalletMetadata(
            presentationDefinitionURISupported: nil,
            vpFormatsSupported: vpFormatsRaw,
            clientIdSchemesSupported: nil,
            requestObjectSigningAlgValuesSupported: nil,
            authorizationEncryptionAlgValuesSupported: ["ECDH-ES", "ECDH-ES+A128"]
        )) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Invalid KeyManagementAlgorithm value: ECDH-ES+A128. Its is not supported by the library.",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testWalletMetadataThrowsErrorForAuthorizationEncryptionEncWithUnsupportedValue() {
        XCTAssertThrowsError(try WalletMetadata(
            presentationDefinitionURISupported: nil,
            vpFormatsSupported: vpFormatsRaw,
            clientIdSchemesSupported: nil,
            requestObjectSigningAlgValuesSupported: nil,
            authorizationEncryptionAlgValuesSupported: nil,
            authorizationEncryptionEncValuesSupported: ["A128GCM", "A256GCM"]
        )) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Invalid ContentEncryptionAlgorithm value: A128GCM. Its is not supported by the library.",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    
    func testWalletMetadataWithNilOptionals() throws {
        let metadata = try WalletMetadata(
            presentationDefinitionURISupported: nil,
            vpFormatsSupported: vpFormatsRaw,
            clientIdSchemesSupported: nil
        )
        let walletMetadata = try createWalletMetadataV1(presentationDefinitionURISupported: true, vpFormatsSupported: vpFormatsRaw,
                                                        clientIdSchemesSupported: [ClientIdScheme.preRegistered.rawValue], requestObjectSigningAlgValuesSupported: nil, authorizationEncryptionAlgValuesSupported: nil, authorizationEncryptionEncValuesSupported: nil)
        
        assertDictionariesEqual(expected: convertToDictionary(object: walletMetadata)!, actual: convertToDictionary(object: metadata))
        XCTAssertNil(metadata.requestObjectSigningAlgValuesSupported)
        XCTAssertNil(metadata.authorizationEncryptionAlgValuesSupported)
        XCTAssertNil(metadata.authorizationEncryptionEncValuesSupported)
    }
    
    func testWalletMetadataDefaults() throws {
        let metadata = try WalletMetadata()
        
        XCTAssertTrue(metadata.presentationDefinitionURISupported)
        XCTAssertEqual(metadata.requestObjectSigningAlgValuesSupported, [.edDsa])
        XCTAssertEqual(metadata.authorizationEncryptionAlgValuesSupported, [.ecdhEs])
        XCTAssertEqual(metadata.authorizationEncryptionEncValuesSupported, [.A256GCM])
        XCTAssertEqual(metadata.responseTypesSupported, [.vp_token])
        XCTAssertEqual(Set(metadata.clientIdSchemesSupported), Set([.preRegistered, .did, .redirectUri]))
        XCTAssertEqual(Set(metadata.vpFormatsSupported.keys), [.ldp_vc, .ldp_vp, .mso_mdoc])
    }
    
    func testWalletMetadataConstructor() throws {
        let metadata = try WalletMetadata(
            presentationDefinitionURISupported: true,
            vpFormatsSupported: vpFormats,
            clientIdSchemesSupported: [.preRegistered, .redirectUri, .did],
            requestObjectSigningAlgValuesSupported: [.edDsa],
            authorizationEncryptionAlgValuesSupported: [.ecdhEs],
            authorizationEncryptionEncValuesSupported: [.A256GCM]
        )
        
        XCTAssertTrue(metadata.presentationDefinitionURISupported)
        XCTAssertEqual(metadata.vpFormatsSupported.count, 1)
        XCTAssertEqual(metadata.clientIdSchemesSupported.count, 3)
        XCTAssertEqual(metadata.requestObjectSigningAlgValuesSupported, [.edDsa])
        XCTAssertEqual(metadata.authorizationEncryptionAlgValuesSupported, [.ecdhEs])
        XCTAssertEqual(metadata.authorizationEncryptionEncValuesSupported, [.A256GCM])
        
    }
}
