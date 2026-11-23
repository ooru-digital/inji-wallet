import XCTest
@testable import OpenID4VP

final class ClientMetadataUtilTests: XCTestCase {
    private let clientMetadataKey = AuthorizationRequestFieldConstants.clientMetadata
    private let responseModeKey = AuthorizationRequestFieldConstants.responseMode
    
    // Spec version Draft 23 client metadata parsing tests
    func testParsingOfClientMetadataAvailableAsString() throws {
        let clientMetadataString = """
                {
                    "client_name": "Valid Client",
                    "logo_uri": "https://example.com/logo.png",
                    "vp_formats": { "format1": { "type1": ["value1"] } },
                    "jwks": { "keys": [{ "kty": "RSA", "crv": "P-256", "use": "sig", "alg": "RS256", "kid": "1", "x": "ur76rg" }] }
                }
            """
        
        let authorizationRequest = createAuthorizationRequest(clientMetadata: clientMetadataString)
        
        let updatedAuthorizationRequest = try ClientMetadataSpecVersionHandler.of(.draft23).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletConfig: WalletConfig())
        
        XCTAssertNotNil(updatedAuthorizationRequest[clientMetadataKey])
        assertJsonString(expected: clientMetadataString, actual: convertToJsonString(updatedAuthorizationRequest[clientMetadataKey] as! ClientMetadataDraft23))
    }
    
    func testParsingOfClientMetadataAvailableAsDictionary() throws {
        let clientMetadataDict: [String: Any] = [
            "client_name": "Valid Client",
            "logo_uri": "https://example.com/logo.png",
            "vp_formats": ["format1": ["type1": ["value1"]]],
            "jwks": ["keys": [["kty": "RSA", "crv": "P-256", "use": "sig", "alg": "RS256", "kid": "1", "x": "ur76rg"]]]
        ]
        let authorizationRequest = createAuthorizationRequest(clientMetadata: clientMetadataDict)
        
        let updatedAuthorizationRequest = try ClientMetadataSpecVersionHandler.of(.draft23).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletConfig: WalletConfig())
        
        XCTAssertNotNil(updatedAuthorizationRequest[clientMetadataKey])
        // performing force unwrap here as we know the type is ClientMetadata for sure
        assertDictionariesEqual(expected: clientMetadataDict, actual: convertToDictionary(object: updatedAuthorizationRequest[clientMetadataKey] as! ClientMetadataDraft23))
    }
    
    func testParsingOfClientMetadataWhenClientMetadataAvailableButNotOfExpectedType() throws {
        let authorizationRequest = createAuthorizationRequest(clientMetadata: 12345) // Invalid type for client metadata, accepted - string / map
        XCTAssertThrowsError(try ClientMetadataSpecVersionHandler.of(.draft23).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletConfig: WalletConfig())) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "client_metadata must be of type String or Map",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testParsingOfClientMetadataNotThrowErrorWhenClientMetadataNotPresentAndResponseModeIsDirectPost() throws {
        let authorizationRequest = createAuthorizationRequest()
        
        XCTAssertNoThrowAndVerify(try ClientMetadataSpecVersionHandler.of(.draft23).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletConfig: WalletConfig())) { result in
            XCTAssertNil(result[clientMetadataKey], "Client metadata should not be present when not provided")
        }
    }
    
    
    // Spec version v1 client metadata parsing tests

    func testV1ParsingOfClientMetadataAvailableAsString() throws {
        let clientMetadataString = """
            {
                "client_name": "Valid Client",
                "logo_uri": "https://example.com/logo.png",
                "vp_formats_supported": { "ldp_vc": { "proof_type_values": ["Ed25519Signature2020"] } },
                "jwks": { "keys": [{ "kty": "EC", "use": "enc", "alg": "ECDH-ES", "kid": "1", "crv": "P-256", "x": "ur76rg", "y": "ur76rg" }] }
            }
        """

        let authorizationRequest = createAuthorizationRequest(clientMetadata: clientMetadataString)

        let updatedAuthorizationRequest = try ClientMetadataSpecVersionHandler.of(.v1).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletConfig: WalletConfig())

        XCTAssertNotNil(updatedAuthorizationRequest[clientMetadataKey])
        XCTAssertTrue(updatedAuthorizationRequest[clientMetadataKey] is ClientMetadata)
    }

    func testV1ParsingOfClientMetadataAvailableAsDictionary() throws {
        let clientMetadataDict: NSDictionary = [
            "client_name": "Valid Client",
            "logo_uri": "https://example.com/logo.png",
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]],
            "jwks": ["keys": [["kty": "EC", "use": "enc", "alg": "ECDH-ES", "kid": "1", "crv": "P-256", "x": "ur76rg", "y": "ur76rg"]]]
        ]
        let authorizationRequest = createAuthorizationRequest(clientMetadata: clientMetadataDict)

        let updatedAuthorizationRequest = try ClientMetadataSpecVersionHandler.of(.v1).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletConfig: WalletConfig())

        XCTAssertNotNil(updatedAuthorizationRequest[clientMetadataKey])
        XCTAssertTrue(updatedAuthorizationRequest[clientMetadataKey] is ClientMetadata)
    }

    func testV1ParsingOfClientMetadataWhenAlreadyClientMetadataSpecVersion1Instance() throws {
        let clientMetadataInstance = ClientMetadata(
            vpFormatsSupported: ["ldp_vc": LdpVpFormatSupported()]
        )
        let authorizationRequest = createAuthorizationRequest(clientMetadata: clientMetadataInstance)

        let updatedAuthorizationRequest = try ClientMetadataSpecVersionHandler.of(.v1).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletConfig: WalletConfig())

        XCTAssertTrue(updatedAuthorizationRequest[clientMetadataKey] is ClientMetadata)
    }

    func testV1ParsingOfClientMetadataWhenClientMetadataAvailableButNotOfExpectedType() throws {
        let authorizationRequest = createAuthorizationRequest(clientMetadata: 12345)
        XCTAssertThrowsError(try ClientMetadataSpecVersionHandler.of(.v1).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletConfig: WalletConfig())) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "client_metadata must be of type String or Map",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testV1ParsingOfClientMetadataNotThrowErrorWhenClientMetadataNotPresentAndResponseModeIsDirectPost() throws {
        let authorizationRequest = createAuthorizationRequest()

        XCTAssertNoThrowAndVerify(try ClientMetadataSpecVersionHandler.of(.v1).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletConfig: WalletConfig())) { result in
            XCTAssertNil(result[clientMetadataKey], "Client metadata should not be present when not provided")
        }
    }

    
    private func createAuthorizationRequest(clientMetadata: Any? = nil, responseMode: String = ResponseMode.directPost.rawValue) -> [String: Any] {
        if let clientMetadata = clientMetadata {
            return [
                clientMetadataKey: clientMetadata,
                responseModeKey: responseMode
            ]
        }
        
        return [responseModeKey: responseMode]
    }
}
