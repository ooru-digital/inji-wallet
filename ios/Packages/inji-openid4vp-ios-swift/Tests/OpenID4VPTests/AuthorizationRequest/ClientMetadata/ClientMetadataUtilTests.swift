import XCTest
@testable import OpenID4VP

final class ClientMetadataUtilTests: XCTestCase {
    private let clientMetadataKey = AuthorizationRequestFieldConstants.clientMetadata.rawValue
    private let responseModeKey = AuthorizationRequestFieldConstants.responseMode.rawValue
    
    func testParsingOfClientMetadataAvailableAsString() throws {
        let clientMetadataString = """
                {
                    "client_name": "Valid Client",
                    "logo_uri": "https://example.com/logo.png",
                    "authorization_encrypted_response_alg": "RSA-OAEP",
                    "authorization_encrypted_response_enc": "A256GCM",
                    "vp_formats": { "format1": { "type1": ["value1"] } },
                    "jwks": { "keys": [{ "kty": "RSA", "crv": "P-256", "use": "sig", "alg": "RS256", "kid": "1", "x": "ur76rg" }] }
                }
            """
        
        let authorizationRequest = createAuthorizationRequest(clientMetadata: clientMetadataString)
        
        let updatedAuthorizationRequest = try parseAndValidateClientMetadata(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletMetadata: nil)
        
        XCTAssertNotNil(updatedAuthorizationRequest[clientMetadataKey])
        assertJsonString(expected: clientMetadataString, actual: convertToJsonString(updatedAuthorizationRequest[clientMetadataKey] as! ClientMetadata))
    }
    
    func testParsingOfClientMetadataAvailableAsDictionary() throws {
        let clientMetadataDict: [String: Any] = [
            "client_name": "Valid Client",
            "logo_uri": "https://example.com/logo.png",
            "authorization_encrypted_response_alg": "RSA-OAEP",
            "authorization_encrypted_response_enc": "A256GCM",
            "vp_formats": ["format1": ["type1": ["value1"]]],
            "jwks": ["keys": [["kty": "RSA", "crv": "P-256", "use": "sig", "alg": "RS256", "kid": "1", "x": "ur76rg"]]]
        ]
        let authorizationRequest = createAuthorizationRequest(clientMetadata: clientMetadataDict)
        
        let updatedAuthorizationRequest = try parseAndValidateClientMetadata(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletMetadata: nil)
        
        XCTAssertNotNil(updatedAuthorizationRequest[clientMetadataKey])
        // performing force unwrap here as we know the type is ClientMetadata for sure
        assertDictionariesEqual(expected: clientMetadataDict, actual: convertToDictionary(object: updatedAuthorizationRequest[clientMetadataKey] as! ClientMetadata))
    }
    
    func testParsingOfClientMetadataWhenClientMetadataAvailableButNotOfExpectedType() throws {
        let authorizationRequest = createAuthorizationRequest(clientMetadata: 12345) // Invalid type for client metadata, accepted - string / map
        XCTAssertThrowsError(try parseAndValidateClientMetadata(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletMetadata: nil)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "client_metadata must be of type String or Map",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testParsingOfClientMetadataNotThrowErrorWhenClientMetadataNotPresentAndResponseModeIsDirectPost() throws {
        let authorizationRequest = createAuthorizationRequest()
        
        XCTAssertNoThrowAndVerify(try parseAndValidateClientMetadata(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletMetadata: nil)) { result in
            XCTAssertNil(result[clientMetadataKey], "Client metadata should not be present when not provided")
        }
    }
    
    // In case of response mode direct_post_jwt, client_metadata is mandatory as the response will be signed which required shared key information available in client_metadata.
    func testParsingOfClientMetadataThrowErrorWhenClientMetadataNotPresentAndResponseModeIsDirectPostJwt() throws {
        let authorizationRequest = createAuthorizationRequest(responseMode: ResponseMode.directPostJwt.rawValue)
        
        XCTAssertThrowsError(try parseAndValidateClientMetadata(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletMetadata: nil)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "client_metadata must be present for given response mode",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
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

