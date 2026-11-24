import XCTest
import JSONWebKey
@testable import OpenID4VP

final class DirectPostJwtResponseModeHandlerTests: XCTestCase {
    private let directPostJwtResponseModeHandler = DirectPostJwtResponseModeHandler()
    let mockVPTokens = VPTokenType.vpTokenElement(LdpVPToken(context: ["context"], type: ["typ1"], verifiableCredential: [AnyCodable(ldpVC())], id: "identifier", holder: "holder", proof: Proof(type: "Ed25519Signature2018", created: "2021-03-19T15:30:15Z", challenge: "n-0S6_WzA2Mj", domain: "https://client.example.org/cb", jws: "eyJhbG...IAoDA", proofPurpose: .vpProofPurpose, verificationMethod: "did:example:holder#key-1")))
    
    let mockPresentationSubmission = PresentationSubmission(definitionId: "client-identifier", descriptorMap: [DescriptorMap(id: "input_1", format: .ldp_vp, path: "$", pathNested: PathNested(id: "input_1", format: .ldp_vc, path: "$.verifiableCredential[0]"))])
    private let mockNetworkManager = MockNetworkManager()
    private let responseUri = "https://mock-verifier.com"
    
    private var walletConfig: WalletConfig!
    
    override func setUpWithError() throws {
        walletConfig = createWalletConfig()
    }
    
    /// client metadata validation tests
    
    func testThrowErrorWhenClientMetadataIsNil() throws {
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: nil as ClientMetadata?, walletConfig: walletConfig, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("client_metadata must be present for given response mode", error.localizedDescription)
        }
        
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: nil as ClientMetadataDraft23?, walletConfig: walletConfig, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("client_metadata must be present for given response mode", error.localizedDescription)
        }
    }

    func testThrowErrorWhenClientMetadataDoesNotHaveAuthorizationEncryptedResponseAlg() throws {
        let invalidClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_enc": "A256GCM",
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats": [
                "mso_mdoc": ["alg": ["ES256", "EdDSA"]],
                "ldp_vp": ["proof_type": ["Ed25519Signature2018", "Ed25519Signature2020", "RsaSignature2018"]]
            ]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadataDraft23.self), walletConfig: walletConfig, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Missing Input: client_metadata->authorization_encrypted_response_alg param is required", error.localizedDescription)
        }

        let invalidClientMetadataV1: [String: Any] = [
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataV1, as: ClientMetadata.self), walletConfig: walletConfig, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Missing Input: client_metadata->encrypted_response_enc_values_supported param is required", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenClientMetadataDoesNotHaveAuthorizationEncryptedResponseEnc() throws {
        let invalidClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats": [
                "mso_mdoc": ["alg": ["ES256", "EdDSA"]],
                "ldp_vp": ["proof_type": ["Ed25519Signature2018", "Ed25519Signature2020", "RsaSignature2018"]]
            ]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadataDraft23.self), walletConfig: walletConfig, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Missing Input: client_metadata->authorization_encrypted_response_enc param is required", error.localizedDescription)
        }

        let invalidClientMetadataV1: [String: Any] = [
            "authorization_encrypted_response_alg": "ECDH-ES",
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataV1, as: ClientMetadata.self), walletConfig: walletConfig, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Missing Input: client_metadata->encrypted_response_enc_values_supported param is required", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenClientMetadataDoesNotHaveJwks() throws {
        let invalidClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM",
            "vp_formats": [
                "mso_mdoc": ["alg": ["ES256", "EdDSA"]],
                "ldp_vp": ["proof_type": ["Ed25519Signature2018", "Ed25519Signature2020", "RsaSignature2018"]]
            ]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadataDraft23.self), walletConfig: walletConfig, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Missing Input: client_metadata->jwks param is required", error.localizedDescription)
        }

        let invalidClientMetadataV1: [String: Any] = [
            "authorization_encrypted_response_alg": "ECDH-ES",
            "encrypted_response_enc_values_supported": ["A256GCM"],
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataV1, as: ClientMetadata.self), walletConfig: walletConfig, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Missing Input: client_metadata->jwks param is required", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenClientMetadataDoesNotHaveJwkWithAlgorithmMentioned() throws {
        let invalidClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM",
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats": [
                "mso_mdoc": ["alg": ["ES256", "EdDSA"]],
                "ldp_vp": ["proof_type": ["Ed25519Signature2018", "Ed25519Signature2020", "RsaSignature2018"]]
            ]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadataDraft23.self), walletConfig: walletConfig, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("No jwk matching the specified algorithm found for encryption", error.localizedDescription)
        }

        let invalidClientMetadataV1: [String: Any] = [
            "authorization_encrypted_response_alg": "ECDH-ES",
            "encrypted_response_enc_values_supported": ["A256GCM"],
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataV1, as: ClientMetadata.self), walletConfig: walletConfig, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Authorization response encryption algorithm is not supported", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenClientMetadataResponseEncDoesNotMatchWithWalletMetadataResponseEnc() throws {
        let invalidClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A128GCM",
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats": [
                "ldp_vp": ["proof_type": ["Ed25519Signature2018", "Ed25519Signature2020", "RsaSignature2018"]]
            ]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadataDraft23.self), walletConfig: walletConfig, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("authorization_encrypted_response_enc is not supported", error.localizedDescription)
        }

        let invalidClientMetadataV1: [String: Any] = [
            "encrypted_response_enc_values_supported": ["A128GCM"],
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataV1, as: ClientMetadata.self), walletConfig: walletConfig, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("authorization_encrypted_response_enc is not supported", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenClientMetadataResponseAlgDoesNotMatchWithWalletMetadataResponseAlg() throws {
        let invalidClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_alg": "ECDH-AS",
            "authorization_encrypted_response_enc": "A256GCM",
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-AS",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats": [
                "ldp_vp": ["proof_type": ["Ed25519Signature2018", "Ed25519Signature2020", "RsaSignature2018"]]
            ]
        ]

        let mismatchingWalletMetadata = createWalletConfig()

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadataDraft23.self), walletConfig: mismatchingWalletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Authorization response encryption algorithm is not supported", error.localizedDescription)
        }

        let invalidClientMetadataV1: [String: Any] = [
            "authorization_encrypted_response_alg": "ECDH-AS",
            "encrypted_response_enc_values_supported": ["A256GCM"],
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-AS",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataV1, as: ClientMetadata.self), walletConfig: mismatchingWalletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Authorization response encryption algorithm is not supported", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenWalletMetadataIsNilAndIfRequiredValuesAreNil() throws {
        let validClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM",
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats": [
                "ldp_vp": [
                    "proof_type": [
                        "Ed25519Signature2018",
                        "Ed25519Signature2020",
                        "RsaSignature2018"
                    ]
                ]
            ]
        ]

        let validClientMetadataV1: [String: Any] = [
            "authorization_encrypted_response_alg": "ECDH-ES",
            "encrypted_response_enc_values_supported": ["A256GCM"],
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
        ]

        var invalidWalletMetadata = createWalletConfig(authorizationEncryptionAlgValuesSupported: nil)
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(validClientMetadataForDirectPostJwt, as: ClientMetadataDraft23.self), walletConfig: invalidWalletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            assertOpenID4VPException(error, expectedMessage: "authorization_encryption_alg_values_supported must be present in wallet_metadata", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(validClientMetadataV1, as: ClientMetadata.self), walletConfig: invalidWalletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            assertOpenID4VPException(error, expectedMessage: "authorization_encryption_alg_values_supported must be present in wallet_metadata", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }

        invalidWalletMetadata = createWalletConfig(authorizationEncryptionEncValuesSupported: nil)
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(validClientMetadataForDirectPostJwt, as: ClientMetadataDraft23.self), walletConfig: invalidWalletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            assertOpenID4VPException(error, expectedMessage: "authorization_encryption_enc_values_supported must be present in wallet_metadata", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(validClientMetadataV1, as: ClientMetadata.self), walletConfig: invalidWalletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            assertOpenID4VPException(error, expectedMessage: "authorization_encryption_enc_values_supported must be present in wallet_metadata", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }
    
    func testShouldNotThrowErrorForValidClientMetadataOnValidation() {
        XCTAssertNoThrow(try directPostJwtResponseModeHandler.validate(clientMetadata: mockClientMetadataSpecVersionDraft23[.directPostJwt], walletConfig: walletConfig, shouldValidateWithWalletMetadata: true))
        XCTAssertNoThrow(try directPostJwtResponseModeHandler.validate(clientMetadata: mockClientMetadataSpecVersion1[.directPostJwt], walletConfig: walletConfig, shouldValidateWithWalletMetadata: true))
    }

    func testShouldNotThrowErrorWhenShouldValidateWithWalletMetadataIsFalse() {
        XCTAssertNoThrow(try directPostJwtResponseModeHandler.validate(clientMetadata: mockClientMetadataSpecVersionDraft23[.directPostJwt], walletConfig: walletConfig, shouldValidateWithWalletMetadata: false))
        XCTAssertNoThrow(try directPostJwtResponseModeHandler.validate(clientMetadata: mockClientMetadataSpecVersion1[.directPostJwt], walletConfig: walletConfig, shouldValidateWithWalletMetadata: false))
    }

    func testThrowErrorWhenEncValuesIsEmptyArrayForSpecVersion1() throws {
        let invalidClientMetadataV1: [String: Any] = [
            "authorization_encrypted_response_alg": "ECDH-ES",
            "encrypted_response_enc_values_supported": [],
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
        ]
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataV1, as: ClientMetadata.self), walletConfig: walletConfig, shouldValidateWithWalletMetadata: false)) { error in
            assertOpenID4VPException(error, expectedMessage: "encrypted_response_enc_values_supported must be a non-empty array", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    // MARK: - getVerifierPublicKeyForEncryption tests

    func testGetVerifierPublicKeyForEncryptionReturnsDraft23EncKey() throws {
        let handler = DirectPostJwtResponseModeHandler()
        let key = try handler.getVerifierPublicKeyForEncryption(
            authorizationRequest: getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .draft23),
                    walletConfig: walletConfig
        )
        XCTAssertNotNil(key)
        XCTAssertEqual(key?.algorithm, "ECDH-ES")
        XCTAssertEqual(key?.publicKeyUse, .encryption)
    }

    func testGetVerifierPublicKeyForEncryptionReturnsV1EncKey() throws {
        let handler = DirectPostJwtResponseModeHandler()
        let key = try handler.getVerifierPublicKeyForEncryption(
            authorizationRequest: getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .v1),
                    walletConfig: walletConfig
        )
        XCTAssertNotNil(key)
        XCTAssertEqual(key?.publicKeyUse, .encryption)
    }

    func testGetVerifierPublicKeyForEncryptionThrowsWhenV1ClientMetadataIsNil() throws {
        let handler = DirectPostJwtResponseModeHandler()
        let v1Request = getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .v1)
        let requestWithNilMetadata = AuthorizationDcqlRequest(
            clientId: v1Request.clientId, responseType: v1Request.responseType,
            responseMode: v1Request.responseMode, responseUri: v1Request.responseUri,
            redirectUri: v1Request.redirectUri, nonce: v1Request.nonce,
            walletNonce: v1Request.walletNonce, state: v1Request.state,
            dcqlQuery: validDcqlQuery,
            clientMetadata: nil
        )
        XCTAssertThrowsError(try handler.getVerifierPublicKeyForEncryption(
            authorizationRequest: requestWithNilMetadata,         walletConfig: walletConfig
        )) { error in
            assertOpenID4VPException(error,
                expectedMessage: "client_metadata must be present for given response mode",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testGetVerifierPublicKeyForEncryptionThrowsWhenV1JwksIsNil() throws {
        let handler = DirectPostJwtResponseModeHandler()
        let v1Request = getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .v1)
        let requestWithNoJwks = AuthorizationDcqlRequest(
            clientId: v1Request.clientId, responseType: v1Request.responseType,
            responseMode: v1Request.responseMode, responseUri: v1Request.responseUri,
            redirectUri: v1Request.redirectUri, nonce: v1Request.nonce,
            walletNonce: v1Request.walletNonce, state: v1Request.state,
            dcqlQuery: validDcqlQuery,
            clientMetadata: createInstance([
                "encrypted_response_enc_values_supported": ["A256GCM"],
                "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
            ], as: ClientMetadata.self)
        )
        XCTAssertThrowsError(try handler.getVerifierPublicKeyForEncryption(
            authorizationRequest: requestWithNoJwks,         walletConfig: walletConfig
        )) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Missing Input: client_metadata->jwks param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testGetVerifierPublicKeyForEncryptionThrowsWhenNoEncKeyFoundInV1Jwks() throws {
        let handler = DirectPostJwtResponseModeHandler()
        let v1Request = getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .v1)
        let requestWithSigOnlyJwks = AuthorizationDcqlRequest(
            clientId: v1Request.clientId, responseType: v1Request.responseType,
            responseMode: v1Request.responseMode, responseUri: v1Request.responseUri,
            redirectUri: v1Request.redirectUri, nonce: v1Request.nonce,
            walletNonce: v1Request.walletNonce, state: v1Request.state,
            dcqlQuery: validDcqlQuery,
            clientMetadata: createInstance([
                "encrypted_response_enc_values_supported": ["A256GCM"],
                "jwks": ["keys": [["kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": "sig-key", "x": "5tvU4k_TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc"]]],
                "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
            ], as: ClientMetadata.self)
        )
        XCTAssertThrowsError(try handler.getVerifierPublicKeyForEncryption(
            authorizationRequest: requestWithSigOnlyJwks,         walletConfig: walletConfig
        )) { error in
            assertOpenID4VPException(error,
                expectedMessage: "No jwk matching the specified algorithm found for encryption",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorWhenJwksContainsNoEncryptionKey() throws {
           let clientMetadataWithSigOnlyJwks: [String: Any] = [
               "encrypted_response_enc_values_supported": ["A256GCM"],
               "jwks": [
                   "keys": [[
                       "kty": "OKP",
                       "crv": "Ed25519",
                       "use": "sig",
                       "x": "5tvU4k_TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc",
                       "alg": "EdDSA",
                       "kid": "sig-key1"
                   ]]
               ],
               "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
           ]

           XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(
               clientMetadata: createInstance(clientMetadataWithSigOnlyJwks, as: ClientMetadata.self),
               walletConfig: walletConfig,
               shouldValidateWithWalletMetadata: false
           )) { error in
               assertOpenID4VPException(
                   error,
                   expectedMessage: "No jwk matching the specified algorithm found for encryption",
                   expectedCode: OpenID4VPErrorCodes.invalidRequest
               )
           }
       }

    func testThrowErrorWhenDraft23JwksHasMultipleKeysMatchingAlgorithm() throws {
        // getEncryptionKey throws "Multiple jwks matching the specified algorithm found for encryption"
        // when multiple keys share the same algorithm and no single enc-use key can be selected.
        let cases: [(description: String, keys: [[String: Any]])] = [
            (
                "multiple enc keys with same alg",
                [
                    ["kty": "OKP", "crv": "X25519", "use": "enc", "alg": "ECDH-ES", "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4", "kid": "enc-key-1"],
                    ["kty": "OKP", "crv": "X25519", "use": "enc", "alg": "ECDH-ES", "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA5", "kid": "enc-key-2"]
                ]
            ),
            (
                "multiple keys with same alg but no explicit use",
                [
                    ["kty": "OKP", "crv": "X25519", "alg": "ECDH-ES", "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4", "kid": "key-1"],
                    ["kty": "OKP", "crv": "X25519", "alg": "ECDH-ES", "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA5", "kid": "key-2"]
                ]
            )
        ]

        for testCase in cases {
            let clientMetadata: [String: Any] = [
                "client_name": "Requester name",
                "authorization_encrypted_response_alg": "ECDH-ES",
                "authorization_encrypted_response_enc": "A256GCM",
                "jwks": ["keys": testCase.keys],
                "vp_formats": ["ldp_vp": ["proof_type": ["Ed25519Signature2018"]]]
            ]
            XCTAssertThrowsError(
                try directPostJwtResponseModeHandler.validate(
                    clientMetadata: createInstance(clientMetadata, as: ClientMetadataDraft23.self),
                    walletConfig: walletConfig,
                    shouldValidateWithWalletMetadata: false
                ),
                testCase.description
            ) { error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: "Multiple jwks matching the specified algorithm found for encryption",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }

    // MARK: - getResponseEndpoint

    func testGetResponseEndpointThrowsWhenResponseUriIsNil() throws {
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.getResponseEndpoint(authorizationRequestParameters: [:])) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing Input: response_uri param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testGetResponseEndpointThrowsWhenResponseUriIsNonStringType() throws {
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.getResponseEndpoint(authorizationRequestParameters: [
            AuthorizationRequestFieldConstants.responseUri: 12345
        ])) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "response_uri data is not valid",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - dispatchInfo-based method tests
    // makeJwtDispatchInfo is provided by the shared makeJwtDispatchInfo() free function in TestUtils.swift

    func testGetAuthorizationErrorResponseWithDispatchInfoReturnsEncryptedResponse() throws {
        let handler = DirectPostJwtResponseModeHandler()
        let errorResponse = AuthorizationErrorResponse(error: "invalid_request", errorDescription: "Bad request", state: "err-state")

        let result = try handler.getAuthorizationErrorResponse(
            dispatchInfo: try makeJwtDispatchInfo(),
            authorizationResponse: errorResponse,
            authorizationRequest: getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .draft23)
        )

        XCTAssertEqual(result.keys.count, 1)
        XCTAssertNotNil(result["response"], "Error response should be encrypted for direct_post.jwt")
        XCTAssertFalse(result["response"]!.isEmpty)
        XCTAssertTrue(result["response"]!.contains("."), "Expected a JWE compact serialization (dots)")
        XCTAssertNil(result["error"])
        XCTAssertNil(result["error_description"])
    }

    func testGetAuthorizationErrorResponseWithDispatchInfoReturnsPlainMapWhenEncryptionSpecIsMissing() throws {
        let handler = DirectPostJwtResponseModeHandler()
        let errorResponse = AuthorizationErrorResponse(error: "access_denied", errorDescription: "User denied", state: nil)

        let result = try handler.getAuthorizationErrorResponse(
            dispatchInfo: try makeJwtDispatchInfo(includeEncryption: false),
            authorizationResponse: errorResponse,
            authorizationRequest: nil
        )

        XCTAssertEqual(result["error"], "access_denied")
        XCTAssertEqual(result["error_description"], "User denied")
        XCTAssertNil(result["state"])
        XCTAssertNil(result["response"], "Should not be encrypted when encryption spec is absent")
    }

    func testGetAuthorizationResponseWithDispatchInfoReturnsEncryptedResponse() throws {
        let handler = DirectPostJwtResponseModeHandler()
        let authorizationResponse = AuthorizationResponse.presentationExchange(
            vpToken: mockVPTokens,
            presentationSubmission: mockPresentationSubmission,
            state: "state"
        )

        let result = try handler.getAuthorizationResponse(
            dispatchInfo: try makeJwtDispatchInfo(),
            authorizationResponse: authorizationResponse,
            authorizationRequest: getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .draft23)
        )

        XCTAssertEqual(result.keys.count, 1)
        XCTAssertNotNil(result["response"])
        XCTAssertFalse(result["response"]!.isEmpty)
        XCTAssertTrue(result["response"]!.contains("."), "Expected a JWE compact serialization (dots)")
    }

    func testGetAuthorizationResponseWithDispatchInfoThrowsWhenEncryptionSpecIsMissing() throws {
        let handler = DirectPostJwtResponseModeHandler()
        let authorizationResponse = AuthorizationResponse.presentationExchange(
            vpToken: mockVPTokens,
            presentationSubmission: mockPresentationSubmission,
            state: "state"
        )

        XCTAssertThrowsError(try handler.getAuthorizationResponse(
            dispatchInfo: try makeJwtDispatchInfo(includeEncryption: false),
            authorizationResponse: authorizationResponse,
            authorizationRequest: getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .draft23)
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "responseEncryptionSpecification is required for response mode 'direct_post.jwt'",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testSendAuthorizationErrorWithDispatchInfoPostsEncryptedResponseToUrl() async throws {
        let handler = DirectPostJwtResponseModeHandler()
        mockNetworkManager.clearResponses()
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "error acknowledged")

        let errorResponse = AuthorizationErrorResponse(error: "invalid_scope", errorDescription: "Bad scope", state: "s1")

        let result = try await handler.sendAuthorizationError(
            dispatchInfo: try makeJwtDispatchInfo(),
            authorizationResponse: errorResponse,
            authorizationRequest: getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .draft23),
            networkManager: mockNetworkManager
        )

        let recorded = mockNetworkManager.recordedRequests[responseUri]
        XCTAssertEqual(recorded?.requestMethod, .post)
        XCTAssertEqual(recorded?.requestBody?.keys.count, 1)
        XCTAssertNotNil(recorded?.requestBody?["response"], "Error response should be encrypted for direct_post.jwt")
        XCTAssertNil(recorded?.requestBody?["error"])
        assertDictionariesEqual(expected: ["Content-Type": ContentTypes.applicationFormUrlEncoded.rawValue], actual: recorded?.requestHeaders)
        XCTAssertEqual(result.body, "error acknowledged")
    }

    func testSendAuthorizationResponseWithDispatchInfoPostsEncryptedResponseToUrl() async throws {
        let handler = DirectPostJwtResponseModeHandler()
        mockNetworkManager.clearResponses()
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "response received")

        let authorizationResponse = AuthorizationResponse.presentationExchange(
            vpToken: mockVPTokens,
            presentationSubmission: mockPresentationSubmission,
            state: "state"
        )

        let result = try await handler.sendAuthorizationResponse(
            dispatchInfo: try makeJwtDispatchInfo(),
            authorizationResponse: authorizationResponse,
            authorizationRequest: getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .draft23),
            networkManager: mockNetworkManager
        )

        let recorded = mockNetworkManager.recordedRequests[responseUri]
        XCTAssertEqual(recorded?.requestMethod, .post)
        XCTAssertEqual(recorded?.requestBody?.keys.count, 1)
        XCTAssertNotNil(recorded?.requestBody?["response"])
        assertDictionariesEqual(expected: ["Content-Type": ContentTypes.applicationFormUrlEncoded.rawValue], actual: recorded?.requestHeaders)
        XCTAssertEqual(result.body, "response received")
    }

    func testGetResponseEndpointReturnsResponseUriForDirectPostJwt() throws {
        let handler = DirectPostJwtResponseModeHandler()
        let responseUrl = try handler.getResponseEndpoint(authorizationRequestParameters: [
            AuthorizationRequestFieldConstants.responseUri: "https://mock-verifier.com/callback"
        ])

        XCTAssertEqual(responseUrl, "https://mock-verifier.com/callback")
    }

    func testGetResponseEndpointThrowsForInvalidUriForDirectPostJwt() throws {
        let handler = DirectPostJwtResponseModeHandler()

        XCTAssertThrowsError(try handler.getResponseEndpoint(authorizationRequestParameters: [
            AuthorizationRequestFieldConstants.responseUri: "invalid-uri"
        ])) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "response_uri data is not valid",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testValidateDraft23ThrowsWhenKeyEncryptionAlgorithmIsUnsupported() throws {
        let clientMetadataDict: [String: Any] = [
            "client_name": "Test",
            "authorization_encrypted_response_alg": "unsupported-alg",
            "authorization_encrypted_response_enc": "A256GCM",
            "jwks": [
                "keys": [[
                    "kty": "OKP", "crv": "X25519", "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "unsupported-alg", "kid": "ed-key1"
                ]]
            ],
            "vp_formats": [
                "ldp_vp": [
                    "proof_type": [
                        "Ed25519Signature2018",
                        "Ed25519Signature2020"
                    ]
                ]
            ]
        ]
        let clientMetadata = createInstance(clientMetadataDict, as: ClientMetadataDraft23.self)

        XCTAssertThrowsError(
            try directPostJwtResponseModeHandler.validate(clientMetadata: clientMetadata, walletConfig: walletConfig, shouldValidateWithWalletMetadata: false)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Unsupported key encryption algorithm: unsupported-alg",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testValidateDraft23ThrowsWhenContentEncryptionMethodIsUnsupported() throws {
        let clientMetadataDict: [String: Any] = [
            "client_name": "Test",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "unsupported-enc",
            "jwks": [
                "keys": [[
                    "kty": "OKP", "crv": "X25519", "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-ES", "kid": "ed-key1"
                ]]
            ],
            "vp_formats": [
                "ldp_vp": [
                    "proof_type": [
                        "Ed25519Signature2018",
                        "Ed25519Signature2020"
                    ]
                ]
            ]
        ]
        let clientMetadata = createInstance(clientMetadataDict, as: ClientMetadataDraft23.self)

        XCTAssertThrowsError(
            try directPostJwtResponseModeHandler.validate(clientMetadata: clientMetadata, walletConfig: walletConfig, shouldValidateWithWalletMetadata: false)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Unsupported content encryption algorithm: unsupported-enc",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
