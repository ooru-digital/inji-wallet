import OpenID4VP
import CryptoKit
import Foundation

let jwkSet = """
            { "keys": [
                    { 
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "x": "5tvU4k_TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc",
                    "alg": "EdDSA",
                    "kid": "ed-key2" 
                    },
                {"kty": "OKP",
                "crv": "X25519",
                "use": "enc",
                "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                "alg": "ECDH-ES",
                "kid": "ed-key1"}] }
"""

let clientMetadataString = """
        {
            "client_name": "Valid Client",
            "logo_uri": "https://example.com/logo.png",
            "authorization_encrypted_response_alg": "RSA-OAEP",
            "authorization_encrypted_response_enc": "A256GCM",
            "vp_formats": { "format1": { "type1": ["value1"] } },
            "jwks": \(jwkSet)
        }
    """.data(using: .utf8)!

let jwksUri = "https://mock-verifier.com/.well-known/jwks.json"

private let testVerifierList:  [[String: Any]]  = [
    [
        "client_id": "https://mock-verifier.com",
        "response_uris": [
            "https://mock-verifier.com/response",
        ],
        "allow_unsigned_request": true,
    ],
    [
        "client_id": "mock-client-2",
        "response_uris": [
            "https://mock-verifier.com",
        ]
    ],
    [
        "client_id": "mock-client",
        "response_uris": [
            "https://mock-verifier.com",
        ],
        "jwks_uri": "https://mock-verifier.com/.well-known/jwks.json",
        "allow_unsigned_request": true,
    ]
]

let didUrl = "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs"

let preRegisteredVerifiers = createVerifiers(from: testVerifierList)

let requestUri : URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!

let verifiableCredentialsList : [String : [FormatType : [AnyCodable]]] = ["input_descriptor1": [FormatType.ldp_vc : [AnyCodable(ldpVC())]]]

let didDocumentUrl = "https://inji-ovp/inji-mock-services/openid4vp-service/docs/did.json"
let httpUrlResponseForJWS: HTTPURLResponse = HTTPURLResponse(url: URL(string: didDocumentUrl)!, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/oauth-authz-req+jwt"])!
let didResponse = convertToJsonString([
    "assertionMethod": [
        "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0"
    ],
    "service": [],
    "id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
    "verificationMethod": [
        [
            "publicKeyMultibase": "z6MkwAm9tLpXZNfeEAqj9jcccFhjdiTwxVD32GhcjyeqGYSo",
            "controller": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
            "id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0",
            "type": "Ed25519VerificationKey2020",
            "@context": "https://w3id.org/security/suites/ed25519-2020/v1"
        ]
    ],
    "@context": [
        "https://www.w3.org/ns/did/v1"
    ],
    "alsoKnownAs": [],
    "authentication": [
        "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0"
    ]
])

let publicKey = try! Curve25519.Signing.PublicKey(
    rawRepresentation: Data([
        0x98, 0x8C, 0xD0, 0x5E, 0xA7, 0xD3, 0x76, 0x8A,
        0x66, 0x79, 0x65, 0x05, 0xC0, 0x9E, 0x3E, 0x3F,
        0x8A, 0x49, 0x15, 0x3C, 0x0B, 0x45, 0x1C, 0x14,
        0x41, 0x37, 0x5B, 0x0E, 0x79, 0x48, 0x95, 0xF7
    ])
)

let authorizationRequestParamsWithValue: [String: Any] = [
    "redirect_uri": "https://mock-verifier.com",
    "response_uri": "https://mock-verifier.com",
    "request_uri": "https://mock-verifier.com/verifier/get-auth-request-obj",
    "request_uri_method": "get",
    "presentation_definition": (presentationDefinition),
    "response_type": "vp_token",
    "response_mode": "direct_post",
    "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
    "state": "+mRQe1d6pBoJqF6Ab28klg==",
    "client_metadata": (clientMetadata),
    "presentation_definition_uri": "https://mock-verifier.com/presentation-definition"
]

func baseAuthRequest(clientId: String,
                             clientIdScheme: String? = nil,
                             responseUri: String) -> [String: Any] {
    var request: [String: Any] = [
        "response_type": "vp_token",
        "response_mode": "iar-post",
        "presentation_definition": [
            "id": "vp token example",
            "purpose": "Relying party is requesting your digital ID for the purpose of Self-Authentication",
            "format": [
                "ldp_vc": [
                    "proof_type": ["RsaSignature2018"],
                ],
            ],
            "input_descriptors": [
                [
                    "id": "id card credential",
                    "format": [
                        "ldp_vc": [
                            "proof_type": ["Ed25519Signature2020", "RsaSignature2018"],
                        ],
                    ],
                    "constraints": [
                        "fields": [
                            [
                                "path": ["$.credentialSubject.email"],
                                "filter": [
                                    "type": "string",
                                    "pattern": "@gmail.com",
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ],
        "client_id": clientId,
        "response_uri": responseUri,
        "nonce": "wiuegqgd",
    ]

    if let scheme = clientIdScheme {
        request["client_id_scheme"] = scheme
    }

    return request
}

let redirectUriSchemeClientIdDraft23: [String: String] = [
    "client_id": "redirect_uri:https://mock-verifier.com",
]

let DidSchemeClientIdDraft23: [String: String] = [
    "client_id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
]

let preRegisteredSchemeClientIdDraft23: [String: String] = [
    "client_id": "mock-client",
]

let redirectUriSchemeClientIdDraft21: [String: String] = [
    "client_id": "https://mock-verifier.com",
    "client_id_scheme": "redirect_uri",
]

let DidSchemeClientIdDraft21: [String: String] = [
    "client_id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
    "client_id_scheme": "did",
]

let preRegisteredSchemeClientIdDraft21: [String: String] = [
    "client_id": "mock-client",
    "client_id_scheme": "pre-registered",
]

let authRequestParamsByReferenceDraft23 : [String] = [
    "client_id",
    "request_uri",
    "request_uri_method"
]

let authRequestParamsByReferenceDraft21 : [String] = [
    "client_id",
    "client_id_scheme",
    "request_uri",
    "request_uri_method"
]

let authRequestWithRedirectUriByValue : [String] = [
    "client_id",
    "response_uri",
    "presentation_definition",
    "response_type",
    "response_mode",
    "nonce",
    "state",
    "client_metadata"
]

let authRequestWithRedirectUriWithPresentationDefinitionUri : [String] = [
    "client_id",
    "response_uri",
    "presentation_definition_uri",
    "response_type",
    "response_mode",
    "nonce",
    "state",
    "client_metadata"
]

let authRequestWithPreRegisteredByValueDraft23 : [String] = [
    "client_id",
    "response_mode",
    "response_uri",
    "presentation_definition",
    "response_type",
    "nonce",
    "state",
    "client_metadata"
]

let authRequestWithPreRegisteredByValueDraft21 : [String] = [
    "client_id",
    "client_id_scheme",
    "response_mode",
    "response_uri",
    "presentation_definition",
    "response_type",
    "nonce",
    "state",
    "client_metadata"
]

let authRequestWithDidByValue : [String] = [
    "client_id",
    "response_mode",
    "response_uri",
    "presentation_definition",
    "response_type",
    "nonce",
    "state",
    "client_metadata"
]


let authRequestClientIdSchemeMap : [ClientIdScheme: [String]] = [
    ClientIdScheme.preRegistered : authRequestWithPreRegisteredByValueDraft23,
    ClientIdScheme.redirectUri : authRequestWithRedirectUriByValue,
    ClientIdScheme.did : authRequestWithDidByValue
]

let presentationDefinition: [String: Any] = [
    "id": "vp_presentation_definition",
    "input_descriptors": [
        [
            "id": "input_1",
            "name": "Verifiable Credential",
            "purpose": "To verify identity using Linked Data Proofs",
            "format": [
                "ldp_vc": [
                    "proof_type": ["Ed25519Signature2018", "RsaSignature2018"]
                ]
            ],
            "constraints": [
                "fields": [
                    [
                        "path": ["$.credentialSubject.email"],
                        "filter": [
                            "type": "string",
                            "pattern": "@gmail.com"
                        ]
                    ]
                ]
            ]
        ]
    ]
]

let mockPresentationDefinitionObject = createInstance(presentationDefinition, as: PresentationDefinition.self)

let vpFormatsMap: [String: VPFormatSupported] = [
    "ldp_vc": VPFormatSupported(algValuesSupported: ["Ed25519Signature2018", "Ed25519Signature2020"])
]

let clientMetadata: [String: Any] = [
    "client_name": "Requester name",
    "logo_uri": "https://mock-verifier.com/logo",
    "authorization_encrypted_response_alg": "ECDH-ES",
    "authorization_encrypted_response_enc": "A256GCM",
    "jwks": [
        "keys": [
            [
                "kty": "OKP",
                "crv": "X25519",
                "use": "enc",
                "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                "alg": "ECDH-ES",
                "kid": "ed-key1"
            ],
            [
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "x": "5tvU4k_TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc",
                "alg": "EdDSA",
                "kid": "ed-key2"
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

let clientMetadataWithWrongKey: [String: Any] = [
    "client_name": "Requester name",
    "logo_uri": "https://mock-verifier.com/logo",
    "authorization_encrypted_response_alg": "ECDH-ES",
    "authorization_encrypted_response_enc": "A256GCM",
    "jwks": [
        "keys": [
            [
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "x": "5tvU4k_TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc",
                "alg": "EdDSA",
                "kid": "ed-key2"
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

let mockClientMetadataObject = createInstance(clientMetadata, as: ClientMetadata.self)

let ldpVPTokenSigningResult = LdpVPTokenSigningResult(
    jws: "validJWS", proofValue: "hdjbhdsjdshjv",
    signatureAlgorithm: "JsonWebSignature2020"
)

let mdocSigningResult = MdocVPTokenSigningResult(
    docTypeToDeviceAuthentication: ["docType": DeviceAuthentication(signature: "signature", algorithm: "ES256")]
)

//  client_id_scheme = redirect_uri
let authorizationRequestParamsWithRedirectUri: [String: Any] = [
    "client_id": "redirect_uri:https://mock-verifier.com",
    "redirect_uri":"https://mock-verifier.com",
    "presentation_definition": presentationDefinition,
    "response_type": "vp_token",
    "response_mode": "direct_post",
    "nonce":"VbRRB/LTxLiXmVNZuyMO8A==",
    "state":"+mRQe1d6pBoJqF6Ab28klg==",
    "client_metadata": clientMetadata
]

let urlEncodedAuthRequestWithPresentationDefinitionUri = createUrlEncodedAuthorizationRequest(
    requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23),
    clientIdScheme: .preRegistered,
    applicableFields: authRequestWithPreRegisteredByValueDraft23.map {
        $0 == AuthorizationRequestFieldConstants.presentationDefinition.rawValue ? AuthorizationRequestFieldConstants.presentationDefinitionUri.rawValue : $0
    }
)

// client_id_scheme = redirect_uri
let testValidUrlEncodedVPRequestWithRedirectUri = createUrlEncodedAuthorizationRequest(
    requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23),
    clientIdScheme: .redirectUri,
    applicableFields: authRequestWithRedirectUriByValue.map { $0 == AuthorizationRequestFieldConstants.redirectUri.rawValue ? AuthorizationRequestFieldConstants.responseUri.rawValue : $0 }
)

//  client_id_scheme = redirect_uri, with response uri and response mode
let testVPRequestWithRedirectUriAndResponseUriResponseMode = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps( redirectUriSchemeClientIdDraft23,  authorizationRequestParamsWithValue), clientIdScheme: .redirectUri, applicableFields: authRequestClientIdSchemeMap[.redirectUri]! + ["response_uri","response_mode"])

//  client_id_scheme = redirect_uri, and not equal to client id
let testVPRequestWithRedirectUriAndClientIdNotEqual = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, ["client_id": "redirect_uri:https://mock-verifier-party.com", "redirect_uri": "https://mock-verifier.com", "response_mode": "fragment"]), clientIdScheme: .redirectUri)

//client_id_scheme = pre-registered
let testValidUrlEncodedVPRequestWithResponseUri = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23), clientIdScheme: .preRegistered)

let testUrlEncodedAuthRequestOfUntrustedVerifier = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, ["client_id": "untrusted_client"]), verifierSentAuthRequestByReference: true, clientIdScheme: .preRegistered)

// client_id_scheme = pre-registered draft 21
let testValidUrlEncodedVPRequestWithResponseUriDraft21 = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft21), clientIdScheme: .preRegistered, draftVersion: 21)

// jwt -> client_id_scheme = did
let testValidSignedVPRequestWithDid = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23), verifierSentAuthRequestByReference : true, clientIdScheme: .did)

let testInValidSignedVPRequestWithDidAndClientIdDifferent = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, [
    "client_id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-21",
]), verifierSentAuthRequestByReference : true, clientIdScheme: .did)


let testInvalidPresentationDefinitionVPRequest = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23, ["presentation_definition": convertToJsonString(["input_descriptor":[]])]), clientIdScheme: .preRegistered)

let urlEncodedAuthorizationRequestWithInvalidClientMetadata = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, ["client_id": "mock-client-2"], ["client_metadata": "{}"]),clientIdScheme: .preRegistered, applicableFields: authRequestWithPreRegisteredByValueDraft23 + ["client_metadata"])

let validJwtResponse = createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23))

let invalidJwtResponse = createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23), addValidSignature: false)

let invalidJwtResponseWithoutKid = createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23), jwsHeaderData: [
    "typ": "oauth-authz-req+jwt",
    "alg": "EdDSA"
])

let resquestUriResponseData: [String: Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]

let mockUrlEncodedVPRequestWithDirectPostJwt = createUrlEncodedAuthorizationRequest(
    requestParams: mergeMaps(authorizationRequestParamsWithValue.merging(["response_mode": "direct_post.jwt"]) { _, new in new },preRegisteredSchemeClientIdDraft23),clientIdScheme: .preRegistered
)

let mockAuthorizationRequestObjectWithDirectPostResponseMode = getMockAuthorizationRequest()

let mockAuthorizationRequestObjectWithDirectPostJwtResponseMode = getMockAuthorizationRequest(responseMode: .directPostJwt)

let mockSetResponseUri: (String) -> Void = { value in
}

let credentialsMap: [String: [String: Array<Any>]] = [
    "bank_input":
        ["ldp_vc": ["VC1"]],
]

let sampleMdoc = "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkCADCCAfwwggGjAhQF2zbegdWq1XHLmdrVZZIORS_efDAKBggqhkjOPQQDAjCBgDELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoMBUlJSVRCMQwwCgYDVQQLDANEQ1MxEDAOBgNVBAMMB0NFUlRJRlkxIDAeBgkqhkiG9w0BCQEWEW1vc2lwcWFAZ21haWwuY29tMB4XDTI1MDIxMjEyMzE1N1oXDTI2MDIxMjEyMzE1N1owgYAxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEMMAoGA1UECwwDRENTMRAwDgYDVQQDDAdDRVJUSUZZMSAwHgYJKoZIhvcNAQkBFhFtb3NpcHFhQGdtYWlsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAcZXrsgNSABzg9o_dNKu6S2pXuJ3hgYlX162Ex56IUGDJZP_IlRCrEQPHZSSl53DwlpL4iHisASqFaRQiXAtqkwCgYIKoZIzj0EAwIDRwAwRAIgGI6B63QccJQ4B84hRjRGlRURJ5SSNTuf74w-nE8zqRACIA3diiD3VCA5G6joGeTSX-Xx79shhDrCmUHuj3Lk5uL1WQJR2BhZAkymZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlggoYW5sb6ESFos65JdcrGlpW4Dzbyye02GzxYpdb14lT4GWCBOKmbymvZx9mlX-zq7fKPzM3BPBp5e8KLD_G4k1GsMSwNYIFlKVBXtrEPyDHpCp-E_MT2RTCduZ6Yvo84kjAj9-F79AVggeYDGTfx8w7Sz2hIQvkZ1QhtrXskhDjZkS_cgN6HP18oEWCBeZlkW29iqUBLxAFlOfHrz5qXioXKKaoyEEYI96YyKvwBYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYICT1yy5zwUTPWESS8KRgFLrkMFnWMbOkNP9vZnRlGppvIlggBl7qoNLfjtf_r6M543nalRUGAt-PNi8u5QvhOf3MQKxsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjUtMDQtMTRUMDc6MjE6MjdaaXZhbGlkRnJvbcB0MjAyNS0wNC0xNFQwNzoyMToyN1pqdmFsaWRVbnRpbMB0MjAyNy0wNC0xNFQwNzoyMToyN1pYQMq2sYS6gOyooh4wfLlSN6aAMwTz5ij-gl3whMwvW285Ueasc1qNmsFUnE5-yAphM1xF8F2cMMPWI0CkbiRIGFBqbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGI2BhYWKRoZGlnZXN0SUQCZnJhbmRvbVBthSy1vmphqpoMYRe9Z0PncWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVlajIwMjUtMDQtMTTYGFhZpGhkaWdlc3RJRAZmcmFuZG9tUNyXhXOZjmheiFyzYfhsl0ZxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVlajIwMzAtMDQtMTTYGFifpGhkaWdlc3RJRANmcmFuZG9tUCC-v7ARALJ2VFcYww9AbMhxZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZXhIe2lzc3VlX2RhdGU9MjAyNS0wNC0xNCwgdmVoaWNsZV9jYXRlZ29yeV9jb2RlPUEsIGV4cGlyeV9kYXRlPTIwMzAtMDQtMTR92BhYXaRoZGlnZXN0SUQBZnJhbmRvbVDjoYj_8RBZ62-85iZV371vcWVsZW1lbnRJZGVudGlmaWVyb2RvY3VtZW50X251bWJlcmxlbGVtZW50VmFsdWVqOTI2MTQ4MTAyNNgYWFWkaGRpZ2VzdElEBGZyYW5kb21Qg7iWcNbZ-b9S2D3u3Av2YnFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnlsZWxlbWVudFZhbHVlYklO2BhYWKRoZGlnZXN0SUQAZnJhbmRvbVAFg1zMFq1oLYxHiib0UCeYcWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGVsZWxlbWVudFZhbHVlajE5OTQtMTEtMDbYGFhUpGhkaWdlc3RJRAdmcmFuZG9tUElZm1bdU7M1GlcrQPJ_ctNxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVmSm9zZXBo2BhYVaRoZGlnZXN0SUQFZnJhbmRvbVB_NHtdmXkWLPqVnSgypGGWcWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWZBZ2F0aGE="

let sampeVcSdJwtWithHolderBinding = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlCNVRDQ0FZdWdBd0lCQWdJUUdVZEYwa0JpUUdEYXdwKzBkQlNTNWpBS0JnZ3Foa2pPUFFRREFqQWRNUTR3REFZRFZRUURFd1ZCYm1sdGJ6RUxNQWtHQTFVRUJoTUNUa3d3SGhjTk1qVXdOREV5TVRReU16TXdXaGNOTWpZd05UQXlNVFF5TXpNd1dqQWhNUkl3RUFZRFZRUURFd2xqY21Wa2J5QmtZM014Q3pBSkJnTlZCQVlUQWs1TU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUZYVk5BMGxhYSs1UDJuazVQSkZvdjh4aEJGTno1VU9KQklWc3lrMFNLU2ZxVGZLTUI2UitjRkROaWpkbUJZeXVFYVVnTWd1VWM4aE9Wbm5yZVc5dGhLT0JxRENCcFRBZEJnTlZIUTRFRmdRVVlSOHZGUVRsa2pmMS9ObktlWnh2WTBaejNhQXdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1CVUdBMVVkSlFFQi93UUxNQWtHQnlpQmpGMEZBUUl3SHdZRFZSMGpCQmd3Rm9BVUw5OHdhTll2OVFueElIYjVDRmd4anZaVXRVc3dJUVlEVlIwU0JCb3dHSVlXYUhSMGNITTZMeTltZFc1clpTNWhibWx0Ynk1cFpEQVpCZ05WSFJFRUVqQVFnZzVtZFc1clpTNWhibWx0Ynk1cFpEQUtCZ2dxaGtqT1BRUURBZ05JQURCRkFpQkJ3ZFMvY0ZCczNhd3RmUDlHRlZrZ1NPSVRRZFBCTUxoc0pCeWpnN2wyTFFJaEFQUUpXeTdxUXNmcTJHcmRwY0dYSHJEVkswdy9YblBGMlhBVDZyVFg4dUNQIiwiTUlJQnp6Q0NBWFdnQXdJQkFnSVFWd0FGb2xXUWltOTRnbXlDaWMzYkNUQUtCZ2dxaGtqT1BRUURBakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d0hoY05NalF3TlRBeU1UUXlNek13V2hjTk1qZ3dOVEF5TVRReU16TXdXakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFRQy9ZeUJwY1JRWDhaWHBIZnJhMVROZFNiUzdxemdIWUhKM21zYklyOFRKTFBOWkk4VWw4ekpsRmRRVklWbHM1KzVDbENiTitKOUZVdmhQR3M0QXpBK280R1dNSUdUTUIwR0ExVWREZ1FXQkJRdjN6Qm8xaS8xQ2ZFZ2R2a0lXREdPOWxTMVN6QU9CZ05WSFE4QkFmOEVCQU1DQVFZd0lRWURWUjBTQkJvd0dJWVdhSFIwY0hNNkx5OW1kVzVyWlM1aGJtbHRieTVwWkRBU0JnTlZIUk1CQWY4RUNEQUdBUUgvQWdFQU1Dc0dBMVVkSHdRa01DSXdJS0Flb0J5R0dtaDBkSEJ6T2k4dlpuVnVhMlV1WVc1cGJXOHVhV1F2WTNKc01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRQ1RnODBBbXFWSEpMYVp0MnV1aEF0UHFLSVhhZlAyZ2h0ZDlPQ21kRDUxWndJZ0t2VmtyZ1RZbHhTUkFibUtZNk1sa0g4bU0zU05jbkVKazlmR1Z3SkcrKzA9Il19.eyJpc3N1YW5jZV9kYXRlIjoiMjAyNS0wOC0xOCIsImV4cGlyeV9kYXRlIjoiMjAyNi0wOC0yOCIsImlzc3VpbmdfY291bnRyeSI6IkRFIiwibmJmIjoxNzU1NDc1MjAwLCJleHAiOjE3ODc4NzUyMDAsInZjdCI6Imh0dHBzOi8vZXhhbXBsZS5ldWRpLmVjLmV1cm9wYS5ldS9jb3IvMSIsImNuZiI6eyJraWQiOiJkaWQ6andrOmV5SnJkSGtpT2lKRlF5SXNJbU55ZGlJNklsQXRNalUySWl3aWVDSTZJaTFwYTJsT2VtUnhWMUJETVdsWVNXOUtOREp2VjBNNGNVMTZWSGR2V2pBNGVqWTVSalZaWldOYU9Xc2lMQ0o1SWpvaVVVbFFjR1JQUkV4NFgxaHhkVmhMYVVaaFYzb3lXVzg0TW1SV2VsVXpOV3BGU2pSTmMyTlZSMFo1T0NJc0luVnpaU0k2SW5OcFp5SjkjMCJ9LCJpc3MiOiJodHRwczovL2Z1bmtlLmFuaW1vLmlkIiwiaWF0IjoxNzU2ODk2NjUzLCJfc2QiOlsiQzJQX3FvcTBQdlRvMVlZcnYzXzVGV2k0aUVhWlVHS1lhQ2t6YWtnTUlIYyIsIkY0WmRCUEl4MHJRYmhuaWRuU3AxSEw3LVRSX09DRnFoV0lWSlo3bUIzRlUiLCJVdHYtdEdoSWdvS0lLTlRiOWd0YnI3Ylk5RW1RQU1LTnd0WGpjTXNRcExNIiwiZ3dfRmotNExRRkpDZ3JkVUpwRUJtbTRuemEzMVhSdGFnNVNoX0VQOER6VSIsImthdDRVQW1LOXhuTkd6NS14RXZDVHVmZW5BRzlSdUVveHlrckstbE5LZWciLCJvRUJMS1c0UUQ5Z2NKbkhCRi1YR2VrbEEzeDhMMTV1bEN3NVVxcGV5aElzIiwicXRpVUp6bFNMOU0ybjd5eGdoa0lOSnhVSnQ2S2ZaZFBjRGtxaHRWcTR6USIsInk0THlyMno2QUlkSGhwOGV0NVZxOXJoU2I2NXNHaU1YMDZFVloxLV9pNlEiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.F0gYaWKFzPXoI4pO4mixg6WgN1gM3hfqiJLIgxEAjfQb5yrQEU3G2CCYwJtg7d9bcs9-4lu4ZVS6aWpUJ70UNw~WyI1Njg2Njc5MzY5MTc4MDgxMDA5Nzc0MTQiLCJmYW1pbHlfbmFtZSIsIk11c3Rlcm1hbm4iXQ~WyIxMTc2MjI4NDI0Mzk4MTY4Mzc4NTQ1NTg0IiwiZ2l2ZW5fbmFtZSIsIkVyaWthIl0~WyI1MTI2Mzc4NDkyMDcxOTExMjczMTQwNjAiLCJiaXJ0aF9kYXRlIiwiMTk2NC0wOC0xMiJd~WyIxMTI0MjE5NzQ2NzM0MDA1ODYzMjU3NTAiLCJyZXNpZGVudF9hZGRyZXNzIiwiSGVpZGVzdHJhc3NlIDE3LCA1MTE0NyBLb2xuIl0~WyI1MzcxMzg4MzMyNjMxMDc3MjY5MjQ4NDkiLCJnZW5kZXIiLDJd~WyI5MjcxODEyMjgxOTIyMDY1MDcxOTQyMTMiLCJiaXJ0aF9wbGFjZSIsIkvDtmxuIl0~WyI1MTE2NDk3MzQxMDM5NTU1MTIwMzc0MDQiLCJhcnJpdmFsX2RhdGUiLCIyMDI0LTAzLTAxIl0~WyI5MTQ0NDg4OTMwNzAwNzQ5Mjc3NjMwODkiLCJuYXRpb25hbGl0eSIsIkRFIl0~"

let sampleVcSdJwtWithNoHolderBinding = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlCNVRDQ0FZdWdBd0lCQWdJUUdVZEYwa0JpUUdEYXdwKzBkQlNTNWpBS0JnZ3Foa2pPUFFRREFqQWRNUTR3REFZRFZRUURFd1ZCYm1sdGJ6RUxNQWtHQTFVRUJoTUNUa3d3SGhjTk1qVXdOREV5TVRReU16TXdXaGNOTWpZd05UQXlNVFF5TXpNd1dqQWhNUkl3RUFZRFZRUURFd2xqY21Wa2J5QmtZM014Q3pBSkJnTlZCQVlUQWs1TU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUZYVk5BMGxhYSs1UDJuazVQSkZvdjh4aEJGTno1VU9KQklWc3lrMFNLU2ZxVGZLTUI2UitjRkROaWpkbUJZeXVFYVVnTWd1VWM4aE9Wbm5yZVc5dGhLT0JxRENCcFRBZEJnTlZIUTRFRmdRVVlSOHZGUVRsa2pmMS9ObktlWnh2WTBaejNhQXdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1CVUdBMVVkSlFFQi93UUxNQWtHQnlpQmpGMEZBUUl3SHdZRFZSMGpCQmd3Rm9BVUw5OHdhTll2OVFueElIYjVDRmd4anZaVXRVc3dJUVlEVlIwU0JCb3dHSVlXYUhSMGNITTZMeTltZFc1clpTNWhibWx0Ynk1cFpEQVpCZ05WSFJFRUVqQVFnZzVtZFc1clpTNWhibWx0Ynk1cFpEQUtCZ2dxaGtqT1BRUURBZ05JQURCRkFpQkJ3ZFMvY0ZCczNhd3RmUDlHRlZrZ1NPSVRRZFBCTUxoc0pCeWpnN2wyTFFJaEFQUUpXeTdxUXNmcTJHcmRwY0dYSHJEVkswdy9YblBGMlhBVDZyVFg4dUNQIiwiTUlJQnp6Q0NBWFdnQXdJQkFnSVFWd0FGb2xXUWltOTRnbXlDaWMzYkNUQUtCZ2dxaGtqT1BRUURBakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d0hoY05NalF3TlRBeU1UUXlNek13V2hjTk1qZ3dOVEF5TVRReU16TXdXakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFRQy9ZeUJwY1JRWDhaWHBIZnJhMVROZFNiUzdxemdIWUhKM21zYklyOFRKTFBOWkk4VWw4ekpsRmRRVklWbHM1KzVDbENiTitKOUZVdmhQR3M0QXpBK280R1dNSUdUTUIwR0ExVWREZ1FXQkJRdjN6Qm8xaS8xQ2ZFZ2R2a0lXREdPOWxTMVN6QU9CZ05WSFE4QkFmOEVCQU1DQVFZd0lRWURWUjBTQkJvd0dJWVdhSFIwY0hNNkx5OW1kVzVyWlM1aGJtbHRieTVwWkRBU0JnTlZIUk1CQWY4RUNEQUdBUUgvQWdFQU1Dc0dBMVVkSHdRa01DSXdJS0Flb0J5R0dtaDBkSEJ6T2k4dlpuVnVhMlV1WVc1cGJXOHVhV1F2WTNKc01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRQ1RnODBBbXFWSEpMYVp0MnV1aEF0UHFLSVhhZlAyZ2h0ZDlPQ21kRDUxWndJZ0t2VmtyZ1RZbHhTUkFibUtZNk1sa0g4bU0zU05jbkVKazlmR1Z3SkcrKzA9Il19.ewogICJpc3N1YW5jZV9kYXRlIjogIjIwMjUtMDgtMTgiLAogICJleHBpcnlfZGF0ZSI6ICIyMDI2LTA4LTI4IiwKICAiaXNzdWluZ19jb3VudHJ5IjogIkRFIiwKICAibmJmIjogMTc1NTQ3NTIwMCwKICAiZXhwIjogMTc4Nzg3NTIwMCwKICAidmN0IjogImh0dHBzOi8vZXhhbXBsZS5ldWRpLmVjLmV1cm9wYS5ldS9jb3IvMSIsCiAgImlzcyI6ICJodHRwczovL2Z1bmtlLmFuaW1vLmlkIiwKICAiaWF0IjogMTc1Njg5NjY1MywKICAiX3NkIjogWwogICAgIkMyUF9xb3EwUHZUbzFZWXJ2M181RldpNGlFYVpVR0tZYUNremFrZ01JSGMiLAogICAgIkY0WmRCUEl4MHJRYmhuaWRuU3AxSEw3LVRSX09DRnFoV0lWSlo3bUIzRlUiLAogICAgIlV0di10R2hJZ29LSUtOVGI5Z3RicjdiWTlFbVFBTUtOd3RYamNNc1FwTE0iLAogICAgImd3X0ZqLTRMUUZKQ2dyZFVKcEVCbW00bnphMzFYUnRhZzVTaF9FUDhEelUiLAogICAgImthdDRVQW1LOXhuTkd6NS14RXZDVHVmZW5BRzlSdUVveHlrckstbE5LZWciLAogICAgIm9FQkxLVzRRRDlnY0puSEJGLVhHZWtsQTN4OEwxNXVsQ3c1VXFwZXloSXMiLAogICAgInF0aVVKemxTTDlNMm43eXhnaGtJTkp4VUp0NktmWmRQY0RrcWh0VnE0elEiLAogICAgInk0THlyMno2QUlkSGhwOGV0NVZxOXJoU2I2NXNHaU1YMDZFVloxLV9pNlEiCiAgXSwKICAiX3NkX2FsZyI6ICJzaGEtMjU2Igp9.F0gYaWKFzPXoI4pO4mixg6WgN1gM3hfqiJLIgxEAjfQb5yrQEU3G2CCYwJtg7d9bcs9-4lu4ZVS6aWpUJ70UNw~WyI1Njg2Njc5MzY5MTc4MDgxMDA5Nzc0MTQiLCJmYW1pbHlfbmFtZSIsIk11c3Rlcm1hbm4iXQ~WyIxMTc2MjI4NDI0Mzk4MTY4Mzc4NTQ1NTg0IiwiZ2l2ZW5fbmFtZSIsIkVyaWthIl0~WyI1MTI2Mzc4NDkyMDcxOTExMjczMTQwNjAiLCJiaXJ0aF9kYXRlIiwiMTk2NC0wOC0xMiJd~WyIxMTI0MjE5NzQ2NzM0MDA1ODYzMjU3NTAiLCJyZXNpZGVudF9hZGRyZXNzIiwiSGVpZGVzdHJhc3NlIDE3LCA1MTE0NyBLb2xuIl0~WyI1MzcxMzg4MzMyNjMxMDc3MjY5MjQ4NDkiLCJnZW5kZXIiLDJd~WyI5MjcxODEyMjgxOTIyMDY1MDcxOTQyMTMiLCJiaXJ0aF9wbGFjZSIsIkvDtmxuIl0~WyI1MTE2NDk3MzQxMDM5NTU1MTIwMzc0MDQiLCJhcnJpdmFsX2RhdGUiLCIyMDI0LTAzLTAxIl0~WyI5MTQ0NDg4OTMwNzAwNzQ5Mjc3NjMwODkiLCJuYXRpb25hbGl0eSIsIkRFIl0~"
