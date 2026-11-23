import Foundation
import XCTest
@testable import OpenID4VP

final class SdJwtVPTokenBuilderTests: XCTestCase {
    let builder = SdJwtVPTokenBuilder(authorizationRequest: getMockAuthorizationRequest())
    
    let credentialWithBinding = sampeVcSdJwtWithHolderBinding
    let credentialWithoutBinding = sampleVcSdJwtWithNoHolderBinding
    
    // MARK: - Single credential with holder binding
    
    func testBuildWithHolderBinding() throws {
        let uuid = "uuid-with-binding"
        let unsignedKBJwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJpYXQiOjE3NTc0NzcxNjQsIm5vbmNlIjoibm9uY2UifQ"
        let signature = Data("kbSignature".utf8)
        
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "id1",
                identifier: uuid
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuid: unsignedKBJwt] as [String: String],
            unsignedVPTokens: []
        )
        let signingResults = [VPTokenSigningResult(id: uuid, signedData: signature)]
        
        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: signingResults,
            rootIndex: 0
        )
        
        XCTAssertEqual(result.vpTokens.count, 1)
        let vpToken = try XCTUnwrap(result.vpTokens[0] as? SdJwtVPToken)
        XCTAssertEqual(vpToken.value, "\(credentialWithBinding)\(unsignedKBJwt).\(signature.toBase64UrlEncoded())")
        XCTAssertEqual(result.DescriptorMaps.count, 1)
        XCTAssertEqual(result.DescriptorMaps[0].id, "id1")
        XCTAssertEqual(result.DescriptorMaps[0].format, .vc_sd_jwt)
        XCTAssertEqual(result.DescriptorMaps[0].path, "$[0]")
        XCTAssertEqual(result.nextIndex, 1)
    }
    
    // MARK: - Single credential without holder binding
    
    func testBuildWithoutHolderBinding() throws {
        let uuid = "uuid-no-binding"
        
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithoutBinding),
                inputDescriptorId: "id1",
                identifier: uuid
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String](),
            unsignedVPTokens: []
        )
        
        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )
        
        XCTAssertEqual(result.vpTokens.count, 1)
        let vpToken = try XCTUnwrap(result.vpTokens[0] as? SdJwtVPToken)
        XCTAssertEqual(vpToken.value, credentialWithoutBinding)
        XCTAssertEqual(result.DescriptorMaps.count, 1)
        XCTAssertEqual(result.DescriptorMaps[0].id, "id1")
        XCTAssertEqual(result.DescriptorMaps[0].format, .vc_sd_jwt)
        XCTAssertEqual(result.DescriptorMaps[0].path, "$[0]")
        XCTAssertEqual(result.nextIndex, 1)
    }
    
    // MARK: - Mixed: credentials with and without holder binding
    
    func testBuildWithMixOfHolderBindingAndNoHolderBinding() throws {
        let uuidWithBinding = "uuid-with-binding"
        let uuidNoBinding = "uuid-no-binding"
        let unsignedKBJwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJpYXQiOjE3NTc0NzcxNjQsIm5vbmNlIjoibm9uY2UifQ"
        let signature = Data("kbSignature".utf8)
        
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "id_with_binding",
                identifier: uuidWithBinding
            ),
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithoutBinding),
                inputDescriptorId: "id_no_binding",
                identifier: uuidNoBinding
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuidWithBinding: unsignedKBJwt] as [String: String],
            unsignedVPTokens: []
        )
        let signingResults = [VPTokenSigningResult(id: uuidWithBinding, signedData: signature)]
        
        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: signingResults,
            rootIndex: 0
        )
        
        XCTAssertEqual(result.vpTokens.count, 2)
        
        let boundToken = try XCTUnwrap(result.vpTokens[0] as? SdJwtVPToken)
        XCTAssertEqual(boundToken.value, "\(credentialWithBinding)\(unsignedKBJwt).\(signature.toBase64UrlEncoded())")
        
        let unboundToken = try XCTUnwrap(result.vpTokens[1] as? SdJwtVPToken)
        XCTAssertEqual(unboundToken.value, credentialWithoutBinding)
        
        XCTAssertEqual(result.DescriptorMaps[0].id, "id_with_binding")
        XCTAssertEqual(result.DescriptorMaps[0].path, "$[0]")
        XCTAssertEqual(result.DescriptorMaps[1].id, "id_no_binding")
        XCTAssertEqual(result.DescriptorMaps[1].path, "$[1]")
        XCTAssertEqual(result.nextIndex, 2)
    }
    
    func testBuildWithMixNoBindingFirst() throws {
        let uuidWithBinding = "uuid-with-binding"
        let uuidNoBinding = "uuid-no-binding"
        let unsignedKBJwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJpYXQiOjE3NTc0NzcxNjQsIm5vbmNlIjoibm9uY2UifQ"
        let signature = Data("kbSignature".utf8)
        
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithoutBinding),
                inputDescriptorId: "id_no_binding",
                identifier: uuidNoBinding
            ),
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "id_with_binding",
                identifier: uuidWithBinding
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuidWithBinding: unsignedKBJwt] as [String: String],
            unsignedVPTokens: []
        )
        let signingResults = [VPTokenSigningResult(id: uuidWithBinding, signedData: signature)]
        
        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: signingResults,
            rootIndex: 0
        )
        
        XCTAssertEqual(result.vpTokens.count, 2)
        
        let unboundToken = try XCTUnwrap(result.vpTokens[0] as? SdJwtVPToken)
        XCTAssertEqual(unboundToken.value, credentialWithoutBinding)
        
        let boundToken = try XCTUnwrap(result.vpTokens[1] as? SdJwtVPToken)
        XCTAssertEqual(boundToken.value, "\(credentialWithBinding)\(unsignedKBJwt).\(signature.toBase64UrlEncoded())")
        
        XCTAssertEqual(result.DescriptorMaps[0].id, "id_no_binding")
        XCTAssertEqual(result.DescriptorMaps[0].path, "$[0]")
        XCTAssertEqual(result.DescriptorMaps[1].id, "id_with_binding")
        XCTAssertEqual(result.DescriptorMaps[1].path, "$[1]")
        XCTAssertEqual(result.nextIndex, 2)
    }
    
    // MARK: - Multiple credentials all with holder binding
    
    func testBuildMultipleCredentialsAllWithHolderBinding() throws {
        let uuid1 = "uuid-1"
        let uuid2 = "uuid-2"
        let unsignedKBJwt1 = "eyJhbGciOiJFUzI1NiJ9.payload1"
        let unsignedKBJwt2 = "eyJhbGciOiJFUzI1NiJ9.payload2"
        let sig1 = Data("sig1".utf8)
        let sig2 = Data("sig2".utf8)
        
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "id1",
                identifier: uuid1
            ),
            CredentialInputDescriptorMapping(
                format: .dc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "id2",
                identifier: uuid2
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuid1: unsignedKBJwt1, uuid2: unsignedKBJwt2] as [String: String],
            unsignedVPTokens: []
        )
        let signingResults = [
            VPTokenSigningResult(id: uuid1, signedData: sig1),
            VPTokenSigningResult(id: uuid2, signedData: sig2)
        ]
        
        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: signingResults,
            rootIndex: 0
        )
        
        XCTAssertEqual(result.vpTokens.count, 2)
        let token1 = try XCTUnwrap(result.vpTokens[0] as? SdJwtVPToken)
        XCTAssertEqual(token1.value, "\(credentialWithBinding)\(unsignedKBJwt1).\(sig1.toBase64UrlEncoded())")
        let token2 = try XCTUnwrap(result.vpTokens[1] as? SdJwtVPToken)
        XCTAssertEqual(token2.value, "\(credentialWithBinding)\(unsignedKBJwt2).\(sig2.toBase64UrlEncoded())")
        XCTAssertEqual(result.DescriptorMaps[0].format, .vc_sd_jwt)
        XCTAssertEqual(result.DescriptorMaps[1].format, .dc_sd_jwt)
        XCTAssertEqual(result.nextIndex, 2)
    }
    
    // MARK: - Multiple credentials all without holder binding
    
    func testBuildMultipleCredentialsAllWithoutHolderBinding() throws {
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithoutBinding),
                inputDescriptorId: "id1",
                identifier: "uuid-1"
            ),
            CredentialInputDescriptorMapping(
                format: .dc_sd_jwt,
                credential: AnyCodable(credentialWithoutBinding),
                inputDescriptorId: "id2",
                identifier: "uuid-2"
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String](),
            unsignedVPTokens: []
        )
        
        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )
        
        XCTAssertEqual(result.vpTokens.count, 2)
        let token1 = try XCTUnwrap(result.vpTokens[0] as? SdJwtVPToken)
        XCTAssertEqual(token1.value, credentialWithoutBinding)
        let token2 = try XCTUnwrap(result.vpTokens[1] as? SdJwtVPToken)
        XCTAssertEqual(token2.value, credentialWithoutBinding)
        XCTAssertEqual(result.nextIndex, 2)
    }
    
    // MARK: - rootIndex offset
    
    func testBuildRespectsRootIndexOffset() throws {
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithoutBinding),
                inputDescriptorId: "id1",
                identifier: "uuid-1"
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String](),
            unsignedVPTokens: []
        )
        
        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 5
        )
        
        XCTAssertEqual(result.DescriptorMaps[0].path, "$[5]")
        XCTAssertEqual(result.nextIndex, 6)
    }
    
    // MARK: - dc+sd-jwt format mapping
    
    func testBuildMapsDcSdJwtFormat() throws {
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .dc_sd_jwt,
                credential: AnyCodable(credentialWithoutBinding),
                inputDescriptorId: "id1",
                identifier: "uuid-1"
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String](),
            unsignedVPTokens: []
        )
        
        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )
        
        XCTAssertEqual(result.DescriptorMaps[0].format, .dc_sd_jwt)
    }
    
    // MARK: - Error: missing identifier
    
    func testBuildThrowsWhenIdentifierIsMissing() {
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "id1",
                identifier: nil
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String](),
            unsignedVPTokens: []
        )
        
        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "identifier is null in CredentialInputDescriptorMapping for SD-JWT",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    // MARK: - Error: invalid payload type
    
    func testBuildThrowsWhenPayloadIsNotStringDictionary() {
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "id1",
                identifier: "uuid-1"
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: ["uuid-1":1],
            unsignedVPTokens: []
        )
        
        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid-1", signedData: Data("sig".utf8))],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing identifierToUnsignedKBT in payload",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    // MARK: - Error: credential is not a string
    
    func testBuildThrowsWhenCredentialIsNotString() {
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(12345),
                inputDescriptorId: "id1",
                identifier: "uuid-1"
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String](),
            unsignedVPTokens: []
        )
        
        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "SD-JWT credential is not a String",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    // MARK: - Error: missing signing result for bound credential
    
    func testBuildThrowsWhenSigningResultMissingForBoundCredential() {
        let uuid = "uuid-with-binding"
        let unsignedKBJwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJpYXQiOjE3NTc0NzcxNjR9"
        
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "id1",
                identifier: uuid
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuid: unsignedKBJwt] as [String: String],
            unsignedVPTokens: []
        )
        
        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing VP token signing result for credential identifier uuid-with-binding",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    // MARK: - Error: empty signature for bound credential
    
    func testBuildThrowsWhenSignatureIsEmptyForBoundCredential() {
        let uuid = "uuid-with-binding"
        let unsignedKBJwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJpYXQiOjE3NTc0NzcxNjR9"
        
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "id1",
                identifier: uuid
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuid: unsignedKBJwt] as [String: String],
            unsignedVPTokens: [UnsignedVPToken(id: uuid, format: .vc_sd_jwt, holderKeyReference: "did:example:holder", signatureAlgorithm: SignatureAlgorithm.edDsa.rawValue, dataToSign: Data("eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJpYXQiOjE3NTc0NzcxNjR9".utf8))]
        )
        
        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: uuid, signedData: Data("".utf8))],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid signature for identifier uuid-with-binding",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    // MARK: - Mixed with three credentials: binding, no binding, binding
    
    func testBuildMixedThreeCredentials() throws {
        let uuid1 = "uuid-bound-1"
        let uuid2 = "uuid-unbound"
        let uuid3 = "uuid-bound-2"
        let unsignedKB1 = "eyJhbGciOiJFUzI1NiJ9.kb1"
        let unsignedKB2 = "eyJhbGciOiJFUzI1NiJ9.kb2"
        let sig1 = Data("sig1".utf8)
        let sig2 = Data("sig2".utf8)
        
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "desc1",
                identifier: uuid1
            ),
            CredentialInputDescriptorMapping(
                format: .dc_sd_jwt,
                credential: AnyCodable(credentialWithoutBinding),
                inputDescriptorId: "desc2",
                identifier: uuid2
            ),
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "desc3",
                identifier: uuid3
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuid1: unsignedKB1, uuid3: unsignedKB2] as [String: String],
            unsignedVPTokens: []
        )
        let signingResults = [
            VPTokenSigningResult(id: uuid1, signedData: sig1),
            VPTokenSigningResult(id: uuid3, signedData: sig2)
        ]
        
        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: signingResults,
            rootIndex: 3
        )
        
        XCTAssertEqual(result.vpTokens.count, 3)
        
        let token1 = try XCTUnwrap(result.vpTokens[0] as? SdJwtVPToken)
        XCTAssertEqual(token1.value, "\(credentialWithBinding)\(unsignedKB1).\(sig1.toBase64UrlEncoded())")
        
        let token2 = try XCTUnwrap(result.vpTokens[1] as? SdJwtVPToken)
        XCTAssertEqual(token2.value, credentialWithoutBinding)
        
        let token3 = try XCTUnwrap(result.vpTokens[2] as? SdJwtVPToken)
        XCTAssertEqual(token3.value, "\(credentialWithBinding)\(unsignedKB2).\(sig2.toBase64UrlEncoded())")
        
        XCTAssertEqual(result.DescriptorMaps[0].id, "desc1")
        XCTAssertEqual(result.DescriptorMaps[0].path, "$[3]")
        XCTAssertEqual(result.DescriptorMaps[0].format, .vc_sd_jwt)
        XCTAssertEqual(result.DescriptorMaps[1].id, "desc2")
        XCTAssertEqual(result.DescriptorMaps[1].path, "$[4]")
        XCTAssertEqual(result.DescriptorMaps[1].format, .dc_sd_jwt)
        XCTAssertEqual(result.DescriptorMaps[2].id, "desc3")
        XCTAssertEqual(result.DescriptorMaps[2].path, "$[5]")
        XCTAssertEqual(result.DescriptorMaps[2].format, .vc_sd_jwt)
        XCTAssertEqual(result.nextIndex, 6)
    }
    
    // MARK: - Empty mappings
    
    func testBuildWithEmptyMappings() throws {
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String](),
            unsignedVPTokens: []
        )
        
        let result = try builder.build(
            credentialInputDescriptorMappings: [],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )
        
        XCTAssertEqual(result.vpTokens.count, 0)
        XCTAssertEqual(result.DescriptorMaps.count, 0)
        XCTAssertEqual(result.nextIndex, 0)
    }
    
    // MARK: - build(credentialToCredentialQueryIdMappings:) — success paths
    
    func testDcqlBuildHolderBindingTrueProducesKBJwtAppendedToken() throws {
        let uuid = "uuid-bound"
        let unsignedKBJwt = "eyJhbGciOiJFUzI1NiJ9.kbpayload"
        let signature = Data("kbSig".utf8)
        
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        let mappings = [
            credentialQueryMapping(format: .dc_sd_jwt, credential: AnyCodable(credentialWithBinding), credentialQueryId: "q1", identifier: uuid)
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuid: unsignedKBJwt] as [String: String],
            unsignedVPTokens: []
        )
        
        let result = try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: uuid, signedData: signature)]
        )
        
        XCTAssertEqual(result.keys.sorted(), ["q1"])
        XCTAssertEqual(result["q1"]?.count, 1)
        let vpToken = try XCTUnwrap(result["q1"]?.first as? SdJwtVPToken)
        XCTAssertEqual(vpToken.value, "\(credentialWithBinding)\(unsignedKBJwt).\(signature.toBase64UrlEncoded())")
    }
    
    func testDcqlBuildHolderBindingFalseProducesBareCredentialToken() throws {
        let uuid = "uuid-unbound"
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: false)
        let mappings = [
            credentialQueryMapping(format: .dc_sd_jwt, credential: AnyCodable(credentialWithoutBinding), credentialQueryId: "q1", identifier: uuid)
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String]() as [String: String],
            unsignedVPTokens: []
        )
        
        let result = try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )
        
        XCTAssertEqual(result.keys.sorted(), ["q1"])
        XCTAssertEqual(result["q1"]?.count, 1)
        let vpToken = try XCTUnwrap(result["q1"]?.first as? SdJwtVPToken)
        XCTAssertEqual(vpToken.value, credentialWithoutBinding)
    }
    
    func testDcqlBuildMultipleCredentialsSameQueryIdAppendsAll() throws {
        let uuid1 = "uuid-1"
        let uuid2 = "uuid-2"
        let kb1 = "eyJhbGciOiJFUzI1NiJ9.kb1"
        let kb2 = "eyJhbGciOiJFUzI1NiJ9.kb2"
        let sig1 = Data("sig1".utf8)
        let sig2 = Data("sig2".utf8)
        
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        let mappings = [
            credentialQueryMapping(format: .dc_sd_jwt, credential: AnyCodable(credentialWithBinding), credentialQueryId: "q1", identifier: uuid1),
            credentialQueryMapping(format: .dc_sd_jwt, credential: AnyCodable(credentialWithBinding), credentialQueryId: "q1", identifier: uuid2)
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuid1: kb1, uuid2: kb2] as [String: String],
            unsignedVPTokens: []
        )
        
        let result = try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: uuid1, signedData: sig1), VPTokenSigningResult(id: uuid2, signedData: sig2)]
        )
        
        XCTAssertEqual(result.keys.sorted(), ["q1"])
        XCTAssertEqual(result["q1"]?.count, 2)
        let token1 = try XCTUnwrap(result["q1"]?[0] as? SdJwtVPToken)
        let token2 = try XCTUnwrap(result["q1"]?[1] as? SdJwtVPToken)
        XCTAssertEqual(token1.value, "\(credentialWithBinding)\(kb1).\(sig1.toBase64UrlEncoded())")
        XCTAssertEqual(token2.value, "\(credentialWithBinding)\(kb2).\(sig2.toBase64UrlEncoded())")
    }
    
    func testDcqlBuildMultipleDifferentQueryIdsProducesKeyedResult() throws {
        let uuid1 = "uuid-q1"
        let uuid2 = "uuid-q2"
        let kb1 = "eyJhbGciOiJFUzI1NiJ9.kb1"
        let sig1 = Data("sig1".utf8)
        
        let dcqlBuilder = builderWithDcqlRequest(
            credentials: [("q1", "dc+sd-jwt", true), ("q2", "dc+sd-jwt", false)]
        )
        let mappings = [
            credentialQueryMapping(format: .dc_sd_jwt, credential: AnyCodable(credentialWithBinding), credentialQueryId: "q1", identifier: uuid1),
            credentialQueryMapping(format: .dc_sd_jwt, credential: AnyCodable(credentialWithoutBinding), credentialQueryId: "q2", identifier: uuid2)
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuid1: kb1] as [String: String],
            unsignedVPTokens: []
        )
        
        let result = try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: uuid1, signedData: sig1)]
        )
        
        XCTAssertEqual(result.keys.sorted(), ["q1", "q2"])
        let token1 = try XCTUnwrap(result["q1"]?.first as? SdJwtVPToken)
        let token2 = try XCTUnwrap(result["q2"]?.first as? SdJwtVPToken)
        XCTAssertEqual(token1.value, "\(credentialWithBinding)\(kb1).\(sig1.toBase64UrlEncoded())")
        XCTAssertEqual(token2.value, credentialWithoutBinding)
    }
    
    func testDcqlBuildEmptyMappingsReturnsEmptyDict() throws {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: false)
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String]() as [String: String],
            unsignedVPTokens: []
        )
        
        let result = try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )
        
        XCTAssertEqual(result.count, 0)
    }
    
    // MARK: - build(credentialToCredentialQueryIdMappings:) — error paths
    
    func testDcqlBuildThrowsWhenPayloadIsNotStringDictionary() {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: false)
        let mappings = [
            credentialQueryMapping(format: .dc_sd_jwt, credential: AnyCodable(credentialWithoutBinding), credentialQueryId: "q1", identifier: "uuid-1")
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: ["uuid1": 1],
            unsignedVPTokens: []
        )
        
        XCTAssertThrowsError(try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing identifierToUnsignedKBT in payload",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testDcqlBuildThrowsWhenIdentifierIsNil() {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: false)
        let mappings = [
            credentialQueryMapping(format: .dc_sd_jwt, credential: AnyCodable(credentialWithoutBinding), credentialQueryId: "q1", identifier: nil)
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String]() as [String: String],
            unsignedVPTokens: []
        )
        
        XCTAssertThrowsError(try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "identifier is null in CredentialInputDescriptorMapping for SD-JWT",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testDcqlBuildThrowsWhenCredentialIsNotString() {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: false)
        let mappings = [
            credentialQueryMapping(format: .dc_sd_jwt, credential: AnyCodable(12345), credentialQueryId: "q1", identifier: "uuid-1")
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String]() as [String: String],
            unsignedVPTokens: []
        )
        
        XCTAssertThrowsError(try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "SD-JWT credential is not a String",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testDcqlBuildThrowsWhenMissingSigningResultForBoundCredential() {
        let uuid = "uuid-bound"
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        let mappings = [
            credentialQueryMapping(format: .dc_sd_jwt, credential: AnyCodable(credentialWithBinding), credentialQueryId: "q1", identifier: uuid)
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuid: "eyJhbGciOiJFUzI1NiJ9.kb"] as [String: String],
            unsignedVPTokens: []
        )
        
        XCTAssertThrowsError(try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing VP token signing result for credential identifier uuid-bound",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testDcqlBuildThrowsWhenSignatureIsEmptyForBoundCredential() {
        let uuid = "uuid-bound"
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        let mappings = [
            credentialQueryMapping(format: .dc_sd_jwt, credential: AnyCodable(credentialWithBinding), credentialQueryId: "q1", identifier: uuid)
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuid: "eyJhbGciOiJFUzI1NiJ9.kb"] as [String: String],
            unsignedVPTokens: []
        )
        
        XCTAssertThrowsError(try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(id: uuid, signedData: Data("".utf8))]
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid signature for identifier uuid-bound",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testDcqlBuildThrowsWhenUnexpectedKBJwtForUnboundCredential() {
        let uuid = "uuid-unbound"
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: false)
        let mappings = [
            credentialQueryMapping(format: .dc_sd_jwt, credential: AnyCodable(credentialWithoutBinding), credentialQueryId: "q1", identifier: uuid)
        ]
        let unsignedResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuid: "eyJhbGciOiJFUzI1NiJ9.unexpected"] as [String: String],
            unsignedVPTokens: []
        )
        
        XCTAssertThrowsError(try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing VP token signing result for credential identifier uuid-unbound",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    // MARK: - Helpers
    
    private func credentialQueryMapping(
        format: FormatType,
        credential: AnyCodable,
        credentialQueryId: String,
        identifier: String?
    ) -> CredentialToCredentialQueryIdMapping {
        var mapping = CredentialToCredentialQueryIdMapping(format: format, credential: credential, credentialQueryId: credentialQueryId)
        mapping.identifier = identifier
        return mapping
    }
    
    private func builderWithDcqlRequest(
        credentialQueryId: String,
        requireCryptographicHolderBinding: Bool
    ) -> SdJwtVPTokenBuilder {
        builderWithDcqlRequest(credentials: [(credentialQueryId, "dc+sd-jwt", requireCryptographicHolderBinding)])
    }
    
    private func builderWithDcqlRequest(
        credentials: [(id: String, format: String, requireCryptographicHolderBinding: Bool)]
    ) -> SdJwtVPTokenBuilder {
        let dcqlJson: [String: Any] = [
            "credentials": credentials.map { cred in
                [
                    "id": cred.id,
                    "format": cred.format,
                    "meta": [:] as [String: Any],
                    "require_cryptographic_holder_binding": cred.requireCryptographicHolderBinding
                ] as [String: Any]
            }
        ]
        let dcqlQuery = createInstance(dcqlJson, as: DCQLQuery.self)
        let authorizationRequest = AuthorizationDcqlRequest(
            clientId: "client_id",
            responseType: ResponseType.vp_token.rawValue,
            responseMode: ResponseMode.directPost.rawValue,
            responseUri: "https://mock-verifier.com",
            redirectUri: nil,
            nonce: "nonce",
            walletNonce: nil,
            state: "state",
            dcqlQuery: dcqlQuery,
            clientMetadata: nil
        )
        return SdJwtVPTokenBuilder(authorizationRequest: authorizationRequest)
    }
}
