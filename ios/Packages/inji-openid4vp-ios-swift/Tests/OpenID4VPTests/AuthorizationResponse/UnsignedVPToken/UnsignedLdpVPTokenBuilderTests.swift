import XCTest
@testable import OpenID4VP

final class UnsignedLdpVPTokenBuilderTests: XCTestCase {

    func testCreationOfUnsignedLdpVPToken() async throws {
       
        let vc = ldpVC()
        
        let builder = UnsignedLdpVPTokenBuilder(
            id: "ebc6f1c2",
            holder: "did:example:wallet",
            challenge: "test-challenge",
            domain: "test-domain",
            signatureSuite: SignatureAlgorithm.ed25519Signature2020.rawValue
        )
        var credentialInputDescriptorMappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(vc), inputDescriptorId: "cred-input-1")
        ]
   
        let (payload, unsignedVPToken) = try await builder.build(
            credentialInputDescriptorMappings: &credentialInputDescriptorMappings
        )
        
       
        let token = payload as! LdpVPToken

        XCTAssertEqual(token.context, [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ])
        XCTAssertEqual(token.type, ["VerifiablePresentation"])
        XCTAssertEqual(token.id, "ebc6f1c2")
        XCTAssertEqual(token.holder, "did:example:wallet")
        XCTAssertEqual(token.verifiableCredential.count, 1)
        assertJsonString(expected: "{\"holder\":\"did:example:wallet\",\"type\":[\"VerifiablePresentation\"],\"@context\":[\"https:\\/\\/www.w3.org\\/2018\\/credentials\\/v1\",\"https:\\/\\/w3id.org\\/security\\/suites\\/ed25519-2020\\/v1\"],\"id\":\"ebc6f1c2\",\"verifiableCredential\":[{\"type\":[\"VerifiableCredential\"],\"issuanceDate\":\"2020-08-19T21:41:50Z\",\"credentialSubject\":{\"id\":\"did:example:subject\"},\"@context\":[\"https:\\/\\/www.w3.org\\/2018\\/credentials\\/v1\"],\"issuer\":\"did:example:issuer\"}],\"proof\":{\"verificationMethod\":\"did:example:wallet\",\"challenge\":\"test-challenge\",\"domain\":\"test-domain\",\"type\":\"Ed25519Signature2020\"}}", actual: (unsignedVPToken as! UnsignedLdpVPToken).dataToSign)
    }

    func testCreationOfUnsignedLdpVPTokenWithDifferentSignatureSuite() async throws {
       
        let vc = ldpVC()
        
        let builder = UnsignedLdpVPTokenBuilder(
            id: "ebc6f1c2",
            holder: "did:example:wallet",
            challenge: "test-challenge",
            domain: "test-domain",
            signatureSuite: SignatureAlgorithm.jsonWebSignature2020.rawValue
        )
        var credentialInputDescriptorMappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(vc), inputDescriptorId: "cred-input-1")
        ]
   
        let (payload, unsignedVPToken) = try await builder.build(
            credentialInputDescriptorMappings: &credentialInputDescriptorMappings
        )
        
       
        let token = payload as! LdpVPToken

        XCTAssertEqual(token.context, [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ])
        XCTAssertEqual(token.type, ["VerifiablePresentation"])
        XCTAssertEqual(token.id, "ebc6f1c2")
        XCTAssertEqual(token.holder, "did:example:wallet")
        XCTAssertEqual(token.verifiableCredential.count, 1)
        assertJsonString(expected: "{\"holder\":\"did:example:wallet\",\"type\":[\"VerifiablePresentation\"],\"@context\":[\"https:\\/\\/www.w3.org\\/2018\\/credentials\\/v1\",\"https:\\/\\/w3id.org\\/security\\/suites\\/jws-2020\\/v1\"],\"id\":\"ebc6f1c2\",\"verifiableCredential\":[{\"type\":[\"VerifiableCredential\"],\"issuanceDate\":\"2020-08-19T21:41:50Z\",\"credentialSubject\":{\"id\":\"did:example:subject\"},\"@context\":[\"https:\\/\\/www.w3.org\\/2018\\/credentials\\/v1\"],\"issuer\":\"did:example:issuer\"}],\"proof\":{\"verificationMethod\":\"did:example:wallet\",\"challenge\":\"test-challenge\",\"domain\":\"test-domain\",\"type\":\"JsonWebSignature2020\"}}", actual: (unsignedVPToken as! UnsignedLdpVPToken).dataToSign)
    }


    private func ldpVC() -> [String: Any] {
        return [
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "issuer": "did:example:issuer",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": ["id": "did:example:subject"]
        ]
    }
}
