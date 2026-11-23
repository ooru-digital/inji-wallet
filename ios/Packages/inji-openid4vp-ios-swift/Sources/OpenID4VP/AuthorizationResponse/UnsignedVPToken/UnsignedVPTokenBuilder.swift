import Foundation

typealias VPTokenSigningPayload = [String: Any]

protocol UnsignedVPTokenBuilder {
    var specVersion: SpecVersion { get }
    var authorizationRequest: AuthorizationRequest { get }
    var walletConfig: WalletConfig { get }
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken])
    
    func build(credentialToCredentialQueryIdMappings: inout [CredentialToCredentialQueryIdMapping]) async throws -> (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken])
}
