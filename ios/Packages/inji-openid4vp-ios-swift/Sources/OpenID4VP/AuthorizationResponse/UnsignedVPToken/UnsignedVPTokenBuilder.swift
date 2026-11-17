import Foundation

typealias VPTokenSigningPayload = LdpVPToken

protocol UnsignedVPTokenBuilder {
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (vpTokenSigningPayload: VPTokenSigningPayload?, unsignedVPToken : UnsignedVPToken)
}
