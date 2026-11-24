import Foundation

class VPTokenFactory {
    static let className = String(describing: VPTokenFactory.self)
    
    static func getVPTokenBuilder(authorizationRequest: AuthorizationRequest, credentialFormat: FormatType) throws -> VPTokenBuilder {
        switch credentialFormat {
        case .ldp_vc:
            return LdpVPTokenBuilder(authorizationRequest: authorizationRequest)

        case .mso_mdoc:
            return MdocVPTokenBuilder(authorizationRequest: authorizationRequest)

        case .dc_sd_jwt, .vc_sd_jwt:
            return SdJwtVPTokenBuilder(authorizationRequest: authorizationRequest)
        }
    }
}

