import Foundation

class VPTokenFactory {
    static let className = String(describing: VPTokenFactory.self)
    
    static func getVPTokenBuilder(credentialFormat: FormatType) throws -> VPTokenBuilder {
        switch credentialFormat {
        case .ldp_vc:
            return LdpVPTokenBuilder()
            
        case .mso_mdoc:
            return MdocVPTokenBuilder()
            
        case .dc_sd_jwt, .vc_sd_jwt:
            return SdJwtVPTokenBuilder()
            
        default:
            throw UnsupportedOperationException(
                message: "Unsupported credential format: \(credentialFormat.rawValue)",
                className: VPTokenFactory.className,
                code: "UNSUPPORTED_CREDENTIAL_FORMAT"
            )
        }
    }
}

