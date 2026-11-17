import Foundation

public enum VPFormatType: String, Codable {
    case ldp_vp = "ldp_vp"
    case ldp_vc = "ldp_vc"
    case mso_mdoc = "mso_mdoc"
    case dc_sd_jwt = "dc+sd-jwt"
    case vc_sd_jwt = "vc+sd-jwt"
    
    public static func fromValue(_ value: String) -> VPFormatType? {
        return VPFormatType(rawValue: value)
    }
}
