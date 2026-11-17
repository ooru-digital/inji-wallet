import Foundation

public struct SdJwtVpTokenSigningResult : VPTokenSigningResult {
    let uuidToKbJWTSignature : [String: String]
    
    public init(uuidToKbJWTSignature: [String : String]) {
        self.uuidToKbJWTSignature = uuidToKbJWTSignature
    }
}
