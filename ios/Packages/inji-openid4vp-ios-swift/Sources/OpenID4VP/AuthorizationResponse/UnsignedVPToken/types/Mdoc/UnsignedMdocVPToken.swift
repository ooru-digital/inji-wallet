import SwiftCBOR
import Foundation

struct UnsignedMdocVPToken: Codable, UnsignedVPToken {
    // map of docType to deviceAuthenticationBytes which will be used as payload for signing
    let docTypeToDeviceAuthenticationBytes : [String : String]
}
