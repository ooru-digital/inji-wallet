import SwiftCBOR
import Foundation

public struct UnsignedSdJwtVPToken: Codable, UnsignedVPToken {
    let uuidToUnsignedKBT : [String : String]
}
