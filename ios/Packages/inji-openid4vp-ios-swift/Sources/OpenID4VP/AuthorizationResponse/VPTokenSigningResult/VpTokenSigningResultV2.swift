import Foundation

public struct VPTokenSigningResultV2: Codable {

    public let signedData: String

    public init(signedData: String) {
        self.signedData = signedData
    }
}
