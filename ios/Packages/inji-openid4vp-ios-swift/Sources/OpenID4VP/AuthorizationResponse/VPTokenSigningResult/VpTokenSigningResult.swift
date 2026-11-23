import Foundation

public struct VPTokenSigningResult: Codable {

    public let id: String
    public let signedData: Data

    public init(id: String, signedData: Data) {
        self.id = id
        self.signedData = signedData
    }
}
