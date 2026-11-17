import Foundation

public struct UnsignedVPTokenV2: Codable {

    public let format: FormatType
    public let holderKeyReference: String
    public let signatureAlgorithm: String
    public let dataToSign: String

    public init(
        format: FormatType,
        holderKeyReference: String,
        signatureAlgorithm: String,
        dataToSign: String
    ) {
        self.format = format
        self.holderKeyReference = holderKeyReference
        self.signatureAlgorithm = signatureAlgorithm
        self.dataToSign = dataToSign
    }
}
