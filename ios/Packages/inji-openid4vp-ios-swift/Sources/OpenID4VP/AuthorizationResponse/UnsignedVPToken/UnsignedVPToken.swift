import Foundation

public struct UnsignedVPToken: Codable {
    public let id: String
    public let format: FormatType
    public let holderKeyReference: String
    public let signatureAlgorithm: String
    // Base64 encoded byte array of the actual data to sign
    public let dataToSign: Data

    public init(
        id: String,
        format: FormatType,
        holderKeyReference: String,
        signatureAlgorithm: String,
        dataToSign: Data
    ) {
        self.id = id
        self.format = format
        self.holderKeyReference = holderKeyReference
        self.signatureAlgorithm = signatureAlgorithm
        self.dataToSign = dataToSign
    }
}

