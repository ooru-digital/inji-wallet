import Foundation

struct Proof: Encodable {
    let type: String
    let created: String?
    let challenge: String
    let domain: String
    var jws: String? = nil
    var proofPurpose: ProofPurpose? = nil
    var verificationMethod: String
    var proofValue: String? = nil

    @available(*, deprecated, message: "Use VPResponseMetadata to construct Proof")
    static func construct(
        from vpResponseMetadata: VPResponseMetadata,
        challenge: String
    ) -> Proof {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        let createdDateAndTime = formatter.string(from: Date())

        return Proof(
            type: vpResponseMetadata.signatureAlgorithm,
            created: createdDateAndTime,
            challenge: challenge,
            domain: vpResponseMetadata.domain,
            verificationMethod: vpResponseMetadata.publicKey, proofValue: vpResponseMetadata.jws
        )
    }
}
