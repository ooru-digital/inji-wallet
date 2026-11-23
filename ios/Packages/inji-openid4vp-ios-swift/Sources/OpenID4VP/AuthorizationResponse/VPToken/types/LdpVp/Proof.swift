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
    var signatureValue: String? = nil
    var cryptosuite: String? = nil
}
