import Foundation

public struct LdpVPTokenSigningResult: VPTokenSigningResult {
    var jws: String?
    let proofValue: String?
    let signatureAlgorithm: String
    
    public init(jws: String? = nil, proofValue: String?, signatureAlgorithm: String) {
        self.jws = jws
        self.proofValue = proofValue
        self.signatureAlgorithm = signatureAlgorithm
    }

    static let className = String(describing: LdpVPTokenSigningResult.self)

    func validate() throws {
        switch signatureAlgorithm {
        case SignatureAlgorithm.ed25519Signature2020.rawValue:
            guard let proofValue = proofValue, !proofValue.isEmpty else {
                throw InvalidInput(
                    fieldPath: ["LdpVPTokenSigningResult", "proofValue"],
                    className: LdpVPTokenSigningResult.className
                )
            }

        case SignatureAlgorithm.jsonWebSignature2020.rawValue,
            SignatureAlgorithm.rsaSignature2018.rawValue,
            SignatureAlgorithm.ed25519Signature2018.rawValue:
            guard let jws = jws, !jws.isEmpty else {
                throw InvalidInput(
                    fieldPath: ["LdpVPTokenSigningResult", "jws"],
                    className: LdpVPTokenSigningResult.className
                )
            }

        default:
            throw UnsupportedSignatureAlgorithm(
                message: "Unsupported algorithm: \(signatureAlgorithm)",
                className: LdpVPTokenSigningResult.className
            )
        }
    }
}
