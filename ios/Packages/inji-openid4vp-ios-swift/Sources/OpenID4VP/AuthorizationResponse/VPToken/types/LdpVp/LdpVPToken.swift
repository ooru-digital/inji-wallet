struct LdpVPToken: Encodable, VPToken {
    let context: [String]
    let type: [String]
    let verifiableCredential: [AnyCodable]
    let id: String
    let holder: String
    var proof: Proof?

    init(
        context: [String] = ["https://www.w3.org/2018/credentials/v1"],
        type: [String] = ["VerifiablePresentation"],
        verifiableCredential: [AnyCodable],
        id: String,
        holder: String,
        proof: Proof
    ) {
        self.context = context
        self.type = type
        self.verifiableCredential = verifiableCredential
        self.id = id
        self.holder = holder
        self.proof = proof
    }

    enum CodingKeys: String, CodingKey {
        case context = "@context"
        case type
        case verifiableCredential
        case id
        case holder
        case proof
    }
}
