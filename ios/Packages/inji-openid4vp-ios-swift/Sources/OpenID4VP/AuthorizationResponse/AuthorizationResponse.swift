import Foundation

struct AuthorizationResponse {
    let vpToken: VPTokenType
    let presentationSubmission: PresentationSubmission
    let state: String?

    static let className = String(describing: AuthorizationResponse.self)

    func toJsonEncodedMap() throws -> [String: String] {
        var bodyParams: [String: String] = [:]

        bodyParams["vp_token"] = try vpToken.encodedString(fieldName: "vp_token", className: Self.className)
        bodyParams["presentation_submission"] = try encode(
            presentationSubmission,
            fieldName: "presentation_submission",
            className: Self.className
        )

        if let state = state {
            bodyParams["state"] = state
        }

        return bodyParams
    }
}


public struct AnyEncodable: Encodable {
    private let _encode: (Encoder) throws -> Void

    public init<T: Encodable>(_ value: T) {
        self._encode = value.encode
    }

    public func encode(to encoder: Encoder) throws {
        try _encode(encoder)
    }
}



public enum VPTokenType {
    case vpTokenArray([VPToken])
    case vpTokenElement(VPToken)

    func encodedString(fieldName: String, className: String) throws -> String {
        switch self {
        case .vpTokenArray(let tokens):
            let wrapped = tokens.map { AnyEncodable($0) }
            return try encode(wrapped, fieldName: fieldName, className: className)
        case .vpTokenElement(let token):
            return try encode(AnyEncodable(token), fieldName: fieldName, className: className)
        }
    }
}
