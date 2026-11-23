import Foundation

fileprivate let className = String(describing: AuthorizationResponse.self)

enum AuthorizationResponse {
    // Spec v1.0 compliant : DCQL structure
    case dcql(vpToken: [String: [VPToken]], state: String?)
    
    // Draft 23 compliant: DIF Presentation Exchange structure
    case presentationExchange(vpToken: VPTokenType, presentationSubmission: PresentationSubmission, state: String?)
    
    func payloadData() throws -> Data {
           var payload: [String: Any] = [:]

           switch self {

           case .dcql(let vpToken, let state):
               let encodableMap = vpToken.mapValues { tokens in
                   tokens.map { AnyEncodable($0) }
               }

               let vpTokenData = try JSON.encoder.encode(encodableMap)
               payload["vp_token"] = try JSONSerialization.jsonObject(with: vpTokenData)

               if let state {
                   payload["state"] = state
               }

           case .presentationExchange(let vpToken,
                                      let presentationSubmission,
                                      let state):

               switch vpToken {

               case .vpTokenArray(let tokens):
                   let data = try JSON.encoder.encode(tokens.map { AnyEncodable($0) })
                   payload["vp_token"] = try JSONSerialization.jsonObject(with: data)

               case .vpTokenElement(let token):
                   let data = try JSON.encoder.encode(AnyEncodable(token))
                   payload["vp_token"] = try JSONSerialization.jsonObject(with: data)
               }

               let psData = try JSON.encoder.encode(presentationSubmission)
               payload["presentation_submission"] = try JSONSerialization.jsonObject(with: psData)

               if let state {
                   payload["state"] = state
               }
           }

           return try JSONSerialization.data(
               withJSONObject: payload,
               options: []
           )
       }
    
    func toJsonEncodedMap() throws -> [String: String] {
        var jsonEncodedAuthorizationResponse: [String: String] = [:]
        
        switch self {
        case .dcql(let vpToken, let state):
            let encodableMap = vpToken.mapValues { tokens in tokens.map { AnyEncodable($0) } }
            jsonEncodedAuthorizationResponse["vp_token"] = try encode(encodableMap, fieldName: "vp_token", className: className)
            if let state = state { jsonEncodedAuthorizationResponse["state"] = state }
            
        case .presentationExchange(let vpToken, let presentationSubmission, let state):
            jsonEncodedAuthorizationResponse["vp_token"] = try vpToken.encodedString(fieldName: "vp_token", className: className)
            jsonEncodedAuthorizationResponse["presentation_submission"] = try encode(
                presentationSubmission,
                fieldName: "presentation_submission",
                className: className
            )
            
            if let state = state {
                jsonEncodedAuthorizationResponse["state"] = state
            }
        }
        
        return jsonEncodedAuthorizationResponse
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
