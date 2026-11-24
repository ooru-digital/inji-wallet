import Foundation

struct ResponseModeBasedHandlerFactory {
    static let className = String(describing: ResponseModeBasedHandlerFactory.self)
    
    static func get(responseMode: String?) throws -> ResponseModeBasedHandler {
        switch responseMode {
        case ResponseMode.directPost.rawValue,
             ResponseMode.iarPost.rawValue,
             ResponseMode.iaePost.rawValue:
            return DirectPostResponseModeHandler()

        case ResponseMode.directPostJwt.rawValue,
             ResponseMode.iarPostJwt.rawValue,
             ResponseMode.iaePostJwt.rawValue:
            return DirectPostJwtResponseModeHandler()

        default:
            throw InvalidData(
                message: "Given response_mode - \(responseMode ?? "nil") is not supported",
                className: className,
                code: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
