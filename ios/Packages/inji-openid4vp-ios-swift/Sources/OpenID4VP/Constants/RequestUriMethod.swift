internal enum RequestUriMethod: String, Codable {
    case get = "get"
    case post = "post"
    
    func toHttpMethod() -> HttpMethod {
        switch self {
        case .post:
            return .post
        case .get:
            return .get
        }
    }
}
