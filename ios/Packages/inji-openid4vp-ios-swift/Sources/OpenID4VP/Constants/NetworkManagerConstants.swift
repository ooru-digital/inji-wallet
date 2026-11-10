import Foundation
import Alamofire

public typealias HttpMethod = HTTPMethod

enum Header : String {
    case contentType = "Content-Type"
    case accept = "Accept"
}


public enum ContentTypes : String {
    case applicationJwt = "application/oauth-authz-req+jwt"
    case applicationFormUrlEncoded = "application/x-www-form-urlencoded"
}


public enum StatusCodes : Int {
    case ok = 200
    case multipleChoices = 300
}
