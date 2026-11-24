import Foundation

public enum ResponseMode: String {
    case directPost = "direct_post"
    case directPostJwt = "direct_post.jwt"

    // Backward compatible response modes
    case iarPost = "iar-post"
    case iarPostJwt = "iar-post.jwt"

    // OpenID4VCI 1.1 (IAE)
    case iaePost = "iae_post"
    case iaePostJwt = "iae_post.jwt"
}
