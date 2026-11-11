import Foundation
import Alamofire

public protocol NetworkManaging {
    func sendHTTPRequest(
        url: String,
        method: HttpMethod,
        bodyParams: [String: String]?,
        headers: [String: String]?
    ) async throws -> NetworkResponse
}
