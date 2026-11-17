import Foundation
@testable import OpenID4VP

class MockNetworkManager: NetworkManaging {
    private var mockResponses: [URL: (response: (responseBody: String, httpUrlResponse: HTTPURLResponse)?, error: Error?)] = [:]
    
    var recordedRequests: [String: (
        requestMethod: HttpMethod,
        requestBody: [String: String]?,
        requestHeaders: [String: String]?
    )] = [:]
    
    func setMockResponse(
        for urlString: String,
        response: (responseBody: String, httpUrlResponse: HTTPURLResponse?)? = nil,
        responseBody: String? = nil,
        statusCode: Int? = nil,
        error: Error? = nil
    ) {
        guard let url = URL(string: urlString) else {
            print("invalid url provided so mocking is not done here")
            return
        }

        let defaultHttpUrlResponse = HTTPURLResponse(
            url: url,
            statusCode: statusCode ?? 200,
            httpVersion: "",
            headerFields: ["Content-Type": "application/json"]
        )!

        var finalResponse: (responseBody: String, httpUrlResponse: HTTPURLResponse)?

        if let response = response {
            let urlResponse = response.httpUrlResponse ?? defaultHttpUrlResponse
            finalResponse = (responseBody: response.responseBody, httpUrlResponse: urlResponse)
        } else if let responseBody = responseBody {
            finalResponse = (responseBody: responseBody, httpUrlResponse: defaultHttpUrlResponse)
        }

        mockResponses[url] = (finalResponse, error)
    }
    
    func clearResponses() {
        mockResponses = [:]
        recordedRequests = [:]
    }
    
    public func sendHTTPRequest(
        url: String,
        method: HttpMethod,
        bodyParams: [String: String]? = nil,
        headers: [String: String]? = nil
    ) async throws -> NetworkResponse {
        recordedRequests[url] = (
            requestMethod: method,
            requestBody: bodyParams,
            requestHeaders: headers
        )
        guard let url = URL(string: url) else {
            fatalError("url creation failed with input string")
        }
        let defaultHttpUrlResponse = HTTPURLResponse(
            url: url,
            statusCode: 200,
            httpVersion: "",
            headerFields: ["Content-Type": "text/json"]
        )!
        if let (response, error) = mockResponses[url] {
            if let error = error {
                throw error
            }
            let resp = response ?? (
                responseBody: "Success: Request completed successfully.",
                httpUrlResponse: defaultHttpUrlResponse
            )
            return NetworkResponse(
                statusCode: resp.httpUrlResponse.statusCode,
                body: resp.responseBody,
                headers: resp.httpUrlResponse.headers.dictionary
            )
        }
        return NetworkResponse(
            statusCode: defaultHttpUrlResponse.statusCode,
            body: "Success: Request completed successfully.",
            headers: defaultHttpUrlResponse.headers.dictionary
        )
    }
}
