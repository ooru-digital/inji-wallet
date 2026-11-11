import Foundation

enum NetworkRequestException: Error, LocalizedError {
    case invalidResponse(message: String)
    case networkRequestFailed(message: String)
    case networkRequestTimeout
    case urlCreationFailed(message: String)
    case invalidInput(message: String)
    
    public var errorDescription: String? {
        switch self {
        case .networkRequestFailed(let message):
            return "Network request failed with error response - \(message)"
        case .invalidResponse(let message):
            return message
        case .networkRequestTimeout:
            return "VP sharing failed due to connection timeout"
        case .urlCreationFailed(let message):
            return message
        case .invalidInput(let message):
            return message
        }
    }
}
