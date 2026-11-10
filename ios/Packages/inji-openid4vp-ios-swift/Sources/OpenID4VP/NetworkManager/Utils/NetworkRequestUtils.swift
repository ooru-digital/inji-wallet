import Foundation
import UniformTypeIdentifiers

extension HTTPURLResponse {
    func isHeaderContentType(equalTo expectedvalue: String) -> Bool {
        let contentType = self.value(forHTTPHeaderField: Header.contentType.rawValue)
        let mediaType = contentType?.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: true).first?.trimmingCharacters(in: .whitespaces)
        return mediaType == expectedvalue
    }
}
