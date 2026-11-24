import Foundation

public final class DCQLHelper {
    private static let className = String(describing: DCQLHelper.self)
    
    private let jsonLdExpander: JsonLdExpanderCallback?
    
    public init(jsonLdExpander: JsonLdExpanderCallback? = nil) {
        self.jsonLdExpander = jsonLdExpander
    }
    
    public func getMatchingCredentials(inputCredentials: [Credential], dcqlQuery: DCQLQuery) async throws -> MatchingCredentialsResult {
        return try await DcqlEvaluator(jsonLdExpander: jsonLdExpander).evaluate(dcqlQuery, inputCredentials: inputCredentials)
    }
}

