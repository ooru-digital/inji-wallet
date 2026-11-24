public struct MatchingCredentialsResult : Codable {
    public let success: Bool
    /// Results for each individual credential query, keyed by the `id` provided in the request.
    public let queryMatches: [String: QueryMatchResult]
    /// Logical groupings (AND/OR) of which queries must be satisfied to complete the presentation.
    public let credentialSets: [CredentialSetQuery]
    
    public init(success: Bool, queryMatches: [String: QueryMatchResult], credentialSets: [CredentialSetQuery]) {
        self.success = success
        self.queryMatches = queryMatches
        self.credentialSets = credentialSets
    }
}

public struct QueryMatchResult: Codable {
    /// List of credentials that satisfy the query. Populated only if credentials are matching, otherwise `nil`.
    public let matchingCredentials: [MatchingCredential]?
    /// Reason of failure related to the claims requested by the Verifier. Populated only if no credentials match.
    public let failedClaims: [ClaimFailure]?
    /// Reason of failure related to the evaluation of the DCQL query, such as requested credential format,
    /// cryptographic holder binding, or meta not matching any credential in the wallet. Populated only if no credentials match.
    public let failureReason: String?
    /// `true` if the user can select more than one credential to satisfy this specific query.
    public let allowMultipleCredentials: Bool
    
    public init(matchingCredentials: [MatchingCredential]? = nil, failedClaims: [ClaimFailure]? = nil,failureReason: DCQLEvaluationErrorCodes? = nil , allowMultipleCredentials: Bool = false) {
        self.matchingCredentials = matchingCredentials
        self.failedClaims = failedClaims
        self.failureReason = failureReason?.rawValue
        self.allowMultipleCredentials = allowMultipleCredentials
    }
    
    private enum CodingKeys: String, CodingKey {
        case matchingCredentials
        case failedClaims
        case failureReason
        case allowMultipleCredentials
    }
}

public struct MatchingCredential: Codable {
    public let credentialId: String
    public let matchingClaims: [ClaimsQuery]
    
    public init(credentialId: String, matchingClaims: [ClaimsQuery]) {
        self.credentialId = credentialId
        self.matchingClaims = matchingClaims
    }
}

public struct ClaimFailure: Codable {
    public let claim: ClaimsQuery
    public let reason: String
    
    public init(claim: ClaimsQuery, reason: DCQLEvaluationErrorCodes) {
        self.claim = claim
        self.reason = reason.rawValue
    }
    
    private enum CodingKeys: String, CodingKey {
        case claim
        case reason
    }
}
