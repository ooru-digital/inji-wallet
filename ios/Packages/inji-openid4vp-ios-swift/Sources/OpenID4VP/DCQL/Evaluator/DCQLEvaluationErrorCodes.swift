public enum DCQLEvaluationErrorCodes : String {
    case noMatchingFormatsFound = "no_matching_credentials_with_requested_credential_formats_found"
    case cryptographicHolderBindingOrMetaFilterMismatch = "cryptographic_holderbinding_or_meta_filter_mismatch"
    case noClaimsSetOptionSatisfied = "no_claims_set_option_satisfied"
    
    case claimUnavailable = "claim_unavailable"
    case claimValueMismatch = "claim_value_not_matching"
    
    case requiredClaimsNotSatisfied = "required_claims_not_satisfied"
}
