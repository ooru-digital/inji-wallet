
public enum OpenID4VPErrorCodes {
    static let newUnknown = "new_unknown"
    static let invalidRequest = "invalid_request"
    static let invalidRequestObject = "invalid_request_object"
    static let invalidClient = "invalid_client"
    static let invalidScope = "invalid_scope"
    static let invalidPresentationDefinitionUri = "invalid_presentation_definition_uri"
    static let vpFormatsNotSupported = "vp_formats_not_supported"
    static let invalidPresentationDefinitionReference = "invalid_presentation_definition_reference"
    static let invalidRequestUriMethod = "invalid_request_uri_method"
    public static let invalidTransactionData = "invalid_transaction_data"
    public static let accessDenied = "access_denied"
    public static let serverError = "server_error"
    
    // custom error codes
    public static let errorDispatchFailure = "error_dispatch_failure"
}
