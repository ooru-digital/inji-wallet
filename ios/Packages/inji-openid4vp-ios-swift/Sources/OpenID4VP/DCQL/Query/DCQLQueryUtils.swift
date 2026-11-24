import Foundation

fileprivate let className = "DcqlQueryParser"

fileprivate let dcqlQueryKey = AuthorizationRequestFieldConstants.dcqlQuery

func parseAndValidateDcqlQuery(
    _ authorizationRequest: [String: Any]
) throws -> [String: Any] {
    if let dcqlQuery = authorizationRequest[dcqlQueryKey] {
        if authorizationRequest[AuthorizationRequestFieldConstants.scope] != nil {
            throw InvalidData(
                message: "The request contains both a dcql_query parameter and a scope parameter",
                className: className
            )
        }
        
        var modifiedAuthorizationRequest = authorizationRequest
        
        if let dcqlQueryAsString = dcqlQuery as? String {
            modifiedAuthorizationRequest[dcqlQueryKey] = try convertToInstance(dcqlQueryAsString, as: DCQLQuery.self)
        } else if let dcqlQueryAsDictionary = dcqlQuery as? [String: Any] {
            modifiedAuthorizationRequest[dcqlQueryKey] = try convertToInstance(dcqlQueryAsDictionary, as: DCQLQuery.self)
        } else {
            throw InvalidData(
                message: "The dcql_query parameter must be a string or a JSON object",
                className: className
            )
        }
        
        
        return modifiedAuthorizationRequest
    }
    
    throw InvalidInput(
        fieldPath: ["authorizationRequest", dcqlQueryKey],
        className: className
    )
}
