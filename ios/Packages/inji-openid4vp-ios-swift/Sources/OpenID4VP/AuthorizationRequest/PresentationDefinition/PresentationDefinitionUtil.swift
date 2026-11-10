import Foundation

fileprivate let className = "PresentationDefinitionUtil"

func parseAndValidatePresentationDefinition(
    _ authorizationRequest: [String: Any],
    _ isPresentationDefinitionUriSupported: Bool,
    _ networkManager: NetworkManaging
) async throws -> [String: Any] {
    
    let hasPresentationDefinition = authorizationRequest.keys.contains("presentation_definition")
    let hasPresentationDefinitionUri = authorizationRequest.keys.contains("presentation_definition_uri")
    var finalPresentationDefinition: PresentationDefinition

    if hasPresentationDefinition && hasPresentationDefinitionUri {
        throw InvalidData(
            message: "Either presentation_definition or presentation_definition_uri request param can be provided but not both",
            className: AuthorizationRequest.className
        )
    }

    if !hasPresentationDefinition && !hasPresentationDefinitionUri {
        throw InvalidData(
            message: "Either presentation_definition or presentation_definition_uri request param must be present",
            className: AuthorizationRequest.className
        )
    }
    
    
    if hasPresentationDefinition, let value = authorizationRequest["presentation_definition"] {
        if let presentationDefinitionString = value as? String {
            //Presentation Definition is of type String when auth request obtained by value
            guard let valueStr = getStringValue(presentationDefinitionString), isNeitherNullNorEmpty(field: valueStr), valueStr != "null" else {
                throw InvalidInput(
                    fieldPath: ["presentation_definition"],
                    className: AuthorizationRequest.className
                )
            }
            
            finalPresentationDefinition = try convertToInstance(valueStr, as: PresentationDefinition.self, fieldPath: [AuthorizationRequestFieldConstants.presentationDefinition.rawValue], className: AuthorizationRequest.className)
        } else if let presentationDefinitionJson = value as? [String: Any] {
            //Presentation Definition is of type Dictionary when auth request obtained by reference
            do {
                finalPresentationDefinition = try convertToInstance(presentationDefinitionJson, as: PresentationDefinition.self)
            } catch {
                throw InvalidData(
                    message: "presentation_definition data is not valid",
                    className: AuthorizationRequest.className,
                    code: OpenID4VPErrorCodes.invalidPresentationDefinitionReference
                )
            }
        } else {
            throw InvalidData(
                message: "presentation_definition data is not valid",
                className: AuthorizationRequest.className,
                code: OpenID4VPErrorCodes.invalidPresentationDefinitionReference
            )
        }
    } else if hasPresentationDefinitionUri, let uriValue = authorizationRequest[AuthorizationRequestFieldConstants.presentationDefinitionUri.rawValue] {
        
        if !isPresentationDefinitionUriSupported {
            throw InvalidData(
                message: "presentation_definition_uri is not supported",
                className: AuthorizationRequest.className,
                code: OpenID4VPErrorCodes.invalidPresentationDefinitionReference
            )
        }
        
        guard let uriString = getStringValue(uriValue),
              isNeitherNullNorEmpty(field: uriString),
              uriString != "null" else {
            throw InvalidInput(
                fieldPath: [AuthorizationRequestFieldConstants.presentationDefinitionUri.rawValue],
                className: AuthorizationRequest.className
            )
        }
        
        guard isValidUri(uriString) else {
            throw InvalidData(
                message: "presentation_definition_uri is not valid",
                className: AuthorizationRequest.className,
                code: OpenID4VPErrorCodes.invalidPresentationDefinitionUri
            )
        }
        
        let response: NetworkResponse
        do {
            response = try await networkManager.sendHTTPRequest(
                url: uriString, method: .get, bodyParams: nil, headers: nil
            )
            if(!response.isOK){
                throw InvalidData(
                    message: "Error while fetching presentation_definition from presentation_definition_uri: \(uriString), status code: \(response.statusCode) with body: \(response.body)",
                    className: AuthorizationRequest.className
                )
            }
        } catch {
            throw InvalidData(
                message: "presentation_definition_uri could not be reached: \(uriString)",
                className: AuthorizationRequest.className,
                code: OpenID4VPErrorCodes.invalidPresentationDefinitionUri
            )
        }
        
        guard let data = response.body.data(using: .utf8) else {
            throw InvalidData(
                message: "presentation_definition_uri response body is not valid",
                className: AuthorizationRequest.className,
                code: OpenID4VPErrorCodes.invalidPresentationDefinitionReference
            )
        }
        
        do {
            finalPresentationDefinition = try data.toInstance(as: PresentationDefinition.self)
        } catch {
            throw InvalidData(
                message: "presentation_definition_uri did not contain valid presentation_definition",
                className: AuthorizationRequest.className,
                code: OpenID4VPErrorCodes.invalidPresentationDefinitionReference
            )
        }

        
    } else {
        throw InvalidData(
            message: "Either presentation_definition or presentation_definition_uri request param must be present",
            className: AuthorizationRequest.className
        )
    }
    
    let responseMode = getStringValue(authorizationRequest[AuthorizationRequestFieldConstants.responseMode.rawValue])
    try validateForCredentialFormat(finalPresentationDefinition, responseMode: responseMode)
    
    var mutableParams = authorizationRequest
    mutableParams[AuthorizationRequestFieldConstants.presentationDefinition.rawValue] = finalPresentationDefinition
    
    return mutableParams
}

//Credential Format specific authorization request's presentation definition checks w.r.t to response_mode
fileprivate func validateForCredentialFormat(_ presentationDefinition: PresentationDefinition, responseMode: String?) throws {
    //In case of mso_mdoc format VCs requested in Authorization Request, direct_post.jwt is the allowed response_mode
    let hasMsoMdocFormat: Bool =  presentationDefinition.format?.contains(where: { $0.key == FormatType.mso_mdoc.rawValue }) ?? false || presentationDefinition.inputDescriptors.contains(where: {$0.format?.contains(where: { $0.key == FormatType.mso_mdoc.rawValue }) ?? false})
    if(hasMsoMdocFormat && (responseMode != ResponseMode.directPostJwt.rawValue && responseMode != ResponseMode.iarPostJwt.rawValue)){
        throw InvalidData(
            message: "When mso_mdoc format is present in presentation definition, response_mode must be direct_post.jwt or iar_post.jwt",
            className: className
        )
    }
}
