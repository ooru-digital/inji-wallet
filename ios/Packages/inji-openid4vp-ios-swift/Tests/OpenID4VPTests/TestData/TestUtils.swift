import Foundation
@testable import OpenID4VP
import XCTest

func createVerifiers(from verifierList: [[String: Any]]) -> [Verifier] {
    var verifiers: [Verifier] = []
    
    for verifierData in verifierList {
        if let clientId = verifierData[AuthorizationRequestFieldConstants.clientId.rawValue] as? String,
           let responseUris = verifierData["response_uris"] as? [String] {
            let jwksUri = verifierData["jwks_uri"] as? String
            
            if let allowUnsignedRequest = verifierData["allow_unsigned_request"] as? Bool {
                let verifier = Verifier(clientId: clientId, responseUris: responseUris, jwksUri: jwksUri, allowUnsignedRequest: allowUnsignedRequest)
                verifiers.append(verifier)
                continue
            }
            let verifier = Verifier(clientId: clientId, responseUris: responseUris)
            verifiers.append(verifier)
            
        }
    }
    
    return verifiers
}

func createUrlEncodedAuthorizationRequest(
    requestParams: [String: Any?],
    verifierSentAuthRequestByReference: Bool? = false,
    clientIdScheme: ClientIdScheme,
    applicableFields: [String]? = nil,
    draftVersion: Int = 23
) -> String {
    let paramList: [String]
    if verifierSentAuthRequestByReference == true {
        if draftVersion == 23 {
            paramList = authRequestParamsByReferenceDraft23
        } else {
            paramList = authRequestParamsByReferenceDraft21
        }
    } else {
        paramList = applicableFields ?? authRequestClientIdSchemeMap[clientIdScheme]!
    }
    
    let authorizationRequestParam = createAuthorizationRequest(paramList: paramList, requestParams: requestParams)
    let queryString = encodeToQueryParameters(authorizationRequestParam)
    
    return "OPENID4VP://authorize?\(queryString)"
}

private func encodeToQueryParameters(_ parameters: [String: Any?]) -> String {
    let queryString = parameters.compactMap { (key, value) -> String? in
        guard let encodedKey = key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) else { return nil }
        
        let encodedValue: String
        if let stringValue = value as? String {
            encodedValue = stringValue
        } else if let jsonData = try? JSONSerialization.data(withJSONObject: value as Any, options: []),
                  //       stringify client_metdata and presentation defintiion
                  let jsonString = String(data: jsonData, encoding: .utf8) {
            encodedValue = jsonString
        } else {
            return nil // Skip values that can't be converted
        }
        
        guard var finalEncodedValue = encodedValue.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) else { return nil }
        finalEncodedValue = finalEncodedValue.replacingOccurrences(of: "+", with: "%2B")
        return "\(encodedKey)=\(finalEncodedValue)"
    }.joined(separator: "&")
    
    return queryString
}

func createAuthorizationRequest(
    paramList: [String],
    requestParams: [String: Any?],
    isSigned: Bool = false
) -> [String: Any?] {
    var authorizationRequestParam: [String: Any?] = [:]
    for param in paramList {
        if let value = requestParams[param], value != nil {
            authorizationRequestParam[param] = value
        }
    }
    if(isSigned){
        let request = JWSUtil.create(payload: authorizationRequestParam as [String : Any])
        authorizationRequestParam = [
            AuthorizationRequestFieldConstants.request.rawValue: request,
            AuthorizationRequestFieldConstants.clientId.rawValue: requestParams[AuthorizationRequestFieldConstants.clientId.rawValue] ?? ""
        ]
    }
    return authorizationRequestParam
}

func createAuthorizationRequestObject(
    clientIdScheme: ClientIdScheme,
    authorizationRequestParams: [String: Any],
    jwsHeaderData: [String: Any]? = nil,
    applicableFields: [String]? = nil,
    addValidSignature: Bool = true
) -> String {
    
    let parametersList = applicableFields ?? authRequestClientIdSchemeMap[clientIdScheme]!
    let authorizaitonRequestParameters = createAuthorizationRequest(paramList: parametersList, requestParams: authorizationRequestParams)
    //    authorizaitonRequestParameters[AuthorizationRequestFieldConstants.walletNonce.rawValue] = "mock-nonce"
    
    return JWSUtil.create(header: jwsHeaderData, payload: authorizaitonRequestParameters as [String : Any], addValidSignature: addValidSignature)
}


func convertToJsonString(_ data: [String: Any]) -> String {
    let jsonData = try? JSONSerialization.data(withJSONObject: data, options: [])
    let jsonString = String(data: jsonData!, encoding: .utf8)
    return jsonString!
}

func convertToJsonString(_ array: [Any]) -> String {
    do {
        let jsonData = try JSONSerialization.data(withJSONObject: array, options: .prettyPrinted)
        if let jsonString = String(data: jsonData, encoding: .utf8) {
            return jsonString
        }
    } catch {
        print("Error converting array to JSON: \(error)")
    }
    return ""
}

func convertToJsonString<T: Encodable>(_ object: T) -> String {
    do {
        let jsonData = try JSONEncoder().encode(object)
        return String(data: jsonData, encoding: .utf8) ?? ""
    } catch {
        print("Error converting object to JSON string: \(error)")
        return ""
    }
}

func convertToDictionary<T: Encodable>(object: T) -> [String: Any]? {
    guard let data = try? JSONEncoder().encode(object) else {
        return nil
    }
    return try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
}

func addingPercentEncoding(_ value: String) -> String {
    return value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? value
}

func mergeMaps<K, V>(_ maps: [K: V]...) -> [K: V] {
    return maps.reduce(into: [:]) { result, map in
        result.merge(map) { (_, new) in new }
    }
}


// Assert equality of errors
public func == (lhs: Error, rhs: Error) -> Bool {
    guard type(of: lhs) == type(of: rhs) else { return false }
    let error1 = lhs as NSError
    let error2 = rhs as NSError
    return error1.domain == error2.domain && error1.code == error2.code && "\(lhs)" == "\(rhs)"
}

extension Equatable where Self : Error {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs as Error == rhs as Error
    }
}

func decodeQueryValue(_ value: String) -> String {
    return value.removingPercentEncoding ?? value
}

func jsonString(_ any: Any, prettyPrinted: Bool = false) -> String? {
    guard JSONSerialization.isValidJSONObject(any) else {
        print("Not a valid JSON object")
        return nil
    }
    
    do {
        let options: JSONSerialization.WritingOptions = prettyPrinted ? [.prettyPrinted] : []
        let data = try JSONSerialization.data(withJSONObject: any, options: options)
        return String(data: data, encoding: .utf8)
    } catch {
        print("Error serializing to JSON: \(error)")
        return nil
    }
}

func createInstance<T: Decodable>(_ json: [String: Any], as type: T.Type) -> T {
    let jsonData = try? JSONSerialization.data(withJSONObject: json, options: [])
    let decoder = JSONDecoder()
    return (try? decoder.decode(T.self, from: jsonData!))!
}

func createRequestUriResponse(_ body: String, httpUrlResponse: HTTPURLResponse? = nil) -> (body: String, httpUrlResponse: HTTPURLResponse) {    
    let defaultHttpUrlResponse = httpUrlResponseForJWS
    let modifiedResponse: HTTPURLResponse = httpUrlResponse ?? defaultHttpUrlResponse
    
    return (body: body, httpUrlResponse: modifiedResponse)
}

func getMockAuthorizationRequest(responseMode: ResponseMode = .directPost, responseType: String? = nil, responseModeValue: String? = nil) -> AuthorizationRequest {
    let responseType = responseType ?? ResponseType.vp_token.rawValue
    return AuthorizationRequest(
        clientId: "client_id",
        clientIdScheme: nil,
        presentationDefinition: mockPresentationDefinitionObject,
        responseType: responseType,
        responseMode: responseModeValue ?? responseMode.rawValue,
        nonce: "nonce",
        state: "state",
        redirectUri: "1234",
        responseUri: "https://mock-verifier.com",
        walletNonce: nil,
        clientMetadata: mockClientMetadataObject
    )
}

@available(*, deprecated, renamed: "createWalletMetadataV2", message: "This uses deprecated WalletMetadata initializer. Use `createWalletMetadataV2` instead")
func createWalletMetadataV1(
    presentationDefinitionURISupported: Bool = true,
        vpFormatsSupported: [String: VPFormatSupported] = ["ldp_vc": VPFormatSupported(algValuesSupported: ["ES256", "EdDSA"])],
        clientIdSchemesSupported: [String] = ["pre-registered","did","redirect_uri"],
        requestObjectSigningAlgValuesSupported: [String]? = ["EdDSA"],
        authorizationEncryptionAlgValuesSupported: [String]? = ["ECDH-ES"],
        authorizationEncryptionEncValuesSupported: [String]? = ["A256GCM"]
    ) throws -> WalletMetadata {
        return try WalletMetadata(
            presentationDefinitionURISupported: presentationDefinitionURISupported,
            vpFormatsSupported: vpFormatsSupported,
            clientIdSchemesSupported: clientIdSchemesSupported,
            requestObjectSigningAlgValuesSupported: requestObjectSigningAlgValuesSupported,
            authorizationEncryptionAlgValuesSupported: authorizationEncryptionAlgValuesSupported,
            authorizationEncryptionEncValuesSupported: authorizationEncryptionEncValuesSupported
        )
    }


func createWalletMetadataV2(
    presentationDefinitionURISupported: Bool = true,
    vpFormatsSupported: [VPFormatType: VPFormatSupported] = [
        .ldp_vc: VPFormatSupported(algValuesSupported: ["EdDSA"]),
        .ldp_vp: VPFormatSupported(algValuesSupported: ["EdDSA"]),
        .mso_mdoc: VPFormatSupported(algValuesSupported: ["EdDSA"])
    ],
    clientIdSchemesSupported: [ClientIdScheme] = [.preRegistered, .redirectUri, .did],
    requestObjectSigningAlgValuesSupported: [RequestSigningAlgorithm]? = [.edDsa],
    authorizationEncryptionAlgValuesSupported: [KeyManagementAlgorithm]? = [.ecdhEs],
    authorizationEncryptionEncValuesSupported: [ContentEncryptionAlgorithm]? = [.A256GCM]
) throws -> WalletMetadata {
    return try WalletMetadata(
        presentationDefinitionURISupported: presentationDefinitionURISupported,
        vpFormatsSupported: vpFormatsSupported,
        clientIdSchemesSupported: clientIdSchemesSupported,
        requestObjectSigningAlgValuesSupported: requestObjectSigningAlgValuesSupported,
        authorizationEncryptionAlgValuesSupported: authorizationEncryptionAlgValuesSupported,
        authorizationEncryptionEncValuesSupported: authorizationEncryptionEncValuesSupported
    )
}

func ldpVC(credentialType : String = "IDCardCredential", context: [Any] = [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
    [
        "sec": "https://w3id.org/security#"
    ]
    
]) -> [String: Any] {
    let data : [String: Any] = [
        "@context": context,
        "id": "https://example.com/credentials/1872",
        "type": [
            "VerifiableCredential",
            credentialType
        ],
        "issuer": [
            "id": "did:example:issuer"
        ],
        "issuanceDate": "2010-01-01T19:23:24Z",
        "credentialSubject": [
            "given_name": "MockUser",
            "family_name": "Mockister",
            "birthdate": "1949-01-22"
        ],
        "proof": [
            "type": "Ed25519Signature2018",
            "created": "2021-03-19T15:30:15Z",
            "jws": "eyJhb...JQdBw",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:example:issuer#keys-1"
        ]
    ]
    return data
}
