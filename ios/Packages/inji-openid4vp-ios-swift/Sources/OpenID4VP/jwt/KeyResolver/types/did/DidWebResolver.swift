import Foundation

class DidWebResolver : BaseDidPublicKeyResolver {
    private static let className: String = String(describing: DidWebResolver.self)
    
    private let docPath = "/did.json"
    private let wellKnownPath = ".well-known"
    private static let supportedPublicKeyTypes = PublicKeyVerificationMaterial.allCases.map { $0.rawValue }
    
    let networkManager: NetworkManaging
    
    init(networkManager: NetworkManaging) {
        self.networkManager = networkManager
    }
    
    func extractPublicKey(parsedDID: ParsedDID, keyId: String? = nil) async throws -> PublicKeyType {
        do {
            
            let urlString = constructDIDUrl(from: parsedDID)
            
            let response = try await networkManager.sendHTTPRequest(url: urlString, method: .get, bodyParams: nil, headers: nil)
            
            if(!response.isOK){
                throw InvalidData(
                    message: "Error while resolving did, status code: \(response.statusCode) with body: \(response.body)",
                    className: AuthorizationRequest.className
                )
            }
            guard let responseBody = response.body.data(using: .utf8) else {
                throw InvalidData(
                    message: "Conversion failed: resolved DID response body could not be encoded",
                    className: Self.className
                )
            }
            guard let didResponse = try JSONSerialization.jsonObject(with: responseBody, options: []) as? [String: Any]  else {
                throw InvalidData(
                    message: "Conversion failed: resolved DID response is not a valid JSON object",
                    className: Self.className
                )
            }
            let verificationMethodId = keyId ?? parsedDID.didUrl
            
            return try self.extractPublicKey(for: verificationMethodId, from: didResponse)!
        } catch {
            throw DidResolutionFailed(message: error.localizedDescription, className: Self.className)
        }
    }
    
    private func constructDIDUrl(from parsedDID: ParsedDID) -> String {
        let idComponents = parsedDID.id.split(separator: ":").map(String.init)
        let baseDomain = idComponents.first!
        let path = idComponents.dropFirst().joined(separator: "/")
        let urlPath = path.isEmpty ? "\(wellKnownPath)\(docPath)" : "\(path)\(docPath)"
        
        return "https://\(baseDomain)/\(urlPath)"
    }
    
    private func extractPublicKey(for kid: String, from didDoc: [String: Any]) throws -> PublicKeyType? {
        if let verificationMethods = didDoc["verificationMethod"] as? [[String: Any]] {
            for method in verificationMethods {
                if let id = method["id"] as? String, id == kid {
                    if !Self.supportedPublicKeyTypes.contains(where: { method[$0] != nil }) {
                        throw UnsupportedPublicKeyType(className: Self.className)
                    }
                    
                    let methodKeys = method.keys
                    
                    if methodKeys.contains(PublicKeyVerificationMaterial.multibase.rawValue) {
                        return try extractAndParse(from: method, key: .multibase, parse: publicKeyFromMultibase)
                    }
                    else if methodKeys.contains(PublicKeyVerificationMaterial.jwk.rawValue), let jwk = method[PublicKeyVerificationMaterial.jwk.rawValue] as? [String: Any] {
                        return try publicKeyFromJWK(jwk)
                    }
                    else if methodKeys.contains(PublicKeyVerificationMaterial.pem.rawValue) {
                        return try extractAndParse(from: method, key: .pem, parse: publicKeyFromPEM)
                    }
                    else {
                        return try extractAndParse(from: method, key: .hex, parse: publicKeyFromHex)
                    }
                }
            }
        }
        
        throw PublicKeyResolutionFailed(
            message: "Public key extraction failed for kid: \(kid)",
            className: Self.className
        )
    }
    
    func extractAndParse<T>(
        from method: [String: Any],
        key: PublicKeyVerificationMaterial,
        parse: (String) throws -> T
    ) throws -> T {
        let rawValue = method[key.rawValue] as? String
        if(isNullOrEmpty(rawValue)) {
            throw InvalidData(
                message: "\(key.rawValue) cannot be null or empty",
                className: String(describing: Self.self)
            )
        }
        return try parse(rawValue!)
    }
    
}
