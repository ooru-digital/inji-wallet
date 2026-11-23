import Foundation
import CryptoKit
import XCTest
@testable import OpenID4VP

class MockClientIdPrefixAuthRequestHandler: ClientIdPrefixBasedAuthorizationRequestHandler {
    private let isSignedRequestSupportedFlag: Bool
    private let isUnsignedRequestSupportedFlag: Bool
    private let clientIdPrefixValue: String
    private var extractPublicKeyError: OpenID4VPException?
    private var errorToBeThrown: OpenID4VPException?
    var specVersionAndVPRequestMatch: Bool = true
    
    init(authorizationRequestParameters: [String: Any],
         setResponseDispatchInfo: @escaping (ResponseDispatchInfo) -> Void,
         walletNonce: String,
         networkManager: NetworkManaging,
         clientId: String = "mock-client",
         specVersion: SpecVersion = .v1,
         walletConfig: WalletConfig = WalletConfig(),
         isSignedRequestSupported: Bool = true,
         isUnsignedRequestSupported: Bool = true) {
        self.isSignedRequestSupportedFlag = isSignedRequestSupported
        self.isUnsignedRequestSupportedFlag = isUnsignedRequestSupported
        do {
            self.clientIdPrefixValue = try extractClientIdPrefix(authorizationRequestParams: authorizationRequestParameters)
        } catch {
            self.clientIdPrefixValue = "unknown"
        }
        
        super.init(clientId: clientId,
                   specVersion: specVersion,
                   authorizationRequestParameters: authorizationRequestParameters,
                   walletConfig: walletConfig,
                   setResponseDispatchInfo: setResponseDispatchInfo,
                   walletNonce: walletNonce,
                   networkManager: networkManager)
        delegate = self
        super.className = String(describing: Self.self)
    }
    
    func clientIdPrefix() -> String {
        return clientIdPrefixValue
    }
    
    func setExtractPublicKeyError(error: OpenID4VPException){
        self.extractPublicKeyError = error
    }
    
    func extractPublicKey(keyId: String?, algorithm: String) async throws -> PublicKeyType {
        if(errorToBeThrown != nil) {
            throw errorToBeThrown!
        }
        if(extractPublicKeyError != nil){
            throw extractPublicKeyError!
        }
        
        if(clientIdPrefixValue == ClientIdScheme.did.rawValue || clientIdPrefixValue == ClientIdPrefix.decentralizedIdentifier.rawValue){
            return try PublicKeyType.ed25519(Curve25519.Signing.PublicKey(rawRepresentation: [248, 92, 183, 148, 198, 169, 205, 29, 240, 165, 166, 13, 8, 90, 182, 244, 96, 196, 159, 243, 104, 71, 122, 65, 177, 206, 117, 214, 173, 66, 198, 172]))
        }
        return PublicKeyType.ed25519(publicKey)
    }
    
    override func validateAndParseRequestFields() async throws {
        if(errorToBeThrown != nil) {
            throw errorToBeThrown!
        }
        try await super.validateAndParseRequestFields()
    }
    
    func isUnsignedRequestSupported() -> Bool {
        return self.isUnsignedRequestSupportedFlag
    }
    
    func isSignedRequestSupported() -> Bool {
        return self.isSignedRequestSupportedFlag
    }
    
    func getWalletMetadata(walletConfig: WalletConfig) throws -> [String : Any] {
        return try walletConfig.toWalletMetadata(specVersion: super.specVersion)
    }
    
    func confirmSpecVersionIdentifiedFromRequest() -> Bool {
        return specVersionAndVPRequestMatch
    }
    
    var capturedRequestUriResponse: (body: String, httpUrlResponse: HTTPURLResponse)?
    
    func setErrorToBeThrown(error: OpenID4VPException){
        self.errorToBeThrown = error
    }
    
    func getSpecVersion() -> SpecVersion {
        return super.specVersion
    }
}
