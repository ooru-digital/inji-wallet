import Foundation
import CryptoKit
import XCTest
@testable import OpenID4VP

class MockClientIdSchemeAuthRequestHandler: ClientIdSchemeBasedAuthorizationRequestHandler {
    private let isSignedRequestSupportedFlag: Bool
    private let isUnsignedRequestSupportedFlag: Bool
    private let clientIdSchemeValue: String
    private var extractPublicKeyError: OpenID4VPException?
    
    init(authorizationRequestParameters: [String: Any],
         walletMetadata: WalletMetadata? = nil,
         setResponseUri: @escaping (String) -> Void,
         walletNonce: String,
         networkManager: NetworkManaging,
         isSignedRequestSupported: Bool = true,
         isUnsignedRequestSupported: Bool = true) {
        self.isSignedRequestSupportedFlag = isSignedRequestSupported
        self.isUnsignedRequestSupportedFlag = isUnsignedRequestSupported
        do {
            self.clientIdSchemeValue = try extractClientIdScheme(authorizationRequestParams: authorizationRequestParameters)
        } catch {
            self.clientIdSchemeValue = "unknown"
        }
        
        super.init(authorizationRequestParameters: authorizationRequestParameters,
                   walletMetadata: walletMetadata,
                   setResponseUri: setResponseUri,
                   walletNonce: walletNonce,
                   networkManager: networkManager)
        delegate = self
        super.className = String(describing: Self.self)
    }
    
    func clientIdScheme() -> String {
        return clientIdSchemeValue
    }
    
    func setExtractPublicKeyError(error: OpenID4VPException){
        self.extractPublicKeyError = error
    }
    
    func extractPublicKey(keyId: String?, algorithm: String) async throws -> PublicKeyType {
        if(extractPublicKeyError != nil){
            throw extractPublicKeyError!
        }
        
        if(clientIdSchemeValue == ClientIdScheme.did.rawValue){
            return try PublicKeyType.ed25519(Curve25519.Signing.PublicKey(rawRepresentation: [248, 92, 183, 148, 198, 169, 205, 29, 240, 165, 166, 13, 8, 90, 182, 244, 96, 196, 159, 243, 104, 71, 122, 65, 177, 206, 117, 214, 173, 66, 198, 172]))
        }
        return PublicKeyType.ed25519(publicKey)
    }
    
    func isUnsignedRequestSupported() -> Bool {
        return self.isUnsignedRequestSupportedFlag
    }
    
    func isSignedRequestSupported() -> Bool {
        return self.isSignedRequestSupportedFlag
    }

    func process(walletMetadata: WalletMetadata) -> WalletMetadata {
        return walletMetadata
    }
    var capturedRequestUriResponse: (body: String, httpUrlResponse: HTTPURLResponse)?
}
