import Foundation
import OpenID4VP
import OpenID4VPBridge
import React
import VCIClient

/**
 * Must be an RCTEventEmitter, not a plain RCTBridgeModule.
 *
 * JS drives the whole issuance flow through `new NativeEventEmitter(NativeModules.InjiVciClient)`
 * (shared/vciClient/VciClient.ts) and waits on onRequestProof / onRequestTokenResponse /
 * onRequestAuthCode before it can answer the continuations below. On Android the argument to
 * NativeEventEmitter is ignored — listeners bind to the global RCTDeviceEventEmitter, which is what
 * InjiVCIClientCallback.kt emits to — so the flow works there regardless. On iOS that argument is
 * mandatory and React Native calls `addListener`/`removeListeners` *on this module*; a plain
 * RCTBridgeModule has neither, so the listeners silently never attach, the hooks are never
 * answered, and every download hangs forever. RCTEventEmitter supplies both methods.
 *
 * Otherwise this is upstream Inji Wallet 1.0.0-alpha.1's module (VCI client 1.0.0-alpha.1).
 */
@objc(InjiVciClient)
class RNVCIClientModule: RCTEventEmitter {

  private var vciClient: VCIClient?

  private var pendingProofContinuation: ((String) -> Void)?
  private var pendingAuthCodeContinuation: ((String) -> Void)?
  private var pendingTxCodeContinuation: ((String) -> Void)?
  private var pendingTokenResponseContinuation: ((String) -> Void)?
  private var pendingIssuerTrustDecision: ((Bool) -> Void)?
  private var pendingSelectedCredentialsContinuation: CheckedContinuation<AnyObject, Error>?
  private var pendingSignVPContinuation: CheckedContinuation<NSArray, Error>?
  private var pendingJsonLdCanonicalizeContinuation: CheckedContinuation<String, Error>?

  override static func moduleName() -> String {
    return "InjiVciClient"
  }

  /// Every event JS subscribes to in VciClient.ts. RCTEventEmitter drops any event not listed
  /// here, so this must stay in step with the `emitter.addListener(...)` calls on the JS side.
  override func supportedEvents() -> [String]! {
    return [
      "onRequestProof",
      "onRequestAuthCode",
      "onRequestTxCode",
      "onRequestTokenResponse",
      "onCheckIssuerTrust",
      "onPresentationRequest",
      "onRequestSignedVPToken",
      "onJsonLdCanonicalize",
    ]
  }

  @objc
  func `init`(_ traceabilityId: String) {
    vciClient = VCIClient(traceabilityId: traceabilityId)
  }

  // MARK: - Public API

  fileprivate func getSupportedAuthorizationMethods(openId4VpWalletConfig: AnyObject) throws
    -> [AuthorizationMethod]
  {
    let parsedOpenId4VpWalletConfig = try OpenId4VPUtils.parseWalletConfig(openId4VpWalletConfig)
    
    return [
      .redirectToWeb(openWebPage: { authUrl in
        let result: [String: String] = try await self.getAuthCodeContinuationHook(authUrl: authUrl)

        return result
      }),
      .presentationDuringIssuance(
        jsonLdCanonicalizer: { data in
          try await self.invokeJsonLdCanonicalize(data)
        },
        openid4vpWalletConfig: parsedOpenId4VpWalletConfig,
        selectCredentialsForPresentation: { vpRequest in
          try await self.getSelectedCredentialsContinuationHook(vpRequest: vpRequest)
        },
        signVerifiablePresentation: { unsignedVPTokens in
          try await self.getSignVerifiablePresentationContinuationHook(
            unsignedVPTokens: unsignedVPTokens)
        }
      ),
    ]
  }

  @objc
  func requestCredentialByOffer(
    _ credentialOffer: String,
    clientMetadata: String,
    openId4VpWalletConfig: AnyObject,
    resolver resolve: @escaping RCTPromiseResolveBlock,
    rejecter reject: @escaping RCTPromiseRejectBlock
  ) {
    Task {
      do {
        guard let vciClient = vciClient else {
          reject(nil, "VCIClient not initialized", nil)
          return
        }

        let clientMeta = try parseClientMetadata(from: clientMetadata)

        let response = try await vciClient.fetchCredentialsUsingCredentialOffer(
          credentialOffer: credentialOffer,
          clientMetadata: clientMeta,
          getTxCode: { inputMode, description, length in
            try await self.getTxCodeHook(
              inputMode: inputMode,
              description: description,
              length: length
            )
          },
          authorizationMethods: try getSupportedAuthorizationMethods(openId4VpWalletConfig: openId4VpWalletConfig),
          getTokenResponse: { tokenRequest in
            try await self.getTokenResponseHook(tokenRequest: tokenRequest)
          },
          getProofs: { metadata in
            try await self.getProofsContinuationHook(metadata: metadata)
          },
          onCheckIssuerTrust: { credentialIssuer, issuerDisplay in
            try await self.getIssuerTrustDecisionHook(
              credentialIssuer: credentialIssuer,
              issuerDisplay: issuerDisplay
            )
          }
        )

        resolve(try self.toSingleCredentialResponseJson(response))
      } catch {
        rejectVCIError(error, reject: reject)
      }
    }
  }

  @objc
  func requestCredentialFromTrustedIssuer(
    _ credentialIssuer: String,
    credentialConfigurationId: String,
    clientMetadata: String,
    openId4VpWalletConfig: AnyObject,
    resolver resolve: @escaping RCTPromiseResolveBlock,
    rejecter reject: @escaping RCTPromiseRejectBlock
  ) {
    Task {
      do {
        guard let vciClient = vciClient else {
          reject(nil, "VCIClient not initialized", nil)
          return
        }

        let clientMeta = try parseClientMetadata(from: clientMetadata)

        let response = try await vciClient.fetchCredentialsFromTrustedIssuer(
          credentialIssuer: credentialIssuer,
          credentialConfigurationId: credentialConfigurationId,
          clientMetadata: clientMeta,
          getTokenResponse: { tokenRequest in
            try await self.getTokenResponseHook(tokenRequest: tokenRequest)
          },
          authorizationMethods: try getSupportedAuthorizationMethods(openId4VpWalletConfig: openId4VpWalletConfig),
          getProofs: { metadata in
            try await self.getProofsContinuationHook(metadata: metadata)
          },
          downloadTimeoutInMillis: 200000)

        resolve(try self.toSingleCredentialResponseJson(response))
      } catch {
        rejectVCIError(error, reject: reject)
      }
    }
  }

  @objc
  func getIssuerMetadata(
    _ credentialIssuer: String,
    resolver resolve: @escaping RCTPromiseResolveBlock,
    rejecter reject: @escaping RCTPromiseRejectBlock
  ) {
    Task {
      do {
        guard let vciClient = vciClient else {
          reject(nil, "VCIClient not initialized", nil)
          return
        }

        let metadata = try await vciClient.getIssuerMetadata(credentialIssuer: credentialIssuer)

        let data = try JSONSerialization.data(withJSONObject: metadata, options: [])
        guard let jsonString = String(data: data, encoding: .utf8) else {
          throw NSError(domain: "JSONEncodingError", code: 0)
        }

        resolve(jsonString)
      } catch {
        rejectVCIError(error, reject: reject)
      }
    }
  }

  private func rejectVCIError(
    _ error: Error,
    reject: RCTPromiseRejectBlock
  ) {
    if let vciError = error as? VCIClientException {

      var userInfo: [String: Any] = [
        "code": vciError.code
      ]

      if let issuerErrorCode = vciError.issuerErrorCode {
        userInfo["issuerErrorCode"] = issuerErrorCode
      }

      if let issuerErrorDescription = vciError.issuerErrorDescription {
        userInfo["issuerErrorDescription"] = issuerErrorDescription
      }

      let nsError = NSError(
        domain: "InjiVciClient",
        code: 0,
        userInfo: userInfo
      )

      reject(vciError.code, vciError.message, nsError)

    } else {
      reject(
        "UNKNOWN_ERROR",
        (error as NSError).localizedDescription,
        error
      )
    }
  }

  // MARK: - Callbacks to JS

  private func getTxCodeHook(
    inputMode: String?,
    description: String?,
    length: Int?
  ) async throws -> String {
    sendEvent(
      withName: "onRequestTxCode",
      body: [
        "inputMode": inputMode,
        "description": description,
        "length": length,
      ]
    )

    return try await withCheckedThrowingContinuation { continuation in
      self.pendingTxCodeContinuation = { code in continuation.resume(returning: code) }
    }
  }

  private func getAuthCodeContinuationHook(authUrl: String) async throws -> [String: String] {
    sendEvent(
      withName: "onRequestAuthCode",
      body: ["authorizationUrl": authUrl]
    )

    return try await withCheckedThrowingContinuation { continuation in
      self.pendingAuthCodeContinuation = { code in continuation.resume(returning: ["code": code]) }
    }
  }

  // metadata.nonce is the one the library fetched from the issuer's nonce_endpoint (OpenID4VCI
  // 1.0), or nil when the issuer advertises none.
  private func getProofsContinuationHook(
    metadata: CredentialRequestProofMetadata
  ) async throws -> CredentialRequestProofs {
    let proof = try await getProofContinuationHook(
      credentialIssuer: metadata.credentialIssuer,
      cNonce: metadata.nonce,
      proofSigningAlgorithmsSupported: metadata.proofSigningAlgorithmsSupported
    )

    return CredentialRequestProofs(proofs: [proof])
  }

  private func getProofContinuationHook(
    credentialIssuer: String,
    cNonce: String?,
    proofSigningAlgorithmsSupported: [String]
  ) async throws -> String {
    let jsonData = try JSONSerialization.data(
      withJSONObject: proofSigningAlgorithmsSupported, options: [])
    let jsonString = String(data: jsonData, encoding: .utf8) ?? "[]"
    sendEvent(
      withName: "onRequestProof",
      body: [
        "credentialIssuer": credentialIssuer,
        "cNonce": cNonce,
        "proofSigningAlgorithmsSupported": jsonString,
      ]
    )

    return try await withCheckedThrowingContinuation { continuation in
      self.pendingProofContinuation = { jwt in continuation.resume(returning: jwt) }
    }
  }

  private func getSelectedCredentialsContinuationHook(vpRequest: AuthorizationRequest) async throws
    -> [String: [Credential]]
  {
    let vpRequestJson = try OpenId4VPUtils.toJsonString(jsonObject: vpRequest)
    sendEvent(
      withName: "onPresentationRequest",
      body: [
        "presentationRequest": vpRequestJson
      ]
    )

    let selectedCredentials = try await withCheckedThrowingContinuation {
      (continuation: CheckedContinuation<AnyObject, Error>) in
      self.pendingSelectedCredentialsContinuation = continuation
    }

    guard let credentialsMap = selectedCredentials as? [String: [Any]] else {
      print("Invalid credentials map format")
      return [:]
    }

    return try OpenId4VPUtils.parseSelectedVCs(credentialsMap)
  }

  private func getSignVerifiablePresentationContinuationHook(
    unsignedVPTokens: [UnsignedVPToken]
  ) async throws -> [VPTokenSigningResult] {
    let unsignedVPTokensJson = try OpenId4VPUtils.toJson(unsignedVPTokens)
    sendEvent(
      withName: "onRequestSignedVPToken",
      body: [
        "vpTokenSigningRequest": unsignedVPTokensJson
      ]
    )

    let signedVPTokensAny = try await withCheckedThrowingContinuation { continuation in
      self.pendingSignVPContinuation = continuation
    }
    guard let signedVPTokens = signedVPTokensAny as? [[String: Any]] else {
      throw NSError(
        domain: "VPTokenSigning",
        code: -1,
        userInfo: [NSLocalizedDescriptionKey: "Invalid VP token structure from JS"]
      )
    }

    return try OpenId4VPUtils.parseVPTokenSigningResult(signedVPTokens)
  }

  private func getTokenResponseHook(tokenRequest: TokenRequest) async throws -> TokenResponse {
    let tokenRequestBody: [String: Any] = [
      "grantType": tokenRequest.grantType.rawValue,
      "tokenEndpoint": tokenRequest.tokenEndpoint,
      "authCode": tokenRequest.authCode ?? NSNull(),
      "preAuthCode": tokenRequest.preAuthCode ?? NSNull(),
      "txCode": tokenRequest.txCode ?? NSNull(),
      "clientId": tokenRequest.clientId ?? NSNull(),
      "redirectUri": tokenRequest.redirectUri ?? NSNull(),
      "codeVerifier": tokenRequest.codeVerifier ?? NSNull(),
      // Set only when the authorization server advertises dpop_signing_alg_values_supported;
      // sent as the DPoP header.
      "dpopProof": tokenRequest.dpopProof ?? NSNull(),
    ]

    sendEvent(
      withName: "onRequestTokenResponse",
      body: ["tokenRequest": tokenRequestBody]
    )

    let json = try await withCheckedThrowingContinuation { continuation in
      self.pendingTokenResponseContinuation = { json in continuation.resume(returning: json) }
    }

    guard let data = json.data(using: .utf8) else {
      throw NSError(domain: "Invalid JSON", code: 0)
    }

    return try JSONDecoder().decode(TokenResponse.self, from: data)
  }

  private func getIssuerTrustDecisionHook(
    credentialIssuer: String,
    issuerDisplay: [[String: Any]]
  ) async throws -> Bool {
    // Convert issuerDisplay to JSON string
    let jsonData = try JSONSerialization.data(withJSONObject: issuerDisplay, options: [])
    let jsonString = String(data: jsonData, encoding: .utf8) ?? "[]"
    sendEvent(
      withName: "onCheckIssuerTrust",
      body: [
        "credentialIssuer": credentialIssuer,
        "issuerDisplay": jsonString,
      ]
    )

    return try await withCheckedThrowingContinuation { continuation in
      self.pendingIssuerTrustDecision = { decision in continuation.resume(returning: decision) }
    }
  }

  private func toSingleCredentialResponseJson(
    _ response: CredentialResponse
  ) throws -> String {
    guard let firstItem = response.credentials?.first else {
      throw VCIClientException(code: "DOWNLOAD_FAILED", message: "No credential returned from issuer", issuerErrorCode: nil, issuerErrorDescription: nil)
    }

    var dict: [String: Any] = [
      "credential": firstItem.credential?.value
    ]
    if let issuer = response.credentialIssuer {
      dict["credentialIssuer"] = issuer
    }
    if let configId = response.credentialConfigurationId {
      dict["credentialConfigurationId"] = configId
    }

    let data = try JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted)
    guard let jsonString = String(data: data, encoding: .utf8) else {
      throw VCIClientException(code: "DOWNLOAD_FAILED", message: "Failed to serialize credential response")
    }
    return jsonString
  }

  // MARK: - Receivers from JS

  @objc(sendProofFromJS:)
  func sendProofFromJS(_ jwt: String) {
    pendingProofContinuation?(jwt)
    pendingProofContinuation = nil
  }

  @objc(sendSelectedCredentialsForVPSharingFromJS:)
  func sendSelectedCredentialsForVPSharingFromJS(_ selectedCredentials: AnyObject) {
    pendingSelectedCredentialsContinuation?.resume(returning: selectedCredentials)
    pendingSelectedCredentialsContinuation = nil
  }

  @objc(sendVPTokenSigningResultFromJS:)
  func sendVPTokenSigningResultFromJS(_ vpTokenSigningResult: NSArray) {
    pendingSignVPContinuation?.resume(returning: vpTokenSigningResult)
    pendingSignVPContinuation = nil
  }

  @objc(sendAuthCodeFromJS:)
  func sendAuthCodeFromJS(_ code: String) {
    pendingAuthCodeContinuation?(code)
    pendingAuthCodeContinuation = nil
  }

  @objc(sendTxCodeFromJS:)
  func sendTxCodeFromJS(_ code: String) {
    pendingTxCodeContinuation?(code)
    pendingTxCodeContinuation = nil
  }

  @objc(sendTokenResponseFromJS:)
  func sendTokenResponseFromJS(_ json: String) {
    pendingTokenResponseContinuation?(json)
    pendingTokenResponseContinuation = nil
  }

  @objc(sendIssuerTrustResponseFromJS:)
  func sendIssuerTrustResponseFromJS(_ trusted: Bool) {
    pendingIssuerTrustDecision?(trusted)
    pendingIssuerTrustDecision = nil
  }
  
  @objc(abortPresentationFlowFromJS:message:)
  func abortPresentationFlowFromJS(_ code: String, message: String) {
    let error = OpenId4VPUtils.convertToOpenID4VPException(
      errorCode: code, error: message, moduleName: Self.moduleName())

    pendingSelectedCredentialsContinuation?.resume(throwing: error)
    pendingSignVPContinuation?.resume(throwing: error)

    pendingSelectedCredentialsContinuation = nil
    pendingSignVPContinuation = nil

    pendingProofContinuation = nil
    pendingAuthCodeContinuation = nil
    pendingTxCodeContinuation = nil
    pendingTokenResponseContinuation = nil
    pendingIssuerTrustDecision = nil
  }
  
  @objc(sendJsonLdCanonicalizeResultFromJS:)
  func sendJsonLdCanonicalizeResultFromJS(_ result: String) {
    pendingJsonLdCanonicalizeContinuation?.resume(returning: result)
    pendingJsonLdCanonicalizeContinuation = nil
  }
  
  @objc
  func notifyCanonicalizationFailureFromJS(_ code: String, message: String) {
    let error = OpenId4VPUtils.convertToOpenID4VPException(
      errorCode: code, error: message, moduleName: Self.moduleName()
    )

    pendingJsonLdCanonicalizeContinuation?.resume(throwing: error)
    pendingJsonLdCanonicalizeContinuation = nil
  }

  // MARK: - JSON Parsing

  private func parseClientMetadata(from jsonString: String) throws -> VciClientMetadata {
    guard let data = jsonString.data(using: .utf8) else {
      throw NSError(domain: "Invalid JSON string for clientMetadata", code: 0)
    }
    return try JSONDecoder().decode(VciClientMetadata.self, from: data)
  }

  override static func requiresMainQueueSetup() -> Bool {
    return true
  }
  
  private func invokeJsonLdCanonicalize(_ data: String) async throws -> String {
    sendEvent(
      withName: "onJsonLdCanonicalize",
      body: [
        "data": data,
      ]
    )
    
    return try await withCheckedThrowingContinuation { (continuation : CheckedContinuation<String, Error>) in
      self.pendingJsonLdCanonicalizeContinuation = continuation
    }
  }
}
