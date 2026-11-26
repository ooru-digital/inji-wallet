import Foundation
import OpenID4VP
import React

/**
 * Bridge to inji-openid4vp-ios-swift 1.0.0-rc.1 (stock, via SPM), based on upstream Inji Wallet
 * 1.0.0-alpha.1's module. Its methods have the same shape as Android's InjiOpenID4VPModule, so
 * shared/openID4VP/OpenID4VP.ts calls one API:
 *
 * - initSdk(appId, walletConfig): the wallet config, trusted verifiers and
 *   validate_trusted_verifier included.
 * - authenticateVerifier(url).
 * - getMatchingCredentials(vpRequest, credentials): DCQL matching.
 * - constructUnsignedVPToken(selectedVCs).
 * - shareVerifiablePresentation([{id, signedData}]), sendErrorToVerifier(message, code).
 *
 * The library hands JSON-LD expansion (DCQL type matching) and canonicalization (ldp_vc VP data)
 * to JS through the onJsonLdExpand / onJsonLdCanonicalize events. The library awaits each call
 * before making the next, so one pending continuation of each kind is enough.
 *
 * Must be an RCTEventEmitter, not a plain RCTBridgeModule: on iOS, NativeEventEmitter calls
 * addListener/removeListeners on the module itself, and without them the JS listeners never attach
 * and every JSON-LD call hangs. See RNVCIClientModule.swift.
 */
@objc(InjiOpenID4VP)
class RNOpenId4VpModule: RCTEventEmitter {

  private var openID4VP: OpenID4VP?
  private var pendingJsonLdCanonicalizeContinuation: CheckedContinuation<String, Error>?
  private var pendingJsonLdExpandContinuation: CheckedContinuation<[String: Any], Never>?

  override static func moduleName() -> String {
    return "InjiOpenID4VP"
  }

  override func supportedEvents() -> [String]! {
    return ["onJsonLdCanonicalize", "onJsonLdExpand"]
  }

  override static func requiresMainQueueSetup() -> Bool {
    return true
  }

  @objc
  func `initSdk`(_ appId: String, walletConfig: AnyObject?) {
    do {
      openID4VP = OpenID4VP(
        traceabilityId: appId,
        walletConfig: try OpenId4VPUtils.parseWalletConfig(walletConfig),
        jsonLdCanonicalizer: { [weak self] data in
          guard let self = self else {
            throw NSError(domain: "OPENID4VP", code: 0, userInfo: [NSLocalizedDescriptionKey: "Module released"])
          }
          return try await self.invokeJsonLdCanonicalize(data)
        }
      )
    } catch {
      os_log("Error occurred while initialization of OVP instance \(error)")
    }
  }

  @objc
  func authenticateVerifier(_ urlEncodedAuthorizationRequest: String,
                            resolver resolve: @escaping RCTPromiseResolveBlock,
                            rejecter reject: @escaping RCTPromiseRejectBlock) {
    Task {
      do {
        let authenticationResponse: AuthorizationRequest = try await requireOpenID4VP().authenticateVerifier(
          urlEncodedAuthorizationRequest: urlEncodedAuthorizationRequest
        )

        resolve(try OpenId4VPUtils.toJsonString(jsonObject: authenticationResponse))
      } catch {
        rejectWithOpenID4VPError(error, reject: reject)
      }
    }
  }

  @objc
  func getMatchingCredentials(_ vpRequest: AnyObject,
                              availableWalletCredentials: AnyObject,
                              resolver resolve: @escaping RCTPromiseResolveBlock,
                              rejecter reject: @escaping RCTPromiseRejectBlock) {
    Task {
      do {
        guard let vpRequest = vpRequest as? [String: Any],
              let dcqlQuery = vpRequest["dcql_query"] as? [String: Any] else {
          reject("OPENID4VP", "Invalid VP request format or missing DCQL query", nil)
          return
        }
        let parsedDCQLQuery: DCQLQuery = try JSONDecoder().decode(
          DCQLQuery.self, from: try JSONSerialization.data(withJSONObject: dcqlQuery, options: []))
        let credentials: [Credential] = try OpenId4VPUtils.parseCredentials(availableWalletCredentials)

        let response = try await DCQLHelper(
          jsonLdExpander: { [weak self] data in
            guard let self = self else { return [:] }
            return await self.invokeJsonLdExpand(data)
          }
        ).getMatchingCredentials(inputCredentials: credentials, dcqlQuery: parsedDCQLQuery)

        resolve(try OpenId4VPUtils.toJson(response))
      } catch {
        rejectWithOpenID4VPError(error, reject: reject)
      }
    }
  }

  /// selectedVCs: {queryOrInputDescriptorId: [{format, credentialId, credential}]}.
  /// The library takes each ldp_vc VP's holder (and signing key) from the card's
  /// credentialSubject.id, so ldp_vc cards must be bound to the wallet's did:jwk at issuance.
  @objc
  func constructUnsignedVPToken(_ selectedVCs: AnyObject,
                                resolver resolve: @escaping RCTPromiseResolveBlock,
                                rejecter reject: @escaping RCTPromiseRejectBlock) {
    Task {
      do {
        guard let rawCredentialsMap = selectedVCs as? [String: [Any]] else {
          reject("OPENID4VP", "Invalid credentials map format", nil)
          return
        }
        let credentialsMap: [String: [Credential]] = try OpenId4VPUtils.parseSelectedVCs(rawCredentialsMap)

        let response = try await requireOpenID4VP().constructUnsignedVPToken(
          selectedCredentials: credentialsMap
        )

        resolve(try OpenId4VPUtils.toJson(response))
      } catch {
        rejectWithOpenID4VPError(error, reject: reject)
      }
    }
  }

  /// vpTokenSigningResults: [{id, signedData (base64url)}].
  @objc
  func shareVerifiablePresentation(_ vpTokenSigningResults: NSArray,
                                   resolver resolve: @escaping RCTPromiseResolveBlock,
                                   rejecter reject: @escaping RCTPromiseRejectBlock) {
    Task {
      do {
        guard let signedVPTokens = vpTokenSigningResults as? [[String: Any]] else {
          reject("OPENID4VP", "Invalid VP token structure from JS", nil)
          return
        }
        let signingResults = try OpenId4VPUtils.parseVPTokenSigningResult(signedVPTokens)

        let verifierResponse = try await requireOpenID4VP().sendVPResponseToVerifier(
          vpTokenSigningResults: signingResults)
        try resolveToJsonData(verifierResponse, resolver: resolve, rejecter: reject)
      } catch {
        rejectWithOpenID4VPError(error, reject: reject)
      }
    }
  }

  @objc
  func sendErrorToVerifier(_ error: String, _ errorCode: String,
                           resolver resolve: @escaping RCTPromiseResolveBlock,
                           rejecter reject: @escaping RCTPromiseRejectBlock) {
    Task {
      let exception: OpenID4VPException = OpenId4VPUtils.convertToOpenID4VPException(
        errorCode: errorCode, error: error, moduleName: Self.moduleName())

      do {
        let verifierResponse = try await requireOpenID4VP().sendErrorInfoToVerifier(error: exception)
        try resolveToJsonData(verifierResponse, resolver: resolve, rejecter: reject)
      } catch {
        rejectWithOpenID4VPError(error, reject: reject)
      }
    }
  }

  private func requireOpenID4VP() throws -> OpenID4VP {
    guard let openID4VP = openID4VP else {
      throw NSError(domain: "OPENID4VP", code: 0, userInfo: [NSLocalizedDescriptionKey: "OpenID4VP is not initialized"])
    }
    return openID4VP
  }

  // MARK: - JSON-LD, done in JS

  private func invokeJsonLdCanonicalize(_ data: String) async throws -> String {
    return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<String, Error>) in
      self.pendingJsonLdCanonicalizeContinuation = continuation
      self.sendEvent(withName: "onJsonLdCanonicalize", body: ["data": data])
    }
  }

  /// Never throws: a credential whose expansion fails (e.g. an unreachable @context) gets no
  /// expanded types, so it matches no type_values, as on Android, instead of failing the whole
  /// match.
  private func invokeJsonLdExpand(_ data: [String: Any]) async -> [String: Any] {
    return await withCheckedContinuation { (continuation: CheckedContinuation<[String: Any], Never>) in
      self.pendingJsonLdExpandContinuation = continuation
      self.sendEvent(withName: "onJsonLdExpand", body: ["data": data])
    }
  }

  @objc(sendJsonLdCanonicalizeResultFromJS:)
  func sendJsonLdCanonicalizeResultFromJS(_ result: String) {
    pendingJsonLdCanonicalizeContinuation?.resume(returning: result)
    pendingJsonLdCanonicalizeContinuation = nil
  }

  @objc(notifyCanonicalizationFailureFromJS:message:)
  func notifyCanonicalizationFailureFromJS(_ code: String, message: String) {
    let error = OpenId4VPUtils.convertToOpenID4VPException(
      errorCode: code, error: message, moduleName: Self.moduleName())
    pendingJsonLdCanonicalizeContinuation?.resume(throwing: error)
    pendingJsonLdCanonicalizeContinuation = nil
  }

  /// result: jsonld.expand's output, an array with the expanded document first.
  @objc(sendJsonLdExpandResultFromJS:)
  func sendJsonLdExpandResultFromJS(_ result: AnyObject) {
    let expanded = (result as? [[String: Any]])?.first ?? [:]
    pendingJsonLdExpandContinuation?.resume(returning: expanded)
    pendingJsonLdExpandContinuation = nil
  }

  @objc(notifyJsonLdExpansionFailureFromJS:message:)
  func notifyJsonLdExpansionFailureFromJS(_ code: String, message: String) {
    os_log("JSON-LD expansion failed in JS: \(code) \(message)")
    pendingJsonLdExpandContinuation?.resume(returning: [:])
    pendingJsonLdExpandContinuation = nil
  }

  func rejectWithOpenID4VPError(_ error: Error, reject: RCTPromiseRejectBlock) {
    if let openidError = error as? OpenID4VPException {
      let errorMap: [String: Any] = [
        "errorCode": openidError.errorCode,
        "message": openidError.message,
        "verifierResponse": Inji.toJsonString(openidError.verifierResponse) ?? "",
        "cause": openidError.cause?.localizedDescription ?? ""
      ]
      let nsError = NSError(
        domain: "OPENID4VP",
        code: 0,
        userInfo: errorMap
      )
      reject(openidError.errorCode, openidError.message, nsError)
    } else {
      let nsError = NSError(domain: error.localizedDescription, code: 0)
      reject("ERR_UNKNOWN", nsError.localizedDescription, nsError)
    }
  }
}

struct EncodableWrapper: Encodable {
  private let value: Encodable
  init(_ value: Encodable) {
    self.value = value
  }
  func encode(to encoder: Encoder) throws {
    try value.encode(to: encoder)
  }
}

extension Dictionary {
  func mapKeys<T: Hashable>(_ transform: (Key) -> T) -> [T: Value] {
    Dictionary<T, Value>(uniqueKeysWithValues: map { (transform($0.key), $0.value) })
  }
}

func mapStringsToEnum<T: RawRepresentable>(
  _ input: [String],
  using fromValue: (String) -> T?
) throws -> [T] where T.RawValue == String {
  return try input.map { str in
    guard let match = fromValue(str) else {
      throw NSError(
        domain: "EnumMappingError",
        code: 1001,
        userInfo: [NSLocalizedDescriptionKey: "Invalid value '\(str)' for enum \(T.self)"]
      )
    }
    return match
  }
}

func mapStringsToRawEnum<T: RawRepresentable>(_ input: [String]) throws -> [T] where T.RawValue == String {
  return try input.map { str in
    guard let value = T(rawValue: str) else {
      throw NSError(
        domain: "EnumMappingError",
        code: 1002,
        userInfo: [NSLocalizedDescriptionKey: "Invalid value '\(str)' for enum \(T.self)"]
      )
    }
    return value
  }
}

fileprivate func resolveToJsonData(_ response: VerifierResponse?, resolver resolve: @escaping RCTPromiseResolveBlock,
                                   rejecter reject: @escaping RCTPromiseRejectBlock) throws {
  let jsonData = try toJsonData(response)

  if let jsonObject = try JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any] {
    resolve(jsonObject)
  } else {
    reject("ERROR", "Failed to serialize JSON", nil)
  }
}

fileprivate func toJsonString<T>(_ input: T) -> String? where T: Encodable {
  if let jsonData = try? toJsonData(input),
     let jsonString = String(data: jsonData, encoding: .utf8) {
    return jsonString
  }
  return nil
}

fileprivate func toJsonData<T>(_ input: T) throws -> Data where T: Encodable {
  let encoder = JSONEncoder()
  encoder.keyEncodingStrategy = .convertToSnakeCase
  return try encoder.encode(input)
}

func decode<T: Decodable>(
    _ type: T.Type,
    from dictionary: [String: Any]
) throws -> T {

    let data = try JSONSerialization.data(withJSONObject: dictionary)

    return try JSONDecoder().decode(T.self, from: data)
}
