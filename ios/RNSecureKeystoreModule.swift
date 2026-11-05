import Foundation
import Security
import LocalAuthentication
import React
import securekeystore

@objc(RNSecureKeystoreModule)
class RNSecureKeystoreModule: NSObject,RCTBridgeModule {
  static func moduleName() -> String! {
    return "RNSecureKeystoreModule"
  }


  private var secureKeystore:SecureKeystoreProtocol
  /// The ES256 holder key. Every other key type goes through the MOSIP library.
  private let holderKey = SecureEnclaveHolderKey()

  override init() {
    self.secureKeystore=SecureKeystoreImpl()
  }

  @objc
  static func requiresMainQueueSetup() -> Bool {
    return true
  }

  @objc
  func generateKeyPair(_ type: String, isAuthRequired: Bool, authTimeout: Int, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    if SecureEnclaveHolderKey.handles(type) {
      holderKey.generate(isAuthRequired: isAuthRequired, resolve: resolve, reject: reject)
      return
    }
    let successLambda: (String) -> Void = { success in
      resolve(success)
    }

    let failureLambda: (String, String) -> Void = { code, message in
      reject(code, message, nil)
    }
    var tag=""
    if(type=="RS256")
    {
      tag="RSA"
    }
    else
    {
      tag="ECR1"

    }
      
      secureKeystore.generateKeyPair(type: tag, tag: tag, isAuthRequired: isAuthRequired, authTimeout: Int32(authTimeout), onSuccess: successLambda, onFailure: failureLambda)
      }
  
  @objc
  func deleteKeyPair(_ tag: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    if SecureEnclaveHolderKey.handles(tag) {
      resolve(holderKey.delete())
      return
    }
    let successLambda: (Bool) -> Void = { success in
      resolve(success)
    }
    
    let failureLambda: (String, String) -> Void = { code, message in
      reject(code, message, nil)
    }
    
    
    secureKeystore.deleteKeyPair(tag: tag,onSuccess: successLambda,onFailure: failureLambda)
  }
  
  @objc
  func hasAlias(_ tag: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    if SecureEnclaveHolderKey.handles(tag) {
      resolve(holderKey.exists())
      return
    }
    let successLambda: (Bool) -> Void = { success in
      resolve(success)
    }
    
    let failureLambda: (String, String) -> Void = { code, message in
      reject(code, message, nil)
    }
    
    secureKeystore.hasAlias(tag: tag,onSuccess: successLambda,onFailure: failureLambda)
  }
  
  @objc
  func sign(_ signAlgorithm: String, alias: String, data: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    if SecureEnclaveHolderKey.handles(alias) {
      // The UTF-8 bytes of `data`, the same input Android's `sign` takes.
      holderKey.sign(Data(data.utf8), resolve: resolve, reject: reject)
      return
    }
    let successLambda: (String) -> Void = { success in
      resolve(success)
    }
    
    let failureLambda: (String, String) -> Void = { code, message in
      reject(code, message, nil)
    }
    var tag=""
    if(alias=="RS256")
    {
      tag="RSA"
    }
    else
    {
      tag="ECR1"

    }
    secureKeystore.sign(signAlgorithm: tag,alias: tag,data: data,onSuccess: successLambda,onFailure: failureLambda)
  }

  /// Signs raw bytes (base64) with the ES256 holder key, for mdoc proximity DeviceAuth, whose
  /// COSE input is binary. Resolves with a base64 DER signature, like `sign`.
  @objc
  func signBytes(_ alias: String, data: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    guard SecureEnclaveHolderKey.handles(alias) else {
      reject("UNSUPPORTED_ALIAS", "signBytes only supports the ES256 holder key", nil)
      return
    }
    guard let bytes = Data(base64Encoded: data) else {
      reject("INVALID_DATA", "signBytes expects base64 data", nil)
      return
    }
    holderKey.sign(bytes, resolve: resolve, reject: reject)
  }
  
  @objc
  func storeGenericKey(_ publickKey:String,privateKey:String, account: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    let successLambda: (Bool) -> Void = { success in
      resolve(success)
    }
    
    let failureLambda: (String, String) -> Void = { code, message in
      reject(code, message, nil)
    }
    
    secureKeystore.storeGenericKey(publicKey: publickKey, privateKey: privateKey, account: account, onSuccess: successLambda, onFailure: failureLambda)
  }

  @objc
  func storeData(_ key:String,value:String,resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    let successLambda: (Bool) -> Void = { success in
      resolve(success)
    }
    
    let failureLambda: (String, String) -> Void = { code, message in
      reject(code, message, nil)
    }
    
    secureKeystore.storeGenericKey(publicKey: value, privateKey: "", account: key, onSuccess: successLambda, onFailure: failureLambda)
  }
  
  @objc
  func retrieveGenericKey(_ account: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    let successLambda: (String?,String?) -> Void = { privateKey,publicKey in
      let keyPair=[privateKey,publicKey]
      resolve(keyPair)
      
    }
    
    let failureLambda: (String, String) -> Void = { code, message in
      reject(code, message, nil)
    }
    
    secureKeystore.retrieveGenericKey(account: account,onSuccess: successLambda,onFailure: failureLambda)
  }

  @objc
  func getData(_ key: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock)
  {
     let successLambda: (String?,String?) -> Void = { privateKey,publicKey in
      let keyPair=[privateKey,publicKey]
      resolve(keyPair)
      
    }
    
    let failureLambda: (String, String) -> Void = { code, message in
      reject(code, message, nil)
    }
    
    secureKeystore.retrieveGenericKey(account: key,onSuccess: successLambda,onFailure: failureLambda)
  }

  @objc
  func hasBiometricsEnabled(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        let success = secureKeystore.hasBiometricsEnabled()
        resolve(success)
    }
    
    @objc
    func updatePopup(_ title: String, desc: String) {
        holderKey.setPrompt(title: title, description: desc)
        secureKeystore.updatePopup(title: title, desc: desc)
    }
    
    @objc
    func generateKey(_ alias: String, authRequired: Bool, authTimeout: Int, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        let successLambda: (Bool) -> Void = { success in
            resolve(success)
        }
        
        let failureLambda: (String, String) -> Void = { code, message in
            reject(code, message, nil)
        }
        
        secureKeystore.generateKey(alias: alias, authRequired: authRequired, authTimeout: Int32(authTimeout), onSuccess: successLambda, onFailure: failureLambda)
    }
    
    @objc
    func encryptData(_ alias: String, data: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        let successLambda: (String) -> Void = { encryptedData in
            resolve(encryptedData)
        }
        
        let failureLambda: (String, String) -> Void = { code, message in
            reject(code, message, nil)
        }
        
        secureKeystore.encryptData(alias: alias, data: data, onSuccess: successLambda, onFailure: failureLambda)
    }
    
    @objc
    func decryptData(_ alias: String, data: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        let successLambda: (String) -> Void = { decryptedData in
            resolve(decryptedData)
        }
        
        let failureLambda: (String, String) -> Void = { code, message in
            reject(code, message, nil)
        }
        
        secureKeystore.decryptData(alias: alias, data: data, onSuccess: successLambda, onFailure: failureLambda)
    }
    
    @available(iOS 13.0, *)
    @objc
    func generateHmacshaKey(_ alias: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        let successLambda: (Bool) -> Void = { success in
            resolve(success)
        }
        
        let failureLambda: (String, String) -> Void = { code, message in
            reject(code, message, nil)
        }
        
        secureKeystore.generateHmacshaKey(alias: alias, onSuccess: successLambda, onFailure: failureLambda)
    }
    
    @available(iOS 13.0, *)
    @objc
    func generateHmacSha(_ alias: String, data: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        let successLambda: (String?) -> Void = { hash in
            resolve(hash)
        }
        
        let failureLambda: (String, String) -> Void = { code, message in
            reject(code, message, nil)
        }
        
        secureKeystore.generateHmacSha(alias: alias, data: data, onSuccess: successLambda, onFailure: failureLambda)
    }
    
    @objc
    func clearKeys(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        // The MOSIP library doesn't know about the Secure Enclave key.
        _ = holderKey.delete()
        let successLambda: (Bool) -> Void = { success in
            resolve(success)
        }
        
        let failureLambda: (String, String) -> Void = { code, message in
            reject(code, message, nil)
        }
        
        secureKeystore.clearKeys(onSuccess: successLambda, onFailure: failureLambda)
    }

  @objc
  func retrieveKey(_ alias:String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock){
    if SecureEnclaveHolderKey.handles(alias) {
      holderKey.publicKey(resolve: resolve, reject: reject)
      return
    }
    let successLambda: (String) -> Void = { success in
      resolve(success)
    }
    
    let failureLambda: (String, String) -> Void = { code, message in
      reject(code, message, nil)
    }
    secureKeystore.retrieveKey(tag: alias, onSuccess: successLambda, onFailure: failureLambda)
  }
  
  @objc
    func storeValueInCloud(_ key: String, value: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        let successLambda: (Bool) -> Void = { success in
            resolve(success)
        }
        
        let failureLambda: (String, String) -> Void = { code, message in
            reject(code, message, nil)
        }
        
        secureKeystore.storeValueInCloud(key: key, value: value, onSuccess: successLambda, onFailure: failureLambda)
    }
    
    @objc
    func retrieveValueFromCloud(_ key: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        let successLambda: (String?) -> Void = { value in
            resolve(value)
        }
        
        let failureLambda: (String, String) -> Void = { code, message in
            reject(code, message, nil)
        }
        
        secureKeystore.retrieveValueFromCloud(key: key, onSuccess: successLambda, onFailure: failureLambda)
    }


}

/// The ES256 holder key, created and used inside the Secure Enclave: the iOS counterpart of the
/// Android keystore key. The private key never leaves the chip; JS only ever gets the public key
/// and signatures.
///
/// As on Android: if biometrics are set up when the key is created, every signature needs Face ID
/// or Touch ID, and re-enrolling biometrics invalidates the key (`.biometryCurrentSet`). Without
/// biometrics there is no prompt.
final class SecureEnclaveHolderKey {
  private static let alias = "ES256"
  private static let tag = Data("io.ooru.credissuerwallet.holder.ES256".utf8)
  /// The biometric enrolment the key was bound to, to tell an invalidated key from other failures.
  /// Not secret: it only identifies the enrolment set.
  private static let domainStateDefaultsKey = "io.ooru.credissuerwallet.holder.ES256.biometryDomainState"
  /// Must match BIOMETRIC_CANCELLED in shared/constants.ts.
  private static let cancelledMessage = "User has cancelled biometric"
  /// Must match keyinvalidatedString in machines/store.ts.
  private static let invalidatedMessage = "Key Invalidated due to biometric enrollment"
  private static let logTag = "[HolderKey]"

  /// Face ID blocks the calling thread until the user answers, so key work runs off the bridge queue.
  private let queue = DispatchQueue(label: "io.ooru.credissuerwallet.holderkey", qos: .userInitiated)
  private let promptLock = NSLock()
  private var promptTitle = ""
  private var promptDescription = ""

  static func handles(_ alias: String) -> Bool {
    return alias == SecureEnclaveHolderKey.alias
  }

  /// The text of the biometric prompt, from the same `updatePopup` the other keys use.
  func setPrompt(title: String, description: String) {
    promptLock.lock()
    promptTitle = title
    promptDescription = description
    promptLock.unlock()
  }

  /// Replaces any existing holder key and resolves with the public key: base64 of the 65-byte
  /// uncompressed point, the shape the JS JWK code already reads on iOS.
  func generate(isAuthRequired: Bool, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    queue.async {
      _ = self.delete()
      do {
        let privateKey = try self.createKey(isAuthRequired: isAuthRequired)
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
          reject("KEY_GENERATION_FAILED", "Could not read the holder public key", nil)
          return
        }
        var error: Unmanaged<CFError>?
        guard let point = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
          let cause = error?.takeRetainedValue()
          reject("KEY_GENERATION_FAILED", "Could not export the holder public key", cause as Error?)
          return
        }
        self.saveBiometryDomainState(isAuthRequired: isAuthRequired)
        self.logKeySecurity(isAuthRequired: isAuthRequired)
        resolve(point.base64EncodedString())
      } catch {
        reject("KEY_GENERATION_FAILED", error.localizedDescription, error)
      }
    }
  }

  func exists() -> Bool {
    let (_, status) = lookupPrivateKey(context: Self.silentContext())
    // A key that needs Face ID is still there when the lookup isn't allowed to prompt.
    return status == errSecSuccess || status == errSecInteractionNotAllowed
  }

  func publicKey(resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    queue.async {
      var (key, status) = self.lookupPrivateKey(context: Self.silentContext())
      if status == errSecInteractionNotAllowed {
        // Looking up a key normally needs no Face ID (only using it does); if this one does,
        // ask rather than fail every download and share.
        (key, status) = self.lookupPrivateKey(context: LAContext())
      }
      guard let key = key, let publicKey = SecKeyCopyPublicKey(key) else {
        reject("KEY_NOT_FOUND", "No ES256 holder key (status \(status))", nil)
        return
      }
      var error: Unmanaged<CFError>?
      guard let point = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
        let cause = error?.takeRetainedValue()
        reject("KEY_NOT_FOUND", "Could not export the holder public key", cause as Error?)
        return
      }
      resolve(point.base64EncodedString())
    }
  }

  /// ECDSA P-256 over SHA-256 of `data`, resolved as base64 DER (the same output as Android).
  func sign(_ data: Data, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    queue.async {
      if self.isBiometryEnrolmentChanged() {
        NSLog("%@ biometric enrolment changed since the key was created; key invalidated", Self.logTag)
        reject("KEY_INVALIDATED", Self.invalidatedMessage, nil)
        return
      }

      let context = LAContext()
      self.promptLock.lock()
      let reason = self.promptDescription.isEmpty ? self.promptTitle : self.promptDescription
      self.promptLock.unlock()
      if !reason.isEmpty {
        context.localizedReason = reason
      }

      let (key, status) = self.lookupPrivateKey(context: context)
      guard let privateKey = key else {
        // Onboarding always creates the key, so a missing one was removed with the enrolment.
        if status == errSecItemNotFound {
          reject("KEY_INVALIDATED", Self.invalidatedMessage, nil)
        } else {
          reject("KEY_NOT_FOUND", "Could not load the ES256 holder key (status \(status))", nil)
        }
        return
      }

      var error: Unmanaged<CFError>?
      guard let signature = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256, data as CFData, &error) as Data? else {
        let cause = error?.takeRetainedValue() as Error?
        if Self.isCancellation(cause) {
          reject("BIOMETRIC_CANCELLED", Self.cancelledMessage, cause)
        } else {
          reject("SIGN_FAILED", cause?.localizedDescription ?? "Signing failed", cause)
        }
        return
      }
      resolve(signature.base64EncodedString())
    }
  }

  @discardableResult
  func delete() -> Bool {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: Self.tag,
    ]
    let status = SecItemDelete(query as CFDictionary)
    UserDefaults.standard.removeObject(forKey: Self.domainStateDefaultsKey)
    return status == errSecSuccess || status == errSecItemNotFound
  }

  // MARK: - Private

  private func createKey(isAuthRequired: Bool) throws -> SecKey {
    #if targetEnvironment(simulator)
    // The simulator has no Secure Enclave. Never fall back on a device: that would quietly put
    // the holder key in ordinary storage.
    NSLog("%@ WARNING: no Secure Enclave on the simulator; creating a software ES256 key", Self.logTag)
    return try makeKey(inSecureEnclave: false, isAuthRequired: isAuthRequired)
    #else
    return try makeKey(inSecureEnclave: true, isAuthRequired: isAuthRequired)
    #endif
  }

  private func makeKey(inSecureEnclave: Bool, isAuthRequired: Bool) throws -> SecKey {
    var flags: SecAccessControlCreateFlags = []
    if inSecureEnclave {
      flags.insert(.privateKeyUsage)
    }
    if isAuthRequired {
      flags.insert(.biometryCurrentSet)
    }
    var accessError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      flags,
      &accessError
    ) else {
      throw (accessError?.takeRetainedValue() as Error?) ?? NSError(domain: NSOSStatusErrorDomain, code: Int(errSecParam))
    }

    var attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: Self.tag,
        kSecAttrAccessControl as String: access,
      ] as [String: Any],
    ]
    if inSecureEnclave {
      attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
    }

    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      throw (error?.takeRetainedValue() as Error?) ?? NSError(domain: NSOSStatusErrorDomain, code: Int(errSecParam))
    }
    return key
  }

  private func lookupPrivateKey(context: LAContext) -> (SecKey?, OSStatus) {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: Self.tag,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
      kSecReturnRef as String: true,
      kSecUseAuthenticationContext as String: context,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let found = item else {
      return (nil, status)
    }
    return ((found as! SecKey), status)
  }

  /// A context that fails instead of prompting, for lookups that don't sign.
  private static func silentContext() -> LAContext {
    let context = LAContext()
    context.interactionNotAllowed = true
    return context
  }

  private static func isCancellation(_ error: Error?) -> Bool {
    guard let nsError = error as NSError? else {
      return false
    }
    if nsError.domain == NSOSStatusErrorDomain && nsError.code == Int(errSecUserCanceled) {
      return true
    }
    if nsError.domain == LAErrorDomain {
      let cancelled: [LAError.Code] = [.userCancel, .systemCancel, .appCancel]
      return cancelled.map { $0.rawValue }.contains(nsError.code)
    }
    return false
  }

  private enum BiometryEnrolment {
    case enrolled(Data)
    case notEnrolled
    /// Lockout, passcode turned off and the like: the enrolment can't be read right now.
    case unknown
  }

  private static func currentBiometryEnrolment() -> BiometryEnrolment {
    let context = LAContext()
    var error: NSError?
    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
      if let state = context.evaluatedPolicyDomainState {
        return .enrolled(state)
      }
      return .unknown
    }
    if let code = error?.code, code == LAError.Code.biometryNotEnrolled.rawValue {
      return .notEnrolled
    }
    return .unknown
  }

  private func saveBiometryDomainState(isAuthRequired: Bool) {
    if isAuthRequired, case .enrolled(let state) = Self.currentBiometryEnrolment() {
      UserDefaults.standard.set(state, forKey: Self.domainStateDefaultsKey)
    } else {
      UserDefaults.standard.removeObject(forKey: Self.domainStateDefaultsKey)
    }
  }

  /// True when the key was bound to a biometric enrolment that is no longer the current one:
  /// faces or fingers added or removed, or biometrics removed altogether.
  private func isBiometryEnrolmentChanged() -> Bool {
    guard let saved = UserDefaults.standard.data(forKey: Self.domainStateDefaultsKey) else {
      return false
    }
    switch Self.currentBiometryEnrolment() {
    case .enrolled(let state):
      return state != saved
    case .notEnrolled:
      return true
    case .unknown:
      // Let the Secure Enclave decide; a lockout must not look like a re-enrolment.
      return false
    }
  }

  /// Evidence of where the key lives, the iOS counterpart of Android's key security-level log.
  private func logKeySecurity(isAuthRequired: Bool) {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: Self.tag,
      kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
      kSecReturnAttributes as String: true,
      kSecUseAuthenticationContext as String: Self.silentContext(),
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    let attributes = item as? [String: Any]
    let token = attributes?[kSecAttrTokenID as String] as? String ?? "none"
    let isSecureEnclave = token == (kSecAttrTokenIDSecureEnclave as String)
    NSLog(
      "%@ ES256 key created: status=%ld token=%@ secureEnclave=%@ privateKeyUsage=%@ biometryCurrentSet=%@ accessible=WhenUnlockedThisDeviceOnly",
      Self.logTag,
      Int(status),
      token,
      isSecureEnclave ? "true" : "false",
      isSecureEnclave ? "true" : "false",
      isAuthRequired ? "true" : "false"
    )
  }
}
