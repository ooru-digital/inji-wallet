import Foundation
import React
import UIKit
import BioChqFaceLiveness

/// iOS counterpart of Android's `RNSnapKycLivenessModule`: the face check of the "share with
/// selfie" flows. Same JS name, method and result shape, so `shared/snapKyc/SnapKycLiveness.ts`
/// drives both platforms.
///
/// It runs the BioChqFaceLiveness SDK. Until the real iOS SDK is ready the Podfile links a dummy
/// with the same API (`BioChqFaceLivenessDummy`): it shows "Hello World" and a Proceed button, and
/// Proceed always passes. Switching to the real SDK is a Podfile change only.
@objc(SnapKycLivenessModule)
class RNSnapKycLivenessModule: NSObject, RCTBridgeModule {
  static func moduleName() -> String {
    return "SnapKycLivenessModule"
  }

  static func requiresMainQueueSetup() -> Bool {
    return false
  }

  /// Android's verdict string for a pass, which the JS side compares against.
  private static let genuineVerdict = "Genuine"
  /// How long to wait for a screen that is still sliding in or out (the face check opens inside
  /// a React Native modal) before presenting over it. UIKit ignores a presentation made during
  /// another transition, which would leave the JS promise waiting for ever.
  private static let presenterRetryInterval: TimeInterval = 0.1
  private static let presenterMaxRetries = 30

  private var isRunning = false

  @objc
  func startLiveness(
    _ config: NSDictionary,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    // The reference photo, language and relying party name are what the Android SDK takes; the
    // iOS SDK has no face matching and no such options, so they are not used here.
    DispatchQueue.main.async {
      guard !self.isRunning else {
        reject("E_IN_PROGRESS", "Liveness session already in progress", nil)
        return
      }
      self.isRunning = true
      self.presentWhenReady(attempt: 0, resolve: resolve, reject: reject)
    }
  }

  private func presentWhenReady(
    attempt: Int,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let presenter = RCTPresentedViewController() else {
      isRunning = false
      reject("E_NO_ACTIVITY", "No screen to show the liveness check from", nil)
      return
    }
    let isMidTransition =
      presenter.isBeingPresented || presenter.isBeingDismissed
      || presenter.transitionCoordinator != nil
    if isMidTransition && attempt < Self.presenterMaxRetries {
      DispatchQueue.main.asyncAfter(deadline: .now() + Self.presenterRetryInterval) {
        self.presentWhenReady(attempt: attempt + 1, resolve: resolve, reject: reject)
      }
      return
    }

    Task { @MainActor in
      defer { self.isRunning = false }
      do {
        let result = try await BioChqLiveness.present(from: presenter)
        resolve(Self.payload(for: result))
      } catch BioChqLivenessError.cancelled {
        reject("E_CANCELLED", "Liveness session cancelled", nil)
      } catch BioChqLivenessError.cameraAccessDenied {
        reject("E_CAMERA_PERMISSION", "Camera permission not granted", nil)
      } catch {
        reject("E_LAUNCH_FAILED", error.localizedDescription, error)
      }
    }
  }

  /// The same keys Android's module resolves with (see `SnapKycLivenessResult` in JS).
  private static func payload(for result: BioChqLivenessResult) -> [String: Any] {
    var payload: [String: Any] = [
      "verdict": verdict(for: result.status),
      "isGenuine": result.isLive,
      "timedOut": false,
      "hasProbeImage": result.probeImage != nil,
      "probeDetectionScore": result.score,
    ]
    if let probeImage = result.probeImage {
      payload["probeImageBase64"] = probeImage.base64EncodedString()
    }
    if !result.isLive, let message = result.message {
      payload["errorMessage"] = message
    }
    return payload
  }

  private static func verdict(for status: BioChqLivenessResult.Status) -> String {
    switch status {
    case .genuine: return genuineVerdict
    case .suspicious: return "Suspicious"
    case .possibleReplay: return "PossibleReplay"
    case .error: return "Error"
    case .other(let value): return value
    @unknown default: return "Unknown"
    }
  }
}
