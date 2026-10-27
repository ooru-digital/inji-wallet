import Foundation
import React
import UIKit
import BioChqFaceLiveness

/// iOS counterpart of Android's `RNSnapKycLivenessModule`: the face check of the "share with
/// selfie" flows. Same JS name, method and result shape, so `shared/snapKyc/SnapKycLiveness.ts`
/// drives both platforms.
///
/// It runs the BioChq face SDK, a binary Swift package downloaded from the BioChq Nexus
/// (ios/Packages/BioChqFaceLivenessBinary; Xcode logs in to Nexus through ~/.netrc). Everything
/// runs on the device: the liveness check returns a verdict and the face it captured, and
/// `matchFace` compares that face with the credential's photo.
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
  /// The SDK asks for phone photos scaled to about this many pixels on the long side.
  private static let maxMatchImageSide: CGFloat = 1600
  /// The SDK's own passed / failed screen judges liveness only, so it would say "passed" to a live
  /// face that then fails the face match. The app shows the one result, after both.
  private static let livenessConfiguration = BioChqLivenessConfiguration(showResult: false)

  private var isRunning = false
  /// Kept between the liveness check and the matches after it, so the model loads once. Only
  /// touched on the main thread.
  private var faceMatcher: BioChqFaceMatch?

  @objc
  func startLiveness(
    _ config: NSDictionary,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    // Language and relying party name are Android SDK options with no iOS equivalent. The
    // reference photo is matched afterwards through `matchFace`; here it only means a match will
    // follow, so the matcher loads its model while the check runs.
    let willMatch = config["faceImageBase64"] is String
    Task { @MainActor in
      guard !self.isRunning else {
        // Not freed here: the check already running still needs the matcher.
        reject("E_IN_PROGRESS", "Liveness session already in progress", nil)
        return
      }
      self.isRunning = true
      if willMatch {
        self.matcher().warmUp()
      }
      // No match follows a check that failed or found no live face, so the matcher is freed here
      // too, not only by the JS caller's `closeFaceMatch`.
      let rejectAndFree: RCTPromiseRejectBlock = { code, message, error in
        self.closeFaceMatch()
        reject(code, message, error)
      }
      let resolveAndFreeIfUnused: RCTPromiseResolveBlock = { payload in
        if let payload = payload as? [String: Any],
          payload["isGenuine"] as? Bool != true || payload["probeImageBase64"] == nil
        {
          self.closeFaceMatch()
        }
        resolve(payload)
      }
      self.presentWhenReady(attempt: 0, resolve: resolveAndFreeIfUnused, reject: rejectAndFree)
    }
  }

  /// Compares the live face with a credential photo. Resolves with the SDK's result; rejects with
  /// the SDK's error code (e.g. `NO_FACE_IN_GALLERY`) when no decision could be made.
  @objc
  func matchFace(
    _ probeBase64: String,
    galleryBase64: String,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard
      let probe = Self.matchableImage(probeBase64),
      let gallery = Self.matchableImage(galleryBase64)
    else {
      reject("BAD_IMAGE", "Face image could not be read", nil)
      return
    }
    Task { @MainActor in
      do {
        let result = try await self.matcher().match(gallery: gallery, probe: probe)
        resolve([
          "isMatch": result.isMatch,
          "cosine": result.cosine,
          "l2": result.l2,
          "cosineThreshold": result.cosineThreshold,
          "l2Threshold": result.l2Threshold,
          "durationMs": result.durationMs,
        ])
      } catch let error as BioChqFaceMatchError {
        reject(error.code, error.localizedDescription, error)
      } catch {
        reject("MATCH_FAILED", error.localizedDescription, error)
      }
    }
  }

  /// Frees the matcher's model once the face check is over.
  @objc
  func closeFaceMatch() {
    Task { @MainActor in
      self.faceMatcher?.close()
      self.faceMatcher = nil
    }
  }

  @objc
  func invalidate() {
    closeFaceMatch()
  }

  @MainActor
  private func matcher() -> BioChqFaceMatch {
    if let faceMatcher {
      return faceMatcher
    }
    let created = BioChqFaceMatch()
    faceMatcher = created
    return created
  }

  /// JPEG or PNG bytes, as the matcher takes them. Other formats a credential may hold (WebP,
  /// GIF, BMP) and oversized photos are redrawn as a JPEG of at most `maxMatchImageSide`.
  private static func matchableImage(_ base64: String) -> Data? {
    guard let data = Data(base64Encoded: base64, options: .ignoreUnknownCharacters),
      let image = UIImage(data: data)
    else {
      return nil
    }
    let longSide = max(image.size.width, image.size.height) * image.scale
    if isJpegOrPng(data) && longSide <= maxMatchImageSide {
      return data
    }
    let scale = min(1, maxMatchImageSide / longSide)
    let size = CGSize(
      width: (image.size.width * image.scale * scale).rounded(),
      height: (image.size.height * image.scale * scale).rounded())
    let format = UIGraphicsImageRendererFormat()
    format.scale = 1
    // Drawing applies the EXIF orientation, so the JPEG comes out upright.
    let redrawn = UIGraphicsImageRenderer(size: size, format: format).image { _ in
      image.draw(in: CGRect(origin: .zero, size: size))
    }
    return redrawn.jpegData(compressionQuality: 0.95)
  }

  private static func isJpegOrPng(_ data: Data) -> Bool {
    let jpeg: [UInt8] = [0xFF, 0xD8, 0xFF]
    let png: [UInt8] = [0x89, 0x50, 0x4E, 0x47]
    return data.starts(with: jpeg) || data.starts(with: png)
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
        let result = try await BioChqLiveness.present(
          from: presenter, configuration: Self.livenessConfiguration)
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
