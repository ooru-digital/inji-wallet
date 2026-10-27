package io.mosip.residentapp

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.util.Log
import androidx.core.content.ContextCompat
import com.facebook.react.bridge.ActivityEventListener
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableMap
import io.ooru.biochq.liveness.BioChqFaceMatch
import io.ooru.biochq.liveness.BioChqLivenessActivity
import io.ooru.biochq.liveness.BioChqLivenessConfiguration
import io.ooru.biochq.liveness.BioChqLivenessContract
import io.ooru.biochq.liveness.BioChqLivenessError
import io.ooru.biochq.liveness.BioChqLivenessResult
import java.io.ByteArrayOutputStream
import java.util.concurrent.atomic.AtomicReference
import kotlin.math.max

/**
 * The face check of the "share with selfie" flows, on the BioChq face SDK (the same SDK as iOS's
 * `RNSnapKycLivenessModule.swift`). Same JS name, methods and result shape on both platforms, so
 * `shared/snapKyc/SnapKycLiveness.ts` drives both.
 *
 * Everything runs on the device: the liveness check returns a verdict and the face it captured,
 * and `matchFace` compares that face with the credential's photo.
 */
class RNSnapKycLivenessModule(reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext), ActivityEventListener {

  private val contract = BioChqLivenessContract()
  private val mainHandler = Handler(Looper.getMainLooper())
  /**
   * The open check's promise. Set on the native-modules thread and taken on the UI thread, so it
   * is atomic: two quick calls can't both start a check.
   */
  private val livenessPromise = AtomicReference<Promise?>(null)

  /**
   * Kept between the liveness check and the matches after it, so the model loads once. Only
   * touched on the main thread, as the SDK requires.
   */
  private var faceMatcher: BioChqFaceMatch? = null

  init {
    reactContext.addActivityEventListener(this)
  }

  override fun getName() = NAME

  @ReactMethod
  fun startLiveness(config: ReadableMap, promise: Promise) {
    val activity = reactApplicationContext.currentActivity
    if (activity == null) {
      promise.reject("E_NO_ACTIVITY", "Activity does not exist")
      return
    }
    if (ContextCompat.checkSelfPermission(activity, Manifest.permission.CAMERA) !=
      PackageManager.PERMISSION_GRANTED
    ) {
      promise.reject("E_CAMERA_PERMISSION", "Camera permission not granted")
      return
    }
    if (!livenessPromise.compareAndSet(null, promise)) {
      promise.reject("E_IN_PROGRESS", "Liveness session already in progress")
      return
    }

    // The relying party name is an option of the old SDK with no equivalent here. The reference
    // photo is matched afterwards through `matchFace`; here it only means a match will follow, so
    // the matcher loads its model while the check runs.
    val willMatch = config.hasKey("faceImageBase64") && !config.isNull("faceImageBase64")
    val configuration = BioChqLivenessConfiguration(
      languageCode = if (config.hasKey("languageCode")) config.getString("languageCode") else null,
      // The SDK's own passed / failed screen judges liveness only, so it would say "passed" to a
      // live face that then fails the face match. The app shows the one result, after both.
      showResult = false,
    )

    try {
      activity.startActivityForResult(
        contract.createIntent(activity, configuration),
        LIVENESS_REQUEST_CODE,
      )
      if (willMatch) {
        mainHandler.post { matcher().warmUp() }
      }
    } catch (e: Exception) {
      livenessPromise.set(null)
      promise.reject("E_LAUNCH_FAILED", e.message, e)
    }
  }

  override fun onActivityResult(
    activity: Activity,
    requestCode: Int,
    resultCode: Int,
    data: Intent?,
  ) {
    if (requestCode != LIVENESS_REQUEST_CODE) return
    val promise = livenessPromise.getAndSet(null) ?: return

    when (val outcome = contract.parseResult(resultCode, data)) {
      is BioChqLivenessContract.Outcome.Completed -> {
        Log.i(TAG, "Liveness result status=${outcome.result.rawStatus} score=${outcome.result.score}")
        promise.resolve(payload(outcome.result, outcome.probeImage))
      }
      is BioChqLivenessContract.Outcome.Failed -> {
        val error = outcome.error
        Log.w(TAG, "Liveness gave no verdict: ${error.code} ${error.message}")
        if (error is BioChqLivenessError.CameraAccessDenied) {
          promise.reject("E_CAMERA_PERMISSION", error.message)
        } else {
          promise.reject("E_LAUNCH_FAILED", "${error.code}: ${error.message}")
        }
      }
      BioChqLivenessContract.Outcome.Cancelled ->
        promise.reject("E_CANCELLED", "Liveness session cancelled")
    }
    // The SDK leaves the selfie in its cache until the next check starts. It has been read into
    // memory above, so delete it now rather than leave a biometric image on the device.
    try {
      BioChqLivenessActivity.deleteProbeImages(reactApplicationContext)
    } catch (e: Exception) {
      Log.w(TAG, "Could not delete the probe image", e)
    }
  }

  override fun onNewIntent(intent: Intent) {}

  /**
   * Compares the live face with a credential photo. Resolves with the SDK's result; rejects with
   * the SDK's error code (e.g. `NO_FACE_IN_GALLERY`) when no decision could be made.
   */
  @ReactMethod
  fun matchFace(probeBase64: String, galleryBase64: String, promise: Promise) {
    val probe = matchableImage(probeBase64)
    val gallery = matchableImage(galleryBase64)
    if (probe == null || gallery == null) {
      promise.reject("BAD_IMAGE", "Face image could not be read")
      return
    }
    mainHandler.post {
      matcher().match(gallery, probe) { outcome ->
        when (outcome) {
          is BioChqFaceMatch.Outcome.Matched -> {
            val result = outcome.result
            promise.resolve(
              Arguments.createMap().apply {
                putBoolean("isMatch", result.isMatch)
                putDouble("cosine", result.cosine)
                putDouble("l2", result.l2)
                putDouble("cosineThreshold", result.cosineThreshold)
                putDouble("l2Threshold", result.l2Threshold)
                putDouble("durationMs", result.durationMs.toDouble())
              },
            )
          }
          is BioChqFaceMatch.Outcome.Failed ->
            promise.reject(outcome.error.code, outcome.error.message)
        }
      }
    }
  }

  /** Frees the matcher's model once the face check is over. */
  @ReactMethod
  fun closeFaceMatch() {
    mainHandler.post {
      faceMatcher?.close()
      faceMatcher = null
    }
  }

  override fun invalidate() {
    closeFaceMatch()
    super.invalidate()
  }

  private fun matcher(): BioChqFaceMatch =
    faceMatcher ?: BioChqFaceMatch(reactApplicationContext).also { faceMatcher = it }

  /** The same keys the iOS module resolves with (see `SnapKycLivenessResult` in JS). */
  private fun payload(result: BioChqLivenessResult, probeUri: Uri?): WritableMap {
    val probeBase64 = probeUri?.let { readUriAsBase64(it) }
    return Arguments.createMap().apply {
      putString("verdict", verdict(result))
      putBoolean("isGenuine", result.isLive)
      putBoolean("timedOut", false)
      putBoolean("hasProbeImage", probeBase64 != null)
      putDouble("probeDetectionScore", result.score)
      probeBase64?.let { putString("probeImageBase64", it) }
      if (!result.isLive) {
        result.message?.let { putString("errorMessage", it) }
      }
    }
  }

  private fun verdict(result: BioChqLivenessResult): String =
    when (result.status) {
      BioChqLivenessResult.Status.GENUINE -> GENUINE_VERDICT
      BioChqLivenessResult.Status.SUSPICIOUS -> "Suspicious"
      BioChqLivenessResult.Status.POSSIBLE_REPLAY -> "PossibleReplay"
      BioChqLivenessResult.Status.ERROR -> "Error"
      BioChqLivenessResult.Status.OTHER -> result.rawStatus
    }

  /** The probe JPEG; `onActivityResult` deletes the file once this has read it. */
  private fun readUriAsBase64(uri: Uri): String? =
    try {
      reactApplicationContext.contentResolver.openInputStream(uri)?.use { it.readBytes() }
        ?.takeIf { it.isNotEmpty() }
        ?.let { Base64.encodeToString(it, Base64.NO_WRAP) }
    } catch (e: Exception) {
      Log.w(TAG, "Could not read the probe image", e)
      null
    }

  /**
   * JPEG or PNG bytes, as the matcher takes them. Other formats a credential may hold (WebP, GIF,
   * BMP) and oversized photos are redrawn as a JPEG of at most [MAX_MATCH_IMAGE_SIDE].
   */
  private fun matchableImage(base64: String): ByteArray? {
    val bytes =
      try {
        Base64.decode(base64, Base64.DEFAULT)
      } catch (e: IllegalArgumentException) {
        return null
      }
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null

    val longSide = max(bounds.outWidth, bounds.outHeight)
    if (isJpegOrPng(bytes) && longSide <= MAX_MATCH_IMAGE_SIDE) return bytes

    var sampleSize = 1
    while (longSide / (sampleSize * 2) >= MAX_MATCH_IMAGE_SIDE) sampleSize *= 2
    val decoded =
      BitmapFactory.decodeByteArray(
        bytes,
        0,
        bytes.size,
        BitmapFactory.Options().apply { inSampleSize = sampleSize },
      ) ?: return null
    val scale = minOf(1f, MAX_MATCH_IMAGE_SIDE.toFloat() / max(decoded.width, decoded.height))
    val scaled =
      if (scale < 1f) {
        Bitmap.createScaledBitmap(
          decoded,
          Math.round(decoded.width * scale),
          Math.round(decoded.height * scale),
          true,
        )
      } else {
        decoded
      }
    val output = ByteArrayOutputStream()
    scaled.compress(Bitmap.CompressFormat.JPEG, 95, output)
    if (scaled !== decoded) scaled.recycle()
    decoded.recycle()
    return output.toByteArray()
  }

  private fun isJpegOrPng(bytes: ByteArray): Boolean {
    fun startsWith(vararg magic: Int) =
      bytes.size >= magic.size && magic.indices.all { bytes[it] == magic[it].toByte() }
    return startsWith(0xFF, 0xD8, 0xFF) || startsWith(0x89, 0x50, 0x4E, 0x47)
  }

  companion object {
    private const val NAME = "SnapKycLivenessModule"
    private const val TAG = "SnapKycLiveness"
    private const val LIVENESS_REQUEST_CODE = 9101

    /** Android's verdict string for a pass, which the JS side compares against. */
    private const val GENUINE_VERDICT = "Genuine"

    /** The SDK asks for phone photos scaled to about this many pixels on the long side. */
    private const val MAX_MATCH_IMAGE_SIDE = 1600
  }
}
