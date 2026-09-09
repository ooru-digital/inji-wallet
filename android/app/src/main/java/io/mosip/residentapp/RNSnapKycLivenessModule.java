package io.mosip.residentapp;

import android.Manifest;
import android.app.Activity;
import android.content.ClipData;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.Base64;
import android.util.Log;

import androidx.core.content.ContextCompat;
import androidx.core.content.FileProvider;

import com.facebook.react.bridge.ActivityEventListener;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;

import io.ooru.face.liveness.frontend.BioChqFaceLivenessMainActivity;

public class RNSnapKycLivenessModule extends ReactContextBaseJavaModule
    implements ActivityEventListener {

  private static final String NAME = "SnapKycLivenessModule";
  private static final int LIVENESS_REQUEST_CODE = 9101;
  private static final int CAMERA_FACING_FRONT = 1;
  private static final String LIVENESS_SDK_PACKAGE = "io.ooru.face.liveness.frontend";
  private static final String GENUINE_VERDICT = "Genuine";

  private static final String TAG = "SnapKycLiveness";

  // Kept for newer SnapKYC builds — 1.0.1-SNAPSHOT ignores this extra and falls back to its own
  // defaults. Matches @color/colorPrimary so a build that does honour it looks like the wallet.
  private static final String THEME_CONFIG_JSON =
      "{\"primary\":\"#023c69\",\"settings_background\":\"#F8F8F8\",\"instruction_text\":\"#023c69\"}";

  private Promise livenessPromise;

  public RNSnapKycLivenessModule(ReactApplicationContext reactContext) {
    super(reactContext);
    reactContext.addActivityEventListener(this);
  }

  @Override
  public String getName() {
    return NAME;
  }

  @ReactMethod
  public void startLiveness(ReadableMap config, Promise promise) {
    Activity activity = getCurrentActivity();
    if (activity == null) {
      promise.reject("E_NO_ACTIVITY", "Activity does not exist");
      return;
    }

    if (livenessPromise != null) {
      promise.reject("E_IN_PROGRESS", "Liveness session already in progress");
      return;
    }

    if (ContextCompat.checkSelfPermission(activity, Manifest.permission.CAMERA)
        != PackageManager.PERMISSION_GRANTED) {
      promise.reject("E_CAMERA_PERMISSION", "Camera permission not granted");
      return;
    }

    try {
      ReactApplicationContext context = getReactApplicationContext();
      File picturesDir = context.getExternalFilesDir(Environment.DIRECTORY_PICTURES);
      if (picturesDir != null && !picturesDir.exists()) {
        picturesDir.mkdirs();
      }

      File livenessDir = new File(context.getExternalFilesDir(null), "face_liveness");
      if (!livenessDir.exists()) {
        livenessDir.mkdirs();
      }

      File probeFile = new File(picturesDir, "probe.jpg");
      if (!probeFile.exists()) {
        probeFile.createNewFile();
      }

      String authority = context.getPackageName() + ".fileprovider";
      Uri probeUri = FileProvider.getUriForFile(context, authority, probeFile);

      context.grantUriPermission(
          context.getPackageName(),
          probeUri,
          Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
      context.grantUriPermission(
          LIVENESS_SDK_PACKAGE,
          probeUri,
          Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);

      String relayingPartyName =
          config.hasKey("relayingPartyName")
              ? config.getString("relayingPartyName")
              : "YourRelyingPartyName";
      String languageCode =
          config.hasKey("languageCode") ? config.getString("languageCode") : "en";

      Intent intent = new Intent(activity, BioChqFaceLivenessMainActivity.class);
      intent.putExtra("relayingPartyName", relayingPartyName);
      intent.putExtra("language_code", languageCode);
      intent.putExtra("offline_mode", true);
      intent.putExtra("save_results", true);
      intent.putExtra("export_images", true);
      intent.putExtra("export_data", true);
      intent.putExtra("sendFramesZipInResult", true);
      intent.putExtra("liveness_stages_config", "[\"smile\",\"blink\"]");
      intent.putExtra("liveness_theme_config", THEME_CONFIG_JSON);
      intent.putExtra("android.intent.extras.CAMERA_FACING", CAMERA_FACING_FRONT);
      intent.putExtra(MediaStore.EXTRA_OUTPUT, probeUri);
      intent.putExtra("output", probeUri);
      intent.setData(probeUri);
      intent.setClipData(ClipData.newRawUri("", probeUri));
      intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
      intent.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION);

      boolean skipFaceImage =
          config.hasKey("skipFaceImage") && config.getBoolean("skipFaceImage");
      int faceImageBytesLength = 0;

      if (!skipFaceImage
          && config.hasKey("faceImageBase64")
          && !config.isNull("faceImageBase64")) {
        byte[] faceImageBytes = decodeAndCompressFaceImage(config.getString("faceImageBase64"));
        if (faceImageBytes != null && faceImageBytes.length > 0) {
          faceImageBytesLength = faceImageBytes.length;
          intent.putExtra("face_image", faceImageBytes);
        }
      }

      Log.w(
          TAG,
          "Launching liveness relayingParty="
              + relayingPartyName
              + " skipFaceImage="
              + skipFaceImage
              + " faceImageBytes="
              + faceImageBytesLength
              + " probeUri="
              + probeUri);

      livenessPromise = promise;
      activity.startActivityForResult(intent, LIVENESS_REQUEST_CODE);
    } catch (Exception e) {
      livenessPromise = null;
      promise.reject("E_LAUNCH_FAILED", e.getMessage(), e);
    }
  }

  @Override
  public void onActivityResult(
      Activity activity, int requestCode, int resultCode, Intent data) {
    if (requestCode != LIVENESS_REQUEST_CODE || livenessPromise == null) {
      return;
    }

    Promise promise = livenessPromise;
    livenessPromise = null;

    if (resultCode != Activity.RESULT_OK) {
      String errorMessage = extractErrorMessage(data);
      String cancelMessage =
          errorMessage != null && !errorMessage.isEmpty()
              ? errorMessage
              : "Liveness session cancelled (resultCode=" + resultCode + ")";
      Log.w(
          TAG,
          "Liveness cancelled resultCode="
              + resultCode
              + " errorMessage="
              + cancelMessage
              + " hasData="
              + (data != null));
      promise.reject("E_CANCELLED", cancelMessage);
      return;
    }

    if (data == null) {
      Log.w(TAG, "Liveness returned RESULT_OK but data intent is null");
      promise.reject("E_NO_RESULT", "Liveness result data is missing");
      return;
    }

    try {
      WritableMap result = new WritableNativeMap();
      String verdict = data.getStringExtra("face_liveness_result");
      boolean timedOut = data.getBooleanExtra("liveness_timeout", false);
      boolean hasProbeImage = data.getBooleanExtra("has_probe_image", false);
      double probeDetectionScore = data.getDoubleExtra("probe_detection_score", 0.0);
      String errorMessage = data.getStringExtra("error_message");

      Log.w(
          TAG,
          "Liveness result verdict="
              + verdict
              + " timedOut="
              + timedOut
              + " hasProbeImage="
              + hasProbeImage
              + " errorMessage="
              + errorMessage);

      result.putString("verdict", verdict != null ? verdict : "");
      result.putBoolean(
          "isGenuine", GENUINE_VERDICT.equalsIgnoreCase(verdict != null ? verdict : ""));
      result.putBoolean("timedOut", timedOut);
      result.putBoolean("hasProbeImage", hasProbeImage);
      result.putDouble("probeDetectionScore", probeDetectionScore);
      if (errorMessage != null) {
        result.putString("errorMessage", errorMessage);
      }

      Uri probeUri = data.getParcelableExtra("probe_image");
      if (probeUri == null) {
        probeUri = data.getParcelableExtra("output");
      }

      if (probeUri != null) {
        String probeBase64 = readUriAsBase64(probeUri);
        if (probeBase64 != null) {
          result.putString("probeImageBase64", probeBase64);
        }
      }

      promise.resolve(result);
    } catch (Exception e) {
      promise.reject("E_RESULT_PARSE", e.getMessage(), e);
    }
  }

  @Override
  public void onNewIntent(Intent intent) {}

  private String extractErrorMessage(Intent data) {
    if (data == null) {
      return null;
    }
    return data.getStringExtra("error_message");
  }

  private byte[] decodeAndCompressFaceImage(String faceImageBase64) {
    if (faceImageBase64 == null || faceImageBase64.isEmpty()) {
      return null;
    }

    try {
      byte[] decoded = Base64.decode(faceImageBase64, Base64.DEFAULT);
      Bitmap bitmap = BitmapFactory.decodeByteArray(decoded, 0, decoded.length);
      if (bitmap == null) {
        return decoded;
      }

      int maxDimension = 640;
      int width = bitmap.getWidth();
      int height = bitmap.getHeight();
      float scale = 1f;
      if (width > maxDimension || height > maxDimension) {
        scale = Math.min((float) maxDimension / width, (float) maxDimension / height);
      }

      Bitmap scaledBitmap = bitmap;
      if (scale < 1f) {
        int scaledWidth = Math.round(width * scale);
        int scaledHeight = Math.round(height * scale);
        scaledBitmap = Bitmap.createScaledBitmap(bitmap, scaledWidth, scaledHeight, true);
      }

      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      scaledBitmap.compress(Bitmap.CompressFormat.JPEG, 80, outputStream);

      if (scaledBitmap != bitmap) {
        scaledBitmap.recycle();
      }
      bitmap.recycle();

      return outputStream.toByteArray();
    } catch (Exception e) {
      return null;
    }
  }

  private String readUriAsBase64(Uri uri) {
    try (InputStream inputStream =
        getReactApplicationContext().getContentResolver().openInputStream(uri)) {
      if (inputStream == null) {
        return null;
      }

      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      byte[] buffer = new byte[8192];
      int bytesRead;
      while ((bytesRead = inputStream.read(buffer)) != -1) {
        outputStream.write(buffer, 0, bytesRead);
      }

      byte[] bytes = outputStream.toByteArray();
      if (bytes.length == 0) {
        return null;
      }
      return Base64.encodeToString(bytes, Base64.NO_WRAP);
    } catch (Exception e) {
      return null;
    }
  }
}
