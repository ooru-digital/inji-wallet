package io.mosip.residentapp;

import androidx.annotation.Nullable;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableNativeArray;

import java.util.List;

import io.mosip.injivcrenderer.InjiVcRenderer;
import io.mosip.injivcrenderer.exceptions.VcRendererExceptions;
import io.mosip.injivcrenderer.constants.CredentialFormat;

public class RNInjiVcRendererModule extends ReactContextBaseJavaModule {
    private static final String MODULE_NAME = "InjiVcRenderer";

    private InjiVcRenderer injiVcRenderer;

    public RNInjiVcRendererModule(@Nullable ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return MODULE_NAME;
    }
    @ReactMethod
    public void init(String appId) {
        injiVcRenderer = new InjiVcRenderer(appId);
    }

    @ReactMethod
    public void generateCredentialDisplayContent(String credentialFormat, String wellKnown, String vcJsonString, Promise promise) {
        try {
            CredentialFormat format = CredentialFormat.Companion.fromValue(credentialFormat);
            if (format == null) {
                throw new UnsupportedOperationException("Invalid credential format: " + credentialFormat);
            }
            List<Object> results = injiVcRenderer.generateCredentialDisplayContent(
                    format,
                    wellKnown,
                    vcJsonString
            );

            WritableArray resultArray = new WritableNativeArray();
            for (Object obj : results) {
                String svg = obj.toString();
                resultArray.pushString(svg);
            }
            promise.resolve(resultArray);
        } catch (Exception e) {
            rejectWithVcRendererExceptions(e, promise);
        }
    }

    // Deliberately NOT @ReactMethod — same defect as InjiOpenID4VPModule's own reject helper. A
    // private helper annotated @ReactMethod with a java.lang.Exception parameter is unparseable by
    // the new architecture's TurboModuleInteropUtils, which eagerly builds a JNI signature for
    // every annotated method and fails the entire module when one of them can't be parsed. Left
    // as-is this would break NativeModules.RNInjiVcRenderer the same way it broke InjiOpenID4VP.
    private static void rejectWithVcRendererExceptions(Exception e, Promise promise) {
        if (e instanceof VcRendererExceptions) {
            VcRendererExceptions ex = (VcRendererExceptions) e;
            promise.reject(ex.getErrorCode(), ex.getMessage(), ex);
        } else {
            promise.reject("ERR_UNKNOWN", e.getMessage(), e);
        }
    }
}
