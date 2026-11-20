package io.mosip.residentapp;

import static io.mosip.residentapp.utils.OpenId4VPUtils.parseUnsignedVPTokens;
import static io.mosip.residentapp.utils.OpenId4VPUtils.parseVPTokenSigningResults;
import static io.mosip.residentapp.utils.OpenId4VPUtils.parseWalletConfig;
import static io.mosip.residentapp.utils.OpenId4VPUtils.withTrustedVerifiers;

import android.annotation.SuppressLint;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.util.List;
import java.util.Map;

import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.WalletConfig;
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken;
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult;
import io.mosip.openID4VP.dcql.evaluator.MatchingCredentialsResult;
import io.mosip.openID4VP.dcql.query.DCQLQuery;
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions;
import io.mosip.openID4VP.helper.DCQLHelper;
import io.mosip.openID4VP.verifier.VerifierResponse;
import io.mosip.openID4VP.wallet.Credential;
import io.mosip.residentapp.utils.OpenId4VPUtils;

/**
 * Bridge to inji-openid4vp 1.0 (Android). iOS still runs the 0.7 library, so the JS keeps one
 * call shape for authenticateVerifier and branches on the platform for the rest
 * (shared/openID4VP/OpenID4VP.ts).
 */
public class InjiOpenID4VPModule extends ReactContextBaseJavaModule {
    private static final String TAG = "InjiOpenID4VPModule";
    private static final String MODULE_NAME = "InjiOpenID4VP";

    private String appId;
    private WalletConfig baseWalletConfig;
    private OpenID4VP openID4VP;
    private final Gson gson = new GsonBuilder()
            .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
            .disableHtmlEscaping()
            .create();
    private final Gson gsonCamelCase = new GsonBuilder().disableHtmlEscaping().create();

    InjiOpenID4VPModule(@Nullable ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @NonNull
    @Override
    public String getName() {
        return MODULE_NAME;
    }

    @SuppressLint("LogNotTimber")
    @ReactMethod
    public void initSdk(String appId, ReadableMap walletConfigMap) {
        Log.d(TAG, "Initializing InjiOpenID4VPModule with " + appId);
        this.appId = appId;
        try {
            baseWalletConfig = parseWalletConfig(walletConfigMap);
        } catch (Exception exception) {
            // A malformed remote config must not leave sharing dead: fall back to the library's
            // defaults, which cover ldp_vc, mso_mdoc and dc+sd-jwt.
            Log.e(TAG, "Invalid OpenID4VP wallet config, using the library defaults", exception);
            baseWalletConfig = new WalletConfig();
        }
        openID4VP = new OpenID4VP(appId, baseWalletConfig);
    }

    /**
     * Same arguments as the iOS (0.7) bridge. 1.0 reads the trusted verifiers from its config,
     * so a fresh client is built for each request with this scan's list.
     */
    @ReactMethod
    public void authenticateVerifier(String urlEncodedAuthorizationRequest,
            ReadableArray trustedVerifiers,
            Boolean shouldValidateClient,
            Promise promise) {
        try {
            if (baseWalletConfig == null) {
                throw new IllegalStateException("InjiOpenID4VP is not initialised (initSdk not called)");
            }
            openID4VP = new OpenID4VP(
                    appId,
                    withTrustedVerifiers(
                            baseWalletConfig,
                            trustedVerifiers,
                            Boolean.TRUE.equals(shouldValidateClient)));

            AuthorizationRequest authRequest =
                    openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest);

            // Serialised by its runtime type, so the DCQL or presentation-definition fields of the
            // subclass are included.
            promise.resolve(gson.toJson(authRequest));
        } catch (Exception e) {
            rejectWithOpenID4VPExceptions(e, promise);
        }
    }

    /**
     * DCQL requests only: evaluates the query against the wallet's credentials. Presentation
     * definition requests are still matched in JS.
     */
    @ReactMethod
    public void getMatchingCredentials(ReadableMap vpRequest, ReadableArray availableWalletCredentials,
            Promise promise) {
        try {
            List<Credential> credentials = OpenId4VPUtils.parseCredentials(availableWalletCredentials);

            // The query parsed by authenticateVerifier, not the JSON round trip: Gson writes the
            // query's ClaimValue wrappers as objects, which do not parse back.
            DCQLQuery dcqlQuery = null;
            AuthorizationRequest current = openID4VP != null ? openID4VP.getAuthorizationRequest() : null;
            if (current instanceof AuthorizationDcqlRequest) {
                dcqlQuery = ((AuthorizationDcqlRequest) current).getDcqlQuery();
            } else if (vpRequest != null && vpRequest.hasKey("dcql_query")) {
                dcqlQuery = OpenId4VPUtils.parseDcqlQuery(vpRequest.getMap("dcql_query"));
            }
            if (dcqlQuery == null) {
                throw new IllegalStateException("The request has no DCQL query");
            }

            MatchingCredentialsResult result =
                    new DCQLHelper().getMatchingCredentials(credentials, dcqlQuery);
            promise.resolve(gsonCamelCase.toJson(result));
        } catch (Exception e) {
            rejectWithOpenID4VPExceptions(e, promise);
        }
    }

    /**
     * selectedVCs: {queryOrInputDescriptorId: [{format, credentialId, credential}]}.
     * fallbackHolderId: the wallet's did:jwk. The patched library uses it as the ldp_vc VP holder
     * only when a card's credentialSubject.id is not a supported DID (CredIssuer's urn:uuid).
     */
    @ReactMethod
    public void constructUnsignedVPToken(ReadableMap selectedVCs, @Nullable String fallbackHolderId, Promise promise) {
        try {
            Map<String, List<Credential>> selectedCredentials = OpenId4VPUtils.parseSelectedVCs(selectedVCs);
            List<UnsignedVPToken> vpTokens = openID4VP.constructUnsignedVPToken(selectedCredentials, fallbackHolderId);
            promise.resolve(parseUnsignedVPTokens(vpTokens));
        } catch (Exception e) {
            rejectWithOpenID4VPExceptions(e, promise);
        }
    }

    /** vpTokenSigningResults: [{id, signedData (base64url)}]. */
    @ReactMethod
    public void shareVerifiablePresentation(ReadableArray vpTokenSigningResults, Promise promise) {
        try {
            List<VPTokenSigningResult> parsedSigningResults = parseVPTokenSigningResults(vpTokenSigningResults);
            VerifierResponse verifierResponse = openID4VP.sendVPResponseToVerifier(parsedSigningResults);
            promise.resolve(gson.toJson(verifierResponse, VerifierResponse.class));
        } catch (Exception e) {
            rejectWithOpenID4VPExceptions(e, promise);
        }
    }

    @ReactMethod
    public void sendErrorToVerifier(String errorMessage, String errorCode, Promise promise) {
        try {
            OpenID4VPExceptions exception = OpenId4VPUtils.convertToOpenID4VPException(
                    errorCode,
                    errorMessage,
                    MODULE_NAME);

            VerifierResponse verifierResponse = openID4VP.sendErrorInfoToVerifier(exception);

            promise.resolve(gson.toJson(verifierResponse, VerifierResponse.class));

        } catch (Exception exception) {
            rejectWithOpenID4VPExceptions(exception, promise);
        }
    }

    // Deliberately NOT @ReactMethod: this is a private helper the other methods call, never
    // something JS invokes. The new architecture's TurboModuleInteropUtils eagerly parses a JNI
    // signature for every @ReactMethod on the module, and java.lang.Exception is not a bridgeable
    // parameter type. That single unparseable signature failed the whole module, so
    // NativeModules.InjiOpenID4VP threw on property access and every call into it was unreachable.
    private void rejectWithOpenID4VPExceptions(Exception e, Promise promise) {
        if (e instanceof OpenID4VPExceptions exception) {
            Log.e(TAG, "OpenID4VP failure " + exception.getErrorCode() + ": " + exception.getMessage(), e);
            WritableMap errorMap = Arguments.createMap();
            errorMap.putString("errorCode", exception.getErrorCode());
            errorMap.putString("message", exception.getMessage());
            errorMap.putString("verifierResponse", gson.toJson(exception.getVerifierResponse()));

            promise.reject(exception.getErrorCode(), exception.getMessage(), exception, errorMap);
        } else {
            // Anything the SDK throws that isn't one of its typed exceptions only reaches JS as
            // ERR_UNKNOWN, so the cause is logged here, where every method's failures pass.
            Log.e(TAG, "Non-OpenID4VPExceptions failure, rejecting as ERR_UNKNOWN", e);
            promise.reject("ERR_UNKNOWN", e.getMessage(), e);
        }
    }
}
