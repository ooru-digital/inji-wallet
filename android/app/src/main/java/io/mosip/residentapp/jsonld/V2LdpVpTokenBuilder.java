package io.mosip.residentapp.jsonld;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponseHandler;
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping;
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken;
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken;
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken;
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.Proof;
import io.mosip.openID4VP.common.DateUtil;
import io.mosip.openID4VP.common.URDNA2015Canonicalization;
import io.mosip.openID4VP.common.UUIDGenerator;
import io.mosip.openID4VP.common.UtilsKt;
import io.mosip.openID4VP.constants.FormatType;
import kotlin.Pair;

/**
 * inji-openid4vp 0.7.0 always emits a VC Data Model v1 presentation
 * ({@code https://www.w3.org/2018/credentials/v1}). Canonicalizing that wrapper
 * around a nested v2 credential throws {@code PROTECTED_TERM_REDEFINITION}.
 * This builder stores a v2 presentation on the SDK handler so share can proceed.
 */
public final class V2LdpVpTokenBuilder {

    private static final String CREDENTIALS_V2 = "https://www.w3.org/ns/credentials/v2";
    private static final String JWS_2020 = "https://w3id.org/security/suites/jws-2020/v1";
    private static final String ED25519_2020 = "https://w3id.org/security/suites/ed25519-2020/v1";
    private static final String LDP_PATH = "verifiableCredential";
    private static final String JSON_WEB_SIGNATURE_2020 = "JsonWebSignature2020";
    private static final String ED25519_SIGNATURE_2020 = "Ed25519Signature2020";

    private V2LdpVpTokenBuilder() {}

    public static boolean containsVcDataModelV2(
            Map<String, Map<FormatType, List<Object>>> selectedVCs) {
        if (selectedVCs == null) {
            return false;
        }
        for (Map<FormatType, List<Object>> byFormat : selectedVCs.values()) {
            if (byFormat == null) {
                continue;
            }
            List<Object> ldpVcs = byFormat.get(FormatType.LDP_VC);
            if (ldpVcs == null) {
                continue;
            }
            for (Object credential : ldpVcs) {
                if (contextContainsV2(extractContext(credential))) {
                    return true;
                }
            }
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    public static Map<FormatType, UnsignedVPToken> constructAndStore(
            OpenID4VP openID4VP,
            Map<String, Map<FormatType, List<Object>>> selectedVCs,
            String holderId,
            String signatureSuite)
            throws Exception {
        AuthorizationRequest authorizationRequest = openID4VP.getAuthorizationRequest();
        if (authorizationRequest == null) {
            throw new IllegalStateException("Authorization request is not available");
        }
        String suite =
                (signatureSuite == null || signatureSuite.isEmpty())
                        ? ED25519_SIGNATURE_2020
                        : signatureSuite;

        AuthorizationResponseHandler handler = getHandler(openID4VP);
        copyWalletNonce(openID4VP, handler);
        setField(handler, "signatureSuite", suite);
        invokeCreateFormatMapping(handler, selectedVCs);

        List<CredentialInputDescriptorMapping> ldpMappings = getLdpMappings(handler);
        List<Object> verifiableCredentials = new ArrayList<>();
        for (int i = 0; i < ldpMappings.size(); i++) {
            CredentialInputDescriptorMapping mapping = ldpMappings.get(i);
            mapping.setNestedPath("$." + LDP_PATH + "[" + i + "]");
            verifiableCredentials.add(mapping.getCredential());
        }

        LdpVPToken payload =
                buildPayload(
                        authorizationRequest,
                        holderId,
                        suite,
                        verifiableCredentials,
                        vpContext(suite));
        String dataToSign;
        try {
            dataToSign = canonicalize(payload);
        } catch (Exception first) {
            payload =
                    buildPayload(
                            authorizationRequest,
                            holderId,
                            suite,
                            verifiableCredentials,
                            listOf(CREDENTIALS_V2));
            dataToSign = canonicalize(payload);
        }

        UnsignedLdpVPToken unsigned = new UnsignedLdpVPToken(dataToSign);
        Map<FormatType, Pair<LdpVPToken, UnsignedVPToken>> results = new HashMap<>();
        results.put(FormatType.LDP_VC, new Pair<>(payload, unsigned));
        setField(handler, "unsignedVPTokenResults", results);

        Map<FormatType, UnsignedVPToken> tokens = new HashMap<>();
        tokens.put(FormatType.LDP_VC, unsigned);
        return tokens;
    }

    private static LdpVPToken buildPayload(
            AuthorizationRequest authorizationRequest,
            String holderId,
            String signatureSuite,
            List<Object> verifiableCredentials,
            List<String> context) {
        Proof proof =
                new Proof(
                        signatureSuite,
                        DateUtil.INSTANCE.formattedCurrentDateTime(),
                        authorizationRequest.getNonce(),
                        authorizationRequest.getClientId(),
                        null,
                        null,
                        "authentication",
                        holderId);
        return new LdpVPToken(
                context,
                listOf("VerifiablePresentation"),
                verifiableCredentials,
                UUIDGenerator.INSTANCE.generateUUID(),
                holderId,
                proof);
    }

    private static String canonicalize(LdpVPToken payload) throws Exception {
        ObjectMapper mapper = UtilsKt.getObjectMapper().copy();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        String json = mapper.writeValueAsString(payload);
        return URDNA2015Canonicalization.INSTANCE.canonicalize(json);
    }

    private static List<String> vpContext(String signatureSuite) {
        List<String> context = listOf(CREDENTIALS_V2);
        if (JSON_WEB_SIGNATURE_2020.equals(signatureSuite)) {
            context.add(JWS_2020);
        } else if (ED25519_SIGNATURE_2020.equals(signatureSuite)) {
            context.add(ED25519_2020);
        }
        return context;
    }

    private static AuthorizationResponseHandler getHandler(OpenID4VP openID4VP)
            throws Exception {
        Field field = OpenID4VP.class.getDeclaredField("authorizationResponseHandler");
        field.setAccessible(true);
        Object handler = field.get(openID4VP);
        if (!(handler instanceof AuthorizationResponseHandler)) {
            throw new IllegalStateException("OpenID4VP authorizationResponseHandler is not initialized");
        }
        return (AuthorizationResponseHandler) handler;
    }

    private static void copyWalletNonce(OpenID4VP openID4VP, AuthorizationResponseHandler handler)
            throws Exception {
        Field walletNonceField = OpenID4VP.class.getDeclaredField("walletNonce");
        walletNonceField.setAccessible(true);
        setField(handler, "walletNonce", walletNonceField.get(openID4VP));
    }

    private static void invokeCreateFormatMapping(
            AuthorizationResponseHandler handler,
            Map<String, Map<FormatType, List<Object>>> selectedVCs)
            throws Exception {
        Method method = findCreateFormatMapping();
        method.setAccessible(true);
        try {
            method.invoke(handler, selectedVCs);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw e;
        }
    }

    private static Method findCreateFormatMapping() throws NoSuchMethodException {
        for (Method method : AuthorizationResponseHandler.class.getDeclaredMethods()) {
            if (method.getName().startsWith("createFormatToCredentialInputDescriptorMapping")
                    && method.getParameterCount() == 1) {
                return method;
            }
        }
        throw new NoSuchMethodException("createFormatToCredentialInputDescriptorMapping");
    }

    @SuppressWarnings("unchecked")
    private static List<CredentialInputDescriptorMapping> getLdpMappings(
            AuthorizationResponseHandler handler) throws Exception {
        Field field =
                AuthorizationResponseHandler.class.getDeclaredField(
                        "formatToCredentialInputDescriptorMapping");
        field.setAccessible(true);
        Object value = field.get(handler);
        if (!(value instanceof Map)) {
            throw new IllegalStateException("Credential input descriptor mapping is missing");
        }
        Object ldp = ((Map<?, ?>) value).get(FormatType.LDP_VC);
        if (!(ldp instanceof List) || ((List<?>) ldp).isEmpty()) {
            throw new IllegalStateException("No ldp_vc credentials available for v2 VP construction");
        }
        return (List<CredentialInputDescriptorMapping>) ldp;
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static Object extractContext(Object credential) {
        if (credential instanceof Map) {
            return ((Map<?, ?>) credential).get("@context");
        }
        return null;
    }

    private static boolean contextContainsV2(Object context) {
        if (context instanceof String) {
            return ((String) context).contains("www.w3.org/ns/credentials/v2");
        }
        if (context instanceof Iterable) {
            for (Object item : (Iterable<?>) context) {
                if (contextContainsV2(item)) {
                    return true;
                }
            }
        }
        return false;
    }

    @SafeVarargs
    private static <T> List<T> listOf(T... values) {
        List<T> list = new ArrayList<>();
        for (T value : values) {
            list.add(value);
        }
        return list;
    }
}
