import {CACHED_API} from '../../shared/api';
import {fetchKeyPair} from '../../shared/cryptoutil/cryptoUtil';
import {getJWK, hasKeyPair} from '../../shared/openId4VCI/Utils';
import base64url from 'base64url';
import OpenID4VP from '../../shared/openID4VP/OpenID4VP';
import {OVP_ERROR_CODE, OVP_ERROR_MESSAGES} from '../../shared/constants';
import {getVerifierKey, VCShareFlowType} from '../../shared/Utils';
import {
  isClientValidationRequired,
  signUnsignedVPTokens,
} from '../../shared/openID4VP/OpenID4VPHelper';
import {NativeModules} from 'react-native';
import VciClient from '../../shared/vciClient/VciClient';

export const openID4VPServices = () => {
  return {
    fetchTrustedVerifiers: async () => {
      return await CACHED_API.fetchTrustedVerifiersList();
    },

    shouldValidateClient: async () => {
      return await isClientValidationRequired();
    },

    getAuthenticationResponse: (context: any) => async () => {
      // DIAGNOSTIC (dev only) — remove once the authenticateVerifier failure is understood.
      // The xstate machine log truncates this string, and the native side currently reports the
      // failure only as a bare "ERR_UNKNOWN" with an undefined userInfo, so neither end shows
      // what the SDK was actually handed. This is the exact post-normalizeAuthorizationRequest
      // input — worth checking specifically whether client_id_scheme=pre-registered was appended
      // (needsPreRegisteredScheme should add it for this verifier's bare http client_id) and
      // whether client_metadata came through with vp_formats.
      if (__DEV__) {
        console.log(
          '[OpenID4VP] authenticateVerifier request:',
          context.urlEncodedAuthorizationRequest,
        );
        console.log(
          '[OpenID4VP] trustedVerifiers count:',
          Array.isArray(context.trustedVerifiers)
            ? context.trustedVerifiers.length
            : typeof context.trustedVerifiers,
        );
      }
      return await OpenID4VP.authenticateVerifier(
        context.urlEncodedAuthorizationRequest,
        context.trustedVerifiers,
      );
    },

    isVerifierTrusted: (context: any) => async () => {
      if (context.flowType === VCShareFlowType.OPENID4VP_AUTHORIZATION)
        return true;
      const {RNSecureKeystoreModule} = NativeModules;
      const verifier = context.authenticationResponse?.client_id;
      try {
        return await RNSecureKeystoreModule.hasAlias(getVerifierKey(verifier));
      } catch (error) {
        console.error(
          `Error while checking verifier client ID in trusted verifiers:`,
          error,
        );
        return false;
      }
    },

    storeTrustedVerifier: (context: any) => async () => {
      const {RNSecureKeystoreModule} = NativeModules;
      const verifier = context.authenticationResponse?.client_id;
      const trustValue = JSON.stringify({
        trusted: true,
        createdAt: new Date().toISOString(),
      });
      try {
        return await RNSecureKeystoreModule.storeData(
          getVerifierKey(verifier),
          trustValue,
        );
      } catch (error) {
        console.error(
          `Error while storing verifier client ID in trusted verifiers:`,
          error,
        );
        return false;
      }
    },

    getKeyPair: async (context: any) => {
      if (!!(await hasKeyPair(context.keyType))) {
        return await fetchKeyPair(context.keyType);
      }
    },

    getSelectedKey: async (context: any) => {
      return await fetchKeyPair(context.keyType);
    },

    shareDeclineStatus: async () => {
      return await OpenID4VP.sendErrorToVerifier(
        OVP_ERROR_MESSAGES.DECLINED,
        OVP_ERROR_CODE.DECLINED,
      );
    },

    sendSelectedCredentialsForVP: (context: any) => async () => {
      // Android (OpenID4VP 1.0) and iOS (0.7) differ in shape; see processSelectedVCs.
      const selectedCredentials: any =
        await OpenID4VP.prepareCredentialsForVPSharing(
          context.selectedVCs,
          context.selectedDisclosuresByVc,
        );
      await VciClient.getInstance().sendSelectedCredentialsForVPSharing(
        selectedCredentials,
      );
    },

    // Presentation during issuance: the VCI client hands over the tokens to sign. It runs
    // OpenID4VP 1.0, which wants [{id, signedData}] over raw bytes.
    signVP: (context: any) => async () => {
      return await signUnsignedVPTokens(context.unsignedVPToken);
    },

    // DCQL requests (OpenID4VP 1.0): the library matches the credentials. Invoked on
    // DOWNLOADED_VCS, so the event carries the wallet's credentials.
    getDcqlMatchingVCs: (context: any, event: any) => async () => {
      const result = await OpenID4VP.getDcqlMatchingVCs(
        context.authenticationResponse,
        event.vcs ?? [],
      );
      if (Object.keys(result.matchingVCs).length === 0) {
        // Same as the presentation definition path: tell the verifier only when nothing matched.
        void OpenID4VP.sendErrorToVerifier(
          OVP_ERROR_MESSAGES.NO_MATCHING_VCS,
          OVP_ERROR_CODE.NO_MATCHING_VCS,
        );
      }
      return result;
    },

    sendVP: (context: any) => async () => {
      const jwk = await getJWK(context.publicKey, context.keyType);
      const holderId = 'did:jwk:' + base64url(JSON.stringify(jwk)) + '#0';

      const unSignedVpTokens = await OpenID4VP.constructUnsignedVPToken(
        context.selectedVCs,
        context.selectedDisclosuresByVc,
        holderId,
      );
      // OpenID4VP 1.0: a list of tokens, each signed over raw bytes.
      const vpTokenSigningResults = await signUnsignedVPTokens(
        unSignedVpTokens,
      );
      const verifierResponse = await OpenID4VP.shareVerifiablePresentation(
        vpTokenSigningResults,
      );
      if (verifierResponse['status_code'] !== 200) {
        console.error(
          'Error response from verifier during sharing the VP :',
          verifierResponse,
        );
        throw new Error('VERIFIER_RESPONSE_ERROR');
      }
      return verifierResponse;
    },
  };
};
