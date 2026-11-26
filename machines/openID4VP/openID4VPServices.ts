import {CACHED_API} from '../../shared/api';
import {fetchKeyPair} from '../../shared/cryptoutil/cryptoUtil';
import {hasKeyPair} from '../../shared/openId4VCI/Utils';
import OpenID4VP, {credentialIdOf} from '../../shared/openID4VP/OpenID4VP';
import {OVP_ERROR_CODE, OVP_ERROR_MESSAGES} from '../../shared/constants';
import {getVerifierKey, VCShareFlowType} from '../../shared/Utils';
import {
  isClientValidationRequired,
  signDataForVpPreparation,
} from '../../shared/openID4VP/OpenID4VPHelper';
import {NativeModules} from 'react-native';
import VciClient from '../../shared/vciClient/VciClient';
import {VC} from '../VerifiableCredential/VCMetaMachine/vc';

export const openID4VPServices = () => {
  return {
    fetchTrustedVerifiers: async () => {
      return await CACHED_API.fetchTrustedVerifiersList();
    },

    shouldValidateClient: async () => {
      return await isClientValidationRequired();
    },

    // Trusted verifiers and client validation reach the library through the wallet config
    // (OpenID4VPHelper.getWalletConfig), as in upstream Inji Wallet 1.0.0-alpha.1.
    getAuthenticationResponse: (context: any) => async () => {
      return await OpenID4VP.authenticateVerifier(
        context.urlEncodedAuthorizationRequest,
      );
    },

    // DCQL requests: the library matches the credentials. Returns the full result for the DCQL
    // UI plus a credential-query → VC[] map, the shape presentation definition matching produces.
    getDcqlMatchingVCs: (context: any, event: any) => async () => {
      const vcs: VC[] = event.vcs ?? [];
      const dcqlResult = await OpenID4VP.getDcqlMatchingVCs(
        context.authenticationResponse,
        vcs,
      );
      const vcByKey: Record<string, VC> = {};
      vcs.forEach(vc => (vcByKey[credentialIdOf(vc)] = vc));
      const matchingVCs: Record<string, VC[]> = {};
      Object.entries(dcqlResult.matchingVCs).forEach(([queryId, match]) => {
        const matched = (match.matchingVcs ?? [])
          .map(m => vcByKey[m.matchingVcInfo.vcKey])
          .filter(Boolean);
        if (matched.length > 0) {
          matchingVCs[queryId] = matched;
        }
      });
      if (!dcqlResult.success) {
        // As for presentation definitions: tell the verifier only when the request can't be met.
        void OpenID4VP.sendErrorToVerifier(
          OVP_ERROR_MESSAGES.NO_MATCHING_VCS,
          OVP_ERROR_CODE.NO_MATCHING_VCS,
        );
      }
      return {dcqlResult, matchingVCs};
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
      const selectedCredentials =
        await OpenID4VP.prepareCredentialsForVPSharing(
          context.authenticationResponse,
          context.selectedVCs,
          context.selectedDisclosuresByVc,
        );
      await VciClient.getInstance().sendSelectedCredentialsForVPSharing(
        selectedCredentials,
      );
    },

    // Presentation during issuance: the VCI client hands over OpenID4VP 1.0 unsigned tokens.
    signVP: (context: any) => async () => {
      return await signDataForVpPreparation(context.unsignedVPToken);
    },

    sendVP: (context: any) => async () => {
      const unSignedVpTokens = await OpenID4VP.constructUnsignedVPToken(
        context.authenticationResponse,
        context.selectedVCs,
        context.selectedDisclosuresByVc,
      );
      const vpTokenSigningResults = await signDataForVpPreparation(
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
