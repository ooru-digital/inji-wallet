import {NativeModules} from 'react-native';
import {__AppId} from '../GlobalVariables';
import {
  SelectedCredentialsForVPSharing,
  VC,
} from '../../machines/VerifiableCredential/VCMetaMachine/vc';
import {walletMetadata} from './walletMetadata';
import {getWalletMetadata, isClientValidationRequired} from './OpenID4VPHelper';
import {parseJSON} from '../Utils';
import {VCFormat} from '../VCFormat';
import {VCMetadata} from '../VCMetadata';

export const OpenID4VP_Proof_Sign_Algo = 'EdDSA';

class OpenID4VP {
  private static instance: OpenID4VP;
  private InjiOpenID4VP = NativeModules.InjiOpenID4VP;

  private constructor(walletMetadata: any) {
    this.InjiOpenID4VP.initSdk(__AppId.getValue(), walletMetadata);
  }

  private static async getInstance(): Promise<OpenID4VP> {
    if (!OpenID4VP.instance) {
      // Checked explicitly so an absent native module reports itself, rather than surfacing as
      // "Cannot read property 'initSdk' of undefined" from the constructor below — an error with
      // no .code/.userInfo, which is exactly the shape that reached setAuthenticationError as a
      // bare "undefined" with nothing in logcat (the module's own Log.d never runs either).
      if (NativeModules.InjiOpenID4VP == null) {
        throw new Error(
          'InjiOpenID4VP native module is not available. Registered native modules: ' +
            Object.keys(NativeModules).sort().join(', '),
        );
      }
      const walletMetadataConfig =
        (await getWalletMetadata()) || walletMetadata;
      OpenID4VP.instance = new OpenID4VP(walletMetadataConfig);
    }
    return OpenID4VP.instance;
  }

  static async authenticateVerifier(
    urlEncodedAuthorizationRequest: string,
    trustedVerifiersList: any,
  ) {
    // Each step is attributed, because a throw anywhere in here previously arrived at
    // setAuthenticationError as an indistinguishable "undefined". getInstance() in particular
    // runs getAllConfigurations() + JSON.parse(config.walletMetadata) and calls the fire-and-forget
    // initSdk, none of which is otherwise visible from the failure.
    let step = 'isClientValidationRequired';
    try {
      const shouldValidateClient = await isClientValidationRequired();

      step = 'getInstance (walletMetadata / initSdk)';
      const openID4VP = await OpenID4VP.getInstance();

      step = 'InjiOpenID4VP.authenticateVerifier (native)';
      const authenticationResponse =
        await openID4VP.InjiOpenID4VP.authenticateVerifier(
          urlEncodedAuthorizationRequest,
          trustedVerifiersList,
          shouldValidateClient,
        );

      step = 'JSON.parse of native response';
      return JSON.parse(authenticationResponse);
    } catch (e: any) {
      console.error(
        `[OpenID4VP] authenticateVerifier failed at step: ${step}`,
        '\n  name:', e?.name,
        '\n  message:', e?.message,
        '\n  code:', e?.code,
        '\n  stack:', e?.stack,
      );
      throw e;
    }
  }

  static async prepareCredentialsForVPSharing(
    selectedVCs: Record<string, VC[]>,
    selectedDisclosuresByVc: any,
  ) {
    const openID4VP = await OpenID4VP.getInstance();

    return openID4VP.processSelectedVCs(selectedVCs, selectedDisclosuresByVc);
  }

  static async constructUnsignedVPToken(
    selectedVCs: Record<string, VC[]>,
    selectedDisclosuresByVc: any,
    holderId: string,
    signatureAlgorithm: string,
  ) {
    const openID4VP = await OpenID4VP.getInstance();

    const updatedSelectedVCs = openID4VP.processSelectedVCs(
      selectedVCs,
      selectedDisclosuresByVc,
    );
    const unSignedVpTokens =
      await openID4VP.InjiOpenID4VP.constructUnsignedVPToken(
        updatedSelectedVCs,
        holderId,
        signatureAlgorithm,
      );
    return parseJSON(unSignedVpTokens);
  }

  static async shareVerifiablePresentation(
    vpTokenSigningResultMap: Record<string, any>,
  ) {
    const openID4VP = await OpenID4VP.getInstance();

    const verifierResponse =
      await openID4VP.InjiOpenID4VP.shareVerifiablePresentation(
        vpTokenSigningResultMap,
      );
    return parseJSON(verifierResponse);
  }

  static async sendErrorToVerifier(errorMessage: string, errorCode: string) {
    const openID4VP = await OpenID4VP.getInstance();

    return openID4VP.InjiOpenID4VP.sendErrorToVerifier(errorMessage, errorCode);
  }

  private processSelectedVCs(
    selectedVCs: Record<string, VC[]>,
    selectedDisclosuresByVc: any,
  ) {
    const selectedVcsData: SelectedCredentialsForVPSharing = {};
    Object.entries(selectedVCs).forEach(([inputDescriptorId, vcsArray]) => {
      vcsArray.forEach(vcData => {
        const credentialFormat = vcData.vcMetadata.format;
        const credential = this.extractCredential(
          vcData,
          credentialFormat,
          selectedDisclosuresByVc[
            VCMetadata.fromVcMetadataString(vcData.vcMetadata).getVcKey()
          ],
        );
        if (!selectedVcsData[inputDescriptorId]) {
          selectedVcsData[inputDescriptorId] = {};
        }
        if (!selectedVcsData[inputDescriptorId][credentialFormat]) {
          selectedVcsData[inputDescriptorId][credentialFormat] = [];
        }
        selectedVcsData[inputDescriptorId][credentialFormat].push(credential);
      });
    });
    return selectedVcsData;
  }

  private extractCredential(
    vcData: VC,
    credentialFormat: string,
    selectedDisclosures: any,
  ) {
    if (
      credentialFormat === VCFormat.mso_mdoc ||
      credentialFormat === VCFormat.ldp_vc
    ) {
      return vcData.verifiableCredential.credential;
    }
    if (
      credentialFormat === VCFormat.vc_sd_jwt ||
      credentialFormat === VCFormat.dc_sd_jwt
    ) {
      return this.processSdJwtVcForSharing(vcData, selectedDisclosures);
    }
  }

  private processSdJwtVcForSharing(
    vcData: VC,
    selectedDisclosures: string[],
  ): string {
    if (!vcData?.verifiableCredential?.credential) {
      throw new Error('Invalid VC: missing credential');
    }

    const compact = vcData.verifiableCredential.credential;
    const [jwt] = compact.split('~');

    const pathToDisclosures: Record<string, string[]> =
      vcData.verifiableCredential?.processedCredential.pathToDisclosures || {};

    const disclosureSet = new Set<string>();
    selectedDisclosures?.forEach(path => {
      const disclosures = pathToDisclosures[path];
      if (disclosures) {
        disclosures.forEach(d => disclosureSet.add(d));
      }
    });

    const finalSdJwt =
      disclosureSet.size > 0
        ? [jwt, ...disclosureSet].join('~') + '~'
        : jwt + '~';

    return finalSdJwt;
  }
}

export default OpenID4VP;
