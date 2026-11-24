import {NativeEventEmitter, NativeModules} from 'react-native';
import {__AppId} from '../GlobalVariables';
import {VC} from '../../machines/VerifiableCredential/VCMetaMachine/vc';
import {
  getWalletConfig,
  isClientValidationRequired,
  jsonLdCanonicalize,
} from './OpenID4VPHelper';
import {jsonLdExpand, parseJSON} from '../Utils';
import {VCFormat} from '../VCFormat';
import {VCMetadata} from '../VCMetadata';
import {isIOS} from '../constants';

export const OpenID4VP_Proof_Sign_Algo = 'EdDSA';

/*
 * Both platforms run inji-openid4vp 1.0 (DCQL and presentation definition requests): Android the
 * patched AAR, iOS the patched copy in ios/Packages. The two native modules take the same calls.
 */

/** Formats the native layer can take as a wallet credential. */
const SHAREABLE_FORMATS: string[] = [
  VCFormat.ldp_vc,
  VCFormat.mso_mdoc,
  VCFormat.vc_sd_jwt,
  VCFormat.dc_sd_jwt,
];

export type DcqlMatchingResult = {
  /** Credential query id → the wallet's credentials that satisfy it. */
  matchingVCs: Record<string, VC[]>;
  /** Claims the verifier asked for that no credential had, for the no-match screen. */
  requestedClaims: string;
  success: boolean;
};

class OpenID4VP {
  private static instance: OpenID4VP;
  private InjiOpenID4VP = NativeModules.InjiOpenID4VP;

  private constructor(walletConfig: any) {
    if (isIOS()) {
      this.addJsonLdListeners();
    }
    this.InjiOpenID4VP.initSdk(__AppId.getValue(), walletConfig);
  }

  /**
   * The iOS library hands JSON-LD work to JS: expansion for DCQL type matching and
   * canonicalization of the ldp_vc VP it signs. Each event gets exactly one reply, or the native
   * call waits forever. A failed expansion leaves that card with no expanded types; a failed
   * canonicalization fails the share.
   */
  private addJsonLdListeners() {
    const emitter = new NativeEventEmitter(this.InjiOpenID4VP);
    emitter.addListener('onJsonLdExpand', async ({data}: {data: any}) => {
      try {
        this.InjiOpenID4VP.sendJsonLdExpandResultFromJS(
          await jsonLdExpand(data),
        );
      } catch (error) {
        console.error('[OpenID4VP] JSON-LD expansion failed', error);
        this.InjiOpenID4VP.notifyJsonLdExpansionFailureFromJS(
          'server_error',
          'An error occurred during JSON-LD expansion',
        );
      }
    });
    emitter.addListener(
      'onJsonLdCanonicalize',
      async ({data}: {data: string}) => {
        try {
          this.InjiOpenID4VP.sendJsonLdCanonicalizeResultFromJS(
            await jsonLdCanonicalize(data),
          );
        } catch (error) {
          console.error('[OpenID4VP] JSON-LD canonicalization failed', error);
          this.InjiOpenID4VP.notifyCanonicalizationFailureFromJS(
            'server_error',
            'An error occurred during JSON-LD canonicalization',
          );
        }
      },
    );
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
      OpenID4VP.instance = new OpenID4VP(await getWalletConfig());
    }
    return OpenID4VP.instance;
  }

  static async authenticateVerifier(
    urlEncodedAuthorizationRequest: string,
    trustedVerifiersList: any,
  ) {
    // Each step is attributed, because a throw anywhere in here previously arrived at
    // setAuthenticationError as an indistinguishable "undefined". getInstance() in particular
    // runs getAllConfigurations() + JSON.parse of the wallet config and calls the
    // fire-and-forget initSdk, none of which is otherwise visible from the failure.
    let step = 'isClientValidationRequired';
    try {
      const shouldValidateClient = await isClientValidationRequired();

      step = 'getInstance (wallet config / initSdk)';
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
        '\n  name:',
        e?.name,
        '\n  message:',
        e?.message,
        '\n  code:',
        e?.code,
        '\n  stack:',
        e?.stack,
      );
      throw e;
    }
  }

  /** A DCQL request (OpenID4VP 1.0) rather than a presentation definition. */
  static isDcqlRequest(authenticationResponse: any): boolean {
    return authenticationResponse?.dcql_query != null;
  }

  /**
   * Matches the wallet's credentials against a DCQL request. The library evaluates format, meta
   * (vct, doctype, W3C types) and claims.
   */
  static async getDcqlMatchingVCs(
    authenticationResponse: object,
    vcs: VC[],
  ): Promise<DcqlMatchingResult> {
    const openID4VP = await OpenID4VP.getInstance();
    const vcById: Record<string, VC> = {};
    const walletCredentials = vcs
      .filter(vc => SHAREABLE_FORMATS.includes(vc.vcMetadata?.format))
      .map(vc => {
        const credentialId = credentialIdOf(vc);
        vcById[credentialId] = vc;
        return {
          format: vc.vcMetadata.format,
          credentialId,
          credential: (vc.verifiableCredential as any).credential,
        };
      });

    const result = parseJSON(
      await openID4VP.InjiOpenID4VP.getMatchingCredentials(
        authenticationResponse,
        walletCredentials,
      ),
    );

    const matchingVCs: Record<string, VC[]> = {};
    const requestedClaims = new Set<string>();
    Object.entries(result?.queryMatches ?? {}).forEach(
      ([queryId, queryMatch]: [string, any]) => {
        const matched = (queryMatch?.matchingCredentials ?? [])
          .map((match: any) => vcById[match.credentialId])
          .filter(Boolean);
        if (matched.length > 0) {
          matchingVCs[queryId] = matched;
        }
        (queryMatch?.failedClaims ?? []).forEach((failure: any) => {
          const name = claimNameOf(failure?.claim?.path);
          if (name) requestedClaims.add(name);
        });
      },
    );

    return {
      matchingVCs,
      requestedClaims: Array.from(requestedClaims).join(','),
      success: result?.success === true,
    };
  }

  static async prepareCredentialsForVPSharing(
    selectedVCs: Record<string, VC[]>,
    selectedDisclosuresByVc: any,
  ) {
    const openID4VP = await OpenID4VP.getInstance();

    return openID4VP.processSelectedVCs(selectedVCs, selectedDisclosuresByVc);
  }

  /**
   * Returns [{id, format, holderKeyReference, signatureAlgorithm, dataToSign}]. The library takes
   * the holder from each credential; holderId (the wallet's did:jwk) is only a fallback, which the
   * patched library uses as the ldp_vc VP holder when a card's credentialSubject.id is not a DID,
   * as with CredIssuer's urn:uuid subjects.
   */
  static async constructUnsignedVPToken(
    selectedVCs: Record<string, VC[]>,
    selectedDisclosuresByVc: any,
    holderId: string,
  ) {
    const openID4VP = await OpenID4VP.getInstance();

    const unSignedVpTokens =
      await openID4VP.InjiOpenID4VP.constructUnsignedVPToken(
        openID4VP.processSelectedVCs(selectedVCs, selectedDisclosuresByVc),
        holderId,
      );
    return parseJSON(unSignedVpTokens);
  }

  /** vpTokenSigningResults: [{id, signedData}]. */
  static async shareVerifiablePresentation(vpTokenSigningResults: any) {
    const openID4VP = await OpenID4VP.getInstance();

    const verifierResponse =
      await openID4VP.InjiOpenID4VP.shareVerifiablePresentation(
        vpTokenSigningResults,
      );
    return parseJSON(verifierResponse);
  }

  static async sendErrorToVerifier(errorMessage: string, errorCode: string) {
    const openID4VP = await OpenID4VP.getInstance();

    return openID4VP.InjiOpenID4VP.sendErrorToVerifier(errorMessage, errorCode);
  }

  /** {requestId: [{format, credentialId, credential}]}. */
  private processSelectedVCs(
    selectedVCs: Record<string, VC[]>,
    selectedDisclosuresByVc: any,
  ) {
    const selected: Record<
      string,
      {format: string; credentialId: string; credential: any}[]
    > = {};
    Object.entries(selectedVCs).forEach(([requestId, vcsArray]) => {
      selected[requestId] = vcsArray.map(vcData => ({
        format: vcData.vcMetadata.format,
        credentialId: credentialIdOf(vcData),
        credential: this.extractCredential(
          vcData,
          vcData.vcMetadata.format,
          selectedDisclosuresByVc[credentialIdOf(vcData)],
        ),
      }));
    });
    return selected;
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

/** The wallet's key for a stored credential; unique per download. */
function credentialIdOf(vc: VC): string {
  return VCMetadata.fromVcMetadataString(vc.vcMetadata).getVcKey();
}

/** The last named segment of a DCQL claims path, e.g. ['credentialSubject', 'name'] → 'name'. */
function claimNameOf(path: unknown): string {
  if (!Array.isArray(path)) return '';
  for (let i = path.length - 1; i >= 0; i--) {
    if (typeof path[i] === 'string') return path[i];
  }
  return '';
}

export default OpenID4VP;
