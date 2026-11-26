import {NativeEventEmitter, NativeModules} from 'react-native';
import {__AppId} from '../GlobalVariables';
import {VC} from '../../machines/VerifiableCredential/VCMetaMachine/vc';
import {
  getWalletConfig,
  isDcqlFlow,
  jsonLdCanonicalize,
} from './OpenID4VPHelper';
import {jsonLdExpand, parseJSON} from '../Utils';
import {VCFormat} from '../VCFormat';
import {VCMetadata} from '../VCMetadata';
import {isIOS} from '../constants';
import {getDisclosuresForPath} from '../claimsPathMatching';
import {
  CredentialSetOption,
  MatchingVCsResultForDcql,
  MatchResult,
  VCInfo,
  VcWithMatchedClaims,
} from './openid4vp.types';

export const OpenID4VP_Proof_Sign_Algo = 'EdDSA';

/** Formats the native layer can take as a wallet credential. */
const SHAREABLE_FORMATS: string[] = [
  VCFormat.ldp_vc,
  VCFormat.mso_mdoc,
  VCFormat.vc_sd_jwt,
  VCFormat.dc_sd_jwt,
];

/**
 * OpenID4VP 1.0 on both platforms (upstream Inji Wallet 1.0.0-alpha.1's flow): Android the patched
 * AAR in android/libs, iOS the patched copy in ios/Packages. DCQL requests are matched natively
 * (getDcqlMatchingVCs); presentation definition requests keep CredIssuer's matching in
 * machines/openID4VP/openID4VPActions.ts.
 */
class OpenID4VP {
  private static instance: OpenID4VP;
  private InjiOpenID4VP = NativeModules.InjiOpenID4VP;

  private constructor(walletConfig: Record<string, any>) {
    if (isIOS()) {
      this.addJsonLdListeners();
    }
    this.InjiOpenID4VP.initSdk(__AppId.getValue(), walletConfig);
  }

  /**
   * The iOS library hands JSON-LD work to JS: expansion for DCQL type matching, and
   * canonicalization of the ldp_vc VP it signs. Each event needs exactly one reply, or the native
   * call waits forever. A failed expansion leaves that card without expanded types; a failed
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
      // no .code/.userInfo, which reached setAuthenticationError as a bare "undefined".
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

  static async authenticateVerifier(urlEncodedAuthorizationRequest: string) {
    // Each step is attributed, because a throw anywhere in here otherwise arrives at
    // setAuthenticationError as an indistinguishable error. getInstance() in particular reads the
    // config and calls the fire-and-forget initSdk.
    let step = 'getInstance (wallet config / initSdk)';
    try {
      const openID4VP = await OpenID4VP.getInstance();

      step = 'InjiOpenID4VP.authenticateVerifier (native)';
      const authenticationResponse =
        await openID4VP.InjiOpenID4VP.authenticateVerifier(
          urlEncodedAuthorizationRequest,
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
      );
      throw e;
    }
  }

  /**
   * Matches the wallet's credentials against a DCQL request (upstream 1.0.0-alpha.1). The library
   * evaluates format, meta (vct, doctype, W3C types), holder binding and claims; credential sets
   * whose options can't be met are dropped.
   */
  static async getDcqlMatchingVCs(
    vpRequest: object,
    availableWalletCredentials: VC[],
  ): Promise<MatchingVCsResultForDcql> {
    const openID4VP = await OpenID4VP.getInstance();
    const idToCredentialMap: Record<string, VC> = {};
    const walletCredentials = availableWalletCredentials
      .filter(vc => SHAREABLE_FORMATS.includes(vc.vcMetadata?.format))
      .map(vc => {
        const credentialId = credentialIdOf(vc);
        idToCredentialMap[credentialId] = vc;
        return {
          format: vc.vcMetadata.format,
          credentialId,
          credential: (vc.verifiableCredential as any).credential,
        };
      });

    const result = parseJSON(
      await openID4VP.InjiOpenID4VP.getMatchingCredentials(
        vpRequest,
        walletCredentials,
      ),
    );

    const requestedClaims = new Set<string>();
    const credentialSetOptions: CredentialSetOption[] = result.success
      ? filterSatisfiableCredentialSetOptions(
          result.queryMatches ?? {},
          result.credentialSets ?? [],
        )
      : result.credentialSets ?? [];

    const matchingVCs: Record<string, MatchResult> = {};
    Object.entries(result.queryMatches ?? {}).forEach(
      ([queryId, queryMatch]: [string, any]) => {
        if (queryMatch && Array.isArray(queryMatch.matchingCredentials)) {
          matchingVCs[queryId] = {
            matchingVcs: queryMatch.matchingCredentials
              .filter((match: any) => idToCredentialMap[match.credentialId])
              .map((match: any) => {
                const vc = idToCredentialMap[match.credentialId];
                return {
                  matchingVcInfo: new VCInfo(
                    credentialIdOf(vc),
                    vc.vcMetadata as VCMetadata,
                  ),
                  matchedClaims: match.matchingClaims,
                } as VcWithMatchedClaims;
              }),
            allowMultipleCredentials:
              queryMatch.allowMultipleCredentials === true,
          };
        } else if (queryMatch?.failedClaims) {
          (queryMatch.failedClaims as any[]).forEach(failedClaim => {
            const name = getClaimName(failedClaim?.claim?.path ?? []);
            if (name) requestedClaims.add(name);
          });
        }
      },
    );

    return {
      matchingVCs,
      success: result.success === true,
      requestedClaims,
      purpose: '',
      credentialSetOptions,
    };
  }

  /** {requestId: [{format, credentialId, credential}]}, for presentation during issuance. */
  static async prepareCredentialsForVPSharing(
    vpRequest: object,
    selectedVCs: Record<string, VC[]>,
    selectedDisclosuresByVc: Record<string, string[]>,
  ) {
    return processSelectedVCs(vpRequest, selectedVCs, selectedDisclosuresByVc);
  }

  /**
   * Returns [{id, format, holderKeyReference, signatureAlgorithm, dataToSign}]. The library takes
   * each ldp_vc VP's holder from the card's credentialSubject.id (the wallet's did:jwk, bound at
   * issuance).
   */
  static async constructUnsignedVPToken(
    vpRequest: object,
    selectedVCs: Record<string, VC[]>,
    selectedDisclosuresByVc: Record<string, string[]>,
  ) {
    const openID4VP = await OpenID4VP.getInstance();
    const unSignedVpTokens =
      await openID4VP.InjiOpenID4VP.constructUnsignedVPToken(
        processSelectedVCs(vpRequest, selectedVCs, selectedDisclosuresByVc),
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
}

/** The wallet's key for a stored credential; unique per download. */
export function credentialIdOf(vc: VC): string {
  return VCMetadata.fromVcMetadataString(vc.vcMetadata).getVcKey();
}

/** {requestId: [{format, credentialId, credential}]}. */
function processSelectedVCs(
  vpRequest: object,
  selectedVCs: Record<string, VC[]>,
  selectedDisclosuresByVc: Record<string, string[]>,
) {
  const isDcqlRequest = isDcqlFlow(vpRequest as Record<string, unknown>);
  const selected: Record<
    string,
    {format: string; credentialId: string; credential: any}[]
  > = {};
  Object.entries(selectedVCs).forEach(([requestId, vcsArray]) => {
    selected[requestId] = vcsArray.map(vcData => {
      const format = vcData.vcMetadata.format;
      return {
        format,
        credentialId: credentialIdOf(vcData),
        credential: extractCredential(
          vcData,
          format,
          selectedDisclosuresByVc?.[credentialIdOf(vcData)],
          isDcqlRequest,
        ),
      };
    });
  });
  return selected;
}

function extractCredential(
  vcData: VC,
  format: string,
  selectedDisclosures: string[] | undefined,
  isDcqlRequest: boolean,
) {
  if (format === VCFormat.mso_mdoc || format === VCFormat.ldp_vc) {
    return vcData.verifiableCredential.credential;
  }
  if (format === VCFormat.vc_sd_jwt || format === VCFormat.dc_sd_jwt) {
    return isDcqlRequest
      ? sdJwtForClaimsPaths(vcData, selectedDisclosures)
      : sdJwtForSelectedDisclosures(vcData, selectedDisclosures);
  }
}

/**
 * Presentation definition: the disclosures the user picked, keyed by their exact paths in
 * processedCredential.pathToDisclosures.
 */
function sdJwtForSelectedDisclosures(
  vcData: VC,
  selectedDisclosures: string[] | undefined,
): string {
  return sdJwtWithDisclosures(
    vcData,
    selectedDisclosures,
    (map, path) => map[path],
  );
}

/**
 * DCQL: the disclosures for the claims the verifier asked for (JSONPaths from the matched claims),
 * matched through claimsPathMatching so wildcards and array indices resolve.
 */
function sdJwtForClaimsPaths(
  vcData: VC,
  claimsPaths: string[] | undefined,
): string {
  return sdJwtWithDisclosures(vcData, claimsPaths, getDisclosuresForPath);
}

function sdJwtWithDisclosures(
  vcData: VC,
  paths: string[] | undefined,
  disclosuresFor: (
    pathToDisclosures: Record<string, string[]>,
    path: string,
  ) => string[] | undefined,
): string {
  if (!vcData?.verifiableCredential?.credential) {
    throw new Error('Invalid VC: missing credential');
  }
  const [jwt] = (vcData.verifiableCredential.credential as string).split('~');
  const pathToDisclosures: Record<string, string[]> =
    (vcData.verifiableCredential as any)?.processedCredential
      ?.pathToDisclosures || {};

  const disclosureSet = new Set<string>();
  paths?.forEach(path => {
    disclosuresFor(pathToDisclosures, path)?.forEach(d => disclosureSet.add(d));
  });

  return disclosureSet.size > 0
    ? [jwt, ...disclosureSet].join('~') + '~'
    : jwt + '~';
}

/** The last named segment of a claims path, e.g. ['credentialSubject', 'name'] → 'name'. */
function getClaimName(claimPath: Array<string | number | null>): string {
  for (let i = claimPath.length - 1; i >= 0; i--) {
    const segment = claimPath[i];
    if (typeof segment === 'string') return segment;
  }
  return '';
}

/** Drops credential-set options that need a query with no matching card, then empty sets. */
function filterSatisfiableCredentialSetOptions(
  queryMatches: Record<string, any>,
  credentialSetOptions: CredentialSetOption[],
): CredentialSetOption[] {
  return credentialSetOptions
    .map(credentialSet => ({
      ...credentialSet,
      options: credentialSet.options.filter(option =>
        option.every(queryId => {
          const matchingResult = queryMatches[queryId];
          return (
            matchingResult &&
            Array.isArray(matchingResult.matchingCredentials) &&
            matchingResult.matchingCredentials.length > 0
          );
        }),
      ),
    }))
    .filter(credentialSet => credentialSet.options.length > 0);
}

export default OpenID4VP;
