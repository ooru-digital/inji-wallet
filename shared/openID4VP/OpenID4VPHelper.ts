import {NativeModules} from 'react-native';
import forge from 'node-forge';
import {
  createSignatureECK1,
  createSignatureECR1,
  createSignatureED,
  fetchKeyPair,
  replaceCharactersInB64,
} from '../cryptoutil/cryptoUtil';
import {base64ToByteArray, canonicalize, parseJSON} from '../Utils';
import getAllConfigurations, {CACHED_API} from '../api';
import {isAndroid, JWT_ALG_TO_KEY_TYPE} from '../constants';
import {KeyTypes} from '../cryptoutil/KeyTypes';
import {UnsignedVPToken, VPTokenSigningResult} from './openid4vp.types';
import {defaultWalletConfig} from './walletConfig/WalletConfig';

export async function isClientValidationRequired() {
  const config = await getAllConfigurations();
  return config.openid4vpClientValidation === 'true';
}

/**
 * The OpenID4VP 1.0 wallet config (upstream Inji Wallet 1.0.0-alpha.1): `openid4vpWalletConfig`
 * from the config when set, else the default, plus `validate_trusted_verifier` and the trusted
 * verifiers. The native libraries take it once, at init, and for presentation during issuance.
 */
export async function getWalletConfig() {
  const config = await getAllConfigurations();
  let walletConfig: Record<string, any> = {...defaultWalletConfig};
  if (config.openid4vpWalletConfig) {
    try {
      walletConfig = parseJSON(config.openid4vpWalletConfig);
    } catch (e) {
      console.warn('Invalid openid4vpWalletConfig, using the default', e);
    }
  } else {
    console.warn(
      'There is no wallet configuration available in the config. Using default wallet configuration.',
    );
  }

  walletConfig['validate_trusted_verifier'] =
    config.openid4vpClientValidation === 'true';

  try {
    const trustedVerifiersResponse =
      await CACHED_API.fetchTrustedVerifiersList();
    walletConfig['trusted_verifiers'] =
      trustedVerifiersResponse?.response?.verifiers ?? [];
  } catch (e) {
    console.warn('Error fetching trusted verifiers, falling back to none: ', e);
    walletConfig['trusted_verifiers'] = [];
  }

  return walletConfig;
}

/**
 * JSON-LD canonicalization for the iOS libraries, which hand the unsigned ldp_vc VP to JS as a
 * JSON string. Returns base64url(sha256(canonical proof) || sha256(canonical document)), the
 * bytes they sign over. Android's libraries canonicalize natively.
 */
export const jsonLdCanonicalize = async (data: string) => {
  const canonicalized = await canonicalize(JSON.parse(data));
  if (!canonicalized) {
    throw new Error('Canonicalized data to sign is undefined');
  }
  return canonicalized;
};

/**
 * Signs OpenID4VP 1.0 unsigned VP tokens: [{id, format, holderKeyReference, signatureAlgorithm,
 * dataToSign}], where dataToSign is base64url bytes. The library builds the whole VP, proof
 * included; the wallet only signs the bytes with the key that matches `signatureAlgorithm`.
 * Returns [{id, signedData}].
 *
 * One token at a time: hardware keys can show a biometric prompt, and two at once would collide.
 */
export const signDataForVpPreparation = async (
  unsignedVPTokens: Array<UnsignedVPToken>,
): Promise<Array<VPTokenSigningResult>> => {
  const results: VPTokenSigningResult[] = [];
  for (const unsignedVPToken of unsignedVPTokens) {
    results.push({
      id: unsignedVPToken.id,
      signedData: await signBytes(
        unsignedVPToken.signatureAlgorithm,
        base64ToByteArray(unsignedVPToken.dataToSign),
      ),
    });
  }
  return results;
};

async function signBytes(
  algorithm: string,
  payload: Uint8Array,
): Promise<string> {
  const keyType =
    JWT_ALG_TO_KEY_TYPE[algorithm as keyof typeof JWT_ALG_TO_KEY_TYPE];
  switch (keyType) {
    case KeyTypes.ED25519: {
      const {privateKey} = await fetchKeyPair(KeyTypes.ED25519);
      return createSignatureED(privateKey, payload);
    }
    case KeyTypes.ES256K: {
      const {privateKey} = await fetchKeyPair(KeyTypes.ES256K);
      return createSignatureECK1(privateKey, payload);
    }
    case KeyTypes.ES256: {
      // Android: hardware key, signed through RNSecureKeystoreModule.signBytes.
      const {privateKey} = await fetchKeyPair(KeyTypes.ES256);
      return createSignatureECR1(privateKey, payload);
    }
    case KeyTypes.RS256:
      return signRsaBytes(payload);
    default:
      throw new Error(`Unsupported signature algorithm: ${algorithm}`);
  }
}

/**
 * RS256 over raw bytes. createSignatureRSA can't be used: on Android it signs the UTF-8 bytes of a
 * string, and on iOS it digests its input as UTF-8 text, either of which changes bytes above 0x7F.
 */
async function signRsaBytes(payload: Uint8Array): Promise<string> {
  if (isAndroid()) {
    const signature64: string =
      await NativeModules.RNSecureKeystoreModule.signBytes(
        KeyTypes.RS256,
        KeyTypes.RS256,
        Buffer.from(payload).toString('base64'),
      );
    return replaceCharactersInB64(signature64);
  }
  const {privateKey} = await fetchKeyPair(KeyTypes.RS256);
  const key = forge.pki.privateKeyFromPem(privateKey);
  const md = forge.md.sha256.create();
  md.update(forge.util.binary.raw.encode(payload));
  return replaceCharactersInB64(
    Buffer.from(key.sign(md), 'binary').toString('base64'),
  );
}

/**
 * Converts a Claim Path Pointer (array of strings/numbers/null) to a JSONPath string.
 *
 * ['credentialSubject', null, 'givenName'] -> 'credentialSubject[*].givenName'
 * ['credentialSubject', 0, 'givenName'] -> 'credentialSubject[0].givenName'
 * ['credentialSubject', 'degree', 'ug'] -> 'credentialSubject.degree.ug'
 */
export function claimPathPointersToJsonPath(
  path: Array<string | number | null>,
): string {
  let currentPath = '';

  for (const token of path) {
    if (typeof token === 'string') {
      currentPath = currentPath ? `${currentPath}.${token}` : token;
      continue;
    }
    if (typeof token === 'number') {
      currentPath = `${currentPath}[${token}]`;
      continue;
    }
    if (token === null) {
      currentPath = `${currentPath}[*]`;
    }
  }

  return currentPath;
}

export const isDcqlFlow = (vpRequest: Record<string, unknown>) =>
  (vpRequest as Record<string, unknown>)?.['dcql_query'] !== undefined;
