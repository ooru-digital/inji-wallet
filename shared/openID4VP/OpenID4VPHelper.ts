import {NativeModules} from 'react-native';
import forge from 'node-forge';
import {
  createSignatureECK1,
  createSignatureECR1,
  createSignatureED,
  fetchKeyPair,
  replaceCharactersInB64,
} from '../cryptoutil/cryptoUtil';
import convertDerToRsFormat from '../cryptoutil/signFormatConverter';
import {base64ToByteArray, canonicalize} from '../Utils';
import getAllConfigurations, {CACHED_API} from '../api';
import {isIOS, JWT_ALG_TO_KEY_TYPE} from '../constants';
import {KeyTypes} from '../cryptoutil/KeyTypes';
import {walletConfig as defaultWalletConfig} from './walletMetadata';

/** An unsigned VP token from inji-openid4vp 1.0; dataToSign is base64url bytes. */
export type UnsignedVPTokenV1 = {
  id: string;
  format: string;
  holderKeyReference: string;
  signatureAlgorithm: string;
  dataToSign: string;
};

/** What inji-openid4vp 1.0 takes back: the raw signature, base64url, per token id. */
export type VPTokenSigningResultV1 = {id: string; signedData: string};

export async function isClientValidationRequired() {
  const config = await getAllConfigurations();
  return config.openid4vpClientValidation === 'true';
}

/**
 * Wallet config for inji-openid4vp 1.0: `openid4vpWalletConfig` from the Mimoto config when set,
 * else the bundled default.
 *
 * withTrustedVerifiers adds the trusted list and the validation flag, for the VCI client's
 * presentation during issuance. OpenID4VP sharing passes those per scan instead.
 */
export async function getWalletConfig(withTrustedVerifiers = false) {
  const config = await getAllConfigurations();
  let walletConfig: Record<string, any> = {...defaultWalletConfig};
  if (config.openid4vpWalletConfig) {
    try {
      walletConfig = JSON.parse(config.openid4vpWalletConfig);
    } catch (e) {
      console.warn('Invalid openid4vpWalletConfig, using the default', e);
    }
  }
  if (!withTrustedVerifiers) {
    return walletConfig;
  }
  walletConfig.validate_trusted_verifier =
    config.openid4vpClientValidation === 'true';
  try {
    const trustedVerifiers = await CACHED_API.fetchTrustedVerifiersList();
    walletConfig.trusted_verifiers =
      trustedVerifiers?.response?.verifiers ?? [];
  } catch (e) {
    console.warn('Could not fetch trusted verifiers for the wallet config', e);
    walletConfig.trusted_verifiers = [];
  }
  return walletConfig;
}

/**
 * JSON-LD canonicalization for the iOS libraries (OpenID4VP and the VCI client's presentation
 * during issuance), which hand the unsigned ldp_vc VP to JS as a JSON string. Returns
 * base64url(sha256(canonical proof) || sha256(canonical document)), the bytes they sign over.
 * Android's libraries canonicalize natively.
 */
export async function jsonLdCanonicalize(data: string): Promise<string> {
  const canonicalized = await canonicalize(JSON.parse(data));
  if (!canonicalized) {
    throw new Error('Canonicalized data to sign is undefined');
  }
  return canonicalized;
}

/**
 * Signs inji-openid4vp 1.0 unsigned VP tokens. The library builds the whole VP, proof included;
 * the wallet only signs `dataToSign` (raw bytes, base64url) with the key that matches
 * `signatureAlgorithm`, which the library derived from the holder key.
 */
export async function signUnsignedVPTokens(
  unsignedVPTokens: UnsignedVPTokenV1[],
): Promise<VPTokenSigningResultV1[]> {
  const results: VPTokenSigningResultV1[] = [];
  // One at a time: hardware keys can show a biometric prompt, and two at once would collide.
  for (const token of unsignedVPTokens) {
    const payload = base64ToByteArray(token.dataToSign);
    results.push({
      id: token.id,
      signedData: await signBytes(token.signatureAlgorithm, payload),
    });
  }
  return results;
}

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
    case KeyTypes.ES256:
    case KeyTypes.RS256: {
      if (isIOS()) {
        // iOS keeps these as software keys that JS can read, so it signs the bytes itself.
        const {privateKey} = await fetchKeyPair(keyType);
        return keyType === KeyTypes.ES256
          ? createSignatureECR1(privateKey, payload)
          : signRsaBytes(privateKey, payload);
      }
      // Android hardware keys. RNSecureKeystoreModule.sign would sign the UTF-8 bytes of a string
      // and corrupt binary payloads such as mdoc DeviceAuthentication; signBytes signs them as is.
      const {RNSecureKeystoreModule} = NativeModules;
      const signature64: string = await RNSecureKeystoreModule.signBytes(
        keyType,
        keyType,
        Buffer.from(payload).toString('base64'),
      );
      if (keyType === KeyTypes.RS256) {
        return replaceCharactersInB64(signature64);
      }
      // JOSE and COSE both want ECDSA as r || s, not the DER the keystore returns.
      const der = Uint8Array.from(Buffer.from(signature64, 'base64'));
      return replaceCharactersInB64(convertDerToRsFormat(der));
    }
    default:
      throw new Error(`Unsupported signature algorithm: ${algorithm}`);
  }
}

/**
 * RS256 over raw bytes with a PEM private key (iOS). createSignatureRSA hashes its input as UTF-8
 * text, which would change any byte above 0x7F, so the bytes go to the digest as a binary string.
 */
function signRsaBytes(privateKeyPem: string, payload: Uint8Array): string {
  const key = forge.pki.privateKeyFromPem(privateKeyPem);
  const md = forge.md.sha256.create();
  md.update(forge.util.binary.raw.encode(payload));
  return replaceCharactersInB64(
    Buffer.from(key.sign(md), 'binary').toString('base64'),
  );
}
