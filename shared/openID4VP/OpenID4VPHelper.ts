import {NativeModules} from 'react-native';
import {
  createSignature,
  createSignatureECK1,
  createSignatureED,
  encodeB64,
  fetchKeyPair,
  replaceCharactersInB64,
} from '../cryptoutil/cryptoUtil';
import convertDerToRsFormat from '../cryptoutil/signFormatConverter';
import {base64ToByteArray, canonicalize} from '../Utils';
import getAllConfigurations, {CACHED_API} from '../api';
import {OpenID4VP_Proof_Sign_Algo} from './OpenID4VP';
import {VCFormat} from '../VCFormat';
import {isIOS, JWT_ALG_TO_KEY_TYPE} from '../constants';
import {getMdocAuthenticationAlorithm} from '../../components/VC/common/VCUtils';
import {KeyTypes} from '../cryptoutil/KeyTypes';
import {signatureSuite} from '../../machines/openID4VP/openID4VPServices';
import {walletConfig as defaultWalletConfig} from './walletMetadata';
import {
  UnsignedVPTokensV2,
  UnsignedVPTokenV2,
  VPTokenSigningResultsV2,
  VPTokenSigningResultV2,
} from './openid4vp.types';

/** An unsigned VP token from inji-openid4vp 1.0 (Android); dataToSign is base64url bytes. */
export type UnsignedVPTokenV1 = {
  id: string;
  format: string;
  holderKeyReference: string;
  signatureAlgorithm: string;
  dataToSign: string;
};

/** What inji-openid4vp 1.0 takes back: the raw signature, base64url, per token id. */
export type VPTokenSigningResultV1 = {id: string; signedData: string};

export async function constructDetachedJWT(
  privateKey: any,
  vpToken: string,
  keyType: string,
): Promise<string> {
  const jwtHeader = {
    alg: OpenID4VP_Proof_Sign_Algo,
    crit: ['b64'],
    b64: false,
  };
  const header64 = encodeB64(JSON.stringify(jwtHeader));
  const headerBytes = new TextEncoder().encode(header64);
  const vpTokenBytes = base64ToByteArray(vpToken);
  const payloadBytes = new Uint8Array([...headerBytes, 46, ...vpTokenBytes]);

  const signature = await createSignatureED(privateKey, payloadBytes);

  return header64 + '..' + signature;
}

export async function isClientValidationRequired() {
  const config = await getAllConfigurations();
  return config.openid4vpClientValidation === 'true';
}

export async function getWalletMetadata() {
  const config = await getAllConfigurations();
  if (!config.walletMetadata) {
    return null;
  }
  const walletMetadata = JSON.parse(config.walletMetadata);
  return walletMetadata;
}

/**
 * Wallet config for inji-openid4vp 1.0 (Android): `openid4vpWalletConfig` from the Mimoto config
 * when set, else the bundled default. The 0.7 `walletMetadata` above is a different shape and is
 * not used here.
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
 * Signs inji-openid4vp 1.0 unsigned VP tokens (Android). The library builds the whole VP, proof
 * included; the wallet only signs `dataToSign` (raw bytes, base64url) with the key that matches
 * `signatureAlgorithm`, which the library derived from the credential's holder key.
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
      // Hardware keys. RNSecureKeystoreModule.sign would sign the UTF-8 bytes of a string and
      // corrupt binary payloads such as mdoc DeviceAuthentication; signBytes signs them as is.
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

export const signDataForVpPreparation = async (
  unSignedVpTokens,
  context: any,
) => {
  // private key, key type and selected VCs are available in context
  const vpTokenSigningResultMap: Record<any, any> = {};
  for (const formatType in unSignedVpTokens) {
    const credentials = unSignedVpTokens[formatType];
    let dataToSign = credentials.dataToSign;
    if (formatType === VCFormat.ldp_vc.valueOf()) {
      if (isIOS()) {
        const canonicalized = await canonicalize(JSON.parse(dataToSign));
        if (!canonicalized) {
          throw new Error('Canonicalized data to sign is undefined');
        }
        dataToSign = canonicalized;
      }
      const proof = await constructDetachedJWT(
        context.privateKey,
        dataToSign,
        context.keyType,
      );
      vpTokenSigningResultMap[formatType] = {
        jws: proof,
        proofValue: null,
        signatureAlgorithm: signatureSuite,
      };
    } else if (formatType === VCFormat.mso_mdoc.valueOf()) {
      const signedData: Record<string, any> = {};

      const mdocCredentialsByDocType = Object.values(context.selectedVCs)
        .flat()
        .reduce((acc, credential) => {
          if (credential.format === 'mso_mdoc') {
            const docType =
              credential?.verifiableCredential?.processedCredential?.docType;
            if (docType) {
              acc[docType] = credential;
            }
          }
          return acc;
        }, {});

      await Promise.all(
        Object.entries(credentials.docTypeToDeviceAuthenticationBytes).map(
          async ([docType, payload]) => {
            const cred = mdocCredentialsByDocType[docType];

            if (!cred) return;

            const mdocAuthenticationAlgorithm = getMdocAuthenticationAlorithm(
              cred.verifiableCredential.processedCredential.issuerSigned
                ?.issuerAuth?.[2] ??
                cred.verifiableCredential.processedCredential?.issuerAuth?.[2],
            );

            if (mdocAuthenticationAlgorithm === KeyTypes.ES256.valueOf()) {
              const key = await fetchKeyPair(mdocAuthenticationAlgorithm);
              const signature = await createSignature(
                key.privateKey,
                payload,
                mdocAuthenticationAlgorithm,
              );

              if (signature) {
                signedData[docType] = {
                  signature,
                  mdocAuthenticationAlgorithm,
                };
              }
            } else {
              throw new Error(
                `Unsupported algorithm: ${mdocAuthenticationAlgorithm}`,
              );
            }
          },
        ),
      );

      vpTokenSigningResultMap[formatType] = signedData;
    } else if (
      formatType === VCFormat.vc_sd_jwt.valueOf() ||
      formatType === VCFormat.dc_sd_jwt.valueOf()
    ) {
      const uuidToUnsignedKBJWT = credentials.uuidToUnsignedKBT;
      const uuidToSignature: Record<string, string> = {};

      for (const [uuid, unsignedKBJWT] of Object.entries(uuidToUnsignedKBJWT)) {
        const header = JSON.parse(atob(unsignedKBJWT.split('.')[0]));
        const alg = header.alg;
        const keyType = JWT_ALG_TO_KEY_TYPE[alg];

        let privateKey: string;

        if (keyType === KeyTypes.ED25519) {
          privateKey = context.privateKey;
        } else {
          const keypair = await fetchKeyPair(keyType);
          privateKey = keypair.privateKey;
        }
        const signature = await createSignature(
          privateKey,
          unsignedKBJWT,
          keyType,
        );
        if (signature) {
          uuidToSignature[uuid] = signature;
        } else {
          throw new Error(`Failed to create signature for UUID: ${uuid}`);
        }
      }

      vpTokenSigningResultMap[formatType] = uuidToSignature;
    }
  }
  return vpTokenSigningResultMap;
};

/**
 *
 * unsignedVPTokens : [{
 *   format: 'ldp_vc' | 'mso_mdoc' | 'vc_sd_jwt' | 'dc_sd_jwt',
 *   holderKeyReference: string,
 *   signatureAlgorithm: string,
 *   dataToSign: string
 * }]
 * @param unSignedVpTokens
 * @param context
 */
export const signDataForVpPreparationV2 = async (
  unSignedVpTokens: Array<UnsignedVPTokenV2>,
  context: any,
): Promise<VPTokenSigningResultsV2> => {
  const result: Promise<VPTokenSigningResultV2[]> = unSignedVpTokens.map(
    async unsignedVPToken => {
      let privateKey: string;
      let keyType: KeyTypes;
      let signature: string | undefined = '';
      const formatType = unsignedVPToken.format;
      let payload: string = unsignedVPToken.dataToSign;
      const signatureAlgorithm: string = unsignedVPToken.signatureAlgorithm;

      switch (formatType) {
        case VCFormat.ldp_vc.valueOf():
          if (isIOS()) {
            const canonicalized = await canonicalize(JSON.parse(payload));
            if (!canonicalized) {
              throw new Error('Canonicalized data to sign is undefined');
            }
            payload = canonicalized;
          }
          signature = await constructDetachedJWT(
            context.privateKey,
            payload,
            signatureAlgorithm,
          );
          return {signedData: signature} as VPTokenSigningResultV2;
          break;

        case VCFormat.mso_mdoc.valueOf():
          if (signatureAlgorithm === KeyTypes.ES256.valueOf()) {
            const key = await fetchKeyPair(KeyTypes.ES256);
            const signature = await createSignature(
              key.privateKey,
              payload,
              KeyTypes.ES256,
            );
            if (signature) {
              return {signedData: signature} as VPTokenSigningResultV2;
            } else {
              throw new Error(
                `Failed to create signature for VP Token of format: ${formatType}`,
              );
            }
          } else {
            throw new Error(`Unsupported algorithm: ${signatureAlgorithm}`);
          }

        case VCFormat.vc_sd_jwt.valueOf():
        case VCFormat.dc_sd_jwt.valueOf():
          keyType =
            JWT_ALG_TO_KEY_TYPE[
              signatureAlgorithm as keyof typeof JWT_ALG_TO_KEY_TYPE
            ];

          if (!keyType) {
            throw new Error(
              `Unsupported signature algorithm: ${signatureAlgorithm}`,
            );
          }

          if (keyType === KeyTypes.ED25519) {
            privateKey = context.privateKey;
          } else {
            const keypair = await fetchKeyPair(keyType);
            privateKey = keypair.privateKey;
          }

          signature = await createSignature(privateKey, payload, keyType);
          if (signature) {
            return {signedData: signature} as VPTokenSigningResultV2;
          } else {
            throw new Error(
              `Failed to create signature for VP Token of format: ${formatType}`,
            );
          }

        default:
          throw new Error(`Unsupported VP Token format: ${formatType}`);
      }
    },
  );

  const vpTokenSigningResults = await Promise.all(result);
  return vpTokenSigningResults as VPTokenSigningResultsV2;
};
