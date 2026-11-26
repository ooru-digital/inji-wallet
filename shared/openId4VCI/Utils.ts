import base64url from 'base64url';
import jose from 'node-jose';
import {NativeModules} from 'react-native';
import {vcVerificationBannerDetails} from '../../components/BannerNotificationContainer';
import {VCProcessor} from '../../components/VC/common/VCProcessor';
import {
  BOTTOM_SECTION_FIELDS_WITH_DETAILED_ADDRESS_FIELDS,
  DETAIL_VIEW_ADD_ON_FIELDS,
  DETAIL_VIEW_BOTTOM_SECTION_FIELDS,
  getCredentialTypeFromWellKnown,
} from '../../components/VC/common/VCUtils';
import {displayType} from '../../machines/Issuers/IssuersMachine';
import {
  Credential,
  CredentialWrapper,
  VerifiableCredential,
} from '../../machines/VerifiableCredential/VCMetaMachine/vc';
import getAllConfigurations, {CACHED_API} from '../api';
import {
  ED25519_PROOF_SIGNING_ALGO,
  isAndroid,
  JWT_ALG_TO_KEY_TYPE,
  KEY_TYPE_TO_JWT_ALG,
} from '../constants';
import {getJWT} from '../cryptoutil/cryptoUtil';
import {verifyCredential} from '../vcjs/verifyCredential';
import {getVerifiableCredential} from '../../machines/VerifiableCredential/VCItemMachine/VCItemSelectors';
import {getErrorEventData, sendErrorEvent} from '../telemetry/TelemetryUtils';
import {TelemetryConstants} from '../telemetry/TelemetryConstants';
import {KeyTypes} from '../cryptoutil/KeyTypes';
import {VCFormat} from '../VCFormat';
import {UnsupportedVcFormat} from '../error/UnsupportedVCFormat';
import {VCMetadata} from '../VCMetadata';
import {displayInAppLanguage} from '../displayLanguage';

export const Protocols = {
  OpenId4VCI: 'OpenId4VCI',
  OTP: 'OTP',
};

export const Issuers = {
  MosipOtp: 'MosipOtp',
  Mosip: 'Mosip',
};

export function getVcVerificationDetails(
  statusType,
  vcMetadata: VCMetadata,
): vcVerificationBannerDetails {
  const credentialType = vcMetadata.credentialType;
  return {
    statusType: statusType,
    isRevoked: vcMetadata.isRevoked,
    isExpired: vcMetadata.isExpired,
    vcType: credentialType,
  };
}

export const ACTIVATION_NEEDED = [Issuers.Mosip, Issuers.MosipOtp];

export const isActivationNeeded = (issuer: string) => {
  return ACTIVATION_NEEDED.indexOf(issuer) !== -1;
};

export const Issuers_Key_Ref = 'OpenId4VCI_KeyPair';

export const updateCredentialInformation = async (
  context: any,
  credential: VerifiableCredential,
): Promise<CredentialWrapper> => {
  let processedCredential;
  if (context.selectedCredentialType.format === VCFormat.mso_mdoc) {
    processedCredential = await VCProcessor.processForRendering(
      credential,
      context.selectedCredentialType.format,
    );
  } else if (
    context.selectedCredentialType.format === VCFormat.vc_sd_jwt ||
    context.selectedCredentialType.format === VCFormat.dc_sd_jwt
  ) {
    processedCredential = await VCProcessor.processForRendering(
      credential,
      context.selectedCredentialType.format,
    );
  }
  let verifiableCredential;
  try {
    verifiableCredential = {
      ...credential,
      credentialConfigurationId: context.selectedCredentialType.id,
      issuerLogo:
        getDisplayObjectForCurrentLanguage(context.selectedIssuer.display)
          ?.logo ?? '',
      processedCredential,
    };
  } catch (e) {
    console.error(
      'Error occurred while processing credential for rendering',
      e,
    );
  }

  return {
    verifiableCredential,
    format: context.selectedCredentialType.format,
    generatedOn: new Date(),
    vcMetadata: {
      ...context.vcMetadata,
      format: context.selectedCredentialType.format,
    },
  };
};

export const getDisplayObjectForCurrentLanguage = (
  display: displayType[],
): displayType => displayInAppLanguage(display) ?? ({} as displayType);

export const getCredentialIssuersWellKnownConfig = async (
  issuerCacheKey: string | undefined,
  defaultFields: string[],
  credentialConfigurationId: string,
  format: string,
  issuerHost: string,
) => {
  let fields: string[] = defaultFields;
  let wellknownFieldsFlag = false;
  let matchingWellknownDetails: any;
  const wellknownResponse = await CACHED_API.fetchIssuerWellknownConfig(
    issuerCacheKey!,
    issuerHost,
    true,
  );
  try {
    if (wellknownResponse) {
      matchingWellknownDetails = getMatchingCredentialIssuerMetadata(
        wellknownResponse,
        credentialConfigurationId,
      );
      if (
        matchingWellknownDetails.order != null &&
        matchingWellknownDetails.order.length > 0
      ) {
        fields = matchingWellknownDetails.order;
      } else {
        if (format === VCFormat.mso_mdoc) {
          fields = [];
          const claims = matchingWellknownDetails?.claims;
          if (claims && typeof claims === 'object') {
            Object.keys(claims).forEach(namespace => {
              const namespaceClaims = claims[namespace];
              if (namespaceClaims && typeof namespaceClaims === 'object') {
                Object.keys(namespaceClaims).forEach(claim => {
                  fields.push(`${namespace}~${claim}`);
                });
              }
            });
          }
        } else if (format === VCFormat.ldp_vc) {
          const credSubject =
            matchingWellknownDetails?.credential_definition?.credentialSubject;
          const ldpFields =
            credSubject && typeof credSubject === 'object'
              ? Object.keys(credSubject)
              : [];
          if (ldpFields.length > 0) {
            fields = ldpFields;
            wellknownFieldsFlag = true;
          }
        } else if (
          format === VCFormat.vc_sd_jwt ||
          format === VCFormat.dc_sd_jwt
        ) {
          const sdClaims = matchingWellknownDetails?.claims;
          const sdJwtFields = sdClaims ? flattenClaimPaths(sdClaims) : [];

          if (sdJwtFields.length > 0) {
            fields = sdJwtFields;
            wellknownFieldsFlag = true;
          }
        } else {
          console.error(`Unsupported credential format - ${format} found`);
          throw new UnsupportedVcFormat(format);
        }
      }
    }
  } catch (error) {
    console.error(
      `Error occurred while parsing well-known response of credential type - ${credentialConfigurationId} so returning default fields only. Error is `,
      error.toString(),
    );
    return {
      matchingCredentialIssuerMetadata: matchingWellknownDetails,
      fields: fields,
      wellknownFieldsFlag: false,
    };
  }
  return {
    matchingCredentialIssuerMetadata: matchingWellknownDetails,
    wellknownResponse,
    fields: fields,
    wellknownFieldsFlag:
      wellknownFieldsFlag || matchingWellknownDetails?.order?.length > 0,
  };
};
const flattenClaimPaths = (
  claims: Record<string, any>,
  prefix = '',
): string[] => {
  return Object.entries(claims).flatMap(([key, value]) => {
    const currentPath = prefix ? `${prefix}.${key}` : key;

    if (
      value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      Object.keys(value).some(k => typeof value[k] === 'object')
    ) {
      // Has nested objects inside, so recurse
      return flattenClaimPaths(value, currentPath);
    } else {
      // Either a primitive or an empty object or a leaf with no metadata
      return [currentPath];
    }
  });
};

export const getDetailedViewFields = async (
  issuerCacheKey: string,
  credentialConfigurationId: string,
  defaultFields: string[],
  format: string,
  issuerHost: string,
) => {
  let response = await getCredentialIssuersWellKnownConfig(
    issuerCacheKey,
    defaultFields,
    credentialConfigurationId,
    format,
    issuerHost,
  );

  let updatedFieldsList = response.fields.concat(DETAIL_VIEW_ADD_ON_FIELDS);

  updatedFieldsList = removeBottomSectionFields(updatedFieldsList, format);
  return {
    matchingCredentialIssuerMetadata: response.matchingCredentialIssuerMetadata,
    fields: updatedFieldsList,
    wellknownFieldsFlag: response.wellknownFieldsFlag,
    wellknownResponse: response.wellknownResponse,
  };
};

export const removeBottomSectionFields = (fields, format) => {
  if (format === VCFormat.vc_sd_jwt || format === VCFormat.dc_sd_jwt) {
    return fields.filter(
      fieldName => !DETAIL_VIEW_BOTTOM_SECTION_FIELDS.includes(fieldName),
    );
  }

  return fields.filter(
    fieldName =>
      !BOTTOM_SECTION_FIELDS_WITH_DETAILED_ADDRESS_FIELDS.includes(fieldName) &&
      fieldName !== 'address',
  );
};

export const vcDownloadTimeout = async (): Promise<number> => {
  const response = await getAllConfigurations();

  return Number(response['openId4VCIDownloadVCTimeout']) || 30000;
};

// OIDCErrors is a collection of external errors from the OpenID library or the issuer
export const OIDCErrors = {
  OIDC_FLOW_CANCELLED_ANDROID: 'User cancelled flow',
  OIDC_FLOW_CANCELLED_IOS: 'org.openid.appauth.general error -3',

  INVALID_TOKEN_SPECIFIED: 'Invalid token specified',
  OIDC_CONFIG_ERROR_PREFIX: 'Config error',

  AUTHORIZATION_ENDPOINT_DISCOVERY: {
    GRANT_TYPE_NOT_SUPPORTED: 'Grant type not supported by Wallet',
    FAILED_TO_FETCH_AUTHORIZATION_ENDPOINT:
      'Failed to fetch authorization endpoint or grant type not supported by wallet',
  },
};

// ErrorMessage is the type of error message shown in the UI

export enum ErrorMessage {
  NO_INTERNET = 'noInternetConnection',
  GENERIC = 'generic',
  REQUEST_TIMEDOUT = 'technicalDifficulty',
  BIOMETRIC_CANCELLED = 'biometricCancelled',
  TECHNICAL_DIFFICULTIES = 'technicalDifficulty',
  CREDENTIAL_TYPE_DOWNLOAD_FAILURE = 'credentialTypeListDownloadFailure',
  AUTHORIZATION_GRANT_TYPE_NOT_SUPPORTED = 'authorizationGrantTypeNotSupportedByWallet',
  NETWORK_REQUEST_FAILED = 'networkRequestFailed',
}

/**
 * Credential download errors, from upstream Inji Wallet 1.0.0-alpha.1: the issuer's OAuth /
 * OpenID4VCI error codes, plus the wallet's own. Each has `IssuersScreen.errors.<code>.title` and
 * `.message` translations.
 */
export enum VCIServerErrorCode {
  INVALID_REQUEST = 'invalid_request',
  UNAUTHORIZED_CLIENT = 'unauthorized_client',
  ACCESS_DENIED = 'access_denied',
  UNSUPPORTED_RESPONSE_TYPE = 'unsupported_response_type',
  INVALID_SCOPE = 'invalid_scope',
  SERVER_ERROR = 'server_error',
  TEMPORARILY_UNAVAILABLE = 'temporarily_unavailable',
  INVALID_CLIENT = 'invalid_client',
  INVALID_GRANT = 'invalid_grant',
  UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type',
  AUTHORIZATION_PENDING = 'authorization_pending',
  SLOW_DOWN = 'slow_down',
  INVALID_CREDENTIAL_REQUEST = 'invalid_credential_request',
  UNSUPPORTED_CREDENTIAL_TYPE = 'unsupported_credential_type',
  UNSUPPORTED_CREDENTIAL_FORMAT = 'unsupported_credential_format',
  INVALID_PROOF = 'invalid_proof',
  INVALID_ENCRYPTION_PARAMETERS = 'invalid_encryption_parameters',
  INVALID_TOKEN = 'invalid_token',
  INSUFFICIENT_SCOPE = 'insufficient_scope',
  INVALID_CREDENTIAL_OFFER = 'invalid_credential_offer',
  CREDENTIAL_OFFER_FETCH_FAILED = 'credential_offer_fetch_failed',
  UNSUPPORTED_GRANT = 'unsupported_grant',
  USER_CANCELLED = 'user_cancelled',
  NETWORK_ERROR = 'network_error',
  TIMEOUT_ERROR = 'timeout_error',
  PARSING_ERROR = 'parsing_error',
  VERIFICATION_FAILED = 'verification_failed',
  STORAGE_ERROR = 'storage_error',
  UNKNOWN_ERROR = 'unknown_error',
}

/** Errors the holder can retry; the error screen offers "Try again". */
export const retryableErrors = new Set<string>([
  VCIServerErrorCode.SERVER_ERROR,
  VCIServerErrorCode.INVALID_GRANT,
  VCIServerErrorCode.SLOW_DOWN,
  VCIServerErrorCode.INVALID_PROOF,
  VCIServerErrorCode.INVALID_ENCRYPTION_PARAMETERS,
  VCIServerErrorCode.CREDENTIAL_OFFER_FETCH_FAILED,
  VCIServerErrorCode.NETWORK_ERROR,
  VCIServerErrorCode.TIMEOUT_ERROR,
  VCIServerErrorCode.PARSING_ERROR,
  VCIServerErrorCode.STORAGE_ERROR,
  VCIServerErrorCode.UNKNOWN_ERROR,
  VCIServerErrorCode.ACCESS_DENIED,
  VCIServerErrorCode.UNSUPPORTED_GRANT_TYPE,
  VCIServerErrorCode.INVALID_CREDENTIAL_OFFER,
  ErrorMessage.NO_INTERNET,
]);

/** Errors a retry can't fix: the holder goes back (to choose another issuer or card). */
export const goBackErrors = new Set<string>([
  VCIServerErrorCode.UNAUTHORIZED_CLIENT,
  VCIServerErrorCode.UNSUPPORTED_RESPONSE_TYPE,
  VCIServerErrorCode.INVALID_SCOPE,
  VCIServerErrorCode.UNSUPPORTED_CREDENTIAL_TYPE,
  VCIServerErrorCode.UNSUPPORTED_CREDENTIAL_FORMAT,
  VCIServerErrorCode.INSUFFICIENT_SCOPE,
  VCIServerErrorCode.UNSUPPORTED_GRANT,
  ErrorMessage.TECHNICAL_DIFFICULTIES,
  ErrorMessage.AUTHORIZATION_GRANT_TYPE_NOT_SUPPORTED,
]);

/** Errors that end the request: the holder goes back to the wallet. */
export const goHomeErrors = new Set<string>([
  VCIServerErrorCode.INVALID_REQUEST,
  VCIServerErrorCode.INVALID_CLIENT,
  VCIServerErrorCode.TEMPORARILY_UNAVAILABLE,
  VCIServerErrorCode.INVALID_CREDENTIAL_REQUEST,
]);

/** Errors about the holder's connection rather than the issuer. */
export const connectionErrors = new Set<string>([
  ErrorMessage.NO_INTERNET,
  ErrorMessage.NETWORK_REQUEST_FAILED,
  VCIServerErrorCode.NETWORK_ERROR,
  VCIServerErrorCode.TIMEOUT_ERROR,
  VCIServerErrorCode.CREDENTIAL_OFFER_FETCH_FAILED,
]);

/** A VCI client failure as VciClient rethrows it (native code plus the issuer's own error). */
export type VciClientError = {
  code?: string;
  message?: string;
  issuerErrorCode?: string;
  issuerErrorMessage?: string;
};

/**
 * The error screen to show for a failed download: the issuer's error code when it sent one
 * (unknown codes become server_error), then the holder's connection, then the VCI client's own
 * code (VCI-008 a bad credential offer, VCI-007 a timeout, any other one server_error), then the
 * older message-based cases, else generic.
 */
export function getVciErrorMessageType(
  error: any,
  isNetworkFailure: (message: string) => boolean,
  noInternetText: string,
  requestTimeoutText: string,
): string {
  const vciError: VciClientError = error ?? {};
  const message = vciError.message ?? String(error ?? '');
  if (vciError.issuerErrorCode) {
    return (Object.values(VCIServerErrorCode) as string[]).includes(
      vciError.issuerErrorCode,
    )
      ? vciError.issuerErrorCode
      : VCIServerErrorCode.SERVER_ERROR;
  }
  if (message.includes(noInternetText)) {
    return ErrorMessage.NO_INTERNET;
  }
  if (isNetworkFailure(message)) {
    return ErrorMessage.NETWORK_REQUEST_FAILED;
  }
  if (message.includes(requestTimeoutText)) {
    return ErrorMessage.REQUEST_TIMEDOUT;
  }
  if (
    message.includes(
      OIDCErrors.AUTHORIZATION_ENDPOINT_DISCOVERY.GRANT_TYPE_NOT_SUPPORTED,
    )
  ) {
    return ErrorMessage.AUTHORIZATION_GRANT_TYPE_NOT_SUPPORTED;
  }
  if (vciError.code === 'VCI-008') {
    return VCIServerErrorCode.INVALID_CREDENTIAL_OFFER;
  }
  if (vciError.code === 'VCI-007') {
    return VCIServerErrorCode.TIMEOUT_ERROR;
  }
  if (vciError.code && /^VCI-\d+$/.test(vciError.code)) {
    return VCIServerErrorCode.SERVER_ERROR;
  }
  return ErrorMessage.GENERIC;
}

export async function constructProofJWT(
  publicKey: any,
  privateKey: any,
  selectedIssuer: string,
  client_id: string | null,
  keyType: string,
  proofSigningAlgosSupported: string[] = [],
  isCredentialOfferFlow: boolean,
  cNonce?: string,
): Promise<string> {
  const jwk = await getJWK(publicKey, keyType);
  if (keyType === KeyTypes.ES256 && jwk) {
    console.log(
      `Wallet key source for issuance: alias=${keyType}, keyId=${keyType}, source=${
        isAndroid() ? 'android-keystore' : 'ios-secure-storage'
      }`,
    );
    console.log(
      `Wallet issuance device key: kty=${jwk.kty}, crv=${jwk.crv}, x=${jwk.x}, y=${jwk.y}`,
    );
  }
  const nonce = cNonce;
  const alg =
    keyType === KeyTypes.ED25519
      ? resolveEd25519Alg(proofSigningAlgosSupported)
      : KEY_TYPE_TO_JWT_ALG[keyType];

  if (!alg) {
    throw new Error(`Unsupported algorithm for keyType: ${keyType}`);
  }

  const jwtHeader: Record<string, any> = {
    alg,
    typ: 'openid4vci-proof+jwt',
    ...(isCredentialOfferFlow
      ? {kid: `did:jwk:${base64url(JSON.stringify(jwk))}#0`}
      : {jwk}),
  };
  const jwtPayload = {
    ...(client_id ? {iss: client_id} : {}),
    nonce,
    aud: selectedIssuer,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 18000,
  };

  return getJWT(jwtHeader, jwtPayload, Issuers_Key_Ref, privateKey, keyType);
}

export const getJWK = async (publicKey, keyType) => {
  try {
    let publicKeyJWK;
    switch (keyType) {
      case KeyTypes.RS256:
        publicKeyJWK = await getJWKRSA(publicKey);
        break;
      case KeyTypes.ES256:
        publicKeyJWK = await getJWKECR1(publicKey);
        break;
      case KeyTypes.ES256K:
        publicKeyJWK = await getJWKECK1(publicKey);
        break;
      case KeyTypes.ED25519:
        publicKeyJWK = await getJWKED(publicKey);
        break;
      default:
        throw Error;
    }
    return {
      ...publicKeyJWK,
      use: 'sig',
    };
  } catch (e) {
    console.error(
      'Exception occurred while constructing JWK from PEM : ' +
        publicKey +
        '  Exception is ',
      e,
    );
  }
};
async function getJWKRSA(publicKey): Promise<any> {
  const publicKeyJWKString = await jose.JWK.asKey(publicKey, 'pem');
  return publicKeyJWKString.toJSON();
}
async function getJWKECR1(publicKey): Promise<any> {
  let jwk = {};
  if (isAndroid()) {
    const publicKeyJWKString = await jose.JWK.asKey(publicKey, 'pem');
    jwk = publicKeyJWKString.toJSON();
  } else {
    /**
     * The key arrives in one of two shapes on iOS, and the slices below are byte
     * offsets into the uncompressed EC point — so it has to be bytes either way:
     *
     *  - fetchKeyPair() already decodes ES256 with Buffer.from(key, 'base64')
     *  - generateKeyPairECR1() returns the base64 *string* it just encoded
     *
     * Slicing the string form would cut base64 characters rather than key bytes and
     * silently produce a wrong x/y — a malformed proof JWT the issuer rejects. Only
     * the generate path (first run, or after clearKeys) hits that, which is why it
     * has stayed hidden. createSignatureECR1 already decodes defensively this way.
     */
    const keyBytes =
      typeof publicKey === 'string'
        ? Buffer.from(publicKey, 'base64')
        : Buffer.from(publicKey);
    const x = base64url(keyBytes.subarray(1, 33)); // Skip the first byte (0x04) in the uncompressed public key
    const y = base64url(keyBytes.subarray(33, 65));
    jwk = {
      kty: 'EC',
      crv: 'P-256',
      x: x,
      y: y,
    };
  }

  return jwk;
}
function getJWKECK1(publicKey): any {
  // Same two shapes as getJWKECR1, but on both platforms: fetchKeyPair() returns a
  // Buffer, generateKeyPairECK1() returns the base64 string it just encoded. Slicing
  // the string form cuts base64 characters instead of key bytes. Normalising is a
  // no-op for the Buffer path, so the usual (post-onboarding) flow is unchanged.
  const keyBytes =
    typeof publicKey === 'string'
      ? Buffer.from(publicKey, 'base64')
      : Buffer.from(publicKey);
  const x = base64url(keyBytes.subarray(1, 33)); // Skip the first byte (0x04) in the uncompressed public key
  const y = base64url(keyBytes.subarray(33));
  const jwk = {
    kty: 'EC',
    crv: 'secp256k1',
    x: x,
    y: y,
  };
  return jwk;
}
function getJWKED(publicKey): any {
  // base64url() encodes the bytes it is given, so handing it the base64 *string* from
  // generateKeyPairED() would encode that text and double-encode the key. Buffers from
  // fetchKeyPair() are already correct, so this only changes the generate path.
  const keyBytes =
    typeof publicKey === 'string'
      ? Buffer.from(publicKey, 'base64')
      : Buffer.from(publicKey);
  const x = base64url(keyBytes);
  const jwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: x,
  };
  return jwk;
}
export async function hasKeyPair(keyType: any): Promise<boolean> {
  const {RNSecureKeystoreModule} = NativeModules;
  try {
    return await RNSecureKeystoreModule.hasAlias(keyType);
  } catch (e) {
    console.error('key not found');
    return false;
  }
}

export function selectCredentialRequestKey(
  proofSigningAlgosSupported: string[],
  keyOrder: Record<string, string>,
): string {
  const supportedKeyTypes = proofSigningAlgosSupported
    .map(algo => JWT_ALG_TO_KEY_TYPE[algo])
    .filter(Boolean);

  for (const index in keyOrder) {
    const keyType = keyOrder[index];
    if (supportedKeyTypes.includes(keyType)) {
      return keyType;
    }
  }
  return keyOrder[0];
}

export function getMatchingCredentialIssuerMetadata(
  wellknown: any,
  credentialConfigurationId: string,
): any {
  for (const credentialTypeKey in wellknown.credential_configurations_supported) {
    if (credentialTypeKey === credentialConfigurationId) {
      return wellknown.credential_configurations_supported[credentialTypeKey];
    }
  }
  console.error(
    'Selected credential type is not available in wellknown config supported credentials list',
  );
  sendErrorEvent(
    getErrorEventData(
      TelemetryConstants.FlowType.wellknownConfig,
      TelemetryConstants.ErrorId.mismatch,
      TelemetryConstants.ErrorMessage.wellknownConfigMismatch,
    ),
  );
  throw new Error(
    `Selected credential type - ${credentialConfigurationId} is not available in wellknown config supported credentials list`,
  );
}

export async function verifyCredentialData(
  credential: Credential,
  credentialFormat: string,
  storedCredential?: unknown,
) {
  const verificationResult = await verifyCredential(
    credential,
    credentialFormat,
    storedCredential ?? credential,
  );
  return verificationResult;
}
function resolveEd25519Alg(proofSigningAlgosSupported: string[]) {
  return proofSigningAlgosSupported.includes(
    KEY_TYPE_TO_JWT_ALG[KeyTypes.ED25519],
  )
    ? KEY_TYPE_TO_JWT_ALG[KeyTypes.ED25519]
    : ED25519_PROOF_SIGNING_ALGO;
}

export function formattedDate(time: number | string): React.ReactNode {
  const date = new Date(time);
  const day = date.getDate();
  const month = date.toLocaleString('default', {month: 'long'});
  const year = date.getFullYear();
  const formattedHours = (date.getHours() % 12 || 12)
    .toString()
    .padStart(2, '0');
  const formattedMinutes = date.getMinutes().toString().padStart(2, '0');
  const period = date.getHours() >= 12 ? 'PM' : 'AM';

  return `${day} ${month} ${year}, ${formattedHours}:${formattedMinutes} ${period}`;
}
