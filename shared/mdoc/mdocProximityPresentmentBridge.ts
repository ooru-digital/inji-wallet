import {Buffer} from 'buffer';
import base64url from 'base64url';
import {NativeModules, Platform} from 'react-native';
import type {VerifiableCredential} from '../../machines/VerifiableCredential/VCMetaMachine/vc';
import {fetchKeyPair} from '../cryptoutil/cryptoUtil';
import {KeyTypes} from '../cryptoutil/KeyTypes';
import {isAndroid, isIOS} from '../constants';
import {getJWK} from '../openId4VCI/Utils';
import {loadPersistedMdocProximityFull} from './mdocProximitySessionStore';
import type {Iso18013PresentmentParams} from './iso18013PresentmentInterop';

function issuerSignedCompactFromVc(vc: VerifiableCredential): string | null {
  const c = vc.credential;
  if (typeof c !== 'string' || c.length === 0) {
    return null;
  }
  return c;
}

function getP256JwkFromUncompressedPublicKey(publicKey: Buffer): {
  kty: string;
  crv: string;
  x: string;
  y: string;
} {
  return {
    kty: 'EC',
    crv: 'P-256',
    x: base64url(Buffer.from(publicKey.slice(1, 33))),
    y: base64url(Buffer.from(publicKey.slice(33, 65))),
  };
}

/**
 * OpenID4VCI often stores Document (`issuerSigned` nested) or bare IssuerSigned.
 * Native Multipaz certify() needs IssuerSigned bytes; Android unwraps Document/DeviceResponse.
 */
function logMdocCredentialShapeForPresentment(vc: VerifiableCredential): void {
  if (!__DEV__) {
    return;
  }
  const processed = vc.processedCredential as
    | {
        issuerAuth?: unknown;
        issuerSigned?: {issuerAuth?: unknown; nameSpaces?: unknown};
        nameSpaces?: unknown;
        docType?: string;
        documents?: unknown;
      }
    | undefined;
  if (!processed || typeof processed !== 'object') {
    console.log(
      '[mdoc presentment] processedCredential missing — native will unwrap raw `credential` CBOR',
    );
    return;
  }
  const nestedAuth = processed.issuerSigned?.issuerAuth;
  const shape = {
    docType: processed.docType,
    hasTopLevelIssuerAuth: processed.issuerAuth != null,
    hasNestedIssuerSigned: processed.issuerSigned != null,
    hasNestedIssuerAuth: nestedAuth != null,
    nestedIssuerAuthIsArray: Array.isArray(nestedAuth),
    nestedIssuerAuthLength: Array.isArray(nestedAuth)
      ? nestedAuth.length
      : undefined,
    nestedIssuerAuthType:
      nestedAuth === null || nestedAuth === undefined
        ? 'none'
        : Array.isArray(nestedAuth)
        ? 'array'
        : typeof nestedAuth,
    hasTopLevelNameSpaces: processed.nameSpaces != null,
    hasDocuments: Array.isArray(processed.documents),
  };
  console.log(
    '[mdoc presentment] credential JSON shape (from PixelPass decode):',
    shape,
  );
  if (!shape.hasTopLevelIssuerAuth && shape.hasNestedIssuerSigned) {
    console.log(
      '[mdoc presentment] Document wrapper detected — Android extractIssuerSignedBytes will use nested issuerSigned',
    );
  }
}

/**
 * Builds native presentment parameters for an mso_mdoc VC (Tap2iD / ISO proximity).
 * Android: hardware ES256 keystore via native bridge. iOS: software device key when private key is available.
 */
export async function buildIso18013PresentmentParamsForVc(
  vcId: string,
  verifiableCredential: VerifiableCredential,
): Promise<Iso18013PresentmentParams | null> {
  const issuerSignedCompact = issuerSignedCompactFromVc(verifiableCredential);
  if (!issuerSignedCompact) {
    if (__DEV__) {
      console.warn(
        '[mdoc presentment] Missing issuer-signed credential string — ISO proximity skipped (Tap2iD will fail). Ensure VC `credential` is the compact mdoc string.',
      );
    }
    return null;
  }
  logMdocCredentialShapeForPresentment(verifiableCredential);
  const proximity = await loadPersistedMdocProximityFull(vcId);
  if (!proximity) {
    if (__DEV__) {
      console.warn(
        '[mdoc presentment] No persisted `*:iso18013_de` session — proximity skipped. Open VC detail to regenerate DeviceEngagement.',
      );
    }
    return null;
  }
  const processed = verifiableCredential.processedCredential as
    | {docType?: string; issuerSigned?: {docType?: string}}
    | undefined;
  // Prefer the credential's own MSO/Document docType — never assume mDL.
  const docType =
    processed?.docType ??
    processed?.issuerSigned?.docType ??
    'org.iso.18013.5.1.mDL';
  if (__DEV__) {
    console.log('[mdoc presentment] using docType:', docType);
  }

  let useSoftwareDeviceKey = false;
  let deviceKeyPrivateBase64: string | undefined;

  if (isIOS()) {
    try {
      const kp = await fetchKeyPair(KeyTypes.ES256);
      const pk = kp?.privateKey as Buffer | string | undefined;
      const pub = kp?.publicKey as Buffer | string | undefined;
      if (pk) {
        const buf = Buffer.isBuffer(pk)
          ? pk
          : Buffer.from(pk as string, 'base64');
        if (buf.length > 0) {
          deviceKeyPrivateBase64 = buf.toString('base64');
          useSoftwareDeviceKey = true;
          console.log(
            'Wallet key source for presentation: alias=ES256, keyId=ES256, source=ios-secure-storage',
          );
          if (pub) {
            const publicKeyBuffer = Buffer.isBuffer(pub)
              ? pub
              : Buffer.from(pub as string, 'base64');
            const jwk = getP256JwkFromUncompressedPublicKey(publicKeyBuffer);
            console.log(
              `Wallet presentation device-auth key: kty=${jwk.kty}, crv=${jwk.crv}, x=${jwk.x}, y=${jwk.y}`,
            );
          }
        }
      }
    } catch {
      // Android or keystore-only key
    }
  } else if (isAndroid()) {
    // TEMP debug: mirror keystore ES256 pubkey to Metro. Native also compares vs MSO in logcat.
    try {
      const kp = await fetchKeyPair(KeyTypes.ES256);
      const jwk = await getJWK(kp?.publicKey, KeyTypes.ES256);
      console.log(
        'Wallet key source for presentation: alias=ES256, keyId=ES256, source=android-keystore',
      );
      if (jwk) {
        console.log(
          `Wallet presentation device-auth key: kty=${jwk.kty}, crv=${jwk.crv}, x=${jwk.x}, y=${jwk.y}`,
        );
        console.log(
          `Wallet presentation keystore ES256 pubkey: kty=${jwk.kty}, crv=${jwk.crv}, x=${jwk.x}, y=${jwk.y}`,
        );
      }
    } catch (e) {
      console.warn(
        'Wallet presentation device-auth key: failed to load Android ES256 pubkey',
        e,
      );
    }
  }

  return {
    vcId,
    msoMdocCredentialCompact: issuerSignedCompact,
    docType,
    deviceEngagementUri: proximity.mdocUri,
    deviceEngagementCbor: proximity.deviceEngagementCbor,
    ephemeralPresentationPrivateKey: proximity.ephemeralPrivateKey,
    useSoftwareDeviceKey,
    deviceKeyPrivateBase64,
  };
}

export function nativeMdocProximityPresentmentAvailable(): boolean {
  return (
    Platform.OS === 'android' &&
    !!(NativeModules as {MdocIso18013Presentment?: unknown})
      .MdocIso18013Presentment
  );
}
