import {sha256} from '@noble/hashes/sha256';
import {VCMetadata} from './VCMetadata';
import {CACHE_TTL, NETWORK_REQUEST_FAILED} from './constants';
import {groupBy} from './javascript';
import {Issuers} from './openId4VCI/Utils';
import {v4 as uuid} from 'uuid';
import {utf8ToBytes} from '@noble/hashes/utils';
import {Buffer} from 'buffer';
import base64url from 'base64url';
// Not the plain 'jsonld' package — @digitalcredentials/jsonld is the RN-safe fork already relied
// on elsewhere in this app (shared/vcjs/verifyCredential.ts) for processing these same W3C VCs.
// canonicalize() below is the one caller that used plain 'jsonld' instead, with no document
// loader configured at all — on iOS (the only platform that calls it; Android's native library
// pre-canonicalizes before this ever runs) that surfaced as
// `jsonld.SyntaxError: Invalid JSON-LD syntax; tried to redefine "VerifiableCredential" which is
// a protected term`, since jsonld.js's default loader isn't reliable in this runtime. Passing the
// same jsonld.documentLoaders.xhr() already proven to work for verifyCredential.ts fixes it here
// too, for the same reason.
import jsonld from '@digitalcredentials/jsonld';

export const getVCsOrderedByPinStatus = (vcMetadatas: VCMetadata[]) => {
  const [pinned, unpinned] = groupBy(
    vcMetadatas,
    (vcMetadata: VCMetadata) => vcMetadata.isPinned,
  );
  return pinned.concat(unpinned);
};

export enum VCShareFlowType {
  SIMPLE_SHARE = 'simple share',
  MINI_VIEW_SHARE = 'mini view share',
  MINI_VIEW_SHARE_WITH_SELFIE = 'mini view share with selfie',
  MINI_VIEW_QR_LOGIN = 'mini view qr login',
  OPENID4VP = 'OpenID4VP',
  OPENID4VP_AUTHORIZATION = 'OpenID4VP authorization',
  MINI_VIEW_SHARE_OPENID4VP = 'OpenID4VP share from mini view',
  MINI_VIEW_SHARE_WITH_SELFIE_OPENID4VP = 'OpenID4VP share with selfie from mini view',
}

export enum VCItemContainerFlowType {
  QR_LOGIN = 'qr login',
  VC_SHARE = 'vc share',
  VP_SHARE = 'vp share',
}

export enum CameraPosition {
  FRONT = 'front',
  BACK = 'back',
}

export interface CommunicationDetails {
  phoneNumber: string;
  emailId: string;
}

export const isMosipVC = (issuer: string) => {
  return issuer === Issuers.Mosip || issuer === Issuers.MosipOtp;
};

export const parseJSON = (input: any) => {
  let result = null;
  try {
    result = JSON.parse(input);
  } catch (e) {
    console.warn('Error occurred while parsing JSON ', e);
    result = JSON.parse(JSON.stringify(input));
  }
  return result;
};

export const isNetworkError = (error: string) => {
  return error.includes(NETWORK_REQUEST_FAILED);
};

export class UUID {
  public static generate(): string {
    return uuid();
  }
}

export const formatTextWithGivenLimit = (value: string, limit = 15) => {
  if (value.length > limit) {
    return value.substring(0, limit) + '...';
  }
  return value;
};

export enum DEEPLINK_FLOWS {
  QR_LOGIN = 'qrLoginFlow',
  OVP = 'ovpFlow',
}

export function base64ToByteArray(base64String) {
  try {
    let cleanBase64 = base64String.trim();
    cleanBase64 = cleanBase64.replace(/-/g, '+').replace(/_/g, '/');
    while (cleanBase64.length % 4) {
      cleanBase64 += '=';
    }
    const binaryString = atob(cleanBase64);
    const byteArray = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      byteArray[i] = binaryString.charCodeAt(i);
    }
    return byteArray;
  } catch (error) {
    throw new Error('Invalid Base64 string: ' + error.message);
  }
}

/**
 * Strips every `@protected` flag out of a fetched JSON-LD context, at the root and inside nested
 * term definitions alike.
 *
 * The VP this app signs is built by the native OpenID4VP library with the VC Data Model **v1**
 * context, while the credential embedded inside it is a **v2** credential. v1 marks
 * `VerifiableCredential` as `@protected`, so when the processor then applies v2 within the
 * credential's scope — which defines that same term with a v2-era scoped context — it refuses
 * outright: `tried to redefine "VerifiableCredential" which is a protected term`.
 *
 * Relaxing protection is safe here specifically because both contexts map the term to the *same*
 * IRI (`https://www.w3.org/2018/credentials#VerifiableCredential`). `@protected` governs only
 * whether redefinition is permitted; it has no effect on what terms expand to. So dropping it
 * leaves the canonical form — and therefore the signature the verifier recomputes — unchanged,
 * while letting a v2 credential be read with v2 semantics as intended.
 *
 * The real fix belongs upstream: a VP wrapping v2 credentials should itself carry the v2 context.
 * That document is assembled inside the native library, so it can't be corrected from here
 * without signing something different from what actually gets sent.
 */
function stripProtectedFlags(node: any): any {
  if (Array.isArray(node)) {
    return node.map(stripProtectedFlags);
  }
  if (node !== null && typeof node === 'object') {
    return Object.fromEntries(
      Object.entries(node)
        .filter(([key]) => key !== '@protected')
        .map(([key, value]) => [key, stripProtectedFlags(value)]),
    );
  }
  return node;
}

export async function canonicalize(unsignedVp: any) {
  try {
    const jsonldProof = {...unsignedVp['proof']};
    jsonldProof['@context'] = unsignedVp['@context'];
    const jsonldObjectClone = {...unsignedVp};
    if ('proof' in jsonldObjectClone) {
      delete jsonldObjectClone.proof;
    }
    const loadRemoteContext = jsonld.documentLoaders.xhr();
    const documentLoader = async (url: string, options?: any) => {
      const remoteDocument = await loadRemoteContext(url, options);
      // The xhr loader hands back `document` as raw JSON text, not a parsed object — passing
      // that straight to stripProtectedFlags made it a silent no-op, since the function returns
      // anything non-object untouched. jsonld accepts an already-parsed object here just fine.
      const parsed =
        typeof remoteDocument.document === 'string'
          ? JSON.parse(remoteDocument.document)
          : remoteDocument.document;
      return {...remoteDocument, document: stripProtectedFlags(parsed)};
    };
    const expandedJsonldObject = await jsonld.expand(jsonldObjectClone, {
      documentLoader,
    });
    const normalizedJsonldObject = await jsonld.canonize(expandedJsonldObject, {
      algorithm: 'URDNA2015',
      documentLoader,
    });

    const expandedJsonldProof = await jsonld.expand(jsonldProof, {
      documentLoader,
    });
    const normalizedJsonldProof = await jsonld.canonize(expandedJsonldProof, {
      algorithm: 'URDNA2015',
      documentLoader,
    });

    const canonicalizationResult = Buffer.alloc(64);
    Buffer.concat([
      //noble sha256 deprecated need to use alternative library
      sha256(utf8ToBytes(normalizedJsonldProof)),
      sha256(utf8ToBytes(normalizedJsonldObject)),
    ]).copy(canonicalizationResult, 0);
    return base64url(canonicalizationResult);
  } catch (err) {
    console.error('Canonization failed:', err);
    // The contexts in play are what actually decide whether expansion can succeed — a
    // "protected term" failure means two of them define the same term incompatibly, and the
    // error itself names only the term, never which documents collided. This is the only place
    // that still holds the document being expanded, so it is the only place that can report it.
    const embeddedCredentials = Array.isArray(unsignedVp?.verifiableCredential)
      ? unsignedVp.verifiableCredential
      : [unsignedVp?.verifiableCredential];
    console.error(
      'Canonization input contexts:',
      JSON.stringify({
        vp: unsignedVp?.['@context'],
        proof: unsignedVp?.['proof']?.['@context'],
        credentials: embeddedCredentials
          .filter(Boolean)
          .map((vc: any) => vc?.['@context']),
      }),
    );
  }
}

export const createCacheObject = (response: any) => {
  const currentTime = Date.now();
  return {
    response,
    cachedTime: currentTime,
  };
};

export const isCacheExpired = (timestamp: number) => {
  return Date.now() - timestamp >= CACHE_TTL;
};

export function getVerifierKey(verifier: string): string {
  return `trusted_verifier_${verifier}`;
}

export const enum VerificationStatus {
  VALID = 'VALID',
  REVOKED = 'REVOKED',
  PENDING = 'PENDING',
  EXPIRED = 'EXPIRED',
}
