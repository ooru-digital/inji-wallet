/**
 * The slice of RFC 8152 / RFC 9052 COSE that ISO 18013-5 actually uses: `COSE_Sign1`, with
 * ES256 (`alg = -7`) over P-256.
 *
 * Two distinct jobs live here:
 *
 *  - **Producing** the `DeviceAuth` signature. The payload is *detached*: the COSE_Sign1 sent on
 *    the wire carries `nil` where the payload would be, and the signature is computed over a
 *    `Sig_structure` that names `DeviceAuthenticationBytes` instead. Emitting the payload inline
 *    is a common mistake that some readers accept and others reject.
 *  - **Inspecting** the reader's `readerAuth`, purely to pull a display name out of the
 *    certificate chain for the consent screen. We do not gate disclosure on reader auth — see
 *    the note on {@link readerCommonNameFromX5Chain}.
 */

import {p256} from '@noble/curves/p256';
import {sha256} from '@noble/hashes/sha256';

import {CborRaw, encodeCbor} from '../cborEncodeMinimal';
import {asArray, asBytes, decodeCbor, DecodedTag} from './cbor';

/** COSE header label 1 (`alg`), value -7 = ES256. */
export const COSE_ALG_ES256 = -7;
/** COSE header label 33 (`x5chain`). */
export const COSE_HEADER_X5CHAIN = 33;

/** Protected header `{1: -7}`, pre-encoded — this exact bstr goes into the Sig_structure. */
const PROTECTED_ES256 = encodeCbor(
  new Map<number, number>([[1, COSE_ALG_ES256]]),
);

/**
 * Signs raw bytes with ES256, returning the 64-byte `r || s` COSE signature.
 *
 * Asynchronous and injected rather than called directly so the same protocol code works on both
 * platforms: iOS can hand the P-256 private key to JS (`useSoftwareDeviceKey`), but Android keeps
 * the device key non-extractable in the hardware keystore and can only sign across the bridge.
 * Whatever implements this is also where a biometric prompt would surface.
 */
export type Es256Signer = (toBeSigned: Uint8Array) => Promise<Uint8Array>;

/** Signer backed by a raw 32-byte P-256 private key held in JS. */
export function softwareEs256Signer(privateKey32: Uint8Array): Es256Signer {
  return async (toBeSigned: Uint8Array) => {
    // noble signs a digest, and defaults to low-S normalisation, which is what COSE expects.
    const signature = p256.sign(sha256(toBeSigned), privateKey32);
    return signature.toCompactRawBytes();
  };
}

/**
 * `Sig_structure = ["Signature1", body_protected, external_aad, payload]` (RFC 9052 §4.4).
 *
 * `external_aad` is always empty for ISO 18013-5. `payload` is the detached content, i.e. the
 * serialized `DeviceAuthenticationBytes`, carried here as the *content* of a bstr.
 */
export function buildSigStructure(
  protectedHeaderBytes: Uint8Array,
  detachedPayload: Uint8Array,
): Uint8Array {
  return encodeCbor([
    'Signature1',
    protectedHeaderBytes,
    new Uint8Array(0),
    detachedPayload,
  ]);
}

/**
 * Builds a detached-payload `COSE_Sign1` over `detachedPayload`.
 *
 * The result is the bare 4-element array (not tag 18). ISO 18013-5 embeds `deviceSignature`
 * untagged, matching how `issuerAuth` appears in credentials we receive.
 */
export async function signCoseSign1Detached(
  detachedPayload: Uint8Array,
  signer: Es256Signer,
): Promise<unknown[]> {
  const toBeSigned = buildSigStructure(PROTECTED_ES256, detachedPayload);
  const signature = await signer(toBeSigned);
  if (signature.length !== 64) {
    throw new Error(
      `ES256 signature must be 64 bytes (r||s), got ${signature.length}`,
    );
  }
  return [
    PROTECTED_ES256,
    new Map<number, unknown>(),
    // Detached: the payload slot is null, and verifiers reconstruct it themselves.
    null,
    signature,
  ];
}

export interface ParsedCoseSign1 {
  protectedHeaderBytes: Uint8Array;
  protectedHeader: Map<unknown, unknown>;
  unprotectedHeader: Map<unknown, unknown>;
  payload: Uint8Array | null;
  signature: Uint8Array;
}

/** Parses a `COSE_Sign1`, accepting either the bare array or the tag-18 form. */
export function parseCoseSign1(value: unknown): ParsedCoseSign1 {
  const unwrapped = value instanceof DecodedTag ? value.value : value;
  const arr = asArray(unwrapped, 'COSE_Sign1');
  if (arr.length !== 4) {
    throw new Error(`COSE_Sign1 must have 4 elements, got ${arr.length}`);
  }
  const protectedHeaderBytes = asBytes(arr[0], 'COSE_Sign1 protected header');
  // An empty protected header is legally a zero-length bstr, which is not decodable CBOR.
  const protectedHeader =
    protectedHeaderBytes.length === 0
      ? new Map<unknown, unknown>()
      : (decodeCbor(protectedHeaderBytes) as Map<unknown, unknown>);
  return {
    protectedHeaderBytes,
    protectedHeader:
      protectedHeader instanceof Map
        ? protectedHeader
        : new Map<unknown, unknown>(),
    unprotectedHeader:
      arr[1] instanceof Map ? arr[1] : new Map<unknown, unknown>(),
    payload: arr[2] instanceof Uint8Array ? arr[2] : null,
    signature: asBytes(arr[3], 'COSE_Sign1 signature'),
  };
}

/** Splices a parsed COSE_Sign1 back out verbatim when we hold its original bytes. */
export function rawCoseSign1(bytes: Uint8Array): CborRaw {
  return new CborRaw(bytes);
}

/**
 * Best-effort reader display name from the `x5chain` header of `readerAuth`.
 *
 * This is **presentation only** — it labels the consent sheet so the user sees who is asking.
 * It is deliberately not a trust decision: validating the chain needs a reader trust list this
 * app does not ship, and Android reached the same conclusion (its session loop is explicitly
 * `iso18013PresentmentTolerantReaderAuth`). Treat the returned string as untrusted text.
 */
export function readerCommonNameFromX5Chain(
  coseSign1: ParsedCoseSign1,
): string | null {
  const x5chain =
    coseSign1.unprotectedHeader.get(COSE_HEADER_X5CHAIN) ??
    coseSign1.protectedHeader.get(COSE_HEADER_X5CHAIN);
  const first =
    x5chain instanceof Uint8Array
      ? x5chain
      : Array.isArray(x5chain) && x5chain[0] instanceof Uint8Array
      ? (x5chain[0] as Uint8Array)
      : null;
  if (!first) {
    return null;
  }
  return commonNameFromDerCertificate(first);
}

/**
 * Pulls the subject CN out of a DER X.509 certificate without a full ASN.1 parser.
 *
 * Scans for the CN OID (2.5.4.3 → `06 03 55 04 03`) and reads the string that follows it. The
 * *last* match is used: issuer RDNs precede subject RDNs in a certificate, so the final CN is
 * the subject's. Good enough for a label, and it cannot throw into the session path.
 */
function commonNameFromDerCertificate(der: Uint8Array): string | null {
  const OID_CN = [0x06, 0x03, 0x55, 0x04, 0x03];
  let found: string | null = null;
  for (let i = 0; i + OID_CN.length + 2 < der.length; i++) {
    let matches = true;
    for (let k = 0; k < OID_CN.length; k++) {
      if (der[i + k] !== OID_CN[k]) {
        matches = false;
        break;
      }
    }
    if (!matches) {
      continue;
    }
    const tagIndex = i + OID_CN.length;
    const tag = der[tagIndex];
    // PrintableString (0x13), UTF8String (0x0c), IA5String (0x16), T61String (0x14).
    if (tag !== 0x13 && tag !== 0x0c && tag !== 0x16 && tag !== 0x14) {
      continue;
    }
    const len = der[tagIndex + 1];
    // Long-form lengths would mean a >127 byte CN; not worth handling for a display label.
    if (len === undefined || len > 0x7f) {
      continue;
    }
    const start = tagIndex + 2;
    if (start + len > der.length) {
      continue;
    }
    try {
      const text = new TextDecoder('utf-8', {fatal: false}).decode(
        der.subarray(start, start + len),
      );
      if (text.trim().length > 0) {
        found = text.trim();
      }
    } catch {
      // A malformed name must never break the session; fall through and keep any earlier match.
    }
  }
  return found;
}
