/**
 * ISO/IEC 18013-5 §9.1.1 session encryption, and the SessionTranscript everything else hangs off.
 *
 * Constants here are load-bearing and were taken from the spec text as implemented by the EU
 * Digital Identity Wallet reference (`eudi-lib-ios-iso18013-security`), not from memory:
 *
 *   Zab      = ECDH-P256(EDeviceKey.private, EReaderKey.public), x-coordinate only (32 bytes)
 *   salt     = SessionTranscriptBytes  ← the raw tagged CBOR, *not* a hash of it
 *   SKDevice = HKDF-SHA256(ikm = Zab, salt, info = "SKDevice", L = 32)
 *   SKReader = HKDF-SHA256(ikm = Zab, salt, info = "SKReader", L = 32)
 *   nonce    = identifier(8 bytes) || messageCounter(uint32 big-endian)
 *              identifier 0x00..00 for reader→mdoc, 0x00..01 for mdoc→reader
 *              each direction counts independently, starting at 1
 *
 * Getting any one of these wrong produces a session that fails at the *verifier* with no local
 * error, so treat changes here as signature-affecting.
 */

import {gcm} from '@noble/ciphers/aes';
import {p256} from '@noble/curves/p256';
import {hkdf} from '@noble/hashes/hkdf';
import {hmac} from '@noble/hashes/hmac';
import {sha256} from '@noble/hashes/sha256';

import {CborRaw, CborTag24, encodeCbor} from '../cborEncodeMinimal';
import {
  asBytes,
  asMap,
  asTag,
  concatBytes,
  decodeCbor,
  requireMapGet,
  toHex,
} from './cbor';

const textEncoder = new TextEncoder();

const INFO_SK_DEVICE = textEncoder.encode('SKDevice');
const INFO_SK_READER = textEncoder.encode('SKReader');

/** IV identifier for messages the reader encrypts (we decrypt these). */
const IDENTIFIER_READER = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0]);
/** IV identifier for messages the mdoc encrypts (we encrypt these). */
const IDENTIFIER_DEVICE = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 1]);

const AES_GCM_TAG_BYTES = 16;

/** ISO 18013-5 §9.1.1.4 SessionData status codes. */
export const SESSION_STATUS_ERROR_SESSION_ENCRYPTION = 10;
export const SESSION_STATUS_ERROR_CBOR_DECODING = 11;
export const SESSION_STATUS_SESSION_TERMINATION = 20;

/**
 * `SessionTranscriptBytes = #6.24(bstr .cbor [DeviceEngagementBytes, EReaderKeyBytes, Handover])`.
 *
 * For QR-code engagement the Handover is `null` (ISO 18013-5 §9.1.5.1).
 *
 * Both embedded members are spliced in as raw bytes on purpose. `deviceEngagementCbor` must be
 * exactly what was base64url-encoded into the `mdoc:` URI the reader scanned, and
 * `eReaderKeyBytes` exactly what the reader sent — re-encoding either from a decoded value is
 * the classic way to break DeviceAuth while every log still looks correct.
 */
export function buildSessionTranscriptBytes(
  deviceEngagementCbor: Uint8Array,
  eReaderKeyBytes: Uint8Array,
): Uint8Array {
  const sessionTranscript = encodeCbor([
    new CborTag24(deviceEngagementCbor),
    new CborRaw(eReaderKeyBytes),
    null,
  ]);
  return encodeCbor(new CborTag24(sessionTranscript));
}

/** Extracts the 32-byte x-coordinate shared secret from an ECDH agreement. */
function ecdhSharedSecretX(
  privateKey32: Uint8Array,
  publicKeyUncompressed: Uint8Array,
): Uint8Array {
  // noble returns the compressed point (33 bytes: 0x02/0x03 prefix + x). Zab is the x-coordinate.
  const shared = p256.getSharedSecret(privateKey32, publicKeyUncompressed);
  return shared.subarray(1, 33);
}

export interface MdocSessionKeys {
  skDevice: Uint8Array;
  skReader: Uint8Array;
  sessionTranscriptBytes: Uint8Array;
}

export function deriveSessionKeys(params: {
  ephemeralPrivateKey: Uint8Array;
  readerPublicKeyUncompressed: Uint8Array;
  deviceEngagementCbor: Uint8Array;
  eReaderKeyBytes: Uint8Array;
}): MdocSessionKeys {
  const sessionTranscriptBytes = buildSessionTranscriptBytes(
    params.deviceEngagementCbor,
    params.eReaderKeyBytes,
  );
  const zab = ecdhSharedSecretX(
    params.ephemeralPrivateKey,
    params.readerPublicKeyUncompressed,
  );
  return {
    skDevice: hkdf(sha256, zab, sessionTranscriptBytes, INFO_SK_DEVICE, 32),
    skReader: hkdf(sha256, zab, sessionTranscriptBytes, INFO_SK_READER, 32),
    sessionTranscriptBytes,
  };
}

/**
 * Holds the two directional AES-256-GCM contexts and their independent message counters.
 *
 * Counters must never repeat for a given key: a reused (key, nonce) pair in GCM is a total
 * break, not a degradation. They are therefore incremented before use and the session is
 * single-use — a new engagement means new keys.
 */
export class MdocSessionCipher {
  private encryptCounter = 0;
  private decryptCounter = 0;

  constructor(private readonly keys: MdocSessionKeys) {}

  get sessionTranscriptBytes(): Uint8Array {
    return this.keys.sessionTranscriptBytes;
  }

  private static nonce(identifier: Uint8Array, counter: number): Uint8Array {
    const out = new Uint8Array(12);
    out.set(identifier, 0);
    out[8] = (counter >>> 24) & 0xff;
    out[9] = (counter >>> 16) & 0xff;
    out[10] = (counter >>> 8) & 0xff;
    out[11] = counter & 0xff;
    return out;
  }

  /** Encrypts an mdoc→reader payload (DeviceResponse). */
  encrypt(plaintext: Uint8Array): Uint8Array {
    this.encryptCounter += 1;
    const nonce = MdocSessionCipher.nonce(
      IDENTIFIER_DEVICE,
      this.encryptCounter,
    );
    return gcm(this.keys.skDevice, nonce).encrypt(plaintext);
  }

  /** Decrypts a reader→mdoc payload (DeviceRequest). */
  decrypt(ciphertext: Uint8Array): Uint8Array {
    if (ciphertext.length <= AES_GCM_TAG_BYTES) {
      throw new Error(
        `session ciphertext too short (${ciphertext.length} bytes; needs more than the ${AES_GCM_TAG_BYTES}-byte GCM tag)`,
      );
    }
    this.decryptCounter += 1;
    const nonce = MdocSessionCipher.nonce(
      IDENTIFIER_READER,
      this.decryptCounter,
    );
    return gcm(this.keys.skReader, nonce).decrypt(ciphertext);
  }
}

/**
 * `SessionEstablishment = {"eReaderKey": EReaderKeyBytes, "data": bstr}` (ISO 18013-5 §9.1.1.4).
 *
 * `eReaderKeyBytes` is returned as the original tagged bytes because the SessionTranscript must
 * embed exactly what the reader sent.
 */
export interface ParsedSessionEstablishment {
  eReaderKeyBytes: Uint8Array;
  readerPublicKeyUncompressed: Uint8Array;
  encryptedData: Uint8Array;
}

export function parseSessionEstablishment(
  bytes: Uint8Array,
): ParsedSessionEstablishment {
  const root = asMap(decodeCbor(bytes), 'SessionEstablishment');
  const eReaderKeyTag = asTag(
    requireMapGet(root, 'eReaderKey', 'SessionEstablishment'),
    'SessionEstablishment.eReaderKey',
  );
  const encryptedData = asBytes(
    requireMapGet(root, 'data', 'SessionEstablishment'),
    'SessionEstablishment.data',
  );
  return {
    eReaderKeyBytes: eReaderKeyTag.raw,
    readerPublicKeyUncompressed: coseKeyToUncompressedP256(
      eReaderKeyTag.embeddedCbor,
    ),
    encryptedData,
  };
}

/** COSE_Key (EC2/P-256) → 65-byte uncompressed SEC1 point, which is what noble's ECDH wants. */
export function coseKeyToUncompressedP256(coseKeyCbor: Uint8Array): Uint8Array {
  const key = asMap(decodeCbor(coseKeyCbor), 'COSE_Key');
  const kty = key.get(1);
  const crv = key.get(-1);
  if (kty !== 2) {
    throw new Error(`COSE_Key kty must be 2 (EC2), got ${String(kty)}`);
  }
  if (crv !== 1) {
    throw new Error(`COSE_Key crv must be 1 (P-256), got ${String(crv)}`);
  }
  const x = asBytes(key.get(-2), 'COSE_Key x');
  const y = asBytes(key.get(-3), 'COSE_Key y');
  if (x.length !== 32 || y.length !== 32) {
    throw new Error(
      `COSE_Key P-256 coordinates must be 32 bytes (got x=${x.length}, y=${y.length})`,
    );
  }
  return concatBytes(new Uint8Array([0x04]), x, y);
}

/** Uncompressed SEC1 P-256 point → COSE_Key CBOR (EC2). */
export function uncompressedP256ToCoseKey(
  publicKeyUncompressed: Uint8Array,
): Uint8Array {
  if (
    publicKeyUncompressed.length !== 65 ||
    publicKeyUncompressed[0] !== 0x04
  ) {
    throw new Error('expected a 65-byte uncompressed SEC1 P-256 point');
  }
  return encodeCbor(
    new Map<number, unknown>([
      [1, 2],
      [-1, 1],
      [-2, publicKeyUncompressed.subarray(1, 33)],
      [-3, publicKeyUncompressed.subarray(33, 65)],
    ]),
  );
}

/**
 * `SessionData = {?"data": bstr, ?"status": uint}` — the frame for everything after establishment.
 */
export function encodeSessionData(params: {
  data?: Uint8Array;
  status?: number;
}): Uint8Array {
  const map = new Map<string, unknown>();
  if (params.data) {
    map.set('data', params.data);
  }
  if (params.status !== undefined) {
    map.set('status', params.status);
  }
  return encodeCbor(map);
}

export function parseSessionData(bytes: Uint8Array): {
  data?: Uint8Array;
  status?: number;
} {
  const root = asMap(decodeCbor(bytes), 'SessionData');
  const data = root.get('data');
  const status = root.get('status');
  return {
    data: data instanceof Uint8Array ? data : undefined,
    status: typeof status === 'number' ? status : undefined,
  };
}

/**
 * ISO 18013-5 §8.3.3.1.1.3 BLE Ident characteristic:
 * first 16 bytes of HMAC-SHA256 over the ASCII string "BLEIdent", keyed with EDeviceKeyBytes.
 *
 * Readers use it to confirm the peripheral they found is the one the QR described, so the key
 * must be the *tagged* EDeviceKeyBytes, matching what went into the engagement.
 */
export function bleIdentValue(eDeviceKeyBytes: Uint8Array): Uint8Array {
  return hmac(sha256, eDeviceKeyBytes, textEncoder.encode('BLEIdent')).subarray(
    0,
    16,
  );
}

/** Dev-only commitment logging, for diffing against the working Android session. */
export function logByteCommitment(label: string, bytes: Uint8Array): void {
  if (!__DEV__ || process.env.NODE_ENV === 'test') {
    return;
  }
  console.log(
    `[mdoc presentment] ${label}: ${bytes.length} bytes, sha256=${toHex(
      sha256(bytes),
    )}`,
  );
}
