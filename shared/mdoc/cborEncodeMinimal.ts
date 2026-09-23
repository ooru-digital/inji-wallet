/**
 * Minimal RFC 8949 CBOR encoder for DeviceEngagement (no Node `stream` dependency).
 * Metro cannot bundle `cbor` because it requires `stream` / Transform.
 */

const textEncoder = new TextEncoder();

/** Tag #6.24: byte string holds nested CBOR (COSE_Key for mdoc Security). */
export class CborTag24 {
  constructor(readonly innerCbor: Uint8Array) {}
}

/**
 * Pre-encoded CBOR to splice in verbatim, bypassing the encoder entirely.
 *
 * ISO 18013-5 signs over *bytes*, not over decoded values: the MSO digests cover each
 * `IssuerSignedItemBytes` exactly as the issuer emitted it, and `issuerAuth` is a COSE_Sign1
 * whose signature covers its own serialization. Decode-then-re-encode is only byte-identical
 * when the producer used the same canonical length headers we emit — true in practice, but a
 * single non-canonical header (`0x59 0x00 0x50` where we would write `0x58 0x50`) silently
 * invalidates the issuer's signature with no local error. Carrying the original slice through
 * removes that whole class of failure from the response path.
 */
export class CborRaw {
  constructor(readonly bytes: Uint8Array) {}
}

/** Tag with an arbitrary number, for tags other than the #6.24 special case. */
export class CborTagged {
  constructor(readonly tag: number, readonly value: unknown) {}
}

function writeUIntHead(mt: number, n: number, bs: number[]): void {
  const major = mt << 5;
  if (n < 24) {
    bs.push(major | n);
  } else if (n < 256) {
    bs.push(major | 24, n);
  } else if (n < 65536) {
    bs.push(major | 25, (n >> 8) & 0xff, n & 0xff);
  } else if (n < 0x1_0000_0000) {
    bs.push(
      major | 26,
      (n >>> 24) & 0xff,
      (n >>> 16) & 0xff,
      (n >>> 8) & 0xff,
      n & 0xff,
    );
  } else if (Number.isSafeInteger(n)) {
    // ai=27 (8-byte argument). Split at 2^32 rather than using bit ops, which are 32-bit in JS.
    const hi = Math.floor(n / 0x1_0000_0000);
    const lo = n % 0x1_0000_0000;
    bs.push(
      major | 27,
      (hi >>> 24) & 0xff,
      (hi >>> 16) & 0xff,
      (hi >>> 8) & 0xff,
      hi & 0xff,
      (lo >>> 24) & 0xff,
      (lo >>> 16) & 0xff,
      (lo >>> 8) & 0xff,
      lo & 0xff,
    );
  } else {
    throw new Error('CBOR: integer too large');
  }
}

function writeNegativeInt(n: number, bs: number[]): void {
  if (n >= 0 || !Number.isInteger(n)) {
    throw new Error('CBOR: expected negative integer');
  }
  const nv = -n - 1;
  writeUIntHead(1, nv, bs);
}

function writeBytes(u8: Uint8Array, bs: number[]): void {
  writeUIntHead(2, u8.length, bs);
  for (let i = 0; i < u8.length; i++) {
    bs.push(u8[i]);
  }
}

function writeUtf8(str: string, bs: number[]): void {
  const u8 = textEncoder.encode(str);
  writeUIntHead(3, u8.length, bs);
  for (let i = 0; i < u8.length; i++) {
    bs.push(u8[i]);
  }
}

function writeTag(tag: number, bs: number[]): void {
  writeUIntHead(6, tag, bs);
}

/** RFC 8949 canonical map key order: ascending bytewise comparison of encoded keys. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) {
      return a[i] - b[i];
    }
  }
  return a.length - b.length;
}

function encodeKeySortBytes(key: unknown): Uint8Array {
  const tmp: number[] = [];
  encodeValue(key, tmp);
  return new Uint8Array(tmp);
}

function compareEncodedMapKeys(a: unknown, b: unknown): number {
  return compareBytes(encodeKeySortBytes(a), encodeKeySortBytes(b));
}

function encodeValue(val: unknown, bs: number[]): void {
  if (val === true) {
    bs.push(0xf5);
    return;
  }
  if (val === false) {
    bs.push(0xf4);
    return;
  }
  if (val === null || val === undefined) {
    bs.push(0xf6);
    return;
  }
  if (typeof val === 'number') {
    if (!Number.isInteger(val)) {
      throw new Error('CBOR: non-integer numbers are not supported');
    }
    if (val >= 0) {
      writeUIntHead(0, val, bs);
    } else {
      writeNegativeInt(val, bs);
    }
    return;
  }
  if (typeof val === 'string') {
    writeUtf8(val, bs);
    return;
  }
  if (ArrayBuffer.isView(val)) {
    if (val instanceof DataView) {
      throw new Error('CBOR: DataView cannot be encoded as a byte string');
    }
    const v = val as ArrayBufferView;
    writeBytes(new Uint8Array(v.buffer, v.byteOffset, v.byteLength), bs);
    return;
  }
  if (val instanceof CborRaw) {
    for (let i = 0; i < val.bytes.length; i++) {
      bs.push(val.bytes[i]);
    }
    return;
  }
  if (val instanceof CborTag24) {
    writeTag(24, bs);
    writeBytes(val.innerCbor, bs);
    return;
  }
  if (val instanceof CborTagged) {
    writeTag(val.tag, bs);
    encodeValue(val.value, bs);
    return;
  }
  if (Array.isArray(val)) {
    writeUIntHead(4, val.length, bs);
    for (const x of val) {
      encodeValue(x, bs);
    }
    return;
  }
  if (val instanceof Map) {
    const entries = [...val.entries()].sort((a, b) =>
      compareEncodedMapKeys(a[0], b[0]),
    );
    writeUIntHead(5, entries.length, bs);
    for (const [k, v] of entries) {
      encodeValue(k, bs);
      encodeValue(v, bs);
    }
    return;
  }
  if (typeof val === 'object') {
    const o = val as Record<string, unknown>;
    const keys = Object.keys(o);
    writeUIntHead(5, keys.length, bs);
    for (const k of keys) {
      writeUtf8(k, bs);
      encodeValue(o[k], bs);
    }
    return;
  }
  throw new Error(`CBOR: unsupported type ${typeof val}`);
}

/** Encode a value as RFC 8949 CBOR bytes (DeviceEngagement-shaped trees only). */
export function encodeCbor(value: unknown): Uint8Array {
  const bs: number[] = [];
  encodeValue(value, bs);
  return new Uint8Array(bs);
}
