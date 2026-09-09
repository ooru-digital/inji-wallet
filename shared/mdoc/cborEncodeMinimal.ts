/**
 * Minimal RFC 8949 CBOR encoder for DeviceEngagement (no Node `stream` dependency).
 * Metro cannot bundle `cbor` because it requires `stream` / Transform.
 */

const textEncoder = new TextEncoder();

/** Tag #6.24: byte string holds nested CBOR (COSE_Key for mdoc Security). */
export class CborTag24 {
  constructor(readonly innerCbor: Uint8Array) {}
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
  if (val instanceof CborTag24) {
    writeTag(24, bs);
    writeBytes(val.innerCbor, bs);
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
