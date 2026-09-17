/**
 * Minimal CBOR reader for DeviceEngagement / COSE_Key validation and tests.
 * Supports definite-length maps, arrays, byte strings, text, uint/negint, bool, tag 6.24.
 */

export class CborDecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CborDecodeError';
  }
}

class Reader {
  constructor(private readonly buf: Uint8Array, private i = 0) {}

  private readU8(): number {
    if (this.i >= this.buf.length) {
      throw new CborDecodeError('unexpected EOF');
    }
    return this.buf[this.i++];
  }

  readUintValue(ai: number): number {
    if (ai < 24) {
      return ai;
    }
    if (ai === 24) {
      return this.readU8();
    }
    if (ai === 25) {
      return (this.readU8() << 8) | this.readU8();
    }
    if (ai === 26) {
      return (
        ((this.readU8() << 24) |
          (this.readU8() << 16) |
          (this.readU8() << 8) |
          this.readU8()) >>>
        0
      );
    }
    throw new CborDecodeError('unsupported integer additional info');
  }

  readBstr(): Uint8Array {
    const b = this.readU8();
    const mt = b >> 5;
    const ai = b & 0x1f;
    if (mt !== 2) {
      throw new CborDecodeError(`expected byte string, got major ${mt}`);
    }
    const len = this.readUintValue(ai);
    if (this.i + len > this.buf.length) {
      throw new CborDecodeError('byte string length past EOF');
    }
    const out = this.buf.subarray(this.i, this.i + len);
    this.i += len;
    return out;
  }

  readText(): string {
    const b = this.readU8();
    const mt = b >> 5;
    const ai = b & 0x1f;
    if (mt !== 3) {
      throw new CborDecodeError(`expected text string, got major ${mt}`);
    }
    const len = this.readUintValue(ai);
    if (this.i + len > this.buf.length) {
      throw new CborDecodeError('text string length past EOF');
    }
    const out = this.buf.subarray(this.i, this.i + len);
    this.i += len;
    return new TextDecoder('utf-8', {fatal: true}).decode(out);
  }

  readValue(): unknown {
    const b = this.readU8();
    const mt = b >> 5;
    const ai = b & 0x1f;
    if (b === 0xf4) {
      return false;
    }
    if (b === 0xf5) {
      return true;
    }
    if (b === 0xf6) {
      return null;
    }
    if (mt === 0) {
      return this.readUintValue(ai);
    }
    if (mt === 1) {
      const n = this.readUintValue(ai);
      return -1 - n;
    }
    if (mt === 2) {
      this.i--;
      return this.readBstr();
    }
    if (mt === 3) {
      this.i--;
      return this.readText();
    }
    if (mt === 4) {
      const len = this.readUintValue(ai);
      const arr: unknown[] = [];
      for (let k = 0; k < len; k++) {
        arr.push(this.readValue());
      }
      return arr;
    }
    if (mt === 5) {
      const len = this.readUintValue(ai);
      const m = new Map<unknown, unknown>();
      for (let k = 0; k < len; k++) {
        const key = this.readValue();
        const val = this.readValue();
        m.set(key, val);
      }
      return m;
    }
    if (mt === 6) {
      const tag = this.readUintValue(ai);
      const value = this.readValue();
      return {__cborTag: tag, value};
    }
    throw new CborDecodeError(
      `unsupported CBOR initial byte 0x${b.toString(16)}`,
    );
  }

  eof(): boolean {
    return this.i >= this.buf.length;
  }

  offset(): number {
    return this.i;
  }
}

/** True if `b` looks like a CBOR definite-length byte string header + 32-byte payload (double-wrap). */
export function looksLikeCborBstr32Wrapper(b: Uint8Array): boolean {
  return b.length === 34 && b[0] === 0x58 && b[1] === 0x20;
}

export interface ParsedCoseEc2P256 {
  kty: number;
  crv: number;
  x: Uint8Array;
  y: Uint8Array;
}

/**
 * Walk interop DeviceEngagement map {0,1,2}, Security[1] = tag 24, inner = COSE_Key map.
 */
export function parseCoseEc2P256FromDeviceEngagement(
  deviceEngagementCbor: Uint8Array,
): ParsedCoseEc2P256 {
  const r = new Reader(deviceEngagementCbor);
  const root = r.readValue();
  if (!(root instanceof Map)) {
    throw new CborDecodeError('DeviceEngagement root must be a CBOR map');
  }
  const security = root.get(1);
  if (!Array.isArray(security) || security.length < 2) {
    throw new CborDecodeError(
      'Security must be an array of at least 2 elements',
    );
  }
  const tagged = security[1];
  if (
    !tagged ||
    typeof tagged !== 'object' ||
    !('__cborTag' in tagged) ||
    (tagged as {__cborTag: number}).__cborTag !== 24
  ) {
    throw new CborDecodeError('Security[1] must be CBOR tag 24');
  }
  const outer = (tagged as {value: unknown}).value;
  if (!(outer instanceof Uint8Array)) {
    throw new CborDecodeError(
      'Tag 24 value must be a byte string (raw CBOR of COSE_Key)',
    );
  }
  const innerReader = new Reader(outer);
  const coseKey = innerReader.readValue();
  if (!innerReader.eof()) {
    throw new CborDecodeError('Trailing bytes after COSE_Key map');
  }
  if (!(coseKey instanceof Map)) {
    throw new CborDecodeError('COSE_Key must be a CBOR map');
  }
  const kty = coseKey.get(1);
  const crv = coseKey.get(-1);
  const x = coseKey.get(-2);
  const y = coseKey.get(-3);
  if (typeof kty !== 'number' || typeof crv !== 'number') {
    throw new CborDecodeError('COSE_Key kty/crv must be integers');
  }
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) {
    throw new CborDecodeError(
      'COSE_Key x/y must be CBOR byte strings (Uint8Array), not nested maps',
    );
  }
  if (looksLikeCborBstr32Wrapper(x) || looksLikeCborBstr32Wrapper(y)) {
    throw new CborDecodeError(
      'COSE_Key x/y look double-CBOR-wrapped (0x58 0x20 prefix inside 34-byte value)',
    );
  }
  if (x.length !== 32 || y.length !== 32) {
    throw new CborDecodeError(
      `COSE_Key P-256 x/y must be exactly 32 bytes (got x=${x.length}, y=${y.length})`,
    );
  }
  return {kty, crv, x, y};
}

/**
 * Counts BLE device-retrieval rows under interop map key `2` (each `[2,1,BleOptions]`).
 * Used to invalidate cached engagements when upgrading Android holder QR layout.
 */
export function countBleTransferMethodRowsInDeviceEngagement(
  deviceEngagementCbor: Uint8Array,
): number {
  const r = new Reader(deviceEngagementCbor);
  const root = r.readValue();
  if (!(root instanceof Map)) {
    return 0;
  }
  const tm = root.get(2);
  if (!Array.isArray(tm)) {
    return 0;
  }
  let n = 0;
  for (const row of tm) {
    if (!Array.isArray(row) || row.length < 1) {
      continue;
    }
    if (row[0] === 2) {
      n++;
    }
  }
  return n;
}

export function parseBlePeripheralUuidFromDeviceEngagement(
  deviceEngagementCbor: Uint8Array,
): Uint8Array {
  const r = new Reader(deviceEngagementCbor);
  const root = r.readValue();
  if (!(root instanceof Map)) {
    throw new CborDecodeError('DeviceEngagement root must be a CBOR map');
  }
  const tm = root.get(2);
  if (!Array.isArray(tm) || tm.length < 1) {
    throw new CborDecodeError('TransferMethods missing');
  }
  const first = tm[0];
  if (!Array.isArray(first) || first.length < 3) {
    throw new CborDecodeError('First transfer method must be [2,1,BleOptions]');
  }
  const ble = first[2];
  if (!(ble instanceof Map)) {
    throw new CborDecodeError('BleOptions must be a map');
  }
  const uuid = ble.get(10);
  if (!(uuid instanceof Uint8Array)) {
    throw new CborDecodeError('BLE key 10 must be a 16-byte bstr');
  }
  if (uuid.length !== 16) {
    throw new CborDecodeError(`BLE UUID must be 16 bytes, got ${uuid.length}`);
  }
  return uuid;
}
