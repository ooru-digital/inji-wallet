/**
 * Complete RFC 8949 CBOR decoder for the ISO 18013-5 presentment path.
 *
 * `../cborDecodeMinimal` deliberately exposes only DeviceEngagement-shaped probes (COSE_Key,
 * BLE UUID, transfer-method counting) — it has no general decode entry point, and its reader
 * drops the byte offsets we need. A `DeviceRequest` arrives from a third-party reader, so
 * unlike our own engagement it can legitimately contain indefinite-length strings, 64-bit
 * integers, floats and arbitrary tags; anything this decoder cannot represent must fail loudly
 * rather than be silently coerced.
 *
 * Every decoded item also carries the exact source byte range it came from. That is what makes
 * byte-preserving re-encoding possible on the response path — see {@link CborRaw}.
 */

import {CborRaw, CborTag24, CborTagged} from '../cborEncodeMinimal';

export {CborRaw, CborTag24, CborTagged};

export class CborError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CborError';
  }
}

/** A decoded tagged item, retaining the source bytes of the whole tagged value. */
export class DecodedTag {
  constructor(
    readonly tag: number,
    readonly value: unknown,
    readonly raw: Uint8Array,
  ) {}

  /** Inner CBOR of a #6.24 "embedded CBOR" byte string. */
  get embeddedCbor(): Uint8Array {
    if (this.tag !== 24) {
      throw new CborError(`expected tag 24, got ${this.tag}`);
    }
    if (!(this.value instanceof Uint8Array)) {
      throw new CborError('tag 24 value must be a byte string');
    }
    return this.value;
  }
}

const MT_UINT = 0;
const MT_NEGINT = 1;
const MT_BSTR = 2;
const MT_TSTR = 3;
const MT_ARRAY = 4;
const MT_MAP = 5;
const MT_TAG = 6;
const MT_SIMPLE = 7;

const BREAK = 0xff;

class CborReader {
  private i = 0;

  constructor(private readonly buf: Uint8Array) {}

  get offset(): number {
    return this.i;
  }

  get atEnd(): boolean {
    return this.i >= this.buf.length;
  }

  private u8(): number {
    if (this.i >= this.buf.length) {
      throw new CborError('unexpected end of CBOR input');
    }
    return this.buf[this.i++];
  }

  private take(n: number): Uint8Array {
    if (n < 0 || this.i + n > this.buf.length) {
      throw new CborError('CBOR length runs past end of input');
    }
    const out = this.buf.subarray(this.i, this.i + n);
    this.i += n;
    return out;
  }

  /** Reads the argument of a head byte. `null` means indefinite length (ai 31). */
  private argument(ai: number): number | null {
    if (ai < 24) {
      return ai;
    }
    if (ai === 24) {
      return this.u8();
    }
    if (ai === 25) {
      return (this.u8() << 8) | this.u8();
    }
    if (ai === 26) {
      return (
        ((this.u8() << 24) |
          (this.u8() << 16) |
          (this.u8() << 8) |
          this.u8()) >>>
        0
      );
    }
    if (ai === 27) {
      // 32-bit bit ops would overflow, so recombine the halves arithmetically.
      const hi =
        ((this.u8() << 24) |
          (this.u8() << 16) |
          (this.u8() << 8) |
          this.u8()) >>>
        0;
      const lo =
        ((this.u8() << 24) |
          (this.u8() << 16) |
          (this.u8() << 8) |
          this.u8()) >>>
        0;
      const n = hi * 0x1_0000_0000 + lo;
      if (!Number.isSafeInteger(n)) {
        throw new CborError('CBOR integer exceeds JS safe integer range');
      }
      return n;
    }
    if (ai === 31) {
      return null;
    }
    throw new CborError(`reserved CBOR additional info ${ai}`);
  }

  /** Concatenates the chunks of an indefinite-length string (major type 2 or 3). */
  private indefiniteString(expectedMt: number): Uint8Array {
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      if (this.buf[this.i] === BREAK) {
        this.i++;
        break;
      }
      const head = this.u8();
      const mt = head >> 5;
      const ai = head & 0x1f;
      if (mt !== expectedMt) {
        throw new CborError(
          `indefinite string chunk has major type ${mt}, expected ${expectedMt}`,
        );
      }
      const len = this.argument(ai);
      if (len === null) {
        throw new CborError('nested indefinite string chunk');
      }
      const chunk = this.take(len);
      chunks.push(chunk);
      total += chunk.length;
    }
    const out = new Uint8Array(total);
    let at = 0;
    for (const c of chunks) {
      out.set(c, at);
      at += c.length;
    }
    return out;
  }

  read(): unknown {
    const start = this.i;
    const head = this.u8();
    const mt = head >> 5;
    const ai = head & 0x1f;

    switch (mt) {
      case MT_UINT: {
        const n = this.argument(ai);
        if (n === null) {
          throw new CborError('indefinite length is invalid for an integer');
        }
        return n;
      }
      case MT_NEGINT: {
        const n = this.argument(ai);
        if (n === null) {
          throw new CborError('indefinite length is invalid for an integer');
        }
        return -1 - n;
      }
      case MT_BSTR: {
        const len = this.argument(ai);
        return len === null ? this.indefiniteString(MT_BSTR) : this.take(len);
      }
      case MT_TSTR: {
        const len = this.argument(ai);
        const bytes =
          len === null ? this.indefiniteString(MT_TSTR) : this.take(len);
        return new TextDecoder('utf-8', {fatal: true}).decode(bytes);
      }
      case MT_ARRAY: {
        const len = this.argument(ai);
        const arr: unknown[] = [];
        if (len === null) {
          while (this.buf[this.i] !== BREAK) {
            arr.push(this.read());
          }
          this.i++;
        } else {
          for (let k = 0; k < len; k++) {
            arr.push(this.read());
          }
        }
        return arr;
      }
      case MT_MAP: {
        const len = this.argument(ai);
        const m = new Map<unknown, unknown>();
        const put = () => {
          const key = this.read();
          const value = this.read();
          // Uint8Array keys would compare by identity in a Map and never match a lookup.
          // No ISO 18013-5 structure uses one, so reject rather than lose the entry.
          if (key instanceof Uint8Array) {
            throw new CborError('byte string map keys are not supported');
          }
          m.set(key, value);
        };
        if (len === null) {
          while (this.buf[this.i] !== BREAK) {
            put();
          }
          this.i++;
        } else {
          for (let k = 0; k < len; k++) {
            put();
          }
        }
        return m;
      }
      case MT_TAG: {
        const tag = this.argument(ai);
        if (tag === null) {
          throw new CborError('indefinite length is invalid for a tag');
        }
        const value = this.read();
        return new DecodedTag(tag, value, this.buf.subarray(start, this.i));
      }
      case MT_SIMPLE: {
        if (ai === 20) {
          return false;
        }
        if (ai === 21) {
          return true;
        }
        if (ai === 22) {
          return null;
        }
        if (ai === 23) {
          return undefined;
        }
        if (ai === 25) {
          return decodeFloat16(this.take(2));
        }
        if (ai === 26) {
          return new DataView(this.take(4).slice().buffer).getFloat32(0, false);
        }
        if (ai === 27) {
          return new DataView(this.take(8).slice().buffer).getFloat64(0, false);
        }
        throw new CborError(`unsupported simple value ${ai}`);
      }
      default:
        throw new CborError(`unsupported CBOR major type ${mt}`);
    }
  }
}

function decodeFloat16(bytes: Uint8Array): number {
  const half = (bytes[0] << 8) | bytes[1];
  const exp = (half >> 10) & 0x1f;
  const frac = half & 0x3ff;
  const sign = half & 0x8000 ? -1 : 1;
  if (exp === 0) {
    return sign * frac * 2 ** -24;
  }
  if (exp === 0x1f) {
    return frac === 0 ? sign * Infinity : NaN;
  }
  return sign * (frac + 1024) * 2 ** (exp - 25);
}

/** Decodes one CBOR item, rejecting trailing bytes. */
export function decodeCbor(bytes: Uint8Array): unknown {
  const r = new CborReader(bytes);
  const value = r.read();
  if (!r.atEnd) {
    throw new CborError(
      `${bytes.length - r.offset} trailing byte(s) after CBOR item`,
    );
  }
  return value;
}

/** Decodes the first CBOR item and reports how many bytes it consumed. */
export function decodeCborPrefix(bytes: Uint8Array): {
  value: unknown;
  bytesRead: number;
} {
  const r = new CborReader(bytes);
  const value = r.read();
  return {value, bytesRead: r.offset};
}

// --- typed accessors -------------------------------------------------------
// ISO 18013-5 structures are maps with fixed key names; these keep the parsers readable
// and make a malformed reader message fail with a field name instead of a TypeError.

export function asMap(value: unknown, what: string): Map<unknown, unknown> {
  if (!(value instanceof Map)) {
    throw new CborError(`${what} must be a CBOR map`);
  }
  return value;
}

export function asArray(value: unknown, what: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new CborError(`${what} must be a CBOR array`);
  }
  return value;
}

export function asBytes(value: unknown, what: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new CborError(`${what} must be a CBOR byte string`);
  }
  return value;
}

export function asText(value: unknown, what: string): string {
  if (typeof value !== 'string') {
    throw new CborError(`${what} must be a CBOR text string`);
  }
  return value;
}

export function asTag(value: unknown, what: string): DecodedTag {
  if (!(value instanceof DecodedTag)) {
    throw new CborError(`${what} must be a tagged CBOR item`);
  }
  return value;
}

/** Reads `#6.24(bstr .cbor X)` and returns the decoded X. */
export function decodeEmbedded(value: unknown, what: string): unknown {
  return decodeCbor(asTag(value, what).embeddedCbor);
}

export function mapGet(
  map: Map<unknown, unknown>,
  key: unknown,
): unknown | undefined {
  return map.get(key);
}

export function requireMapGet(
  map: Map<unknown, unknown>,
  key: unknown,
  what: string,
): unknown {
  const v = map.get(key);
  if (v === undefined) {
    throw new CborError(`${what} is missing key ${String(key)}`);
  }
  return v;
}

/** Bytes → lowercase hex, for the dev-only byte-parity logs. */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) {
    total += p.length;
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
