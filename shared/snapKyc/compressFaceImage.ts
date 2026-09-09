import {Buffer} from 'buffer';

const DATA_URI_REGEX = /data:(?<mime>[\w/\-.]+);(?<encoding>\w+),(?<data>.*)/;

export function extractBase64FromDataUri(dataUri: string): string | undefined {
  const matches = DATA_URI_REGEX.exec(dataUri);
  return matches?.groups?.data;
}

/** Leading bytes of the formats BitmapFactory can decode on Android. */
const IMAGE_SIGNATURES: Array<{format: string; magic: number[]}> = [
  {format: 'jpeg', magic: [0xff, 0xd8, 0xff]},
  {format: 'png', magic: [0x89, 0x50, 0x4e, 0x47]},
  {format: 'gif', magic: [0x47, 0x49, 0x46, 0x38]},
  {format: 'bmp', magic: [0x42, 0x4d]},
  // WEBP is "RIFF"…"WEBP"; the RIFF prefix is enough to tell it apart from junk.
  {format: 'webp', magic: [0x52, 0x49, 0x46, 0x46]},
];

/** Returns the detected image format, or undefined when the bytes are not an image. */
export function detectImageFormat(bytes: Buffer): string | undefined {
  return IMAGE_SIGNATURES.find(
    ({magic}) =>
      bytes.length >= magic.length &&
      magic.every((byte, index) => bytes[index] === byte),
  )?.format;
}

/**
 * Coerces a credential portrait / captured probe into standard base64 that Android's
 * `BitmapFactory.decodeByteArray` can actually decode.
 *
 * This matters because `@iriscan`'s `faceExtractAndEncode` has no try/catch around
 * `extractAndEncode(bitmap)` — handing it undecodable data makes `decodeByteArray` return null
 * and throws out of the native module as an uncatchable "Exception in native call from JS"
 * redbox rather than a rejected promise. So the validation has to happen before the call.
 *
 * mdoc portraits arrive as a CBOR byte string that pixelpass' `toJson` may render as base64,
 * base64url, a plain number array, or a Buffer-shaped object — hence the several shapes here.
 */
export function toDecodableImageBase64(value: unknown): string | undefined {
  let bytes: Buffer | undefined;

  if (typeof value === 'string') {
    const payload = extractBase64FromDataUri(value) ?? value;
    // base64url -> base64; Buffer tolerates missing padding.
    const normalized = payload.trim().replace(/-/g, '+').replace(/_/g, '/');
    if (!normalized) {
      return undefined;
    }
    bytes = Buffer.from(normalized, 'base64');
  } else if (Array.isArray(value)) {
    bytes = Buffer.from(value as number[]);
  } else if (
    value &&
    typeof value === 'object' &&
    Array.isArray((value as {data?: unknown}).data)
  ) {
    // {type: 'Buffer', data: [...]} — how a Buffer survives a JSON round trip.
    bytes = Buffer.from((value as {data: number[]}).data);
  }

  if (!bytes || bytes.length === 0 || !detectImageFormat(bytes)) {
    return undefined;
  }

  return bytes.toString('base64');
}

export function extractReferenceFaceBase64(
  vcImages: string[],
): string | undefined {
  for (const vcImage of vcImages) {
    const base64 = toDecodableImageBase64(vcImage);
    if (base64) {
      return base64;
    }
  }
  return undefined;
}
