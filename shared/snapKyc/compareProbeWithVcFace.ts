import {faceCompare} from '@iriscan/biometric-sdk-react-native';
import {Buffer} from 'buffer';

import {detectImageFormat, toDecodableImageBase64} from './compressFaceImage';

/** Dev-only: says what a value actually is, so a bad portrait is diagnosable from one log line. */
function describeImageValue(label: string, value: unknown) {
  if (!__DEV__) {
    return;
  }
  const normalized = toDecodableImageBase64(value);
  const raw =
    typeof value === 'string'
      ? Buffer.from(
          value.trim().replace(/-/g, '+').replace(/_/g, '/'),
          'base64',
        )
      : undefined;
  console.log(`[SnapKYC] ${label}`, {
    jsType: Array.isArray(value) ? 'array' : typeof value,
    rawLength: typeof value === 'string' ? value.length : undefined,
    isDataUri: typeof value === 'string' && value.startsWith('data:'),
    decodedFormat: raw ? detectImageFormat(raw) ?? 'unrecognised' : undefined,
    firstBytes: raw ? raw.subarray(0, 4).toString('hex') : undefined,
    usable: !!normalized,
  });
}

/**
 * `mismatch` is a real negative — the live face is not the credential holder's, so the caller
 * must reject. `unusable` means no comparison could be attempted at all (no decodable portrait
 * in the credential), which is a different situation and must not be reported as a failed match.
 */
export type FaceMatchOutcome = 'match' | 'mismatch' | 'unusable';

/**
 * Compare the SnapKYC probe (live capture) against the credential portrait(s).
 * Argument order matches machines/faceScanner.ts verifyImage.
 *
 * Both sides are validated as real image bytes first — `faceExtractAndEncode` throws an
 * uncatchable native exception on undecodable input rather than rejecting its promise.
 */
export async function compareProbeWithVcFace(
  probeImageBase64: string,
  vcImages: string[],
): Promise<FaceMatchOutcome> {
  if (!probeImageBase64 || vcImages.length === 0) {
    return 'unusable';
  }

  describeImageValue('probe image', probeImageBase64);

  const probe = toDecodableImageBase64(probeImageBase64);
  if (!probe) {
    console.warn(
      '[SnapKYC] Live probe is not a decodable image — cannot run face match',
    );
    return 'unusable';
  }

  let comparedAny = false;

  for (const vcImage of vcImages) {
    describeImageValue('credential portrait', vcImage);

    const vcFaceBase64 = toDecodableImageBase64(vcImage);
    if (!vcFaceBase64) {
      console.warn(
        '[SnapKYC] Credential portrait is not a decodable image — skipping it',
      );
      continue;
    }

    try {
      comparedAny = true;
      if (await faceCompare(probe, vcFaceBase64)) {
        return 'match';
      }
    } catch (error) {
      console.warn(
        '[SnapKYC] faceCompare failed for credential portrait',
        error,
      );
    }
  }

  return comparedAny ? 'mismatch' : 'unusable';
}
