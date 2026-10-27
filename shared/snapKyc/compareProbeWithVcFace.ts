import {faceCompare} from '@iriscan/biometric-sdk-react-native';
import {Buffer} from 'buffer';

import {detectImageFormat, toDecodableImageBase64} from './compressFaceImage';
import {ensureFaceModelReady} from '../api';
import {hasSdkFaceMatch, matchFaceWithSdk} from './SnapKycLiveness';

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

  // The liveness SDK matches faces itself; @iriscan is only the fallback for an older native build.
  const useSdkMatch = hasSdkFaceMatch();

  // @iriscan's native compare crashes the app (iOS) when the model isn't set up, so this must not
  // reach it without one. Throwing makes the caller reject the check rather than share unverified.
  if (!useSdkMatch && !(await ensureFaceModelReady())) {
    throw new Error('Face matching model could not be set up');
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

    // A comparison that errors (no face found, model failed) counts as tried, not as no photo:
    // it ends in `mismatch` unless another portrait matches, so liveness alone never lets it pass.
    comparedAny = true;
    try {
      if (useSdkMatch) {
        const result = await matchFaceWithSdk(probe, vcFaceBase64);
        if (__DEV__) {
          console.log('[SnapKYC] SDK face match', result);
        }
        if (result.isMatch) {
          return 'match';
        }
      } else if (await faceCompare(probe, vcFaceBase64)) {
        return 'match';
      }
    } catch (error: any) {
      console.warn('[SnapKYC] Face match failed for credential portrait', {
        code: error?.code,
        message: error?.message,
      });
    }
  }

  return comparedAny ? 'mismatch' : 'unusable';
}
