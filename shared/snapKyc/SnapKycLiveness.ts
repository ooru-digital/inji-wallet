import {NativeModules} from 'react-native';

export type SnapKycLivenessResult = {
  verdict: string;
  isGenuine: boolean;
  probeImageBase64?: string;
  probeDetectionScore?: number;
  hasProbeImage: boolean;
  timedOut: boolean;
  errorMessage?: string;
};

export type SnapKycLivenessOptions = {
  languageCode?: string;
  referenceFaceBase64?: string;
  skipFaceImage?: boolean;
};

/** The face SDK's verdict on two faces. */
export type SdkFaceMatchResult = {
  isMatch: boolean;
  cosine: number;
  l2: number;
  cosineThreshold: number;
  l2Threshold: number;
  durationMs: number;
};

type SnapKycLivenessModuleType = {
  startLiveness: (config: {
    relayingPartyName: string;
    languageCode?: string;
    faceImageBase64?: string;
    skipFaceImage?: boolean;
  }) => Promise<SnapKycLivenessResult>;
  /** The BioChq SDK's own face match. Rejects with the SDK's error code. */
  matchFace?: (
    probeBase64: string,
    galleryBase64: string,
  ) => Promise<SdkFaceMatchResult>;
  closeFaceMatch?: () => void;
};

const {SnapKycLivenessModule} = NativeModules as {
  SnapKycLivenessModule?: SnapKycLivenessModuleType;
};

/**
 * Whether the native module has the SDK's face match. It does on both platforms; false means the
 * native module is miswired, and the face check then fails rather than match some other way.
 */
export function hasSdkFaceMatch(): boolean {
  return typeof SnapKycLivenessModule?.matchFace === 'function';
}

/** Compares the live face with a credential photo using the liveness SDK's matcher. */
export function matchFaceWithSdk(
  probeBase64: string,
  galleryBase64: string,
): Promise<SdkFaceMatchResult> {
  if (!SnapKycLivenessModule?.matchFace) {
    throw new Error('The liveness SDK has no face match on this platform');
  }
  return SnapKycLivenessModule.matchFace(probeBase64, galleryBase64);
}

/** Frees the SDK's face-match model; call once the face check is over. */
export function closeSdkFaceMatch() {
  SnapKycLivenessModule?.closeFaceMatch?.();
}

let activeLivenessSession: Promise<SnapKycLivenessResult> | null = null;

export function logSnapKycLivenessResult(
  label: string,
  result: SnapKycLivenessResult,
) {
  if (!__DEV__) {
    return;
  }
  console.log('[SnapKYC]', label, {
    verdict: result.verdict,
    isGenuine: result.isGenuine,
    timedOut: result.timedOut,
    hasProbeImage: result.hasProbeImage,
    probeDetectionScore: result.probeDetectionScore,
    errorMessage: result.errorMessage ?? null,
    probeImageLength: result.probeImageBase64?.length ?? 0,
  });
}

export async function startSnapKycLiveness(
  relayingPartyName: string,
  options: SnapKycLivenessOptions = {},
): Promise<SnapKycLivenessResult> {
  if (!SnapKycLivenessModule?.startLiveness) {
    throw new Error('SnapKycLivenessModule is not available on this platform');
  }

  if (activeLivenessSession) {
    return activeLivenessSession;
  }

  const skipFaceImage = options.skipFaceImage === true;
  const launchConfig = {
    relayingPartyName,
    languageCode: options.languageCode ?? 'en',
    skipFaceImage,
    ...(skipFaceImage || !options.referenceFaceBase64
      ? {}
      : {faceImageBase64: options.referenceFaceBase64}),
  };

  if (__DEV__) {
    console.log('[SnapKYC] Launching liveness', {
      relayingPartyName,
      skipFaceImage,
      hasReferenceFace: !skipFaceImage && !!options.referenceFaceBase64,
      referenceFaceLength: skipFaceImage
        ? 0
        : options.referenceFaceBase64?.length ?? 0,
    });
  }

  activeLivenessSession = SnapKycLivenessModule.startLiveness(launchConfig)
    .then(result => {
      logSnapKycLivenessResult('Session completed', result);
      return result;
    })
    .finally(() => {
      activeLivenessSession = null;
    });

  return activeLivenessSession;
}
