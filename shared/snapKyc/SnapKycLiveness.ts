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

type SnapKycLivenessModuleType = {
  startLiveness: (config: {
    relayingPartyName: string;
    languageCode?: string;
    faceImageBase64?: string;
    skipFaceImage?: boolean;
  }) => Promise<SnapKycLivenessResult>;
};

const {SnapKycLivenessModule} = NativeModules as {
  SnapKycLivenessModule?: SnapKycLivenessModuleType;
};

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
