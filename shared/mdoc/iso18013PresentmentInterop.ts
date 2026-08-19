/**
 * ISO/IEC 18013-5 **proximity presentation** (post–DeviceEngagement QR): BLE session,
 * SessionTranscript, encrypted DeviceRequest / DeviceResponse, DeviceAuthentication, COSE_Sign1.
 *
 * This **cannot** be implemented faithfully in React Native JavaScript alone (Hermes) at the
 * same level as [Multipaz](https://github.com/openwallet-foundation/multipaz): timing, GATT,
 * and byte-exact CBOR/crypto belong in **native** code. Use this module as the **TypeScript
 * contract** for a thin RN bridge to Multipaz (or another ISO-complete SDK).
 *
 * @see https://developer.multipaz.org/docs/getting-started/holder/presentation/
 */

import {Buffer} from 'buffer';
import {
  EmitterSubscription,
  NativeEventEmitter,
  NativeModules,
  Platform,
} from 'react-native';

/** Multipaz holder QR presentment composable (KMP) — wire equivalent in Android/iOS native. */
export const MULTIPAZ_REFERENCE = {
  holderPresentationDoc:
    'https://developer.multipaz.org/docs/getting-started/holder/presentation/',
  samplesPresentmentGradle:
    'https://github.com/openwallet-foundation/multipaz-samples/blob/main/MultipazGettingStartedSample/feature/presentment/build.gradle.kts',
} as const;

export type PresentmentPhase =
  | 'idle'
  | 'bleAdvertising'
  | 'awaitingReader'
  | 'sessionEstablishment'
  | 'deviceRequestReceived'
  | 'userConsent'
  | 'buildingDeviceResponse'
  | 'sendingDeviceResponse'
  | 'completed'
  | 'failed';

export interface Iso18013PresentmentParams {
  /** VC store id (same as `iso18013_de` keystore suffix family). */
  vcId: string;
  /** Issuer-signed mdoc credential (CBOR) as base64 or base64url — native must parse MSO. */
  msoMdocCredentialCompact: string;
  /** e.g. org.iso.18013.5.1.mDL */
  docType: string;
  /** Exact `mdoc:`… string already shown to the user (bytes must not change). */
  deviceEngagementUri: string;
  /** Raw DeviceEngagement CBOR bytes (must equal decoded URI payload). */
  deviceEngagementCbor: Uint8Array;
  /** Ephemeral P-256 private key bytes (must pair with COSE_Key in engagement). */
  ephemeralPresentationPrivateKey: Uint8Array;
  /** When true, native uses software-imported device key (e.g. iOS ES256 material). */
  useSoftwareDeviceKey?: boolean;
  /** Standard base64 of raw P-256 device private key (32 bytes) for software path. */
  deviceKeyPrivateBase64?: string;
}

export interface Iso18013PresentmentCallbacks {
  onPhase?: (phase: PresentmentPhase, detail?: string) => void;
  /** Native layer should log hex only in __DEV__ / gated builds. */
  onDebugHex?: (label: string, hex: string) => void;
  /** Fired when the verifier's DeviceRequest needs user approval before DeviceResponse. */
  onConsentRequired?: (request: MdocPresentmentConsentRequest) => void;
  /** Fired when consent UI should close (approve, deny, session end, cancel). */
  onConsentDismissed?: () => void;
}

/** One data element the verifier asked for (ISO 18013-5 nameSpaces). */
export interface MdocPresentmentConsentElement {
  namespace: string;
  element: string;
  intentToRetain: boolean;
  optional: boolean;
}

export interface MdocPresentmentConsentRequest {
  docType: string;
  /** Human-readable credential label (e.g. "Authorized Inji Certificate"). */
  credentialLabel?: string;
  /** Verifier display name from readerAuth / trust metadata when available. */
  verifierName?: string;
  /** Purpose from deviceRequestInfo.purposeHints or free-text otherInfo. */
  purpose?: string;
  /** Numeric purposeHints code when present (ISO 18013-5 §10.2.5). */
  purposeHintCode?: number | null;
  elements: MdocPresentmentConsentElement[];
}

export const MDOC_PRESENTMENT_CONSENT_REQUIRED =
  'MdocPresentmentConsentRequired';
export const MDOC_PRESENTMENT_CONSENT_DISMISSED =
  'MdocPresentmentConsentDismissed';
export const MDOC_PRESENTMENT_CANNOT_SATISFY = 'MdocPresentmentCannotSatisfy';

export interface MdocPresentmentCannotSatisfyEvent {
  reason: string;
  walletDocType: string;
  requestedDocTypes: string[];
}

export class Iso18013PresentmentNotImplementedError extends Error {
  constructor(message?: string) {
    super(
      message ??
        'ISO/IEC 18013-5 proximity presentation is not available on this platform build. On Android, Multipaz must be on the classpath and MdocIso18013Presentment registered. See shared/mdoc/README.md.',
    );
    this.name = 'Iso18013PresentmentNotImplementedError';
  }
}

type MdocNative = {
  startPresentment: (config: Record<string, unknown>) => Promise<boolean>;
  stopPresentment: () => void;
  approvePresentment?: () => Promise<boolean>;
  denyPresentment?: () => Promise<boolean>;
  addListener?: (eventName: string) => void;
  removeListeners?: (count: number) => void;
};

function getNativeModule(): MdocNative | undefined {
  return (NativeModules as {MdocIso18013Presentment?: MdocNative})
    .MdocIso18013Presentment;
}

function getEventEmitter(): NativeEventEmitter | null {
  const nm = getNativeModule();
  if (Platform.OS !== 'android' || !nm) {
    return null;
  }
  return new NativeEventEmitter(nm as never);
}

function normalizeConsentPayload(raw: unknown): MdocPresentmentConsentRequest {
  const obj = (raw ?? {}) as {
    docType?: string;
    credentialLabel?: string;
    verifierName?: string;
    purpose?: string;
    purposeHintCode?: number | null;
    elements?: Array<{
      namespace?: string;
      element?: string;
      intentToRetain?: boolean;
      optional?: boolean;
    }>;
  };
  const purposeHintCode =
    typeof obj.purposeHintCode === 'number' &&
    Number.isFinite(obj.purposeHintCode)
      ? obj.purposeHintCode
      : null;
  return {
    docType: typeof obj.docType === 'string' ? obj.docType : '',
    credentialLabel:
      typeof obj.credentialLabel === 'string' ? obj.credentialLabel : undefined,
    verifierName:
      typeof obj.verifierName === 'string' ? obj.verifierName : undefined,
    purpose: typeof obj.purpose === 'string' ? obj.purpose : undefined,
    purposeHintCode,
    elements: Array.isArray(obj.elements)
      ? obj.elements.map(el => ({
          namespace: String(el?.namespace ?? ''),
          element: String(el?.element ?? ''),
          intentToRetain: !!el?.intentToRetain,
          optional: !!el?.optional,
        }))
      : [],
  };
}

/**
 * Subscribe to native "consent required" events (after DeviceRequest, before DeviceResponse).
 * Keep the subscription active for the whole presentment lifetime.
 */
export function subscribeMdocPresentmentConsentRequired(
  listener: (request: MdocPresentmentConsentRequest) => void,
): EmitterSubscription | {remove: () => void} {
  const emitter = getEventEmitter();
  if (!emitter) {
    return {remove: () => {}};
  }
  return emitter.addListener(MDOC_PRESENTMENT_CONSENT_REQUIRED, raw => {
    listener(normalizeConsentPayload(raw));
  });
}

/** Subscribe when the consent overlay should close. */
export function subscribeMdocPresentmentConsentDismissed(
  listener: () => void,
): EmitterSubscription | {remove: () => void} {
  const emitter = getEventEmitter();
  if (!emitter) {
    return {remove: () => {}};
  }
  return emitter.addListener(MDOC_PRESENTMENT_CONSENT_DISMISSED, () => {
    listener();
  });
}

/**
 * Subscribe when the wallet cannot satisfy the reader's DeviceRequest
 * (e.g. requested docType is not the credential currently being presented).
 */
export function subscribeMdocPresentmentCannotSatisfy(
  listener: (event: MdocPresentmentCannotSatisfyEvent) => void,
): EmitterSubscription | {remove: () => void} {
  const emitter = getEventEmitter();
  if (!emitter) {
    return {remove: () => {}};
  }
  return emitter.addListener(MDOC_PRESENTMENT_CANNOT_SATISFY, raw => {
    const obj = (raw ?? {}) as {
      reason?: string;
      walletDocType?: string;
      requestedDocTypes?: unknown;
    };
    listener({
      reason: typeof obj.reason === 'string' ? obj.reason : '',
      walletDocType:
        typeof obj.walletDocType === 'string' ? obj.walletDocType : '',
      requestedDocTypes: Array.isArray(obj.requestedDocTypes)
        ? obj.requestedDocTypes.map(String)
        : [],
    });
  });
}

/**
 * Starts full proximity presentation (BLE + session + DeviceResponse) via Android native Multipaz.
 * Consent is requested mid-session via [subscribeMdocPresentmentConsentRequired] / callbacks.
 */
export async function startIso18013ProximityPresentment(
  params: Iso18013PresentmentParams,
  callbacks?: Iso18013PresentmentCallbacks,
): Promise<void> {
  const nm = getNativeModule();
  if (Platform.OS !== 'android' || !nm?.startPresentment) {
    throw new Iso18013PresentmentNotImplementedError();
  }

  const consentSub = callbacks?.onConsentRequired
    ? subscribeMdocPresentmentConsentRequired(request => {
        callbacks.onPhase?.('userConsent');
        callbacks.onConsentRequired?.(request);
      })
    : null;
  const dismissSub = callbacks?.onConsentDismissed
    ? subscribeMdocPresentmentConsentDismissed(() => {
        callbacks.onConsentDismissed?.();
      })
    : null;

  try {
    callbacks?.onPhase?.('bleAdvertising');
    await nm.startPresentment({
      issuerSignedCompact: params.msoMdocCredentialCompact,
      deviceEngagementCborBase64: Buffer.from(
        params.deviceEngagementCbor,
      ).toString('base64'),
      ephemeralPrivateKeyBase64: Buffer.from(
        params.ephemeralPresentationPrivateKey,
      ).toString('base64'),
      useSoftwareDeviceKey: !!params.useSoftwareDeviceKey,
      deviceKeyPrivateBase64: params.deviceKeyPrivateBase64,
    });
    callbacks?.onPhase?.('completed');
  } finally {
    consentSub?.remove();
    dismissSub?.remove();
  }
}

/** Stops active native proximity session (BLE), if any. */
export function stopIso18013ProximityPresentment(): void {
  const nm = getNativeModule();
  nm?.stopPresentment?.();
}

/** Approve sharing after [MDOC_PRESENTMENT_CONSENT_REQUIRED]. */
export async function approveIso18013PresentmentConsent(): Promise<void> {
  const nm = getNativeModule();
  if (!nm?.approvePresentment) {
    throw new Iso18013PresentmentNotImplementedError(
      'approvePresentment is not available on this build',
    );
  }
  await nm.approvePresentment();
}

/** Deny sharing after [MDOC_PRESENTMENT_CONSENT_REQUIRED] — no DeviceResponse is sent. */
export async function denyIso18013PresentmentConsent(): Promise<void> {
  const nm = getNativeModule();
  if (!nm?.denyPresentment) {
    throw new Iso18013PresentmentNotImplementedError(
      'denyPresentment is not available on this build',
    );
  }
  await nm.denyPresentment();
}

/**
 * Standard `mdoc:` QR is **not** DEFLATE-compressed in ISO/IEC 18013-5:2021 §8.1.2.3 / common
 * interop (Multipaz, Tap2iD): **base64url** of raw **DeviceEngagement** CBOR. Do not add
 * compression unless a deployment profile explicitly requires it.
 */
export function mdocUriUsesRawCborBase64url(uri: string): boolean {
  return uri.startsWith('mdoc:') || uri.startsWith('mDL:');
}
