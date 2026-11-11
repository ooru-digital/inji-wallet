/**
 * Public surface of the common (TypeScript) ISO 18013-5 presentment engine.
 *
 * `../iso18013PresentmentInterop` routes here when {@link isMdocPresentmentEngineAvailable} is
 * true and to the Android native Multipaz module otherwise, so callers — `QrCodeOverlay`, the
 * consent overlay — never branch on platform themselves.
 *
 * Events are delivered through a local emitter with the same names and payload shapes the native
 * module uses. That is what lets the existing `subscribeMdocPresentment*` helpers work unchanged
 * against either engine.
 */

import {Buffer} from 'buffer';
import {NativeModules} from 'react-native';

import {derSignatureToCoseRaw, type Es256Signer} from './cose';
import {isMdocBleTransportAvailable} from './bleTransport';
import {
  MdocPresentmentSession,
  type PresentmentEventListener,
  type PresentmentEventName,
} from './presentmentSession';
import type {
  Iso18013PresentmentParams,
  MdocDisclosedElement,
  PresentmentPhase,
} from '../iso18013PresentmentInterop';

export {isMdocBleTransportAvailable} from './bleTransport';

/** True when this build can run a presentment session entirely from TypeScript. */
export function isMdocPresentmentEngineAvailable(): boolean {
  return isMdocBleTransportAvailable();
}

// --- local event bus -------------------------------------------------------
// Mirrors NativeEventEmitter's contract (addListener → {remove}) so the interop layer can treat
// both engines identically.

const listeners = new Map<string, Set<PresentmentEventListener>>();

export function addPresentmentListener(
  event: PresentmentEventName,
  listener: PresentmentEventListener,
): {remove: () => void} {
  let set = listeners.get(event);
  if (!set) {
    set = new Set();
    listeners.set(event, set);
  }
  set.add(listener);
  return {
    remove: () => {
      set?.delete(listener);
    },
  };
}

function emit(event: PresentmentEventName, payload: unknown): void {
  const set = listeners.get(event);
  if (!set) {
    return;
  }
  // Copy first: a listener that unsubscribes itself must not perturb this iteration.
  for (const listener of [...set]) {
    try {
      listener(payload);
    } catch (e) {
      console.warn(`[mdoc presentment] listener for ${event} threw`, e);
    }
  }
}

// --- session lifetime ------------------------------------------------------

let activeSession: MdocPresentmentSession | null = null;

/**
 * Builds the DeviceAuth signer: the ES256 holder key, which never leaves the Secure Enclave, signs
 * the binary COSE input across the bridge (`signBytes`). This engine runs on iOS only; Android
 * presents through its native Multipaz module.
 */
function signerFor(): Es256Signer {
  const keystore = (
    NativeModules as {
      RNSecureKeystoreModule?: {
        signBytes?: (alias: string, dataBase64: string) => Promise<string>;
      };
    }
  ).RNSecureKeystoreModule;
  const signBytes = keystore?.signBytes;
  if (!signBytes) {
    throw new Error(
      'No device key signer for DeviceAuth: RNSecureKeystoreModule.signBytes is missing.',
    );
  }
  return async (toBeSigned: Uint8Array) => {
    const derBase64 = await signBytes(
      'ES256',
      Buffer.from(toBeSigned).toString('base64'),
    );
    return derSignatureToCoseRaw(
      new Uint8Array(Buffer.from(derBase64.replace(/\s/g, ''), 'base64')),
    );
  };
}

/**
 * Starts a proximity session and resolves when it finishes.
 *
 * Any session already running is cancelled first: the QR overlay can remount (navigation,
 * StrictMode, rotation) and two peripherals advertising the same service UUID would make the
 * reader connect to whichever answered first, with keys derived from the other engagement.
 */
export async function startMdocPresentmentSession(
  params: Iso18013PresentmentParams,
  onPhase?: (phase: PresentmentPhase, detail?: string) => void,
): Promise<void> {
  await stopMdocPresentmentSession();

  const session = new MdocPresentmentSession({
    credentialCompact: params.msoMdocCredentialCompact,
    docType: params.docType,
    deviceEngagementCbor: params.deviceEngagementCbor,
    ephemeralPrivateKey: params.ephemeralPresentationPrivateKey,
    signer: signerFor(),
    emit,
    onPhase,
  });
  activeSession = session;

  try {
    await session.run();
  } finally {
    if (activeSession === session) {
      activeSession = null;
    }
  }
}

export async function stopMdocPresentmentSession(): Promise<void> {
  const session = activeSession;
  activeSession = null;
  session?.cancel();
}

export function approveMdocPresentmentConsent(
  disclosedElements?: MdocDisclosedElement[],
): void {
  activeSession?.approveConsent(disclosedElements);
}

export function denyMdocPresentmentConsent(): void {
  activeSession?.denyConsent();
}
