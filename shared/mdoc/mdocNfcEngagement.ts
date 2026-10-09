import {useEffect, useState} from 'react';
import {
  AppState,
  DeviceEventEmitter,
  NativeModules,
  Platform,
} from 'react-native';

/**
 * A reader that tapped the phone (NFC engagement) and is waiting for the holder to pick a card.
 *
 * Android only. The native NFC service does the handshake while the phones touch; from then on the
 * reader waits over BLE, and this module is how the UI learns there is a tap to answer. See
 * `NfcShareModal`, where the holder picks the card and the session starts with this tap's id
 * in place of the card's own QR engagement.
 */

const EVENT_NFC_ENGAGED = 'MdocNfcEngaged';

/**
 * Readers typically stop waiting for BLE after 30 s; native forgets the tap after 25 s. Matching
 * that here keeps the chooser from outliving a tap that can no longer be answered.
 */
const PENDING_FOR_MS = 25_000;

type NfcNative = {
  getPendingNfcEngagement?: () => Promise<string | null>;
  discardNfcEngagement?: (id: string) => void;
};

function native(): NfcNative | undefined {
  return (NativeModules as {MdocIso18013Presentment?: NfcNative})
    .MdocIso18013Presentment;
}

let pendingId: string | null = null;
let expiry: ReturnType<typeof setTimeout> | null = null;
const listeners = new Set<(id: string | null) => void>();

function setPending(id: string | null) {
  if (expiry) {
    clearTimeout(expiry);
    expiry = null;
  }
  pendingId = id;
  if (id) {
    expiry = setTimeout(() => setPending(null), PENDING_FOR_MS);
  }
  listeners.forEach(l => l(id));
}

/** The tap waiting to be answered, if any. */
export function pendingNfcEngagementId(): string | null {
  return pendingId;
}

/** Claims the pending tap for one session; a second card opened after it gets none. */
export function takeNfcEngagement(): string | null {
  const id = pendingId;
  if (id) {
    setPending(null);
  }
  return id;
}

/** The holder backed out without picking: let the reader time out. */
export function dismissNfcEngagement(): void {
  const id = pendingId;
  if (id) {
    native()?.discardNfcEngagement?.(id);
    setPending(null);
  }
}

let started = false;

/**
 * Starts listening for taps. Safe to call more than once. Also asks native on start and whenever
 * the app comes forward, because a tap is what brings the app forward - and may have launched it
 * before anything here was listening.
 */
export function startListeningForNfcEngagement(): void {
  if (started || Platform.OS !== 'android' || !native()) {
    return;
  }
  started = true;
  DeviceEventEmitter.addListener(EVENT_NFC_ENGAGED, (e: {id?: string}) => {
    if (e?.id) {
      setPending(e.id);
    }
  });
  const askNative = () => {
    native()
      ?.getPendingNfcEngagement?.()
      .then(id => {
        if (id && id !== pendingId) {
          setPending(id);
        }
      })
      .catch(() => {});
  };
  askNative();
  AppState.addEventListener('change', state => {
    if (state === 'active') {
      askNative();
    }
  });
}

/** The pending tap id, kept current. */
export function useNfcEngagement(): string | null {
  const [id, setId] = useState(pendingId);
  useEffect(() => {
    startListeningForNfcEngagement();
    listeners.add(setId);
    setId(pendingId);
    return () => {
      listeners.delete(setId);
    };
  }, []);
  return id;
}
