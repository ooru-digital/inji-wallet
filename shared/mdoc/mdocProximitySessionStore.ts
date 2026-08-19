/**
 * Persist ISO 18013-5 proximity DeviceEngagement + ephemeral key so QR bytes stay stable
 * across remounts/navigation until a future BLE layer consumes or clears them.
 */
import {NativeModules} from 'react-native';
import {Buffer} from 'buffer';
import {encode as base64urlEncode} from 'base64url-universal';
import {sha256} from '@noble/hashes/sha256';
import {MDOC_QR_URI_SCHEME} from './deviceEngagement';
import type {MdocDeviceEngagementSession} from './deviceEngagement';
import {validateDeviceEngagementInteroperability} from './deviceEngagement';
import {
  parseBlePeripheralUuidFromDeviceEngagement,
  parseCoseEc2P256FromDeviceEngagement,
} from './cborDecodeMinimal';

const {RNSecureKeystoreModule} = NativeModules;

export const MDOC_PROXIMITY_KEY_SUFFIX = ':iso18013_de';

export function mdocProximitySessionStorageKey(vcId: string): string {
  return `${vcId}${MDOC_PROXIMITY_KEY_SUFFIX}`;
}

export interface PersistedMdocProximityPayload {
  /** Exact string shown in the QR (scheme + base64url CBOR). */
  mdocUri: string;
  ephemeralPrivateKeyBase64: string;
  deviceEngagementCborBase64: string;
  createdAtIso?: string;
}

function u8ToHex(u: Uint8Array): string {
  return Array.from(u, b => b.toString(16).padStart(2, '0')).join('');
}

/** SHA-256 of raw DeviceEngagement CBOR (commitment for logs; not ISO SessionTranscript). */
export function deviceEngagementCborCommitmentHex(cbor: Uint8Array): string {
  return u8ToHex(sha256(cbor));
}

export async function persistMdocProximitySession(
  vcId: string,
  session: MdocDeviceEngagementSession,
): Promise<void> {
  const payload: PersistedMdocProximityPayload = {
    mdocUri: session.mdocUri,
    ephemeralPrivateKeyBase64: Buffer.from(
      session.ephemeralPrivateKey,
    ).toString('base64'),
    deviceEngagementCborBase64: Buffer.from(
      session.deviceEngagementCbor,
    ).toString('base64'),
    createdAtIso: new Date().toISOString(),
  };
  await RNSecureKeystoreModule.storeData(
    mdocProximitySessionStorageKey(vcId),
    JSON.stringify(payload),
  );
}

export async function loadPersistedMdocProximity(
  vcId: string,
): Promise<{mdocUri: string; deviceEngagementCbor: Uint8Array} | null> {
  try {
    const keyData = await RNSecureKeystoreModule.getData(
      mdocProximitySessionStorageKey(vcId),
    );
    if (!keyData || !keyData[1]) {
      return null;
    }
    const parsed = JSON.parse(
      keyData[1],
    ) as Partial<PersistedMdocProximityPayload>;
    if (
      typeof parsed.deviceEngagementCborBase64 !== 'string' ||
      typeof parsed.ephemeralPrivateKeyBase64 !== 'string'
    ) {
      return null;
    }
    const cbor = new Uint8Array(
      Buffer.from(parsed.deviceEngagementCborBase64, 'base64'),
    );
    const v = validateDeviceEngagementInteroperability(cbor);
    if (!v.ok) {
      if (__DEV__) {
        console.warn(
          '[mDoc proximity] Discarding invalid persisted DeviceEngagement:',
          v.error,
        );
      }
      return null;
    }
    const mdocUri =
      typeof parsed.mdocUri === 'string' && parsed.mdocUri.length > 0
        ? parsed.mdocUri
        : `${MDOC_QR_URI_SCHEME}${base64urlEncode(Buffer.from(cbor))}`;
    return {mdocUri, deviceEngagementCbor: cbor};
  } catch {
    return null;
  }
}

/** Full persisted proximity material for native ISO 18013-5 BLE presentment. */
export async function loadPersistedMdocProximityFull(vcId: string): Promise<{
  mdocUri: string;
  deviceEngagementCbor: Uint8Array;
  ephemeralPrivateKey: Uint8Array;
} | null> {
  try {
    const keyData = await RNSecureKeystoreModule.getData(
      mdocProximitySessionStorageKey(vcId),
    );
    if (!keyData || !keyData[1]) {
      return null;
    }
    const parsed = JSON.parse(
      keyData[1],
    ) as Partial<PersistedMdocProximityPayload>;
    if (
      typeof parsed.deviceEngagementCborBase64 !== 'string' ||
      typeof parsed.ephemeralPrivateKeyBase64 !== 'string'
    ) {
      return null;
    }
    const cbor = new Uint8Array(
      Buffer.from(parsed.deviceEngagementCborBase64, 'base64'),
    );
    const v = validateDeviceEngagementInteroperability(cbor);
    if (!v.ok) {
      return null;
    }
    const mdocUri =
      typeof parsed.mdocUri === 'string' && parsed.mdocUri.length > 0
        ? parsed.mdocUri
        : `${MDOC_QR_URI_SCHEME}${base64urlEncode(Buffer.from(cbor))}`;
    const ephemeralPrivateKey = new Uint8Array(
      Buffer.from(parsed.ephemeralPrivateKeyBase64, 'base64'),
    );
    return {mdocUri, deviceEngagementCbor: cbor, ephemeralPrivateKey};
  } catch {
    return null;
  }
}

/**
 * Dev diagnostics: QR engagement vs optional native-reported BLE UUID.
 * SessionTranscript is not available until after BLE + reader ephemeral key — not logged here.
 */
export function logMdocProximitySessionDiagnostics(
  tag: 'new' | 'reused',
  deviceEngagementCbor: Uint8Array,
  options?: {advertisedBleServiceUuidHex?: string | null},
): void {
  if (!__DEV__ || process.env.NODE_ENV === 'test') {
    return;
  }
  try {
    const ble =
      parseBlePeripheralUuidFromDeviceEngagement(deviceEngagementCbor);
    const cose = parseCoseEc2P256FromDeviceEngagement(deviceEngagementCbor);
    const deHex = u8ToHex(ble);
    const adv = options?.advertisedBleServiceUuidHex?.replace(/-/g, '') ?? null;
    console.log(
      `[mDoc proximity ${tag}] DeviceEngagement CBOR SHA-256:`,
      deviceEngagementCborCommitmentHex(deviceEngagementCbor),
    );
    console.log(
      `[mDoc proximity ${tag}] QR BLE peripheral UUID (Engagement key 10, hex):`,
      deHex,
    );
    console.log(
      `[mDoc proximity ${tag}] QR COSE EC2 X (hex):`,
      u8ToHex(cose.x),
    );
    console.log(
      `[mDoc proximity ${tag}] QR COSE EC2 Y (hex):`,
      u8ToHex(cose.y),
    );
    if (adv && adv.length > 0) {
      console.log(
        `[mDoc proximity ${tag}] Native-reported GATT UUID (from optional prop):`,
        adv,
      );
      console.log(
        `[mDoc proximity ${tag}] QR engagement UUID vs native prop match:`,
        deHex.toLowerCase() === adv.toLowerCase(),
      );
    } else {
      console.log(
        `[mDoc proximity ${tag}] Optional \`advertisedBleServiceUuidHex\` prop not set (JS cannot read GATT). The peripheral UUID in the QR (key 10) above is what **Android MdocIso18013Presentment** must advertise. Verify with: adb logcat -s InjiIso18013Proximity MdocIso18013Presentment`,
      );
    }
    console.log(
      `[mDoc proximity ${tag}] If Tap2iD shows 115 after scan: (1) confirm logcat shows advertisement/connection, (2) issuer DS chain trust, (3) device key in MSO matches wallet ES256 hardware key.`,
    );
    console.log(
      `[mDoc proximity ${tag}] Ephemeral private key for ECDH is in secure storage under key *:iso18013_de (must match this engagement until session end).`,
    );
  } catch (e) {
    console.warn(`[mDoc proximity ${tag}] diagnostics failed`, e);
  }
}
