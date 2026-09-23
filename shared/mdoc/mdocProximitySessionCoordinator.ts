import {Platform} from 'react-native';
import {
  countBleTransferMethodRowsInDeviceEngagement,
  deviceEngagementAdvertisesBlePsm,
} from './cborDecodeMinimal';
import type {MdocDeviceEngagementSession} from './deviceEngagement';
import {
  loadPersistedMdocProximity,
  persistMdocProximitySession,
} from './mdocProximitySessionStore';

type CoordinatorResult = {
  mdocUri: string;
  deviceEngagementCbor: Uint8Array;
  reused: boolean;
};

const inflight = new Map<string, Promise<CoordinatorResult | null>>();

/**
 * Single-flight per VC: reuse persisted DeviceEngagement if present; otherwise create once
 * (avoids duplicate sessions under React 18 StrictMode double effect or overlapping mounts).
 *
 * Android expects Multipaz dual-row BLE (2 rows). iOS expects tap2id single-row (1 row).
 * Cached engagements with the wrong row count are regenerated.
 */
export function loadOrCreateMdocProximityQrPayload(
  vcId: string,
  factory: () => MdocDeviceEngagementSession | null,
): Promise<CoordinatorResult | null> {
  let p = inflight.get(vcId);
  if (p) {
    return p;
  }
  p = (async (): Promise<CoordinatorResult | null> => {
    const existing = await loadPersistedMdocProximity(vcId);
    if (existing) {
      const bleRows = countBleTransferMethodRowsInDeviceEngagement(
        existing.deviceEngagementCbor,
      );
      const expectedRows = Platform.OS === 'android' ? 2 : 1;
      // iOS serves GATT only, so a cached engagement advertising an L2CAP PSM (BLE key 21) is
      // stale regardless of row count — readers act on that PSM and can stall on it.
      const stalePsm =
        Platform.OS !== 'android' &&
        deviceEngagementAdvertisesBlePsm(existing.deviceEngagementCbor);
      if (bleRows === expectedRows && !stalePsm) {
        return {
          mdocUri: existing.mdocUri,
          deviceEngagementCbor: existing.deviceEngagementCbor,
          reused: true,
        };
      }
      if (__DEV__) {
        console.warn(
          stalePsm
            ? '[mDoc proximity] Regenerating cached engagement: it advertises a BLE L2CAP PSM ' +
                '(map key 21), which this platform does not serve — readers can stall trying to ' +
                'open L2CAP instead of falling back to GATT.'
            : `[mDoc proximity] Regenerating cached engagement: found ${bleRows} BLE row(s); ` +
                `expected ${expectedRows} for ${Platform.OS} ` +
                `(${
                  Platform.OS === 'android'
                    ? 'multipaz dual-row'
                    : 'tap2id single-row'
                }).`,
        );
      }
    }
    const session = factory();
    if (!session) {
      return null;
    }
    await persistMdocProximitySession(vcId, session);
    return {
      mdocUri: session.mdocUri,
      deviceEngagementCbor: session.deviceEngagementCbor,
      reused: false,
    };
  })();
  inflight.set(vcId, p);
  void p.finally(() => {
    inflight.delete(vcId);
  });
  return p;
}
