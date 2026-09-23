import {Platform} from 'react-native';
import {VerifiableCredential} from '../../machines/VerifiableCredential/VCMetaMachine/vc';
import {VCMetadata} from '../VCMetadata';
import {VCFormat} from '../VCFormat';
import {
  createMdocDeviceEngagementSession,
  inferDefaultDocTypes,
  MdocDeviceEngagementOptions,
  MdocDeviceEngagementSession,
} from './deviceEngagement';

/**
 * Builds a compact ISO 18013-5 DeviceEngagement QR for an `mso_mdoc` VC (same role as Multipaz proximity QR).
 * **Android:** defaults to **`multipaz`** (two BLE rows: peripheral `21:128` + central `11:uuid`) for
 * Multipaz Verifier / dual-role readers.
 * **iOS:** defaults to **`tap2id`** (single peripheral row `21:130`).
 * Override with `proximityPresentationProfile` / `ble.dualBleTransferRows` when needed.
 */
export function buildMdocDeviceEngagementQrForVc(
  verifiableCredential: VerifiableCredential,
  format: string,
  _meta: VCMetadata,
  extra?: Partial<MdocDeviceEngagementOptions>,
): MdocDeviceEngagementSession | null {
  if (format !== VCFormat.mso_mdoc) {
    return null;
  }
  const processed = verifiableCredential.processedCredential as
    | {docType?: string}
    | undefined;
  const docTypes =
    extra?.docTypes ??
    (processed?.docType ? [processed.docType] : undefined) ??
    inferDefaultDocTypes(verifiableCredential.credentialConfigurationId);
  return createMdocDeviceEngagementSession({
    ...extra,
    docTypes,
    proximityPresentationProfile:
      extra?.proximityPresentationProfile ??
      (Platform.OS === 'android' ? 'multipaz' : 'tap2id'),
    ble: {
      ...extra?.ble,
      // iOS serves GATT only (`MdocBleTransport`), so it must not advertise an L2CAP PSM.
      // Readers map BLE option key 21 to `peripheralServerModePsm`: one was observed looping on
      // `L2capcoc client connection … port 130 … result 12` — port 130 being exactly the value
      // the tap2id profile puts at key 21 — and never falling back to GATT. Android keeps its
      // hint because its Multipaz presenter negotiates L2CAP itself.
      interopPairingHint21:
        extra?.ble?.interopPairingHint21 ??
        (Platform.OS === 'android' ? undefined : null),
    },
  });
}
