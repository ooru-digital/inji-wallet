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
  });
}
