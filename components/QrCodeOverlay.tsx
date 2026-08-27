import React, {useEffect, useRef, useState} from 'react';
import {Alert, Pressable, View} from 'react-native';
import {Icon, Overlay} from 'react-native-elements';
import {Centered, Column, Row, Text, Button} from './ui';
import QRCode from 'react-native-qrcode-svg';
import {Theme} from './ui/styleUtils';
import {useTranslation} from 'react-i18next';
import testIDProps from '../shared/commonUtil';
import {SvgImage} from './ui/svg';
import {NativeModules, Platform} from 'react-native';
import {VerifiableCredential} from '../machines/VerifiableCredential/VCMetaMachine/vc';
import {DEFAULT_ECL, MAX_QR_DATA_LENGTH} from '../shared/constants';
import {buildMdocDeviceEngagementQrForVc} from '../shared/mdoc/buildMdocQrData';
import {loadOrCreateMdocProximityQrPayload} from '../shared/mdoc/mdocProximitySessionCoordinator';
import {logMdocProximitySessionDiagnostics} from '../shared/mdoc/mdocProximitySessionStore';
import {VCMetadata} from '../shared/VCMetadata';
import {VCFormat} from '../shared/VCFormat';
import {
  buildIso18013PresentmentParamsForVc,
  nativeMdocProximityPresentmentAvailable,
} from '../shared/mdoc/mdocProximityPresentmentBridge';
import {
  approveIso18013PresentmentConsent,
  denyIso18013PresentmentConsent,
  MdocPresentmentConsentRequest,
  startIso18013ProximityPresentment,
  stopIso18013ProximityPresentment,
  subscribeMdocPresentmentCannotSatisfy,
  subscribeMdocPresentmentConsentDismissed,
  subscribeMdocPresentmentConsentRequired,
} from '../shared/mdoc/iso18013PresentmentInterop';
import {shareImageToAllSupportedApps} from '../shared/sharing/imageUtils';
import {ShareOptions} from 'react-native-share';
import {MdocProximityConsentOverlay} from './MdocProximityConsentOverlay';

type PurposesResponse = Array<{id: string; name: string; accepted: boolean}>;

/**
 * DIAGNOSTIC TOGGLE — remove once the verifier freeze is understood.
 *
 * `false` sends a spec-standard ISO 18013-5 DeviceResponse. `true` (the current product
 * behaviour) makes native add a non-standard top-level `purposes` key to the DeviceResponse
 * CBOR map, see InjiIso18013ProximityPresenter.kt injection block.
 *
 * Flip to false to test whether a strict reader is choking on that extra key.
 */
const SEND_PURPOSES_IN_DEVICE_RESPONSE = true;

type QrSvgRef = {toDataURL: (callback: (dataURL: string) => void) => void};

/**
 * Module-level (not per-instance): StrictMode remount creates a *new* component instance whose
 * useRef would reset to 0 and still allow the previous instance's deferred stop to kill BLE.
 */
let isoPresentmentGeneration = 0;

export const QrCodeOverlay: React.FC<QrCodeOverlayProps> = props => {
  const {RNPixelpassModule} = NativeModules;
  const {t} = useTranslation('VcDetails');
  const [qrString, setQrString] = useState('');
  const [qrError, setQrError] = useState(false);
  const [consentRequest, setConsentRequest] =
    useState<MdocPresentmentConsentRequest | null>(null);
  const [consentBusy, setConsentBusy] = useState(false);
  const base64ImageType = 'data:image/png;base64,';
  const {RNSecureKeystoreModule} = NativeModules;

  /** Latest VC for native proximity — ref avoids BLE cancel/restart when parent re-renders new object identity. */
  const verifiableCredentialRef = useRef(props.verifiableCredential);
  verifiableCredentialRef.current = props.verifiableCredential;

  async function getQRData(): Promise<string> {
    const format = props.meta?.format ?? '';
    if (format === VCFormat.mso_mdoc) {
      try {
        const payload = await loadOrCreateMdocProximityQrPayload(
          props.meta.id,
          () =>
            buildMdocDeviceEngagementQrForVc(
              props.verifiableCredential,
              format,
              props.meta,
            ),
        );
        if (!payload) {
          throw new Error('mDoc DeviceEngagement unavailable');
        }
        logMdocProximitySessionDiagnostics(
          payload.reused ? 'reused' : 'new',
          payload.deviceEngagementCbor,
          {
            advertisedBleServiceUuidHex: props.advertisedBleServiceUuidHex,
          },
        );
        return payload.mdocUri;
      } catch (e) {
        if (__DEV__) {
          console.warn('[QrCodeOverlay] mDoc proximity session / keystore', e);
        }
        throw e;
      }
    }

    let qrData: string;
    try {
      const keyData = await RNSecureKeystoreModule.getData(props.meta.id);
      if (keyData[1] && keyData.length > 0) {
        qrData = keyData[1];
      } else {
        throw new Error('No key data found');
      }
    } catch {
      const {isClaim169QrPresent, claim169QrData} = getClaim169Qr();
      if (isClaim169QrPresent) {
        qrData = claim169QrData;
      } else {
        const {credential} = props.verifiableCredential;
        qrData = await RNPixelpassModule.generateQRData(
          JSON.stringify(credential),
          '',
        );
      }
      await RNSecureKeystoreModule.storeData(props.meta.id, qrData);
    }
    return qrData;
  }

  function getClaim169Qr(): {
    isClaim169QrPresent: boolean;
    claim169QrData: string;
  } {
    const credentialSubject =
      props.verifiableCredential?.credential?.credentialSubject;
    const claim169Qrs = (credentialSubject as any)?.claim169;
    const qr =
      claim169Qrs && typeof claim169Qrs === 'object'
        ? claim169Qrs[Object.keys(claim169Qrs)[0]]
        : undefined;

    if (typeof qr === 'string' && qr.trim().length > 0) {
      return {isClaim169QrPresent: true, claim169QrData: qr};
    }
    return {isClaim169QrPresent: false, claim169QrData: ''};
  }

  const qrRef = useRef<QrSvgRef | null>(null);

  function handleShareQRCodePress() {
    qrRef.current?.toDataURL(dataURL => {
      shareImage(`${base64ImageType}${dataURL}`);
    });
  }

  async function shareImage(base64String: string) {
    const options: ShareOptions = {
      url: base64String,
    };
    const shareStatus = await shareImageToAllSupportedApps(options);
    if (!shareStatus) {
      console.error('Error while sharing QR code::');
    }
  }

  function onQRError() {
    console.warn('Data is too big');
    // QR library may call onError during QRCode render; defer so we do not setState on QrCodeOverlay in that phase.
    queueMicrotask(() => setQrError(true));
  }

  const [isQrOverlayVisible, setIsQrOverlayVisible] = useState(false);
  const overlayVisible = props.forceVisible ?? isQrOverlayVisible;

  useEffect(() => {
    if (
      Platform.OS !== 'android' ||
      props.meta?.format !== VCFormat.mso_mdoc ||
      !nativeMdocProximityPresentmentAvailable()
    ) {
      return;
    }
    const requiredSub = subscribeMdocPresentmentConsentRequired(request => {
      if (__DEV__) {
        console.log(
          '[QrCodeOverlay] mDOC consent required:',
          request.docType,
          request.purpose,
          request.verifierName,
          request.elements.length,
        );
      }
      setConsentRequest(request);
      setConsentBusy(false);
    });
    const dismissedSub = subscribeMdocPresentmentConsentDismissed(() => {
      setConsentRequest(null);
      setConsentBusy(false);
    });
    const cannotSatisfySub = subscribeMdocPresentmentCannotSatisfy(event => {
      setConsentRequest(null);
      setConsentBusy(false);
      const requested =
        event.requestedDocTypes.filter(Boolean).join(', ') || 'unknown';
      const wallet = event.walletDocType || 'unknown';
      Alert.alert(
        t('mdocCannotSatisfy.title'),
        event.reason === 'credential_not_present'
          ? t('mdocCannotSatisfy.message', {requested, wallet})
          : t('mdocCannotSatisfy.messageGeneric'),
        [{text: t('mdocCannotSatisfy.ok')}],
      );
    });
    return () => {
      requiredSub.remove();
      dismissedSub.remove();
      cannotSatisfySub.remove();
    };
  }, [props.meta?.format, t]);

  useEffect(() => {
    let cancelled = false;
    const generation = ++isoPresentmentGeneration;
    (async () => {
      try {
        const qrData = await getQRData();
        if (cancelled) {
          return;
        }
        /**
         * Multipaz `MdocProximityQrPresentment` calls `advertise()` before the QR is shown, then
         * `waitForConnection`. Starting native presentment only after a debounced second effect
         * meant verifiers could scan the `mdoc:` URI while GATT was not yet advertising (Tap2iD 115).
         * Fire native `startPresentment` (non-blocking) before `setQrString` so BLE is up when the QR paints.
         */
        if (
          Platform.OS === 'android' &&
          nativeMdocProximityPresentmentAvailable() &&
          props.meta?.format === VCFormat.mso_mdoc &&
          typeof qrData === 'string' &&
          qrData.startsWith('mdoc:')
        ) {
          try {
            const vc = verifiableCredentialRef.current;
            if (!vc) {
              if (__DEV__) {
                console.warn(
                  '[QrCodeOverlay] Skipping ISO presentment — verifiableCredential not ready',
                );
              }
            } else {
              const p = await buildIso18013PresentmentParamsForVc(
                props.meta.id,
                {
                  ...vc,
                  credential:
                    typeof vc.credential === 'string' ? vc.credential : '',
                  processedCredential: vc.processedCredential,
                },
              );
              if (!cancelled && p && isoPresentmentGeneration === generation) {
                if (__DEV__) {
                  console.log(
                    '[QrCodeOverlay] Starting native ISO 18013-5 presentment before QR paint (Multipaz order)…',
                  );
                }
                void startIso18013ProximityPresentment(p).catch(e => {
                  if (__DEV__) {
                    const detail =
                      e && typeof e === 'object' && 'message' in e
                        ? String((e as Error).message)
                        : String(e);
                    console.warn(
                      '[QrCodeOverlay] ISO 18013-5 proximity session error:',
                      detail,
                      e,
                    );
                  }
                });
              } else if (__DEV__ && !p) {
                console.warn(
                  '[QrCodeOverlay] ISO 18013-5 presentment not started — see earlier [mdoc presentment] warnings (credential / persisted engagement).',
                );
              }
            }
          } catch (e) {
            if (__DEV__) {
              console.warn(
                '[QrCodeOverlay] ISO 18013-5 presentment bootstrap failed:',
                e,
              );
            }
          }
        } else if (
          __DEV__ &&
          props.meta?.format === VCFormat.mso_mdoc &&
          Platform.OS === 'android' &&
          !nativeMdocProximityPresentmentAvailable()
        ) {
          console.warn(
            '[QrCodeOverlay] MdocIso18013Presentment native module unavailable — rebuild Android with Multipaz + InjiPackage registration.',
          );
        }
        if (qrData?.length < MAX_QR_DATA_LENGTH) {
          setQrString(qrData);
        } else {
          setQrError(true);
        }
      } catch {
        if (!cancelled) {
          setQrError(true);
        }
      }
    })();
    return () => {
      cancelled = true;
      setConsentRequest(null);
      // Defer stop so StrictMode remount (sync unmount→mount) can claim a newer generation
      // and keep advertising. Real leave/unmount keeps the same generation → stop runs.
      const genAtCleanup = generation;
      setTimeout(() => {
        if (isoPresentmentGeneration === genAtCleanup) {
          if (__DEV__) {
            console.log(
              '[QrCodeOverlay] Stopping ISO presentment (effect cleanup, generation still current)',
            );
          }
          stopIso18013ProximityPresentment();
        }
      }, 400);
    };
  }, [props.meta.id, props.meta.format, props.advertisedBleServiceUuidHex]);

  const toggleQrOverlay = () => {
    if (props.onClose) props.onClose();
    else setIsQrOverlayVisible(!overlayVisible);
  };

  async function handleConsentAllow(purposesResponse: PurposesResponse) {
    if (consentBusy) {
      return;
    }
    setConsentBusy(true);
    try {
      const purposesJson = JSON.stringify(purposesResponse);
      console.log(
        '[DEBUG] Outgoing purposes response to verifier:\n' +
          JSON.stringify(purposesResponse, null, 2),
      );
      if (SEND_PURPOSES_IN_DEVICE_RESPONSE) {
        await approveIso18013PresentmentConsent(purposesJson);
      } else {
        console.log(
          '[DEBUG] SEND_PURPOSES_IN_DEVICE_RESPONSE=false — sending standard DeviceResponse',
        );
        await approveIso18013PresentmentConsent();
      }
      setConsentRequest(null);
    } catch (e) {
      setConsentBusy(false);
      if (__DEV__) {
        console.warn('[QrCodeOverlay] approve mDOC consent failed:', e);
      }
    }
  }

  async function handleConsentDeny() {
    if (consentBusy) {
      return;
    }
    setConsentBusy(true);
    try {
      await denyIso18013PresentmentConsent();
      setConsentRequest(null);
    } catch (e) {
      setConsentBusy(false);
      if (__DEV__) {
        console.warn('[QrCodeOverlay] deny mDOC consent failed:', e);
      }
    }
  }

  return (
    <>
      {qrString != '' && !qrError && (
        <React.Fragment>
          <View testID="qrCodeView" style={Theme.QrCodeStyles.QrView}>
            {props.showInlineQr !== false && (
              <Pressable
                {...testIDProps('qrCodePressable')}
                accessible={false}
                onPress={toggleQrOverlay}>
                <QRCode
                  {...testIDProps('qrCode')}
                  size={72}
                  value={qrString}
                  backgroundColor={Theme.Colors.QRCodeBackgroundColor}
                  ecl={DEFAULT_ECL}
                  onError={onQRError}
                />
                <View
                  testID="magnifierZoom"
                  style={[Theme.QrCodeStyles.magnifierZoom]}>
                  {SvgImage.MagnifierZoom()}
                </View>
              </Pressable>
            )}
          </View>

          <Overlay
            isVisible={overlayVisible}
            onBackdropPress={toggleQrOverlay}
            overlayStyle={{padding: 1, borderRadius: 21}}>
            <Column style={Theme.QrCodeStyles.expandedQrCode}>
              <Row pY={20} style={Theme.QrCodeStyles.QrCodeHeader}>
                <Text
                  testID="qrCodeHeader"
                  align="center"
                  style={Theme.TextStyles.header}
                  weight="bold">
                  {t('qrCodeHeader')}
                </Text>
                <Icon
                  {...testIDProps('qrCodeCloseIcon')}
                  name="close"
                  onPress={toggleQrOverlay}
                  color={Theme.Colors.Details}
                  size={32}
                />
              </Row>
              <Centered testID="qrCodeDetails" pY={30}>
                <QRCode
                  {...testIDProps('qrCodeExpandedView')}
                  size={300}
                  value={qrString}
                  backgroundColor={Theme.Colors.QRCodeBackgroundColor}
                  ecl={DEFAULT_ECL}
                  quietZone={10}
                  onError={onQRError}
                  getRef={data => (qrRef.current = data)}
                />
                <Button
                  testID="share"
                  styles={Theme.QrCodeStyles.shareQrCodeButton}
                  title={t('shareQRCode')}
                  type="gradient"
                  icon={
                    <Icon
                      name="share-variant-outline"
                      type="material-community"
                      size={24}
                      color="white"
                    />
                  }
                  onPress={handleShareQRCodePress}
                />
              </Centered>
            </Column>
          </Overlay>
        </React.Fragment>
      )}
      <MdocProximityConsentOverlay
        isVisible={consentRequest != null}
        docType={consentRequest?.docType}
        credentialLabel={consentRequest?.credentialLabel}
        verifierName={consentRequest?.verifierName}
        purpose={consentRequest?.purpose}
        elements={consentRequest?.elements ?? []}
        requestInfo={consentRequest?.requestInfo}
        onAllow={handleConsentAllow}
        onDeny={handleConsentDeny}
      />
    </>
  );
};

interface QrCodeOverlayProps {
  verifiableCredential: VerifiableCredential;
  meta: VCMetadata;
  /** When native BLE proximity is implemented, pass the GATT service UUID (hex, with or without dashes) to verify it matches Engagement key 10. */
  advertisedBleServiceUuidHex?: string | null;
  showInlineQr?: boolean;
  forceVisible?: boolean;
  onClose?: () => void;
}
