import React, {useContext, useEffect, useMemo, useState} from 'react';
import {Modal} from 'react-native';
import {useSelector} from '@xstate/react';
import {useTranslation} from 'react-i18next';
import LinearGradient from 'react-native-linear-gradient';
import {Button, Centered, Column, Row, Text} from '../../components/ui';
import {Theme} from '../../components/ui/styleUtils';
import {VcItemContainer} from '../../components/VC/VcItemContainer';
import {QrCodeOverlay} from '../../components/QrCodeOverlay';
import {GlobalContext} from '../../shared/GlobalContext';
import {selectMyVcs} from '../../machines/QrLogin/QrLoginSelectors';
import {VCFormat} from '../../shared/VCFormat';
import {VCItemContainerFlowType} from '../../shared/Utils';
import {VCMetadata} from '../../shared/VCMetadata';
import {VerifiableCredential} from '../../machines/VerifiableCredential/VCMetaMachine/vc';
import {
  dismissNfcEngagement,
  takeNfcEngagement,
  useNfcEngagement,
} from '../../shared/mdoc/mdocNfcEngagement';
import {
  stopIso18013ProximityPresentment,
  subscribeMdocPresentmentCannotSatisfy,
  subscribeMdocPresentmentConsentRequired,
} from '../../shared/mdoc/iso18013PresentmentInterop';

/**
 * How long to wait for the reader to connect over Bluetooth after Share: a little over the 30 s
 * readers typically wait, so a reader that is merely slow still gets through.
 */
const READER_CONNECT_TIMEOUT_MS = 35_000;

type Sharing = {
  nfcEngagementId: string;
  vc: VerifiableCredential;
  meta: VCMetadata;
};

/**
 * What the holder sees when a reader taps their phone (NFC engagement, Android).
 *
 * The same card chooser as sharing over a scanned request (SendVPScreen): the cards that can answer
 * - mdocs - with their checkmarks, then Share or Reject. Share runs the usual proximity session for
 * the chosen card, so the consent screen and the result page are the ones the QR flow shows; only
 * the engagement comes from the tap. One card, because a proximity session presents one document.
 */
export const NfcShareModal: React.FC = () => {
  const {t} = useTranslation('NfcShareModal');
  const {appService} = useContext(GlobalContext);
  const vcMetaService = appService.children.get('vcMeta')!!;
  const myVcs = useSelector(vcMetaService, selectMyVcs) as Record<
    string,
    {vcMetadata: VCMetadata; verifiableCredential: VerifiableCredential}
  >;

  const pendingTap = useNfcEngagement();
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [sharing, setSharing] = useState<Sharing | null>(null);
  const [readerGone, setReaderGone] = useState(false);

  const mdocs = useMemo(
    () =>
      Object.entries(myVcs ?? {}).filter(
        ([, vc]) => vc?.vcMetadata?.format === VCFormat.mso_mdoc,
      ),
    [myVcs],
  );

  // Waiting on the reader: if it never connects - it gave up, or the tap didn't reach it - say so
  // instead of leaving "Connecting to the reader…" up for good. Its request arriving, whether we
  // can answer it or not, means it connected.
  useEffect(() => {
    if (!sharing) {
      return;
    }
    let connected = false;
    const onConnected = () => {
      connected = true;
    };
    const consentSub = subscribeMdocPresentmentConsentRequired(onConnected);
    const cannotSatisfySub = subscribeMdocPresentmentCannotSatisfy(onConnected);
    const timer = setTimeout(() => {
      if (!connected) {
        stopIso18013ProximityPresentment();
        setSharing(null);
        setReaderGone(true);
      }
    }, READER_CONNECT_TIMEOUT_MS);
    return () => {
      clearTimeout(timer);
      consentSub.remove();
      cannotSatisfySub.remove();
    };
  }, [sharing]);

  // A fresh tap starts a fresh choice; with a single card there is nothing to choose.
  useEffect(() => {
    if (pendingTap) {
      setReaderGone(false);
      setSelectedKey(mdocs.length === 1 ? mdocs[0][0] : null);
    }
  }, [pendingTap]);

  const close = () => {
    dismissNfcEngagement();
    setSharing(null);
    setSelectedKey(null);
    setReaderGone(false);
  };

  const share = () => {
    const chosen = selectedKey ? myVcs[selectedKey] : null;
    const nfcEngagementId = takeNfcEngagement();
    if (!chosen) {
      return;
    }
    if (!nfcEngagementId) {
      // Took too long: the reader has given up on Bluetooth by now.
      setReaderGone(true);
      return;
    }
    setSharing({
      nfcEngagementId,
      vc: chosen.verifiableCredential,
      meta: chosen.vcMetadata,
    });
  };

  const visible = pendingTap != null || sharing != null || readerGone;
  if (!visible) {
    return null;
  }

  return (
    <Modal
      visible
      animationType="slide"
      presentationStyle="fullScreen"
      onRequestClose={close}>
      <Column fill backgroundColor={Theme.Colors.lightGreyBackgroundColor}>
        <Row
          padding="18 24 14 24"
          backgroundColor={Theme.Colors.whiteBackgroundColor}>
          <Text weight="semibold" testID="nfcShareTitle">
            {t('title')}
          </Text>
        </Row>

        {sharing ? (
          <>
            <Centered fill>
              <Text color={Theme.Colors.GrayIcon}>{t('connecting')}</Text>
            </Centered>
            <QrCodeOverlay
              verifiableCredential={sharing.vc}
              meta={sharing.meta}
              nfcEngagementId={sharing.nfcEngagementId}
              presentmentOnly
              onClose={close}
            />
          </>
        ) : readerGone || mdocs.length === 0 ? (
          <Column fill padding="24">
            <Centered fill>
              <Text align="center" testID="nfcShareMessage">
                {readerGone ? t('readerGone') : t('noCards')}
              </Text>
            </Centered>
            <Button type="gradient" title={t('close')} onPress={close} />
          </Column>
        ) : (
          <>
            <LinearGradient colors={Theme.Colors.selectIDTextGradient}>
              <Text
                margin="15 0 13 24"
                color={Theme.Colors.textValue}
                style={Theme.VPSharingStyles.selectIDText}>
                {t('SendVcScreen:pleaseSelectAnId')}
              </Text>
            </LinearGradient>
            <Row padding="11 24 11 24" style={{backgroundColor: '#FAFAFA'}}>
              <Text style={Theme.VPSharingStyles.cardsSelectedText}>
                {`${selectedKey ? 1 : 0} ${t('SendVPScreen:cardSelected')}`}
              </Text>
            </Row>
            <Column scroll backgroundColor={Theme.Colors.whiteBackgroundColor}>
              {mdocs.map(([vcKey, vc]) => (
                <VcItemContainer
                  key={vcKey}
                  vcMetadata={vc.vcMetadata}
                  margin="0 2 8 2"
                  onPress={() => setSelectedKey(vcKey)}
                  selectable
                  selected={selectedKey === vcKey}
                  flow={VCItemContainerFlowType.VP_SHARE}
                  isPinned={vc.vcMetadata.isPinned}
                />
              ))}
            </Column>
            <Column
              style={[
                Theme.SendVcScreenStyles.shareOptionButtonsContainer,
                {position: 'relative'},
              ]}
              backgroundColor={Theme.Colors.whiteBackgroundColor}>
              <Button
                type="gradient"
                styles={{marginTop: 12}}
                testID="nfcShareButton"
                title={t('SendVcScreen:acceptRequest')}
                disabled={selectedKey == null}
                onPress={share}
              />
              <Button
                type="clear"
                testID="nfcRejectButton"
                title={t('SendVcScreen:reject')}
                onPress={close}
              />
            </Column>
          </>
        )}
      </Column>
    </Modal>
  );
};
