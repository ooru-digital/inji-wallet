import React, {useContext, useEffect, useMemo, useRef, useState} from 'react';
import {StyleSheet, View} from 'react-native';
import {useSelector} from '@xstate/react';
import {useTranslation} from 'react-i18next';
import {useIsFocused} from '@react-navigation/native';
import {BottomSheet} from '../../components/ui/BottomSheet';
import {QrCodeOverlay} from '../../components/QrCodeOverlay';
import {AlertSheet, ChoiceList, PageButton} from '../../components/revamp/Page';
import {CardRow} from '../../components/revamp/CardRow';
import {AlertCircleIcon} from '../../components/revamp/Icons';
import {ScaledText} from '../../components/revamp/ScaledText';
import {fonts} from '../../components/revamp/tokens';
import {useRevampTheme} from '../../components/revamp/useRevampTheme';
import {GlobalContext} from '../../shared/GlobalContext';
import {
  selectIsRefreshingMyVcs,
  selectMyVcs,
  selectMyVcsMetadata,
} from '../../machines/VerifiableCredential/VCMetaMachine/VCMetaSelectors';
import {VCFormat} from '../../shared/VCFormat';
import {VCMetadata} from '../../shared/VCMetadata';
import {VerifiableCredential} from '../../machines/VerifiableCredential/VCMetaMachine/vc';
import {useIsAppLocked} from '../Settings/autoLock';
import {
  dismissNfcEngagement,
  nfcCardInView,
  nfcShareBlocker,
  takeNfcEngagement,
  useNfcEngagement,
} from '../../shared/mdoc/mdocNfcEngagement';
import {
  stopIso18013ProximityPresentment,
  subscribeMdocPresentmentCannotSatisfy,
  subscribeMdocPresentmentConsentRequired,
} from '../../shared/mdoc/iso18013PresentmentInterop';

/**
 * How long to wait for the reader to connect over Bluetooth after the card is chosen: a little
 * over the 30 s readers typically wait, so a reader that is merely slow still gets through.
 */
const READER_CONNECT_TIMEOUT_MS = 35_000;

type Entry = {
  vcMetadata: VCMetadata;
  verifiableCredential: VerifiableCredential;
};
type Sharing = {nfcEngagementId: string; vcKey: string};

/**
 * What happens when a reader taps the phone (NFC engagement, Android).
 *
 * Nothing shows while the wallet is locked; the tap is answered once it is unlocked. The card is
 * Home's current one when Home is showing an mdoc, else the only mdoc, else the holder picks.
 * From there it is the in-person share flow, starting at Connecting rather than at a QR code.
 */
export const NfcTapShare: React.FC = () => {
  const {t} = useTranslation('NfcTapShare');
  const {c} = useRevampTheme();
  const {appService} = useContext(GlobalContext);
  const vcMetaService = appService.children.get('vcMeta')!!;
  const myVcs = useSelector(vcMetaService, selectMyVcs) as Record<
    string,
    Entry
  >;
  const pendingTap = useNfcEngagement();
  const locked = useIsAppLocked();
  const homeFocused = useIsFocused();
  const [choosing, setChoosing] = useState(false);
  const [sharing, setSharing] = useState<Sharing | null>(null);
  const [notice, setNotice] = useState<
    'noCards' | 'readerGone' | 'bluetooth' | null
  >(null);
  // The card picked while Bluetooth was off or a permission missing, to retry with.
  const [blockedCard, setBlockedCard] = useState<string | null>(null);
  // Set while a share is being started, so the effect can't start a second one meanwhile.
  const starting = useRef(false);

  const metadata = useSelector(vcMetaService, selectMyVcsMetadata);
  const refreshing = useSelector(vcMetaService, selectIsRefreshingMyVcs);
  const mdocs = useMemo(
    () =>
      metadata
        .filter(m => m.format === VCFormat.mso_mdoc)
        .map(m => [m.getVcKey(), m] as const),
    [metadata],
  );
  // A tap can be what launched the app: only cards that have loaded can be shared, and the
  // others join the choice as they load.
  const loadedMdocs = useMemo(
    () => mdocs.filter(([key]) => myVcs?.[key]?.verifiableCredential != null),
    [mdocs, myVcs],
  );

  const share = async (vcKey: string) => {
    if (starting.current) {
      return;
    }
    starting.current = true;
    setChoosing(false);
    // Checked before the tap is taken, so turning Bluetooth on and trying again still works.
    const blocker = await nfcShareBlocker();
    starting.current = false;
    if (blocker) {
      setBlockedCard(vcKey);
      setNotice('bluetooth');
      return;
    }
    const nfcEngagementId = takeNfcEngagement();
    if (!nfcEngagementId) {
      // Took too long: the reader has given up on Bluetooth by now.
      setNotice('readerGone');
      return;
    }
    setSharing({nfcEngagementId, vcKey});
  };

  // Also runs when a share or the choice ends, so a tap that came in meanwhile is offered then.
  useEffect(() => {
    if (!pendingTap || locked || refreshing || sharing || choosing || notice) {
      return;
    }
    const inView = homeFocused ? nfcCardInView() : null;
    if (inView && loadedMdocs.some(([key]) => key === inView)) {
      share(inView);
    } else if (mdocs.length === 0) {
      dismissNfcEngagement();
      setNotice('noCards');
    } else if (mdocs.length === 1) {
      // Wait for the only card to load.
      if (loadedMdocs.length === 1) {
        share(loadedMdocs[0][0]);
      }
    } else if (loadedMdocs.length > 0) {
      setChoosing(true);
    }
  }, [pendingTap, locked, refreshing, sharing, choosing, notice, loadedMdocs]);

  // If the reader never connects - it gave up, or the tap didn't reach it - say so instead of
  // leaving Connecting up. Its request arriving, answerable or not, means it connected.
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
        setNotice('readerGone');
      }
    }, READER_CONNECT_TIMEOUT_MS);
    return () => {
      clearTimeout(timer);
      consentSub.remove();
      cannotSatisfySub.remove();
    };
  }, [sharing]);

  const cancelChoice = () => {
    setChoosing(false);
    dismissNfcEngagement();
  };

  const cancelBlocked = () => {
    setNotice(null);
    setBlockedCard(null);
    dismissNfcEngagement();
  };

  const shared = sharing ? myVcs[sharing.vcKey] : undefined;

  return (
    <>
      <BottomSheet
        testID="nfcTapChooseCard"
        isVisible={choosing}
        onRequestClose={cancelChoice}>
        <View style={styles.head}>
          <ScaledText
            accessibilityRole="header"
            style={[styles.title, {color: c.ink}]}>
            {t('chooseTitle')}
          </ScaledText>
          <ScaledText style={[styles.body, {color: c.inkMuted}]}>
            {t('chooseBody')}
          </ScaledText>
        </View>
        <ChoiceList>
          {loadedMdocs.map(([vcKey, vcMetadata]) => (
            <CardRow
              key={vcKey}
              testID={`nfcTapCard-${vcKey}`}
              vcMetadata={vcMetadata}
              onPress={() => share(vcKey)}
            />
          ))}
        </ChoiceList>
        <View style={styles.footer}>
          <PageButton
            testID="nfcTapCancel"
            variant="mutedLink"
            title={t('common:cancel')}
            onPress={cancelChoice}
          />
        </View>
      </BottomSheet>

      {sharing && shared ? (
        <QrCodeOverlay
          verifiableCredential={shared.verifiableCredential}
          meta={shared.vcMetadata}
          nfcEngagementId={sharing.nfcEngagementId}
          presentmentOnly
          showInlineQr={false}
          onClose={() => setSharing(null)}
        />
      ) : null}

      <AlertSheet
        testID="nfcTapNotice"
        isVisible={notice !== null}
        tone="warn"
        icon={colour => <AlertCircleIcon color={colour} />}
        title={t(`${notice ?? 'readerGone'}Title`)}
        message={t(`${notice ?? 'readerGone'}Body`)}
        primary={
          notice === 'bluetooth' && blockedCard
            ? {
                testID: 'nfcTapNoticeTryAgain',
                title: t('common:tryAgain'),
                onPress: () => {
                  setNotice(null);
                  share(blockedCard);
                },
              }
            : {
                testID: 'nfcTapNoticeOk',
                title: t('common:ok'),
                onPress: () => setNotice(null),
              }
        }
        secondary={
          notice === 'bluetooth'
            ? {
                testID: 'nfcTapNoticeCancel',
                title: t('common:cancel'),
                onPress: cancelBlocked,
              }
            : undefined
        }
        onRequestClose={
          notice === 'bluetooth' ? cancelBlocked : () => setNotice(null)
        }
      />
    </>
  );
};

const styles = StyleSheet.create({
  head: {gap: 6, marginBottom: 16, paddingHorizontal: 4},
  title: {
    fontFamily: fonts.semibold,
    fontSize: 22,
    lineHeight: 27,
    letterSpacing: -0.4,
  },
  body: {fontFamily: fonts.regular, fontSize: 15, lineHeight: 22},
  footer: {marginTop: 16},
});
