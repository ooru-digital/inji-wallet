import React, {
  Fragment,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import {useTranslation} from 'react-i18next';
import {
  InteractionManager,
  Pressable,
  ScrollView,
  StyleSheet,
  TextInput,
  View,
} from 'react-native';
import {useSafeAreaInsets} from 'react-native-safe-area-context';
import {useFocusEffect} from '@react-navigation/native';
import {Header} from '../../components/ui/Header';
import {Theme} from '../../components/ui/styleUtils';
import {Button} from '../../components/ui';
import {IssuerLogo} from '../../components/ui/svg';
import {RootRouteProps} from '../../routes';
import {HomeRouteProps} from '../../routes/routeTypes';
import {useIssuerScreenController} from './IssuerScreenController';
import testIDProps, {
  isTranslationKeyFound,
  removeWhiteSpace,
} from '../../shared/commonUtil';
import {
  ErrorMessage,
  getDisplayObjectForCurrentLanguage,
  Protocols,
} from '../../shared/openId4VCI/Utils';
import {issuerType} from '../../machines/Issuers/IssuersMachine';
import {
  getInteractEventData,
  getStartEventData,
  sendInteractEvent,
  sendStartEvent,
} from '../../shared/telemetry/TelemetryUtils';
import {TelemetryConstants} from '../../shared/telemetry/TelemetryConstants';
import {CredentialTypeSelectionScreen} from './CredentialTypeSelectionScreen';
import {ReplaceCredentialSelectionScreen} from './ReplaceCredentialSelectionScreen';
import {AUTH_ROUTES} from '../../routes/routesConstants';
import {TransactionCodeModal} from './TransactionCodeScreen';
import {TrustIssuerSheet} from '../../components/addCredential/TrustIssuerSheet';
import {DownloadingCard} from '../../components/addCredential/DownloadingCard';
import {DownloadFailed} from '../../components/addCredential/DownloadFailed';
import {AlertSheet, Page, PageButton} from '../../components/revamp/Page';
import {
  BackIcon,
  CheckIcon,
  ChevronIcon,
  CloseIcon,
  IssuersIcon,
  SearchIcon,
  ShieldCheckIcon,
  WarningIcon,
} from '../../components/revamp/Icons';
import {ScaledText} from '../../components/revamp/ScaledText';
import {fonts, radii, shadows} from '../../components/revamp/tokens';
import {useRevampTheme} from '../../components/revamp/useRevampTheme';
import {CACHED_API} from '../../shared/api';
import {getCredentialConfigurationNames} from '../../shared/openId4VCI/credentialOffer';
import {AddedToWalletScreen} from '../../components/addCredential/AddedToWalletScreen';
import {VCMetadata} from '../../shared/VCMetadata';
import {SendVPScreen} from '../Scan/SendVPScreen';

import {AuthorizationType} from '../../shared/constants';
import {useTimer} from '../../shared/hooks/UseTimer';
import {
  ProcessingModal,
  ProgressIndicator,
} from '../../components/ui/processingScreen/ProcessingModal';

export type IssuersScreenParams = {
  service: unknown;
  /** Set when opened from an "Add to Wallet" link: the offer is already known, so there is nothing to scan. */
  credentialOfferUrl?: string;
};

export const IssuersScreen: React.FC<
  HomeRouteProps | RootRouteProps
> = props => {
  const controller = useIssuerScreenController(props);
  const {t} = useTranslation('IssuersScreen');
  const credentialOfferUrl = (
    props.route.params as IssuersScreenParams | undefined
  )?.credentialOfferUrl;
  const isCredentialOfferLink = credentialOfferUrl !== undefined;
  // "Try again" and closing an error both reset the machine to selectingIssuer, so this records
  // which one the user chose.
  const isRetryingCredentialOffer = useRef(false);
  const showFullScreenError = controller.isError;
  const [successDownloadRedirectTimer, initiateSuccessDownloadRedirectTimer] =
    useTimer({initialValue: 5});

  // The credential just saved. The machine leaves `storing`, and finishes, moments after saving,
  // so the success screen keeps its own copy rather than following that state.
  const [addedVcMetadata, setAddedVcMetadata] = useState<VCMetadata | null>(
    null,
  );

  const isVerificationFailed = controller.verificationErrorMessage !== '';

  const translationKey = `errors.verificationFailed.${controller.verificationErrorMessage}`;

  const verificationErrorMessage = isTranslationKeyFound(translationKey, t)
    ? t(translationKey)
    : t('errors.verificationFailed.ERR_GENERIC');

  const isPreparingOffer =
    controller.loadingReason === 'preparingRequest' &&
    !controller.isPresentationAuthorization;
  // Reading an offer and its trust sheet. Offers come from a link or the Scan tab, so the screen
  // shows the download behind the sheet rather than a scanner.
  const isInOfferFlow =
    controller.isQrScanning ||
    controller.isConsentRequested ||
    isPreparingOffer;
  // Opened from the wallet's + button: the list of issuers to sign in with (eSignet).
  const isIssuerList =
    !isCredentialOfferLink &&
    !isInOfferFlow &&
    (controller.isSelectingIssuer || controller.isFetchingIssuers);

  // The list is asked for once, when the + button opens this screen. An offer never needs it.
  useEffect(() => {
    if (!isCredentialOfferLink) {
      controller.FETCH_ISSUERS();
    }
  }, []);

  // Whether the list has answered at least once. Kept here rather than on the list page: the
  // page is replaced while an issuer is opened, and on coming back it would think the list was
  // still on its way, which never arrives again, and show placeholder rows for good.
  const [hasFetchedIssuers, setHasFetchedIssuers] = useState(false);
  const wasFetchingIssuers = useRef(false);
  useEffect(() => {
    if (controller.isFetchingIssuers) {
      wasFetchingIssuers.current = true;
    } else if (wasFetchingIssuers.current) {
      setHasFetchedIssuers(true);
    }
  }, [controller.isFetchingIssuers]);
  const isLoadingIssuers =
    controller.isFetchingIssuers ||
    (!hasFetchedIssuers && !controller.issuersFetchFailed);
  // Here too, so coming back from an issuer doesn't fetch them all again.
  const issuerCredentialTypes = useIssuerCredentialTypes(controller.issuers);

  const selectIssuer = (issuer: issuerType) => {
    sendStartEvent(
      getStartEventData(TelemetryConstants.FlowType.vcDownload, {
        id: issuer.issuer_id,
      }),
    );
    sendInteractEvent(
      getInteractEventData(
        TelemetryConstants.FlowType.vcDownload,
        TelemetryConstants.InteractEventSubtype.click,
        `IssuerType: ${issuer.issuer_id}`,
      ),
    );
    if (issuer.protocol === Protocols.OTP) {
      controller.DOWNLOAD_ID();
    } else {
      controller.SELECTED_ISSUER(issuer.issuer_id);
    }
  };

  // An eSignet download has no offer to name the card and issuer, so they come from the issuer
  // and credential type the user picked.
  const downloadIssuerName =
    controller.issuerName ||
    (controller.selectedIssuer?.display?.length
      ? getDisplayObjectForCurrentLanguage(controller.selectedIssuer.display)
          ?.name
      : undefined);
  const downloadCardType =
    controller.offeredCredentialTypeNames[0] ??
    (controller.selectedCredentialType?.display?.length
      ? getDisplayObjectForCurrentLanguage(
          controller.selectedCredentialType.display,
        )?.name
      : undefined);

  useFocusEffect(
    useCallback(() => {
      const tabs = props.navigation.getParent();
      tabs?.setOptions({tabBarStyle: {display: 'none'}});
      return () =>
        tabs?.setOptions({
          tabBarStyle: {
            ...Theme.BottomTabBarStyle.tabBarStyle,
            display: 'flex',
          },
        });
    }, [props.navigation]),
  );

  // The issuer list is where closing an error returns to. A link's offer has nothing to go back
  // to, so that closes the screen instead, unless the user asked to try the offer again.
  useEffect(() => {
    if (!controller.isSelectingIssuer || !isCredentialOfferLink) {
      return;
    }
    if (isRetryingCredentialOffer.current) {
      isRetryingCredentialOffer.current = false;
      controller.SCAN_CREDENTIAL_OFFER_QR_CODE();
      controller.QR_CODE_SCANNED(credentialOfferUrl);
    } else {
      props.navigation.goBack();
    }
  }, [controller.isSelectingIssuer]);

  useLayoutEffect(() => {
    if (
      addedVcMetadata ||
      controller.loadingReason ||
      showFullScreenError ||
      isInOfferFlow ||
      isIssuerList
    ) {
      props.navigation.setOptions({
        headerShown: false,
      });
    } else {
      props.navigation.setOptions({
        headerShown: true,
        header: props => (
          <Header
            goBack={props.navigation.goBack}
            title={t('title')}
            testID="issuersScreenHeader"
          />
        ),
      });
    }
  }, [
    addedVcMetadata,
    controller.loadingReason,
    controller.errorMessageType,
    isInOfferFlow,
    isIssuerList,
  ]);

  // On the success screen, View in Wallet (or Android's back button) is the way out: it marks the
  // new card on the way home. iOS's swipe-back would pop straight to Home without it.
  useLayoutEffect(() => {
    props.navigation.setOptions({gestureEnabled: !addedVcMetadata});
  }, [addedVcMetadata]);

  useLayoutEffect(() => {
    if (controller.loadingReason && controller.isPresentationAuthorization) {
      props.navigation.setOptions({
        headerShown: true,
        header: props => (
          <Header
            goBack={props.navigation.goBack}
            title={t('selectCard')}
            testID="selectCardIssuersScreenHeader"
          />
        ),
      });
    }
  }, [controller.loadingReason, controller.isPresentationAuthorization]);

  useEffect(() => {
    if (!controller.isDownloadSuccess) {
      return;
    }
    // Sharing to a verifier and downloading in one go keeps its combined progress screen, which
    // returns home on a timer.
    if (
      controller.authorizationType === AuthorizationType.OPENID4VP_PRESENTATION
    ) {
      initiateSuccessDownloadRedirectTimer();
    } else {
      setAddedVcMetadata(new VCMetadata(controller.downloadedVcMetadata));
    }
  }, [controller.isDownloadSuccess]);

  // Back to the wallet, which brings the new card to the front and marks it as new.
  const viewInWallet = useCallback(() => {
    if (!addedVcMetadata) {
      return;
    }
    // HomeScreen is the screen below this one in the home stack, so this goes back to it.
    (props.navigation as any).navigate('HomeScreen', {
      highlightVcKey: addedVcMetadata.getVcKey(),
    });
  }, [addedVcMetadata, props.navigation]);

  useEffect(() => {
    if (successDownloadRedirectTimer === 0) {
      props.navigation.goBack();
    }
  }, [successDownloadRedirectTimer]);

  useEffect(() => {
    if (controller.isAuthEndpointToOpen) {
      (props.navigation as any).navigate(AUTH_ROUTES.AuthView, {
        authorizationURL: controller.authEndpoint,
        clientId: controller.selectedIssuer.client_id ?? 'wallet',
        redirectUri:
          controller.selectedIssuer.redirect_uri ??
          'io.mosip.residentapp.inji://oauthredirect',
        controller: controller,
      });
    }
  }, [controller.isAuthEndpointToOpen]);

  // A failed issuers fetch doesn't come here (it only marks the issuers section), so any error
  // here has selectingIssuer to reset back to.
  const goBack = () => {
    isRetryingCredentialOffer.current = false;
    controller.RESET_ERROR();
  };

  const tryAgain = () => {
    isRetryingCredentialOffer.current = isCredentialOfferLink;
    controller.TRY_AGAIN();
  };

  if (
    controller.authorizationType === AuthorizationType.OPENID4VP_PRESENTATION &&
    (controller.isPresentationAuthorizationInProgress ||
      controller.isDownloadSuccess ||
      controller.isAuthorizationSuccess) &&
    !controller.isError &&
    !isVerificationFailed
  ) {
    return (
      <ProcessingModal
        testID={controller.isDownloadSuccess ? 'download-success' : 'download'}
        isVisible={
          controller.authorizationType ===
            AuthorizationType.OPENID4VP_PRESENTATION &&
          (controller.isPresentationAuthorizationInProgress ||
            controller.isDownloadSuccess ||
            controller.isAuthorizationSuccess) &&
          !controller.isError
        }
        title={
          controller.isDownloadSuccess
            ? t('downloadSuccess')
            : t('loaders.processing')
        }
        subTitle={
          controller.isDownloadSuccess
            ? t('loaders.progressIndicators.redirectToHome', {
                remainingTime: successDownloadRedirectTimer,
              })
            : t('loaders.subTitle.inProgress')
        }
        progressSteps={[
          <ProgressIndicator
            key={1}
            label={
              controller.isAuthorizationSuccess
                ? t('loaders.progressIndicators.sharedCard')
                : t('loaders.progressIndicators.sharingCard')
            }
            completed={controller.isAuthorizationSuccess}
            testID={
              controller.isAuthorizationSuccess ? 'shared-card' : 'sharing-card'
            }
          />,
          <ProgressIndicator
            key={2}
            label={
              controller.isDownloadSuccess
                ? t('loaders.progressIndicators.downloadedCard')
                : t('loaders.progressIndicators.downloadingCard')
            }
            completed={controller.isDownloadSuccess}
            testID={
              controller.isDownloadSuccess
                ? 'downloaded-card'
                : 'downloading-card'
            }
          />,
        ]}
        action={
          <Button
            testID={'go-home'}
            title={t('goHome')}
            type={'gradient'}
            fill
            onPress={props.navigation.goBack}
            disabled={!controller.isDownloadSuccess}
          />
        }
      />
    );
  }

  if (addedVcMetadata) {
    return (
      <AddedToWalletScreen
        vcMetadata={addedVcMetadata}
        onViewInWallet={viewInWallet}
      />
    );
  }

  if (controller.isSelectingCredentialType) {
    return <CredentialTypeSelectionScreen {...props} />;
  }

  if (isVerificationFailed) {
    return (
      <DownloadFailed
        testID="verificationError"
        kind="verification"
        title={t('couldNotAddCard')}
        message={verificationErrorMessage}
        primary={{
          testID: 'goBack',
          title: t('backToWallet'),
          onPress: controller.RESET_VERIFY_ERROR,
        }}
      />
    );
  }
  if (controller.isCredentialAlreadyExists) {
    return (
      <Fragment>
        {offerSheets()}
        <AlertSheet
          testID="credentialAlreadyExists"
          isVisible={controller.isCredentialAlreadyExists}
          tone="warn"
          icon={colour => <WarningIcon color={colour} />}
          title={t('errors.credentialAlreadyExists.title')}
          message={t('errors.credentialAlreadyExists.message', {
            card: controller.offeredCredentialTypeNames[0] ?? t('thisCard'),
          })}
          primary={{
            testID: 'replaceExistingCredential',
            title: t('common:replaceExisting'),
            onPress: controller.REPLACE_EXISTING,
          }}
          outline={{
            testID: 'keepBothCredentials',
            title: t('common:keepBoth'),
            onPress: controller.KEEP_BOTH,
          }}
          dismissOnBackdropPress={false}
          onRequestClose={() => undefined}
        />
      </Fragment>
    );
  }
  if (controller.isSelectingCredentialsToReplace) {
    return <ReplaceCredentialSelectionScreen {...props} />;
  }
  if (controller.isTxCodeRequested) {
    return (
      <TransactionCodeModal
        visible={controller.isTxCodeRequested}
        onDismiss={controller.CANCEL}
        onVerify={controller.TX_CODE_RECEIVED}
        inputMode={controller.txCodeDisplayDetails.inputMode}
        description={controller.txCodeDisplayDetails.description}
        length={controller.txCodeDisplayDetails.length}
      />
    );
  }

  if (controller.isBiometricsCancelled) {
    return (
      <Fragment>
        {offerSheets()}
        <AlertSheet
          testID="biometricsCancelled"
          isVisible={controller.isBiometricsCancelled}
          tone="warn"
          icon={colour => <WarningIcon color={colour} />}
          title={t('errors.biometricsCancelled.title')}
          message={t('errors.biometricsCancelled.message')}
          primary={{
            testID: 'tryAgain',
            title: t('errors.biometricsCancelled.retry'),
            onPress: controller.TRY_AGAIN,
          }}
          secondary={{
            testID: 'stopDownload',
            title: t('errors.biometricsCancelled.stop'),
            destructive: true,
            onPress: controller.RESET_ERROR,
          }}
          onRequestClose={controller.RESET_ERROR}
        />
      </Fragment>
    );
  }
  if (showFullScreenError) {
    const errorType = controller.errorMessageType || ErrorMessage.GENERIC;
    return (
      <DownloadFailed
        testID={`${errorType}Error`}
        kind={errorType === ErrorMessage.NO_INTERNET ? 'connection' : 'generic'}
        title={t('couldNotAddCard')}
        message={t(`errors.${errorType}.message`)}
        onClose={goBack}
        primary={
          errorType != ErrorMessage.TECHNICAL_DIFFICULTIES &&
          errorType != ErrorMessage.AUTHORIZATION_GRANT_TYPE_NOT_SUPPORTED
            ? {
                testID: 'tryAgain',
                title: t('common:tryAgain'),
                onPress: tryAgain,
              }
            : {
                testID: 'backToWallet',
                title: t('backToWallet'),
                onPress: props.navigation.goBack,
              }
        }
        secondary={
          errorType != ErrorMessage.TECHNICAL_DIFFICULTIES &&
          errorType != ErrorMessage.AUTHORIZATION_GRANT_TYPE_NOT_SUPPORTED
            ? {
                testID: 'backToWallet',
                title: t('backToWallet'),
                onPress: props.navigation.goBack,
              }
            : undefined
        }
      />
    );
  }

  if (isIssuerList) {
    return (
      <IssuerListPage
        issuers={controller.issuers}
        credentialTypes={issuerCredentialTypes}
        isLoading={isLoadingIssuers}
        issuersFetchFailed={controller.issuersFetchFailed}
        onSelectIssuer={selectIssuer}
        onRetry={controller.FETCH_ISSUERS}
        onBack={props.navigation.goBack}
      />
    );
  }

  if (isInOfferFlow) {
    return offerSheets();
  }

  if (controller.loadingReason) {
    return (
      <Fragment>
        {controller.isPresentationAuthorization ? (
          <SendVPScreen
            navigation={props.navigation}
            route={{
              ...props.route,
              params: {
                ...props.route.params,
                ovpService: controller.ovpMachine,
              },
            }}
          />
        ) : (
          <DownloadingCard
            reason={controller.loadingReason}
            cardType={downloadCardType}
            issuerName={downloadIssuerName}
            issuerTrusted
            onCancel={
              controller.canCancelDownload ? controller.CANCEL : undefined
            }
          />
        )}
      </Fragment>
    );
  }

  // Nothing else to show on the way out, e.g. once the card is stored and the screen is
  // about to close.
  return offerSheets();

  // The download in progress, with the offer's trust sheet over it when the issuer asks.
  function offerSheets() {
    return (
      <Fragment>
        {isCredentialOfferLink ? (
          <DownloadingCard reason="preparingRequest" />
        ) : (
          <DownloadingCard
            reason="downloadingCredentials"
            cardType={downloadCardType}
            issuerName={downloadIssuerName}
            issuerTrusted
          />
        )}
        <TrustIssuerSheet
          isVisible={controller.isConsentRequested}
          name={controller.issuerName}
          credentialTypes={controller.offeredCredentialTypeNames}
          logo={controller.issuerLogo}
          consentStatus={controller.trustedIssuerConsentStatus}
          onConfirm={controller.ON_CONSENT_GIVEN}
          onCancel={controller.CANCEL}
        />
      </Fragment>
    );
  }
};

// Ring colours around the issuer logos, given out in list order so neighbours differ.
const RING_COLOURS = [
  '#0a3970',
  '#8a5a1c',
  '#3f7d8c',
  '#1f6b57',
  '#5b3fa0',
  '#b3261e',
  '#6b5a2e',
];

const issuerDisplay = (issuer: issuerType) =>
  issuer.display?.length
    ? getDisplayObjectForCurrentLanguage(issuer.display)
    : undefined;

/**
 * Each issuer's credential type names, read from its well-known metadata. Uses the same cached
 * request as the cards, so a list seen before shows its types straight away.
 */
function useIssuerCredentialTypes(issuers: issuerType[]) {
  const [types, setTypes] = useState<Record<string, string[]>>({});
  useEffect(() => {
    let active = true;
    let arrived: Record<string, string[]> = {};
    let drawTimer: ReturnType<typeof setTimeout> | undefined;
    const draw = () => {
      drawTimer = undefined;
      const batch = arrived;
      arrived = {};
      setTypes(previous => ({...previous, ...batch}));
    };

    const queue = issuers.filter(issuer => issuer.credential_issuer_host);
    const fetchNext = async () => {
      while (active) {
        const issuer = queue.shift();
        if (!issuer) {
          return;
        }
        const host = issuer.credential_issuer_host;
        try {
          const wellknown = await CACHED_API.fetchIssuerWellknownConfig(
            host,
            host,
            true,
          );
          if (!active) {
            return;
          }
          arrived[issuer.issuer_id] = getCredentialConfigurationNames(
            wellknown,
            Object.keys(wellknown?.credential_configurations_supported ?? {}),
          );
          if (!drawTimer) {
            drawTimer = setTimeout(draw, CREDENTIAL_TYPES_DRAW_DELAY_MS);
          }
        } catch {
          // The row still shows the issuer, just without its types.
        }
      }
    };

    // Starts once the screen has finished opening, and runs a few at a time, so taps (Back in
    // particular) aren't kept waiting behind every issuer's request.
    const start = InteractionManager.runAfterInteractions(() => {
      for (let i = 0; i < CREDENTIAL_TYPE_FETCHES_AT_ONCE; i++) {
        fetchNext();
      }
    });
    return () => {
      active = false;
      start.cancel();
      clearTimeout(drawTimer);
    };
  }, [issuers]);
  return types;
}

// How many issuers' metadata is fetched at the same time.
const CREDENTIAL_TYPE_FETCHES_AT_ONCE = 3;
// Types arriving close together are drawn in one go rather than a redraw each.
const CREDENTIAL_TYPES_DRAW_DELAY_MS = 250;

/** The + button's page: the issuers to sign in with (eSignet) and download a credential from. */
const IssuerListPage: React.FC<{
  issuers: issuerType[];
  /** Each issuer's credential type names, by issuer id, as they arrive. */
  credentialTypes: Record<string, string[]>;
  /** True until the list has been fetched once, and while it is fetched again. */
  isLoading: boolean;
  issuersFetchFailed: boolean;
  onSelectIssuer: (issuer: issuerType) => void;
  onRetry: () => void;
  onBack: () => void;
}> = ({
  issuers,
  credentialTypes,
  isLoading,
  issuersFetchFailed,
  onSelectIssuer,
  onRetry,
  onBack,
}) => {
  const {t} = useTranslation('IssuersScreen');
  const {c} = useRevampTheme();
  const insets = useSafeAreaInsets();
  const [query, setQuery] = useState('');
  // A stable handler, so a row redraws only when its own details change.
  const onSelectRef = useRef(onSelectIssuer);
  onSelectRef.current = onSelectIssuer;
  const selectIssuer = useCallback(
    (issuer: issuerType) => onSelectRef.current(issuer),
    [],
  );

  // Matches the issuer's name or any of its credential types ("driving licence", "university").
  const filteredIssuers = useMemo(() => {
    const search = query.trim().toLowerCase();
    if (!search) {
      return issuers;
    }
    return issuers.filter(issuer =>
      [
        issuerDisplay(issuer)?.name ?? '',
        ...(credentialTypes[issuer.issuer_id] ?? []),
      ].some(text => text.toLowerCase().includes(search)),
    );
  }, [issuers, query, credentialTypes]);

  const message = (text: string, testID: string) => (
    <ScaledText
      {...testIDProps(testID)}
      style={[styles.message, {color: c.inkMuted}]}>
      {text}
    </ScaledText>
  );

  const list = () => {
    if (isLoading) {
      return (
        <View>
          {[0, 1, 2].map(i => (
            <View
              key={i}
              {...testIDProps('issuerSkeleton')}
              style={[
                styles.row,
                i > 0 && {borderTopColor: c.line},
                i > 0 && styles.divider,
              ]}>
              <View style={[styles.ring, {borderColor: c.sand}]} />
              <View style={styles.rowText}>
                <View
                  style={[styles.skeletonTitle, {backgroundColor: c.sand}]}
                />
                <View
                  style={[styles.skeletonHint, {backgroundColor: c.sand}]}
                />
              </View>
            </View>
          ))}
        </View>
      );
    }
    if (issuersFetchFailed) {
      return (
        <View style={styles.notice}>
          {message(t('issuerList.failed'), 'issuersFetchFailed')}
          <PageButton
            testID="retryIssuers"
            variant="link"
            title={t('common:tryAgain')}
            onPress={onRetry}
          />
        </View>
      );
    }
    if (issuers.length === 0) {
      return message(t('issuerList.noIssuers'), 'noIssuers');
    }
    if (filteredIssuers.length === 0) {
      return message(t('issuerList.noMatch'), 'noIssuersMatch');
    }
    return (
      <View>
        <ScaledText
          {...testIDProps('issuersCount')}
          style={[styles.count, {color: c.inkMuted}]}>
          {t('issuerList.count', {count: filteredIssuers.length})}
        </ScaledText>
        {filteredIssuers.map((issuer, i) => (
          <IssuerRow
            key={issuer.issuer_id}
            issuer={issuer}
            credentialTypes={credentialTypes[issuer.issuer_id]}
            ringColour={
              RING_COLOURS[issuers.indexOf(issuer) % RING_COLOURS.length]
            }
            isFirst={i === 0}
            onSelect={selectIssuer}
          />
        ))}
      </View>
    );
  };

  return (
    <Page
      testID="issuerListPage"
      header={
        <View style={styles.header}>
          <Pressable
            {...testIDProps('goBack')}
            accessibilityRole="button"
            accessibilityLabel={t('common:goBack')}
            hitSlop={8}
            onPress={onBack}
            style={({pressed}) => [
              styles.back,
              shadows.raised,
              {backgroundColor: c.card, borderColor: c.line},
              pressed && {transform: [{scale: 0.95}]},
            ]}>
            <BackIcon color={c.ink} />
          </Pressable>
        </View>
      }>
      <ScrollView
        keyboardShouldPersistTaps="handled"
        showsVerticalScrollIndicator={false}
        contentContainerStyle={[
          styles.content,
          {paddingBottom: Math.max(insets.bottom, 12) + 24},
        ]}>
        <View style={styles.heading}>
          <ScaledText
            {...testIDProps('issuerListTitle')}
            accessibilityRole="header"
            style={[styles.title, {color: c.ink}]}>
            {t('issuerList.title')}
          </ScaledText>
          <ScaledText style={[styles.lead, {color: c.inkMuted}]}>
            {t('issuerList.lead')}
          </ScaledText>
        </View>

        <View style={styles.search}>
          <View style={styles.searchIcon} pointerEvents="none">
            <SearchIcon color={c.inkMuted} size={20} strokeWidth={1.8} />
          </View>
          <TextInput
            {...testIDProps('issuerSearchBar')}
            value={query}
            onChangeText={setQuery}
            placeholder={t('issuerList.searchPlaceholder')}
            placeholderTextColor={c.inkMuted}
            accessibilityLabel={t('issuerList.searchPlaceholder')}
            returnKeyType="search"
            numberOfLines={1}
            multiline={false}
            style={[
              styles.input,
              {
                borderColor: c.line,
                backgroundColor: c.card,
                color: c.ink,
                paddingRight: query ? 48 : 20,
              },
            ]}
          />
          {query ? (
            <Pressable
              {...testIDProps('clearingIssuerSearchIcon')}
              accessibilityRole="button"
              accessibilityLabel={t('issuerList.clearSearch')}
              onPress={() => setQuery('')}
              style={styles.clear}>
              <CloseIcon color={c.inkMuted} />
            </Pressable>
          ) : null}
        </View>

        {list()}

        {!isLoading && !issuersFetchFailed && issuers.length > 0 ? (
          <View
            {...testIDProps('issuersTrustNote')}
            style={[styles.trustNote, {backgroundColor: c.tintPass}]}>
            <ShieldCheckIcon color={c.pass} size={22} strokeWidth={1.8} />
            <ScaledText style={[styles.trustText, {color: c.ink}]}>
              {t('issuerList.trustNote')}
            </ScaledText>
          </View>
        ) : null}
      </ScrollView>
    </Page>
  );
};

/** The issuer's logo inside a coloured ring, with the trusted check at its corner. */
const IssuerRing: React.FC<{colour: string; uri?: string; testID: string}> = ({
  colour,
  uri,
  testID,
}) => {
  const {c} = useRevampTheme();
  return (
    <View style={[styles.ring, {borderColor: colour}]}>
      <View style={[styles.ringInner, {borderColor: colour}]}>
        <IssuerLogo
          uri={uri}
          testID={testID}
          size={26}
          fallback={<IssuersIcon color={colour} size={22} />}
        />
      </View>
      <View
        style={[
          styles.badge,
          {backgroundColor: c.pass, borderColor: c.canvas},
        ]}>
        <CheckIcon color={c.onPrimary} size={11} strokeWidth={3} />
      </View>
    </View>
  );
};

// Memoised: when a batch of credential types arrives, only the rows it changes redraw.
const IssuerRow = React.memo(function IssuerRow({
  issuer,
  credentialTypes,
  ringColour,
  isFirst,
  onSelect,
}: {
  issuer: issuerType;
  credentialTypes?: string[];
  ringColour: string;
  isFirst: boolean;
  onSelect: (issuer: issuerType) => void;
}) {
  const {t} = useTranslation('IssuersScreen');
  const {c} = useRevampTheme();
  const display = issuerDisplay(issuer);
  const testID = removeWhiteSpace(issuer.issuer_id);
  const name = display?.name ?? issuer.issuer_id;
  // The credential types once they are known; the issuer's own description until then.
  const hint = credentialTypes?.length
    ? credentialTypes.join(' · ')
    : display?.description;
  const typeCount = credentialTypes?.length ?? 0;
  return (
    <Pressable
      {...testIDProps(testID)}
      accessibilityRole="button"
      accessibilityLabel={[
        name,
        hint,
        typeCount ? t('issuerList.credentialTypes', {count: typeCount}) : '',
      ]
        .filter(Boolean)
        .join(', ')}
      onPress={() => onSelect(issuer)}
      style={({pressed}) => [
        styles.row,
        !isFirst && styles.divider,
        !isFirst && {borderTopColor: c.line},
        pressed && {opacity: 0.6},
      ]}>
      <IssuerRing
        colour={ringColour}
        // Some issuers send the logo as `uri` rather than `url`.
        uri={display?.logo?.url || (display?.logo as {uri?: string})?.uri}
        testID={`issuerIcon-${testID}`}
      />
      <View style={styles.rowText}>
        <ScaledText numberOfLines={2} style={[styles.rowTitle, {color: c.ink}]}>
          {name}
        </ScaledText>
        {hint ? (
          <ScaledText
            numberOfLines={1}
            style={[styles.rowHint, {color: c.inkMuted}]}>
            {hint}
          </ScaledText>
        ) : null}
      </View>
      {typeCount ? (
        <View style={[styles.countPill, {backgroundColor: c.sand}]}>
          <ScaledText style={[styles.countText, {color: c.ink}]}>
            {typeCount}
          </ScaledText>
        </View>
      ) : null}
      <ChevronIcon color={c.ink} direction="right" />
    </Pressable>
  );
});

const styles = StyleSheet.create({
  header: {paddingHorizontal: 24, paddingTop: 10, paddingBottom: 6},
  back: {
    width: 52,
    height: 52,
    borderRadius: radii.pill,
    borderWidth: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  content: {paddingTop: 14, gap: 24},
  heading: {gap: 8},
  title: {
    fontFamily: fonts.bold,
    fontSize: 32,
    lineHeight: 38,
    letterSpacing: -0.6,
  },
  lead: {fontFamily: fonts.regular, fontSize: 16, lineHeight: 22},
  search: {justifyContent: 'center'},
  searchIcon: {position: 'absolute', left: 20, zIndex: 1},
  input: {
    height: 56,
    borderRadius: radii.pill,
    borderWidth: 1,
    paddingLeft: 52,
    fontSize: 17,
    fontFamily: fonts.regular,
  },
  clear: {
    position: 'absolute',
    right: 4,
    width: 48,
    height: 48,
    alignItems: 'center',
    justifyContent: 'center',
  },
  count: {
    fontFamily: fonts.regular,
    fontSize: 13,
    lineHeight: 16,
    marginBottom: 6,
  },
  row: {
    minHeight: 88,
    paddingVertical: 16,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 14,
  },
  divider: {borderTopWidth: 1},
  ring: {
    width: 56,
    height: 56,
    borderRadius: radii.pill,
    borderWidth: 3,
    alignItems: 'center',
    justifyContent: 'center',
  },
  ringInner: {
    width: 42,
    height: 42,
    borderRadius: radii.pill,
    borderWidth: 1,
    borderStyle: 'dotted',
    alignItems: 'center',
    justifyContent: 'center',
    overflow: 'hidden',
  },
  badge: {
    position: 'absolute',
    right: -4,
    bottom: -4,
    width: 22,
    height: 22,
    borderRadius: radii.pill,
    borderWidth: 2,
    alignItems: 'center',
    justifyContent: 'center',
  },
  rowText: {flex: 1, gap: 4},
  rowTitle: {fontFamily: fonts.semibold, fontSize: 18, lineHeight: 23},
  rowHint: {fontFamily: fonts.regular, fontSize: 15, lineHeight: 20},
  countPill: {
    minWidth: 32,
    height: 32,
    paddingHorizontal: 8,
    borderRadius: radii.pill,
    alignItems: 'center',
    justifyContent: 'center',
  },
  countText: {fontFamily: fonts.semibold, fontSize: 14, lineHeight: 18},
  skeletonTitle: {width: '70%', height: 16, borderRadius: radii.chip / 2},
  skeletonHint: {width: '50%', height: 12, borderRadius: radii.chip / 2},
  notice: {alignItems: 'flex-start', gap: 4},
  message: {fontFamily: fonts.regular, fontSize: 15, lineHeight: 22},
  trustNote: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 12,
    padding: 18,
    borderRadius: radii.card,
  },
  trustText: {flex: 1, fontFamily: fonts.regular, fontSize: 15, lineHeight: 22},
});
