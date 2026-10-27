import React, {useEffect} from 'react';
import {useTranslation} from 'react-i18next';
import {createNativeStackNavigator} from '@react-navigation/native-stack';
import {SendVcScreen} from './SendVcScreen';
import {useScanLayout} from './ScanLayoutController';
import {ScanScreen} from './ScanScreen';
import {SCAN_ROUTES} from '../../routes/routesConstants';
import {
  AlertSheet,
  Page,
  PageButton,
  PageHeading,
  SpinnerGlyph,
} from '../../components/revamp/Page';
import {
  AlertCircleIcon,
  CheckIcon,
  CloseIcon,
  ShareIcon,
} from '../../components/revamp/Icons';
import {ScaledText} from '../../components/revamp/ScaledText';
import {fonts, radii} from '../../components/revamp/tokens';
import {useRevampTheme} from '../../components/revamp/useRevampTheme';
import {Theme} from '../../components/ui/styleUtils';
import {Icon} from 'react-native-elements';
import {VerifyIdentityOverlay} from '../VerifyIdentityOverlay';
import {
  BackHandler,
  I18nManager,
  Pressable,
  StyleSheet,
  View,
} from 'react-native';
import {Text} from './../../components/ui';
import testIDProps from '../../shared/commonUtil';
import {LIVENESS_CHECK} from '../../shared/constants';
import {SendVPScreen} from './SendVPScreen';
import {useSendVPScreen} from './SendVPScreenController';
import {useSendVcScreen} from './SendVcScreenController';
import {ShareSuccessScreen} from './ShareSuccessScreen';
import {VCMetadata} from '../../shared/VCMetadata';

const ScanStack = createNativeStackNavigator();

export const ScanLayout: React.FC = () => {
  const {t} = useTranslation('ScanScreen');
  const controller = useScanLayout();
  const sendVPScreenController = useSendVPScreen();
  const sendVcScreenController = useSendVcScreen();

  // Online shares name the verifier from its request; Bluetooth shares name the receiving device.
  const sharedWithName = controller.isVPSharingSuccess
    ? sendVPScreenController.verifierNameInTrustModal ?? t('unknownVerifier')
    : sendVcScreenController.receiverInfo?.name ||
      sendVcScreenController.receiverInfo?.deviceName ||
      t('unknownVerifier');
  const sharedCards = controller.isVPSharingSuccess
    ? Object.values(sendVPScreenController.userSelectedVCs ?? {})
        .flat()
        .map(vc => ({
          vcMetadata: vc.vcMetadata,
          selectedDisclosures:
            sendVPScreenController.userSelectedDisclosuresByVc?.[
              VCMetadata.fromVcMetadataString(vc.vcMetadata).getVcKey()
            ],
        }))
    : sendVcScreenController.selectedVc?.vcMetadata
    ? [{vcMetadata: sendVcScreenController.selectedVc.vcMetadata}]
    : [];
  if (
    controller.statusOverlay != null &&
    !controller.isAccepted &&
    !controller.isInvalid
  ) {
    const onClosingBanner = controller.isFaceVerifiedInVPSharing
      ? controller.VP_SHARE_CLOSE_BANNER
      : controller.CLOSE_BANNER;

    return (
      <SharingProgressPage
        title={controller.statusOverlay?.title}
        hint={controller.statusOverlay?.hint}
        isHintVisible={
          controller.isStayInProgress ||
          controller.isBleError ||
          controller.isSendingVc ||
          controller.isSendingVP
        }
        onCancel={controller.statusOverlay?.onButtonPress}
        onStayInProgress={controller.statusOverlay?.onStayInProgress}
        onRetry={controller.statusOverlay?.onRetry}
        notice={
          controller.isFaceIdentityVerified ||
          controller.isFaceVerifiedInVPSharing
            ? t('ScanScreen:postFaceCapture:captureSuccessMessage')
            : undefined
        }
        onCloseNotice={onClosingBanner}
      />
    );
  }

  return (
    <React.Fragment>
      <VerifyIdentityOverlay
        credential={controller.credential}
        verifiableCredentialData={controller.verifiableCredentialData}
        isVerifyingIdentity={controller.isVerifyingIdentity}
        onCancel={controller.CANCEL}
        onFaceValid={controller.FACE_VALID}
        onFaceInvalid={controller.FACE_INVALID}
        isInvalidIdentity={controller.isInvalidIdentity}
        onNavigateHome={controller.GOTO_HOME}
        onRetryVerification={controller.RETRY_VERIFICATION}
        isLivenessEnabled={LIVENESS_CHECK}
      />
      {/*
        All three screens are registered unconditionally, always — not gated behind the same
        controller.isReviewing/flowType/openID4VPFlowType values that ScanLayoutController's own
        useEffect (below) uses to decide when to navigate to them.

        That effect fires from a useNavigation() resolved one level up (against MainLayout's tab
        navigator, since this hook runs before this component renders its own ScanStack.Navigator
        below it), so a navigate('SendVPScreen'/'SendVcScreen') dispatched from it has to be
        resolved by drilling down into this stack's *own* registered route list. Conditionally
        registering a screen on the identical state the effect reacts to raced that dispatch
        against this render: react-navigation could resolve the navigate before the conditional
        Screen had (re)registered, and — unlike a queued action — a NAVIGATE to an unregistered
        route is simply dropped, not retried. That is what "liveness check doesn't come up" was:
        openID4VPMachine kept progressing (checkFaceAuthConsent, ...) while the screen meant to
        host it never mounted, logging "The action 'NAVIGATE' ... was not handled by any
        navigator. Do you have a screen named 'SendVPScreen'?".

        Registering every screen up front removes the race — react-navigation only mounts a
        registered Screen once it is actually pushed via navigate(), so this has no eager-render
        cost, same as the equivalent fix in AppLayout.tsx for Main/Notifications.
      */}
      <ScanStack.Navigator initialRouteName="ScanScreen">
        <ScanStack.Screen
          name={SCAN_ROUTES.ScanScreen}
          component={ScanScreen}
          options={{
            // ScanScreen draws its own dark header.
            headerShown: false,
            title: t('MainLayout:share'),
            headerTitleAlign: 'left',
            headerTitleStyle: Theme.Styles.scanLayoutHeaderTitle,
          }}
        />
        <ScanStack.Screen
          name={SCAN_ROUTES.SendVcScreen}
          component={SendVcScreen}
          options={{
            title: t('sharingVc'),
            headerTitleAlign: 'center',
            headerTitle: props => (
              <View style={Theme.Styles.sendVcHeaderContainer}>
                <Text style={Theme.Styles.scanLayoutHeaderTitle}>
                  {props.children}
                </Text>
              </View>
            ),
            headerBackVisible: false,
            headerRight: () =>
              !I18nManager.isRTL && (
                <Icon
                  name="close"
                  color={Theme.Colors.blackIcon}
                  onPress={controller.CANCEL}
                />
              ),
            headerLeft: () =>
              I18nManager.isRTL && (
                <Icon
                  name="close"
                  color={Theme.Colors.blackIcon}
                  onPress={controller.CANCEL}
                />
              ),
          }}
        />
        <ScanStack.Screen
          name={SCAN_ROUTES.SendVPScreen}
          component={SendVPScreen}
          options={{
            title: t('SendVPScreen:requester'),
            headerTitle: props => (
              <View style={Theme.Styles.sendVPHeaderContainer}>
                <Text style={Theme.Styles.sendVPHeaderTitle}>
                  {props.children}
                </Text>
                {controller.vpVerifierName && (
                  <Text style={Theme.Styles.sendVPHeaderSubTitle}>
                    {controller.vpVerifierName}
                  </Text>
                )}
              </View>
            ),
            headerBackVisible: false,
            headerRight: () =>
              !I18nManager.isRTL && (
                <Icon
                  name="close"
                  color={Theme.Colors.blackIcon}
                  onPress={controller.DISMISS}
                />
              ),
            headerLeft: () =>
              I18nManager.isRTL && (
                <Icon
                  name="close"
                  color={Theme.Colors.blackIcon}
                  onPress={controller.DISMISS}
                />
              ),
          }}
        />
      </ScanStack.Navigator>

      <ShareSuccessScreen
        isVisible={controller.isAccepted || controller.isVPSharingSuccess}
        verifierName={sharedWithName}
        sharedCards={sharedCards}
        wasAcceptedByVerifier={controller.isAccepted}
        isViaDeepLink={controller.isOVPViaDeepLink}
        goToHome={controller.GOTO_HOME}
        goToHistory={controller.GOTO_HISTORY}
      />

      {controller.errorStatusOverlay && (
        <AlertSheet
          testID="walletSideSharingErrorModal"
          isVisible={controller.errorStatusOverlay !== null}
          tone="fail"
          icon={colour => <AlertCircleIcon color={colour} />}
          title={controller.errorStatusOverlay.title}
          message={controller.errorStatusOverlay.message}
          primary={{
            testID: 'retry',
            title: t('status.bleError.retry'),
            onPress: controller.onRetry,
          }}
          secondary={{
            testID: 'home',
            title: t('backToWallet'),
            onPress: controller.GOTO_HOME,
          }}
          onRequestClose={controller.GOTO_HOME}
        />
      )}
    </React.Fragment>
  );
};

/**
 * Connecting to the verifier and sharing the card: a spinning share icon, the step's title and
 * hint, and the step's actions. After a face check, a closable notice says it passed.
 */
const SharingProgressPage: React.FC<{
  title?: string;
  hint?: string;
  isHintVisible?: boolean;
  onCancel?: () => void;
  onStayInProgress?: () => void;
  onRetry?: () => void;
  notice?: string;
  onCloseNotice: () => void;
}> = props => {
  const {t} = useTranslation('ScanScreen');
  const {c} = useRevampTheme();

  // Leaving mid-share is only through Cancel, as before.
  useEffect(() => {
    const sub = BackHandler.addEventListener('hardwareBackPress', () => true);
    return () => sub.remove();
  }, []);

  const showActions = props.isHintVisible || !!props.onCancel;

  return (
    <Page
      testID="loader-skeleton-loader-content"
      footer={
        showActions ? (
          <>
            {props.onRetry && (
              <PageButton
                testID="retry"
                title={t('status.retry')}
                onPress={props.onRetry}
              />
            )}
            {props.onStayInProgress && (
              <PageButton
                testID="stayInProgress"
                title={t('status.stayOnTheScreen')}
                variant="outline"
                onPress={props.onStayInProgress}
              />
            )}
            {props.onCancel && (
              <PageButton
                testID="cancel"
                title={t('common:cancel')}
                variant="link"
                onPress={props.onCancel}
              />
            )}
          </>
        ) : undefined
      }>
      {props.notice ? (
        <View
          {...testIDProps('faceVerificationSuccess')}
          accessibilityLiveRegion="polite"
          style={[sharingStyles.notice, {backgroundColor: c.tintPass}]}>
          <CheckIcon color={c.pass} />
          <ScaledText style={[sharingStyles.noticeText, {color: c.ink}]}>
            {props.notice}
          </ScaledText>
          <Pressable
            {...testIDProps('close')}
            accessibilityRole="button"
            accessibilityLabel={t('common:close')}
            hitSlop={12}
            onPress={props.onCloseNotice}>
            <CloseIcon color={c.inkMuted} size={18} />
          </Pressable>
        </View>
      ) : null}
      <View style={sharingStyles.center}>
        <SpinnerGlyph style={sharingStyles.spinner}>
          {colour => <ShareIcon color={colour} size={40} />}
        </SpinnerGlyph>
        <PageHeading
          testID="loaderTitle"
          title={props.title ?? ''}
          body={props.isHintVisible ? props.hint : undefined}
          size="medium"
        />
      </View>
    </Page>
  );
};

const sharingStyles = StyleSheet.create({
  notice: {
    marginTop: 12,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    paddingVertical: 12,
    paddingHorizontal: 14,
    borderRadius: radii.chip,
  },
  noticeText: {flex: 1, fontFamily: fonts.medium, fontSize: 14, lineHeight: 20},
  center: {flex: 1, alignItems: 'center', justifyContent: 'center'},
  spinner: {marginBottom: 32},
});
