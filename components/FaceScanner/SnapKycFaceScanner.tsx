import React, {useCallback, useEffect, useRef, useState} from 'react';
import {Camera} from 'expo-camera';
import {
  I18nManager,
  Linking,
  Modal as RNModal,
  Pressable,
  ScrollView,
  StyleSheet,
  View,
} from 'react-native';
import {useTranslation} from 'react-i18next';
import {useSafeAreaInsets} from 'react-native-safe-area-context';
import Svg, {Circle, Path} from 'react-native-svg';

import {Column, Text, Button} from '../ui';
import {Theme} from '../ui/styleUtils';
import {ScaledText} from '../revamp/ScaledText';
import {ChevronIcon} from '../revamp/Icons';
import {fonts, radii} from '../revamp/tokens';
import {useRevampTheme} from '../revamp/useRevampTheme';
import {SpinnerGlyph} from '../revamp/Page';
import testIDProps from '../../shared/commonUtil';
import {
  SNAPKYC_DEBUG_SKIP_FACE_IMAGE_ENABLED,
  SNAPKYC_RELAYING_PARTY_NAME_VALUE,
} from '../../shared/constants';
import {
  closeSdkFaceMatch,
  startSnapKycLiveness,
} from '../../shared/snapKyc/SnapKycLiveness';
import {compareProbeWithVcFace} from '../../shared/snapKyc/compareProbeWithVcFace';
import {
  extractReferenceFaceBase64,
  resolvePortraitImages,
} from '../../shared/snapKyc/compressFaceImage';

/**
 * Runs the BioChq face SDK's liveness check (Android and iOS), then matches the live probe against
 * the credential portrait with the same SDK's face match.
 * The liveness SDK shows its own camera screen; around it this shows the "Verifying your face" page.
 */
export const SnapKycFaceScanner: React.FC<SnapKycFaceScannerProps> = props => {
  const {t} = useTranslation('FaceScanner');
  const {c} = useRevampTheme();
  const hasStartedRef = useRef(false);
  const [isPermissionDenied, setIsPermissionDenied] = useState(false);
  const [isLaunching, setIsLaunching] = useState(false);

  // Only the first outcome counts: after Cancel (or the screen closing) the match still finishes
  // in the background, and its result must not reach the share flow.
  const settledRef = useRef(false);
  const settle = useCallback((done: () => void) => {
    if (settledRef.current) {
      return;
    }
    settledRef.current = true;
    done();
  }, []);
  useEffect(() => {
    settledRef.current = false;
    return () => {
      settledRef.current = true;
    };
  }, []);

  const runLiveness = useCallback(async () => {
    setIsLaunching(true);

    try {
      // Photos given as a link are downloaded first, so they can be compared at all.
      const vcImages = await resolvePortraitImages(props.vcImages);
      // The credential has a photo but it could not be fetched (offline, expired link): the face
      // cannot be verified, and accepting liveness alone would let any face through.
      if (props.vcImages.length > 0 && vcImages.length === 0) {
        console.warn('[SnapKYC] Credential portrait could not be loaded');
        settle(() => props.onInvalid('portraitUnavailable'));
        return;
      }

      const referenceFaceBase64 = SNAPKYC_DEBUG_SKIP_FACE_IMAGE_ENABLED
        ? undefined
        : extractReferenceFaceBase64(vcImages);

      const result = await startSnapKycLiveness(
        SNAPKYC_RELAYING_PARTY_NAME_VALUE,
        {
          referenceFaceBase64,
          skipFaceImage: SNAPKYC_DEBUG_SKIP_FACE_IMAGE_ENABLED,
        },
      );

      if (!result.isGenuine || result.timedOut) {
        console.warn('[SnapKYC] Liveness did not pass', {
          verdict: result.verdict,
          timedOut: result.timedOut,
          errorMessage: result.errorMessage ?? null,
        });
        settle(() => props.onInvalid('notVerified'));
        return;
      }

      if (!result.probeImageBase64) {
        console.warn('[SnapKYC] Liveness passed but probe image is missing');
        settle(() => props.onInvalid('notVerified'));
        return;
      }

      const outcome = await compareProbeWithVcFace(
        result.probeImageBase64,
        vcImages,
      );

      if (outcome === 'mismatch') {
        console.warn('[SnapKYC] Face did not match credential portrait');
        settle(() => props.onInvalid('mismatch'));
        return;
      }

      /**
       * `unusable` — no decodable portrait to compare against. mDOCs are not required to carry
       * one, so a genuine liveness verdict is the strongest assertion available and blocking here
       * would lock out a holder whose credential simply has no photo.
       */
      if (outcome === 'unusable') {
        console.warn(
          '[SnapKYC] No comparable credential portrait — accepting liveness verdict alone',
        );
      }

      settle(props.onValid);
    } catch (error: any) {
      console.error('[SnapKYC] Liveness session error', {
        code: error?.code,
        message: error?.message,
        userInfo: error?.userInfo,
      });

      if (error?.code === 'E_CANCELLED') {
        settle(props.onCancel);
        return;
      }
      settle(() => props.onInvalid('notVerified'));
    } finally {
      // The SDK's matcher starts loading with the liveness check; free it however it ended.
      closeSdkFaceMatch();
      setIsLaunching(false);
    }
  }, [props, settle]);

  useEffect(() => {
    if (hasStartedRef.current) {
      return;
    }

    hasStartedRef.current = true;

    (async () => {
      const permission = await Camera.getCameraPermissionsAsync();
      if (!permission.granted) {
        const requested = await Camera.requestCameraPermissionsAsync();
        if (!requested.granted) {
          setIsPermissionDenied(true);
          return;
        }
      }

      await runLiveness();
    })();
  }, [runLiveness]);

  // Only once the check has started: while the system's camera prompt is up, "Verifying your
  // face" would be shown behind it before anything is being verified.
  if (isLaunching) {
    return <FaceVerifyingView onCancel={() => settle(props.onCancel)} />;
  }

  if (isPermissionDenied) {
    return (
      <Column padding="24" fill align="space-between">
        <Text
          testID="missingPermissionText"
          align="center"
          color={Theme.Colors.errorMessage}>
          {t('missingPermissionText')}
        </Text>
        <Button
          testID="allowCameraButton"
          title={t('allowCameraButton')}
          onPress={() => Linking.openSettings()}
        />
      </Column>
    );
  }

  // The camera permission check, and the moment after the check ends while the page closes.
  return <View style={[styles.fill, {backgroundColor: c.canvas}]} />;
};

/**
 * Why the face check failed, so the failure page can say what to do: `mismatch` (the face is not
 * the credential holder's), `notVerified` (liveness failed or timed out, or the check itself
 * errored) or `portraitUnavailable` (the credential's photo could not be loaded, e.g. offline).
 */
export type FaceFailureReason =
  | 'mismatch'
  | 'notVerified'
  | 'portraitUnavailable';

interface SnapKycFaceScannerProps {
  vcImages: string[];
  onValid: () => void;
  onInvalid: (reason: FaceFailureReason) => void;
  onCancel: () => void;
}

const BADGE_SIZE = 120;

/** "Verifying your face": shown before the camera opens and while the face is matched. */
const FaceVerifyingView: React.FC<{onCancel: () => void}> = ({onCancel}) => {
  const {t} = useTranslation('FaceScanner');
  const {c} = useRevampTheme();

  return (
    <FaceVerificationLayout
      testID="faceVerifying"
      onBack={onCancel}
      actions={<TextAction label={t('cancel')} onPress={onCancel} />}>
      <SpinnerBadge />
      <ScaledText
        accessibilityRole="header"
        style={[styles.heading, {color: c.ink}]}>
        {t('verifyingTitle')}
      </ScaledText>
      <ScaledText style={[styles.message, {color: c.inkMuted}]}>
        {t('verifyingMessage')}
      </ScaledText>
    </FaceVerificationLayout>
  );
};

/** "We couldn't verify your face": tips, then a retry. Shown full screen over the share flow. */
export const FaceVerificationFailedView: React.FC<{
  isVisible: boolean;
  reason: FaceFailureReason;
  onRetry: () => void;
  onCancel: () => void;
}> = ({isVisible, reason, onRetry, onCancel}) => {
  const {t} = useTranslation('FaceScanner');
  const {c} = useRevampTheme();
  const insets = useSafeAreaInsets();
  // The tips are about the selfie; they don't help when the card's photo could not be loaded.
  const tips =
    reason === 'portraitUnavailable'
      ? []
      : [t('tipLighting'), t('tipCoverings'), t('tipSteady')];
  const message =
    reason === 'mismatch'
      ? t('notMatchedMessage')
      : reason === 'portraitUnavailable'
      ? t('portraitUnavailableMessage')
      : t('notVerifiedMessage');

  return (
    <RNModal
      visible={isVisible}
      animationType="slide"
      statusBarTranslucent
      onRequestClose={onCancel}>
      <View
        style={[
          styles.fill,
          {backgroundColor: c.canvas, paddingBottom: insets.bottom},
        ]}>
        <FaceVerificationLayout
          testID="shareWithSelfieError"
          onBack={onCancel}
          actions={
            <>
              <Pressable
                {...testIDProps('retry')}
                onPress={onRetry}
                accessibilityRole="button"
                style={({pressed}) => [
                  styles.primary,
                  {backgroundColor: c.primary, opacity: pressed ? 0.85 : 1},
                ]}>
                <ScaledText style={[styles.primaryLabel, {color: c.onPrimary}]}>
                  {t('tryAgain')}
                </ScaledText>
              </Pressable>
              <TextAction
                testID="home"
                label={t('cancel')}
                onPress={onCancel}
              />
            </>
          }>
          <View
            style={[
              styles.badge,
              styles.badgeCenter,
              {backgroundColor: c.tintFail},
            ]}
            importantForAccessibility="no-hide-descendants">
            <Svg
              width={44}
              height={44}
              viewBox="0 0 24 24"
              fill="none"
              stroke={c.fail}
              strokeWidth={2}
              strokeLinecap="round">
              <Circle cx={12} cy={12} r={10} />
              <Path d="M12 7v6M12 16.5v.5" />
            </Svg>
          </View>
          <ScaledText
            accessibilityRole="header"
            style={[styles.heading, {color: c.ink}]}>
            {t('notMatchedTitle')}
          </ScaledText>
          <ScaledText style={[styles.message, {color: c.inkMuted}]}>
            {message}
          </ScaledText>
          {tips.length > 0 && (
            <View
              style={[
                styles.tips,
                {backgroundColor: c.card, borderColor: c.line},
              ]}>
              {tips.map((tip, index) => (
                <View
                  key={index}
                  style={[
                    styles.tip,
                    index > 0 && {
                      borderTopWidth: StyleSheet.hairlineWidth,
                      borderTopColor: c.line,
                    },
                  ]}>
                  <View
                    style={[styles.tipNumber, {backgroundColor: c.tintAzure}]}>
                    <ScaledText
                      maxFontSizeMultiplier={1.3}
                      style={[styles.tipNumberText, {color: c.ink}]}>
                      {index + 1}
                    </ScaledText>
                  </View>
                  <ScaledText style={[styles.tipText, {color: c.ink}]}>
                    {tip}
                  </ScaledText>
                </View>
              ))}
            </View>
          )}
        </FaceVerificationLayout>
      </View>
    </RNModal>
  );
};

/** The header with a back arrow, the page's actions at the bottom and the BioChq footer. */
const FaceVerificationLayout: React.FC<{
  testID: string;
  onBack: () => void;
  actions: React.ReactNode;
  children: React.ReactNode;
}> = ({testID, onBack, actions, children}) => {
  const {t} = useTranslation('FaceScanner');
  const {c} = useRevampTheme();
  const insets = useSafeAreaInsets();

  return (
    <View
      {...testIDProps(testID)}
      style={[
        styles.fill,
        styles.screen,
        {backgroundColor: c.canvas, paddingTop: Math.max(insets.top, 24)},
      ]}>
      <View style={styles.header}>
        <Pressable
          {...testIDProps('back')}
          onPress={onBack}
          hitSlop={12}
          accessibilityRole="button"
          accessibilityLabel={t('back')}
          style={styles.back}>
          <ChevronIcon
            direction={I18nManager.isRTL ? 'right' : 'left'}
            color={c.ink}
            size={26}
          />
        </Pressable>
        <ScaledText
          numberOfLines={1}
          maxFontSizeMultiplier={1.3}
          style={[styles.title, {color: c.ink}]}>
          {t('faceVerificationTitle')}
        </ScaledText>
      </View>

      <ScrollView
        style={styles.fill}
        contentContainerStyle={styles.body}
        showsVerticalScrollIndicator={false}>
        {children}
      </ScrollView>

      <View style={styles.actions}>{actions}</View>
      <ScaledText
        maxFontSizeMultiplier={1.3}
        style={[styles.footer, {color: c.inkMuted}]}>
        {t('poweredBy')}
      </ScaledText>
    </View>
  );
};

const TextAction: React.FC<{
  testID?: string;
  label: string;
  onPress: () => void;
}> = ({testID = 'cancel', label, onPress}) => {
  const {c} = useRevampTheme();
  return (
    <Pressable
      {...testIDProps(testID)}
      onPress={onPress}
      accessibilityRole="button"
      style={({pressed}) => [styles.cancel, {opacity: pressed ? 0.6 : 1}]}>
      <ScaledText style={[styles.cancelLabel, {color: c.ink}]}>
        {label}
      </ScaledText>
    </Pressable>
  );
};

/** Face outline in the spinning ring. */
const SpinnerBadge: React.FC = () => (
  <SpinnerGlyph size={BADGE_SIZE} style={styles.badgeSpacing}>
    {colour => (
      <Svg
        width={44}
        height={44}
        viewBox="0 0 24 24"
        fill="none"
        stroke={colour}
        strokeWidth={1.6}
        strokeLinecap="round"
        strokeLinejoin="round">
        <Path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2" />
        <Path d="M9 9v1.5M15 9v1.5M12 9v4l-1 .5M8.5 15.5a5 5 0 0 0 7 0" />
      </Svg>
    )}
  </SpinnerGlyph>
);

const styles = StyleSheet.create({
  fill: {flex: 1, alignSelf: 'stretch'},
  screen: {paddingBottom: 16},
  header: {height: 56, justifyContent: 'center', paddingHorizontal: 56},
  back: {
    position: 'absolute',
    start: 16,
    width: 40,
    height: 40,
    alignItems: 'center',
    justifyContent: 'center',
  },
  title: {
    fontFamily: fonts.semibold,
    fontSize: 18,
    lineHeight: 24,
    textAlign: 'center',
  },
  body: {
    flexGrow: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 24,
  },
  badge: {
    width: BADGE_SIZE,
    height: BADGE_SIZE,
    borderRadius: BADGE_SIZE / 2,
    marginBottom: 32,
  },
  badgeCenter: {alignItems: 'center', justifyContent: 'center'},
  badgeSpacing: {marginBottom: 32},
  heading: {
    fontFamily: fonts.bold,
    fontSize: 24,
    lineHeight: 32,
    textAlign: 'center',
  },
  message: {
    fontFamily: fonts.regular,
    fontSize: 15,
    lineHeight: 22,
    textAlign: 'center',
    marginTop: 12,
    maxWidth: 320,
  },
  tips: {
    alignSelf: 'stretch',
    marginTop: 28,
    borderWidth: 1,
    borderRadius: radii.surface,
    paddingHorizontal: 16,
  },
  tip: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 14,
    paddingVertical: 14,
  },
  tipNumber: {
    width: 28,
    height: 28,
    borderRadius: 14,
    alignItems: 'center',
    justifyContent: 'center',
  },
  tipNumberText: {fontFamily: fonts.semibold, fontSize: 13},
  tipText: {flex: 1, fontFamily: fonts.medium, fontSize: 15, lineHeight: 21},
  actions: {paddingHorizontal: 24, gap: 4},
  primary: {
    minHeight: 52,
    borderRadius: radii.pill,
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: 24,
  },
  primaryLabel: {fontFamily: fonts.semibold, fontSize: 16},
  cancel: {minHeight: 48, alignItems: 'center', justifyContent: 'center'},
  cancelLabel: {fontFamily: fonts.semibold, fontSize: 16},
  footer: {
    fontFamily: fonts.regular,
    fontSize: 12,
    textAlign: 'center',
    marginTop: 12,
  },
});
