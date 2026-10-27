import React, {useCallback, useEffect, useRef, useState} from 'react';
import {Camera} from 'expo-camera';
import {
  Animated,
  Easing,
  I18nManager,
  Linking,
  Pressable,
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
import {fonts} from '../revamp/tokens';
import {useRevampTheme} from '../revamp/useRevampTheme';
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
  const hasStartedRef = useRef(false);
  const [isCheckingPermission, setIsCheckingPermission] = useState(true);
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
        settle(props.onInvalid);
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
        settle(props.onInvalid);
        return;
      }

      if (!result.probeImageBase64) {
        console.warn('[SnapKYC] Liveness passed but probe image is missing');
        settle(props.onInvalid);
        return;
      }

      const outcome = await compareProbeWithVcFace(
        result.probeImageBase64,
        vcImages,
      );

      if (outcome === 'mismatch') {
        console.warn('[SnapKYC] Face did not match credential portrait');
        settle(props.onInvalid);
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
      settle(props.onInvalid);
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
        setIsCheckingPermission(false);
        if (!requested.granted) {
          setIsPermissionDenied(true);
          return;
        }
      } else {
        setIsCheckingPermission(false);
      }

      await runLiveness();
    })();
  }, [runLiveness]);

  if (isCheckingPermission || isLaunching) {
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

  return <Column fill />;
};

interface SnapKycFaceScannerProps {
  vcImages: string[];
  onValid: () => void;
  onInvalid: () => void;
  onCancel: () => void;
}

const BADGE_SIZE = 120;
const RING_WIDTH = 4;

/** "Verifying your face": shown before the camera opens and while the face is matched. */
const FaceVerifyingView: React.FC<{onCancel: () => void}> = ({onCancel}) => {
  const {t} = useTranslation('FaceScanner');
  const {c} = useRevampTheme();
  const insets = useSafeAreaInsets();

  return (
    <View
      {...testIDProps('faceVerifying')}
      style={[
        styles.screen,
        {backgroundColor: c.canvas, paddingTop: Math.max(insets.top, 24)},
      ]}>
      <View style={styles.header}>
        <Pressable
          {...testIDProps('back')}
          onPress={onCancel}
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

      <View style={styles.body}>
        <SpinnerBadge />
        <ScaledText
          accessibilityRole="header"
          style={[styles.heading, {color: c.ink}]}>
          {t('verifyingTitle')}
        </ScaledText>
        <ScaledText style={[styles.message, {color: c.inkMuted}]}>
          {t('verifyingMessage')}
        </ScaledText>
      </View>

      <Pressable
        {...testIDProps('cancel')}
        onPress={onCancel}
        accessibilityRole="button"
        style={({pressed}) => [styles.cancel, {opacity: pressed ? 0.6 : 1}]}>
        <ScaledText style={[styles.cancelLabel, {color: c.ink}]}>
          {t('cancel')}
        </ScaledText>
      </Pressable>
      <ScaledText
        maxFontSizeMultiplier={1.3}
        style={[styles.footer, {color: c.inkMuted}]}>
        {t('poweredBy')}
      </ScaledText>
    </View>
  );
};

/** Face outline in a tinted circle, with a quarter arc running round it. */
const SpinnerBadge: React.FC = () => {
  const {c, reduceMotion} = useRevampTheme();
  const rotation = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    if (reduceMotion) {
      return;
    }
    const spin = Animated.loop(
      Animated.timing(rotation, {
        toValue: 1,
        duration: 1100,
        easing: Easing.linear,
        useNativeDriver: true,
      }),
    );
    spin.start();
    return () => spin.stop();
  }, [reduceMotion, rotation]);

  const center = BADGE_SIZE / 2;
  const radius = (BADGE_SIZE - RING_WIDTH) / 2;
  const circumference = 2 * Math.PI * radius;
  const rotate = rotation.interpolate({
    inputRange: [0, 1],
    outputRange: ['0deg', '360deg'],
  });

  return (
    <View
      style={styles.badge}
      accessibilityRole="progressbar"
      importantForAccessibility="no-hide-descendants">
      <Svg width={BADGE_SIZE} height={BADGE_SIZE}>
        <Circle
          cx={center}
          cy={center}
          r={radius}
          fill={c.tintAzure}
          stroke={c.azureInk}
          strokeOpacity={0.12}
          strokeWidth={RING_WIDTH}
        />
      </Svg>
      <Animated.View style={[StyleSheet.absoluteFill, {transform: [{rotate}]}]}>
        <Svg width={BADGE_SIZE} height={BADGE_SIZE}>
          <Circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke={c.ink}
            strokeWidth={RING_WIDTH}
            strokeLinecap="round"
            strokeDasharray={`${circumference / 4} ${circumference}`}
          />
        </Svg>
      </Animated.View>
      <View style={[StyleSheet.absoluteFill, styles.badgeCenter]}>
        <Svg
          width={44}
          height={44}
          viewBox="0 0 24 24"
          fill="none"
          stroke={c.ink}
          strokeWidth={1.6}
          strokeLinecap="round"
          strokeLinejoin="round">
          <Path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2" />
          <Path d="M9 9v1.5M15 9v1.5M12 9v4l-1 .5M8.5 15.5a5 5 0 0 0 7 0" />
        </Svg>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  screen: {flex: 1, alignSelf: 'stretch', paddingBottom: 16},
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
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 24,
  },
  badge: {
    width: BADGE_SIZE,
    height: BADGE_SIZE,
    borderRadius: BADGE_SIZE / 2,
    marginBottom: 32,
  },
  badgeCenter: {alignItems: 'center', justifyContent: 'center'},
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
  cancel: {minHeight: 48, alignItems: 'center', justifyContent: 'center'},
  cancelLabel: {fontFamily: fonts.semibold, fontSize: 16},
  footer: {
    fontFamily: fonts.regular,
    fontSize: 12,
    textAlign: 'center',
    marginTop: 12,
  },
});
