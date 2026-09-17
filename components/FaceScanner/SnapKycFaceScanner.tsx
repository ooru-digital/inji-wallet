import React, {useCallback, useEffect, useRef, useState} from 'react';
import {Camera} from 'expo-camera';
import {Linking} from 'react-native';
import {useTranslation} from 'react-i18next';

import {Column, Text, Button} from '../ui';
import {Theme} from '../ui/styleUtils';
import {Loader} from '../ui/Loader';
import {
  SNAPKYC_DEBUG_SKIP_FACE_IMAGE_ENABLED,
  SNAPKYC_RELAYING_PARTY_NAME_VALUE,
} from '../../shared/constants';
import {startSnapKycLiveness} from '../../shared/snapKyc/SnapKycLiveness';
import {compareProbeWithVcFace} from '../../shared/snapKyc/compareProbeWithVcFace';
import {extractReferenceFaceBase64} from '../../shared/snapKyc/compressFaceImage';

/**
 * Runs the SnapKYC native liveness activity, then matches the live probe against the credential
 * portrait. Renders almost nothing itself — the SDK takes over with its own full-screen Activity.
 */
export const SnapKycFaceScanner: React.FC<SnapKycFaceScannerProps> = props => {
  const {t} = useTranslation('FaceScanner');
  const hasStartedRef = useRef(false);
  const [isCheckingPermission, setIsCheckingPermission] = useState(true);
  const [isPermissionDenied, setIsPermissionDenied] = useState(false);
  const [isLaunching, setIsLaunching] = useState(false);

  const runLiveness = useCallback(async () => {
    setIsLaunching(true);

    try {
      const referenceFaceBase64 = SNAPKYC_DEBUG_SKIP_FACE_IMAGE_ENABLED
        ? undefined
        : extractReferenceFaceBase64(props.vcImages);

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
        props.onInvalid();
        return;
      }

      if (!result.probeImageBase64) {
        console.warn('[SnapKYC] Liveness passed but probe image is missing');
        props.onInvalid();
        return;
      }

      const outcome = await compareProbeWithVcFace(
        result.probeImageBase64,
        props.vcImages,
      );

      if (outcome === 'mismatch') {
        console.warn('[SnapKYC] Face did not match credential portrait');
        props.onInvalid();
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

      props.onValid();
    } catch (error: any) {
      console.error('[SnapKYC] Liveness session error', {
        code: error?.code,
        message: error?.message,
        userInfo: error?.userInfo,
      });

      if (error?.code === 'E_CANCELLED') {
        props.onCancel();
        return;
      }
      props.onInvalid();
    } finally {
      setIsLaunching(false);
    }
  }, [props]);

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
    return (
      <Loader
        title={t('faceProcessingInfo')}
        hint={t('livenessCaptureGuide')}
        isHintVisible
      />
    );
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
