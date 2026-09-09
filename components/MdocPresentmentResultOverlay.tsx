import React from 'react';
import {Modal, StyleSheet, View} from 'react-native';
import {Icon} from 'react-native-elements';
import {useTranslation} from 'react-i18next';
import {useSafeAreaInsets} from 'react-native-safe-area-context';
import {Button, Centered, Column, Text} from './ui';
import {Theme} from './ui/styleUtils';

/**
 * Full-screen result page shown after the wallet finishes acting on a proximity
 * verifier's DeviceRequest — success (DeviceResponse sent) or failure (native
 * approve call threw). Replaces the previous behaviour of just dropping the user
 * back on the QR page with no feedback either way.
 */
export const MdocPresentmentResultOverlay: React.FC<
  MdocPresentmentResultOverlayProps
> = props => {
  const {t} = useTranslation('VcDetails');
  const insets = useSafeAreaInsets();
  const isSuccess = props.result === 'success';

  return (
    <Modal
      visible={props.result != null}
      animationType="slide"
      presentationStyle="fullScreen"
      onRequestClose={props.onGoHome}>
      <Column fill backgroundColor={Theme.Colors.whiteBackgroundColor}>
        <Centered fill style={styles.content}>
          <View
            style={[
              styles.iconBadge,
              isSuccess ? styles.successBadge : styles.failureBadge,
            ]}>
            <Icon
              name={isSuccess ? 'check' : 'close'}
              type="material"
              size={56}
              color={Theme.Colors.whiteText}
            />
          </View>
          <Text
            testID="mdocResultTitle"
            weight="bold"
            size="large"
            align="center"
            color={Theme.Colors.Details}
            margin="24 0 8 0">
            {isSuccess
              ? t('mdocConsent.shareSuccessTitle')
              : t('mdocConsent.shareFailureTitle')}
          </Text>
          <Text
            testID="mdocResultMessage"
            align="center"
            color={Theme.Colors.GrayIcon}
            style={styles.message}>
            {isSuccess
              ? t('mdocConsent.shareSuccessMessage')
              : t('mdocConsent.shareFailureMessage')}
          </Text>
        </Centered>
        <Column
          style={[styles.footer, {paddingBottom: Math.max(insets.bottom, 16)}]}>
          <Button
            testID={isSuccess ? 'mdocResultGoHome' : 'mdocResultRetry'}
            type="gradient"
            title={t('mdocConsent.goToHome')}
            onPress={props.onGoHome}
          />
        </Column>
      </Column>
    </Modal>
  );
};

const styles = StyleSheet.create({
  content: {
    paddingHorizontal: 32,
  },
  iconBadge: {
    width: 96,
    height: 96,
    borderRadius: 48,
    justifyContent: 'center',
    alignItems: 'center',
  },
  successBadge: {
    backgroundColor: Theme.Colors.VerifiedIcon,
  },
  failureBadge: {
    backgroundColor: Theme.Colors.errorMessage,
  },
  message: {
    maxWidth: 280,
  },
  footer: {
    paddingHorizontal: 20,
    paddingTop: 12,
  },
});

export interface MdocPresentmentResultOverlayProps {
  result: 'success' | 'failure' | null;
  // Both the success and failure pages route to Home now, so a single callback
  // covers both buttons.
  onGoHome: () => void;
}
