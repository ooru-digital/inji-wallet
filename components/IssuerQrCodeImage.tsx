import React, {useState} from 'react';
import {
  ActivityIndicator,
  Image,
  Modal,
  Pressable,
  StyleSheet,
  View,
} from 'react-native';
import {Icon} from 'react-native-elements';
import {useTranslation} from 'react-i18next';
import {Text} from './ui';
import {Theme} from './ui/styleUtils';
import {SvgImage} from './ui/svg';
import testIDProps from '../shared/commonUtil';

/**
 * A remote image renders as an empty box both while it loads and when it fails, so neither state
 * is visible on its own. The spinner covers the loading state; a failure is reported to the caller
 * (with the URL that failed) so it can show something that works instead.
 */
const QrImage: React.FC<{
  uri: string;
  size: number;
  onError?: (uri: string) => void;
}> = ({uri, size, onError}) => {
  const [isLoading, setIsLoading] = useState(true);
  return (
    <View style={{width: size, height: size}}>
      <Image
        source={{uri}}
        style={{width: size, height: size, borderRadius: 10}}
        resizeMode="contain"
        onLoadStart={() => setIsLoading(true)}
        // Fires after a successful load and after a failed one.
        onLoadEnd={() => setIsLoading(false)}
        onError={() => onError?.(uri)}
      />
      {isLoading && (
        <ActivityIndicator
          testID="issuerQrCodeLoader"
          style={StyleSheet.absoluteFill}
          color={Theme.Colors.Loading}
        />
      )}
    </View>
  );
};

/**
 * Holds the QR slot, at the same size as the image tile, while the fresh issuer QR is still being
 * looked up. Deliberately not a QR: anything scannable here could be the wrong one.
 */
export const IssuerQrCodePlaceholder: React.FC = () => (
  <View testID="issuerQrCodePlaceholder" style={Theme.QrCodeStyles.QrView}>
    <View style={styles.placeholder}>
      <ActivityIndicator color={Theme.Colors.Loading} />
    </View>
  </View>
);

export const IssuerQrCodeImage: React.FC<IssuerQrCodeImageProps> = props => {
  const {qrCodeUrl, onLoadError} = props;
  const {t} = useTranslation('VcDetails');
  const [isModalVisible, setIsModalVisible] = useState(false);

  const closeModal = () => setIsModalVisible(false);

  return (
    <>
      <View testID="issuerQrCodeView" style={Theme.QrCodeStyles.QrView}>
        <Pressable
          {...testIDProps('issuerQrCodePressable')}
          accessible={false}
          onPress={() => setIsModalVisible(true)}>
          {/* Keyed by URL so each load gets its own instance: a late error from a previous URL
              can't be reported against the current one, and the spinner restarts per URL. */}
          <QrImage
            key={qrCodeUrl}
            uri={qrCodeUrl}
            size={90}
            onError={onLoadError}
          />
          <View
            testID="magnifierZoom"
            style={[Theme.QrCodeStyles.magnifierZoom]}>
            {SvgImage.MagnifierZoom()}
          </View>
        </Pressable>
      </View>

      <Modal
        visible={isModalVisible}
        transparent
        animationType="fade"
        onRequestClose={closeModal}>
        <Pressable
          {...testIDProps('issuerQrDialogBackdrop')}
          style={styles.backdrop}
          onPress={closeModal}>
          <Pressable
            style={styles.dialogCard}
            onPress={() => {
              // Keep taps inside the dialog from reaching the backdrop.
            }}
            accessible={false}>
            <Pressable
              {...testIDProps('closeIssuerQrDialog')}
              style={styles.dialogCloseButton}
              onPress={closeModal}>
              <Icon
                name="close"
                type="material"
                size={28}
                color={Theme.Colors.GrayIcon}
              />
            </Pressable>
            <Text
              testID="issuerQrCodeHeader"
              weight="semibold"
              margin="0 0 16 0">
              {t('qrCodeHeader')}
            </Text>
            <QrImage
              key={qrCodeUrl}
              uri={qrCodeUrl}
              size={250}
              onError={onLoadError}
            />
          </Pressable>
        </Pressable>
      </Modal>
    </>
  );
};

const styles = StyleSheet.create({
  placeholder: {
    width: 90,
    height: 90,
    alignItems: 'center',
    justifyContent: 'center',
  },
  backdrop: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.5)',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 24,
  },
  dialogCard: {
    width: '100%',
    maxWidth: 340,
    backgroundColor: Theme.Colors.whiteBackgroundColor,
    borderRadius: 20,
    paddingHorizontal: 20,
    paddingTop: 24,
    paddingBottom: 28,
    alignItems: 'center',
  },
  dialogCloseButton: {
    position: 'absolute',
    top: 10,
    right: 10,
    padding: 10,
  },
});

interface IssuerQrCodeImageProps {
  qrCodeUrl: string;
  /** Called with the URL that failed, so the caller can fall back to another QR. */
  onLoadError?: (uri: string) => void;
}
