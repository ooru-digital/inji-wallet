import React, {useState} from 'react';
import {Image, Modal, Pressable, StyleSheet, View} from 'react-native';
import {Icon} from 'react-native-elements';
import {useTranslation} from 'react-i18next';
import {Text} from './ui';
import {Theme} from './ui/styleUtils';
import {SvgImage} from './ui/svg';
import testIDProps from '../shared/commonUtil';

const QrImage: React.FC<{uri: string; size: number}> = ({uri, size}) => (
  <Image
    source={{uri}}
    style={{width: size, height: size, borderRadius: 10}}
    resizeMode="contain"
  />
);

export const IssuerQrCodeImage: React.FC<IssuerQrCodeImageProps> = props => {
  const {qrCodeUrl} = props;
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
          <QrImage uri={qrCodeUrl} size={90} />
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
            onPress={() => {}}
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
            <QrImage uri={qrCodeUrl} size={250} />
          </Pressable>
        </Pressable>
      </Modal>
    </>
  );
};

const styles = StyleSheet.create({
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
}
