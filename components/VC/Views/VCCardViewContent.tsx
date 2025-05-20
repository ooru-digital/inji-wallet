import React from 'react';
import {ImageBackground, Pressable, Image, View} from 'react-native';
import {getLocalizedField} from '../../../i18n';
import {VCMetadata} from '../../../shared/VCMetadata';
import {KebabPopUp} from '../../KebabPopUp';
import {Credential} from '../../../machines/VerifiableCredential/VCMetaMachine/vc';
import {Column, Row} from '../../ui';
import {Theme} from '../../ui/styleUtils';
import {CheckBox, Icon} from 'react-native-elements';
import {SvgImage} from '../../ui/svg';
import {VcItemContainerProfileImage} from '../../VcItemContainerProfileImage';
import {
  isVCLoaded,
  getBackgroundColour,
  getBackgroundImage,
  DisplayName,
} from '../common/VCUtils';
import {VCItemFieldValue} from '../common/VCItemField';
import {WalletBinding} from '../../../screens/Home/MyVcs/WalletBinding';
import {VCVerification} from '../../VCVerification';
import {isActivationNeeded} from '../../../shared/openId4VCI/Utils';
import {VCItemContainerFlowType} from '../../../shared/Utils';
import {RemoveVcWarningOverlay} from '../../../screens/Home/MyVcs/RemoveVcWarningOverlay';
import {HistoryTab} from '../../../screens/Home/MyVcs/HistoryTab';
import {getTextColor} from '../common/VCUtils';
import {useCopilot} from 'react-native-copilot';
import {useTranslation} from 'react-i18next';
import {getIdType} from '../common/VCUtils';

export const VCCardViewContent: React.FC<VCItemContentProps> = props => {
  const vcSelectableButton =
    props.selectable &&
    (props.flow === VCItemContainerFlowType.VP_SHARE ? (
      <CheckBox
        checked={props.selected}
        checkedIcon={SvgImage.selectedCheckBox()}
        uncheckedIcon={
          <Icon
            name="check-box-outline-blank"
            color={Theme.Colors.uncheckedIcon}
            size={22}
          />
        }
        onPress={() => props.onPress()}
      />
    ) : (
      <CheckBox
        checked={props.selected}
        checkedIcon={
          <Icon name="check-circle" type="material" color={Theme.Colors.Icon} />
        }
        uncheckedIcon={
          <Icon
            name="radio-button-unchecked"
            color={Theme.Colors.uncheckedIcon}
          />
        }
        onPress={() => props.onPress()}
      />
    ));
  const issuerLogo = props.verifiableCredentialData.issuerLogo;
  const faceImage = props.verifiableCredentialData.face;
  const {start} = useCopilot();
  const {t} = useTranslation();
  const idType = getIdType(props.wellknown);
  const maskCredentialId = (credentialId: string) => {
    if (!credentialId) return '';
    return credentialId.replace(/.(?=.{4})/g, '*'); 
  };

  function credentialType(text: string): string {
    if (!text) return '';
    const lowerCaseWords = ['of'];
  
    return text
      .replace(/([a-z])([A-Z])/g, '$1 $2')
      .split(' ')
      .map((word, index) =>
        lowerCaseWords.includes(word.toLowerCase()) && index !== 0
          ? word.toLowerCase()
          : word[0].toUpperCase() + word.slice(1)
      )
      .join(' ');
  }
  return (
    <ImageBackground
      source={getBackgroundImage(props.wellknown, Theme.CloseCard)}
      resizeMode="stretch"
      imageStyle={Theme.Styles.vcBg}
      style={[
        Theme.Styles.backgroundImageContainer,
        getBackgroundColour(props.wellknown),
      ]}>
      <View
        onLayout={
          props.isInitialLaunch
            ? () => start(t('copilot:cardTitle'))
            : undefined
        }>
        <Row crossAlign="center" padding="3 0 0 3">
        {isVCLoaded(props.credential, props.fields) && (
            <Image
              src={issuerLogo?.url}
              alt={issuerLogo?.alt_text}
              style={Theme.Styles.issuerLogo}
              resizeMethod="scale"
              resizeMode="contain"
            />
          )}
          <Column fill align="center" justify="center" margin="0 10 0 10">
            <View
                style={{
                  width: '90%',
                  alignItems: 'flex-end', 
                  justifyContent: 'center',
                }}>
             <VCItemFieldValue
                key={'id'}
                testID="id"
                fieldValue={credentialType(
                  getLocalizedField(props.credential?.credentialSubject.type)
                )}
                style={{
                  textAlign: 'left',
                    fontWeight: 'bold',
                    fontSize: 14,
                  width: '100%',
                  alignSelf: 'flex-end',
                }}
                wellknown={props.wellknown} 
                  ellipsizeMode="tail"
              />

              </View>

            <VCItemFieldValue
              key={'fullName'}
              testID="fullName"
              fieldValue={getLocalizedField(
                props.credential?.credentialSubject.recipientName,
              )}
              style={{
                    textAlign: 'left', 
                    fontSize: 13,
                    width: '100%', 
                    alignSelf: 'flex-end', 
                  }}
              wellknown={props.wellknown}
            />
             <VCItemFieldValue
                  key={'credentialId'}
                  testID="credentialId"
                  fieldValue={maskCredentialId(
                    getLocalizedField(props.credential?.credentialSubject.credential_id)
                  )}
                  style={{
                    textAlign: 'left',
                    fontSize: 12,
                    width: '100%',
                    alignSelf: 'flex-end',
                  }}
                  wellknown={props.wellknown}
                />
          </Column>

         
          <Pressable
            onPress={props.KEBAB_POPUP}
            accessible={false}
            style={Theme.Styles.kebabPressableContainer}>
            <KebabPopUp
              iconColor={getTextColor(props.wellknown, Theme.Colors.helpText)}
              vcMetadata={props.vcMetadata}
              iconName="dots-three-horizontal"
              iconType="entypo"
              isVisible={props.isKebabPopUp}
              onDismiss={props.DISMISS}
              service={props.service}
              vcHasImage={faceImage !== undefined}
            />
          </Pressable>

          {vcSelectableButton}
        </Row>

        <WalletBinding service={props.service} vcMetadata={props.vcMetadata} />

        <RemoveVcWarningOverlay
          testID="removeVcWarningOverlay"
          service={props.service}
          vcMetadata={props.vcMetadata}
        />

        <HistoryTab service={props.service} vcMetadata={props.vcMetadata} />
      </View>
    </ImageBackground>
  );
};

export interface VCItemContentProps {
  context: any;
  credential: Credential;
  verifiableCredentialData: any;
  fields: [];
  wellknown: {};
  generatedOn: string;
  selectable: boolean;
  selected: boolean;
  isPinned?: boolean;
  service: any;
  onPress?: () => void;
  isDownloading?: boolean;
  flow?: string;
  walletBindingResponse: {};
  KEBAB_POPUP: () => {};
  DISMISS: () => {};
  isKebabPopUp: boolean;
  vcMetadata: VCMetadata;
  isVerified?: boolean;
  isInitialLaunch?: boolean;
}

VCCardViewContent.defaultProps = {
  isPinned: false,
};
