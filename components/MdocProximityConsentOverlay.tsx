import React, {useState} from 'react';
import {Dimensions, ScrollView, TouchableOpacity} from 'react-native';
import {Overlay, Icon} from 'react-native-elements';
import {useTranslation} from 'react-i18next';
import {Button, Column, Row, Text} from './ui';
import {Theme} from './ui/styleUtils';
import {MdocPresentmentConsentElement} from '../shared/mdoc/iso18013PresentmentInterop';

function formatElementLabel(element: string): string {
  return element
    .split('_')
    .filter(Boolean)
    .map(part => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

/**
 * Consent popup shown when a proximity verifier sends a DeviceRequest and before
 * the wallet builds/sends a DeviceResponse.
 *
 * Displays verifier identity, purpose (from deviceRequestInfo.purposeHints),
 * credential, and requested attributes — Share continues presentment; Cancel rejects.
 */
export const MdocProximityConsentOverlay: React.FC<
  MdocProximityConsentOverlayProps
> = props => {
  const {t} = useTranslation('VcDetails');
  const verifier =
    props.verifierName?.trim() || t('mdocConsent.unknownVerifier');
  const purpose = props.requestInfo?.purpose
    ? formatElementLabel(props.requestInfo.purpose)
    : props.purpose?.trim() || t('mdocConsent.defaultPurpose');
  const credential =
    props.credentialLabel?.trim() ||
    props.docType?.trim() ||
    t('mdocConsent.defaultCredential');

  const purposesList = props.requestInfo?.purposes;
  const [unselectedPurposes, setUnselectedPurposes] = useState<Set<string>>(
    new Set(),
  );

  return (
    <Overlay
      isVisible={props.isVisible}
      onBackdropPress={props.onDeny}
      overlayStyle={Theme.BindingVcWarningOverlay.overlay}>
      <Column
        align="space-between"
        crossAlign="center"
        padding={'10'}
        width={Dimensions.get('screen').width * 0.85}
        style={{maxHeight: Dimensions.get('screen').height * 0.75}}>
        <Column crossAlign="center" margin="10 0 8 0" padding="0" width="100%">
          <Text
            testID="mdocConsentTitle"
            weight="bold"
            size="large"
            color="#000000"
            style={{padding: 3}}>
            {t('mdocConsent.title')}
          </Text>
          <Text
            testID="mdocConsentMessage"
            align="center"
            size="mediumSmall"
            weight="regular"
            margin="10 0 0 0"
            color="#5D5D5D">
            {t('mdocConsent.message', {verifier})}
          </Text>
        </Column>

        <Column width="100%" margin="4 0 4 0">
          <Text
            testID="mdocConsentPurposeHeading"
            weight="bold"
            size="mediumSmall"
            margin="0 0 4 0"
            color="#000000">
            {t('mdocConsent.purposeLabel')}
          </Text>
          <Text
            testID="mdocConsentPurpose"
            size="mediumSmall"
            weight="regular"
            color="#5D5D5D">
            {purpose}
          </Text>

          {purposesList && purposesList.length > 0 && (
            <ScrollView
              persistentScrollbar={true}
              showsVerticalScrollIndicator={true}
              style={{maxHeight: Dimensions.get('screen').height * 0.25}}>
              <Column margin="8 0 0 0">
                {purposesList.map((p, index) => {
                  const isSelected = !unselectedPurposes.has(p.name);
                  const isDisabled = p.is_required;
                  return (
                    <TouchableOpacity
                      key={p.name + index}
                      disabled={isDisabled}
                      onPress={() => {
                        const newSet = new Set(unselectedPurposes);
                        if (isSelected) newSet.add(p.name);
                        else newSet.delete(p.name);
                        setUnselectedPurposes(newSet);
                      }}
                      style={{marginBottom: 12}}>
                      <Row align="flex-start" crossAlign="center">
                        <Icon
                          name={
                            isSelected ? 'check-box' : 'check-box-outline-blank'
                          }
                          type="material"
                          color={
                            isDisabled
                              ? Theme.Colors.GrayIcon
                              : Theme.Colors.Details
                          }
                          size={24}
                          containerStyle={{marginRight: 8}}
                        />
                        <Column style={{flex: 1}}>
                          <Text
                            size="base"
                            color={Theme.Colors.Details}
                            style={Theme.TextStyles.base}>
                            {p.name.replace(/_/g, ' ')}
                          </Text>
                          {!!p.description && (
                            <Text
                              size="small"
                              color={Theme.Colors.GrayIcon}
                              weight="regular">
                              {p.description}
                            </Text>
                          )}
                        </Column>
                      </Row>
                    </TouchableOpacity>
                  );
                })}
              </Column>
            </ScrollView>
          )}
        </Column>

        <Column width="100%" margin="4 0 4 0">
          <Text
            testID="mdocConsentCredentialHeading"
            weight="bold"
            size="mediumSmall"
            margin="0 0 4 0"
            color="#000000">
            {t('mdocConsent.credentialLabel')}
          </Text>
          <Text
            testID="mdocConsentCredential"
            size="mediumSmall"
            weight="regular"
            color="#5D5D5D">
            {credential}
          </Text>
        </Column>

        {props.elements.length > 0 && (
          <Column
            width="100%"
            margin="8 0 8 0"
            style={{maxHeight: Dimensions.get('screen').height * 0.28}}>
            <Text
              testID="mdocConsentRequestedHeading"
              weight="bold"
              size="mediumSmall"
              margin="0 0 6 0"
              color="#000000">
              {t('mdocConsent.requestedData')}
            </Text>
            <ScrollView
              persistentScrollbar={true}
              showsVerticalScrollIndicator={true}>
              {props.elements.map((item, index) => (
                <Row
                  key={`${item.namespace}:${item.element}:${index}`}
                  align="flex-start"
                  margin="6 0 0 0"
                  crossAlign="center">
                  <Text
                    testID={`mdocConsentElementCheck-${index}`}
                    color={Theme.Colors.Details}
                    style={[Theme.TextStyles.base, {marginRight: 8}]}>
                    ✓
                  </Text>
                  <Column style={{flex: 1}}>
                    <Text
                      testID={`mdocConsentElement-${index}`}
                      color={Theme.Colors.Details}
                      style={Theme.TextStyles.base}>
                      {formatElementLabel(item.element)}
                    </Text>
                    {item.intentToRetain ? (
                      <Text
                        size="small"
                        color={Theme.Colors.GrayIcon}
                        weight="semibold">
                        {t('mdocConsent.retain')}
                      </Text>
                    ) : null}
                  </Column>
                </Row>
              ))}
            </ScrollView>
            <Text
              testID="mdocConsentOnlyListed"
              size="small"
              margin="8 0 0 0"
              color="#5D5D5D">
              {t('mdocConsent.onlyListedShared')}
            </Text>
          </Column>
        )}

        <Button
          testID="mdocConsentAllow"
          margin={'10 0 0 0'}
          type="gradient"
          title={t('mdocConsent.confirmButton')}
          onPress={() => {
            const purposesResponse =
              purposesList?.map(p => ({
                id: p.id || 'NA',
                name: p.name,
                accepted: !unselectedPurposes.has(p.name),
              })) || [];
            props.onAllow(purposesResponse);
          }}
        />
        <Button
          testID="mdocConsentDeny"
          margin={'10 0 0 0'}
          type="clear"
          title={t('mdocConsent.cancelButton')}
          onPress={props.onDeny}
        />
      </Column>
    </Overlay>
  );
};

export interface MdocProximityConsentOverlayProps {
  isVisible: boolean;
  docType?: string;
  credentialLabel?: string;
  verifierName?: string;
  purpose?: string;
  elements: MdocPresentmentConsentElement[];
  requestInfo?: {
    intent_to_retain?: boolean;
    purpose?: string;
    purposes?: Array<{
      id?: string;
      name: string;
      is_required: boolean;
      description?: string;
    }>;
  };
  onAllow: (
    purposesResponse: Array<{id: string; name: string; accepted: boolean}>,
  ) => void;
  onDeny: () => void;
}
