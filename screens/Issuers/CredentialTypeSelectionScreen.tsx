import React from 'react';
import {ScrollView, StyleSheet} from 'react-native';
import {useTranslation} from 'react-i18next';
import {useIssuerScreenController} from './IssuerScreenController';
import {removeWhiteSpace} from '../../shared/commonUtil';
import {HomeRouteProps} from '../../routes/routeTypes';
import {RootRouteProps} from '../../routes';
import {getDisplayObjectForCurrentLanguage} from '../../shared/openId4VCI/Utils';
import {getCredentialType} from '../../components/VC/common/VCUtils';
import {IssuerLogo} from '../../components/ui/svg';
import {
  ChoiceList,
  NavRow,
  Page,
  PageHeader,
  PageModal,
} from '../../components/revamp/Page';
import {IssuersIcon} from '../../components/revamp/Icons';
import {ScaledText} from '../../components/revamp/ScaledText';
import {fonts} from '../../components/revamp/tokens';
import {useRevampTheme} from '../../components/revamp/useRevampTheme';
import {CredentialTypes} from '../../machines/VerifiableCredential/VCMetaMachine/vc';

/** After picking an issuer that offers more than one card, the user chooses which one to add. */
export const CredentialTypeSelectionScreen: React.FC<
  HomeRouteProps | RootRouteProps
> = props => {
  const controller = useIssuerScreenController(props);
  const {t} = useTranslation('IssuersScreen');
  const {c} = useRevampTheme();
  const issuerDisplay = controller.selectedIssuer.display
    ? getDisplayObjectForCurrentLanguage(controller.selectedIssuer.display)
    : undefined;

  return (
    <PageModal
      visible={controller.isSelectingCredentialType}
      onRequestClose={controller.CANCEL}>
      <Page
        testID="credentialTypeSelectionScreen"
        header={
          <PageHeader title={issuerDisplay?.name} onBack={controller.CANCEL} />
        }>
        <ScrollView
          showsVerticalScrollIndicator={false}
          contentContainerStyle={styles.content}>
          <ScaledText
            testID="credentialTypeSelectionScreenDescription"
            style={[styles.lead, {color: c.inkMuted}]}>
            {t('credentialTypeDescription')}
          </ScaledText>
          <ChoiceList>
            {controller.supportedCredentialTypes.map(
              (credentialType: CredentialTypes) => {
                // A type without its own display shows the issuer's logo.
                const display = credentialType.display?.length
                  ? getDisplayObjectForCurrentLanguage(credentialType.display)
                  : undefined;
                const logo = display?.logo ?? issuerDisplay?.logo;
                const testID = removeWhiteSpace(credentialType.id);
                return (
                  <NavRow
                    key={credentialType.id}
                    testID={`credentialTypeItem-${testID}`}
                    title={display?.name ?? getCredentialType(credentialType)}
                    icon={
                      <IssuerLogo
                        uri={logo?.url || (logo as {uri?: string})?.uri}
                        testID={`issuerIcon-${testID}`}
                        size={26}
                        fallback={<IssuersIcon color={c.ink} size={20} />}
                      />
                    }
                    onPress={() =>
                      controller.SELECTED_CREDENTIAL_TYPE(credentialType)
                    }
                  />
                );
              },
            )}
          </ChoiceList>
        </ScrollView>
      </Page>
    </PageModal>
  );
};

const styles = StyleSheet.create({
  content: {paddingTop: 8, paddingBottom: 32, gap: 20},
  lead: {fontFamily: fonts.regular, fontSize: 15, lineHeight: 22},
});
