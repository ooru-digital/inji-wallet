import React from 'react';
import {ScrollView, StyleSheet, View} from 'react-native';
import {useTranslation} from 'react-i18next';
import {HomeRouteProps} from '../../routes/routeTypes';
import {RootRouteProps} from '../../routes';
import {useIssuerScreenController} from './IssuerScreenController';
import {VCMetadata} from '../../shared/VCMetadata';
import {
  ChoiceList,
  Page,
  PageModal,
  PageButton,
  PageHeader,
} from '../../components/revamp/Page';
import {ScaledText} from '../../components/revamp/ScaledText';
import {CardRow} from '../../components/revamp/CardRow';
import {fonts} from '../../components/revamp/tokens';
import {useRevampTheme} from '../../components/revamp/useRevampTheme';

/**
 * Lets the user choose which of their existing cards to replace with the one just downloaded.
 *
 * The list is whatever the machine matched on the incoming credential's specific type — download a
 * National ID and only National IDs appear, download a Health ID and only Health IDs do — so it
 * needs no per-type code. Before this screen existed, "replace" deleted whichever single card
 * `find` returned, which (myVcs being newest-first) was the most recent rather than the oldest.
 */
export const ReplaceCredentialSelectionScreen: React.FC<
  HomeRouteProps | RootRouteProps
> = props => {
  const {t} = useTranslation('IssuersScreen');
  const {c} = useRevampTheme();
  const controller = useIssuerScreenController(props);

  const duplicates: VCMetadata[] = controller.duplicateVcMetadatas;
  const selectedKeys: string[] = controller.selectedDuplicateVcKeys;
  const credentialType = duplicates[0]?.credentialType;
  const areAllChecked =
    duplicates.length > 0 && selectedKeys.length === duplicates.length;

  return (
    <PageModal
      visible={controller.isSelectingCredentialsToReplace}
      onRequestClose={controller.CANCEL_REPLACE}>
      <Page
        testID="replaceCredentialSelectionScreen"
        header={
          <PageHeader
            title={t('errors.replaceCredential.title')}
            onBack={controller.CANCEL_REPLACE}
          />
        }
        footer={
          <PageButton
            testID="confirmReplaceCredential"
            title={t('errors.replaceCredential.confirm', {
              count: selectedKeys.length,
            })}
            // Mirrors the machine's `hasSelectedDuplicates` guard, so the button cannot be
            // pressed into a transition that would be refused anyway.
            disabled={selectedKeys.length === 0}
            onPress={controller.CONFIRM_REPLACE}
          />
        }>
        <ScrollView contentContainerStyle={styles.content}>
          <ScaledText
            testID="replaceCredentialDescription"
            style={[styles.lead, {color: c.inkMuted}]}>
            {t('errors.replaceCredential.description', {
              card: credentialType ?? t('thisCard'),
            })}
          </ScaledText>
          <View style={styles.countRow}>
            <ScaledText
              testID="replaceCredentialSelectedCount"
              style={[styles.count, {color: c.inkMuted}]}>
              {t('errors.replaceCredential.selected', {
                count: selectedKeys.length,
              })}
            </ScaledText>
            <ScaledText
              testID="replaceCredentialCheckAll"
              accessibilityRole="button"
              onPress={
                areAllChecked
                  ? controller.UNCHECK_ALL_DUPLICATES
                  : controller.CHECK_ALL_DUPLICATES
              }
              style={[styles.selectAll, {color: c.azureInk}]}>
              {areAllChecked
                ? t('errors.replaceCredential.clear')
                : t('errors.replaceCredential.selectAll')}
            </ScaledText>
          </View>
          <ChoiceList>
            {duplicates.map(vcMetadata => {
              const vcKey = vcMetadata.getVcKey();
              return (
                <CardRow
                  key={vcKey}
                  testID={`replaceCandidate-${vcKey}`}
                  vcMetadata={vcMetadata}
                  selected={selectedKeys.includes(vcKey)}
                  onPress={() => controller.TOGGLE_DUPLICATE_SELECTION(vcKey)}
                />
              );
            })}
          </ChoiceList>
        </ScrollView>
      </Page>
    </PageModal>
  );
};

const styles = StyleSheet.create({
  content: {paddingTop: 8, paddingBottom: 24, gap: 14},
  lead: {fontFamily: fonts.regular, fontSize: 15, lineHeight: 22},
  countRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  count: {fontFamily: fonts.regular, fontSize: 13},
  selectAll: {fontFamily: fonts.semibold, fontSize: 13, padding: 4},
});
