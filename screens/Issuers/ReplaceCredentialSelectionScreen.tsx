import React from 'react';
import {useTranslation} from 'react-i18next';
import {Modal} from '../../components/ui/Modal';
import {Button, Column, Row, Text} from '../../components/ui';
import {Theme} from '../../components/ui/styleUtils';
import {VcItemContainer} from '../../components/VC/VcItemContainer';
import {HomeRouteProps} from '../../routes/routeTypes';
import {RootRouteProps} from '../../routes';
import {useIssuerScreenController} from './IssuerScreenController';
import {VCMetadata} from '../../shared/VCMetadata';

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
  const controller = useIssuerScreenController(props);

  const duplicates: VCMetadata[] = controller.duplicateVcMetadatas;
  const selectedKeys: string[] = controller.selectedDuplicateVcKeys;

  // Every card listed shares the incoming credential's type, so the first one names the whole
  // list. `credentialType` is the issuer's localized display name (e.g. "National ID").
  const credentialType = duplicates[0]?.credentialType;

  const areAllChecked =
    duplicates.length > 0 && selectedKeys.length === duplicates.length;

  // Counting keys rather than a flag keeps this honest when a card is ticked then unticked.
  const cardsSelectedText =
    selectedKeys.length === 1
      ? `${selectedKeys.length} ${t('SendVPScreen:cardSelected')}`
      : `${selectedKeys.length} ${t('SendVPScreen:cardsSelected')}`;

  return (
    <Modal
      testID="replaceCredentialSelectionScreen"
      isVisible={controller.isSelectingCredentialsToReplace}
      arrowLeft={true}
      headerTitle={credentialType || t('errors.replaceCredential.title')}
      headerElevation={2}
      onDismiss={controller.CANCEL_REPLACE}>
      <Column fill backgroundColor={Theme.Colors.lightGreyBackgroundColor}>
        <Text
          testID="replaceCredentialDescription"
          color={Theme.Colors.GrayText}
          margin="16 24 12 24">
          {t('errors.replaceCredential.description')}
        </Text>

        <Row
          padding="11 24 11 24"
          style={{
            backgroundColor: '#FAFAFA',
            justifyContent: 'space-between',
          }}>
          <Text
            testID="replaceCredentialSelectedCount"
            style={Theme.VPSharingStyles.cardsSelectedText}>
            {cardsSelectedText}
          </Text>
          <Text
            testID="replaceCredentialCheckAll"
            style={{
              color: Theme.Colors.Icon,
              fontFamily: 'Montserrat_600SemiBold',
            }}
            onPress={
              areAllChecked
                ? controller.UNCHECK_ALL_DUPLICATES
                : controller.CHECK_ALL_DUPLICATES
            }>
            {areAllChecked
              ? t('SendVPScreen:unCheck')
              : t('SendVPScreen:checkAll')}
          </Text>
        </Row>

        <Column scroll backgroundColor={Theme.Colors.whiteBackgroundColor}>
          {duplicates.map(vcMetadata => {
            const vcKey = vcMetadata.getVcKey();
            return (
              <VcItemContainer
                key={vcKey}
                vcMetadata={vcMetadata}
                margin="0 2 8 2"
                // VcItemContainer hands the item's own service to onPress; the key is already
                // captured here, so the argument is deliberately ignored.
                onPress={() => controller.TOGGLE_DUPLICATE_SELECTION(vcKey)}
                selectable
                selected={selectedKeys.includes(vcKey)}
                isPinned={vcMetadata.isPinned}
              />
            );
          })}
        </Column>

        <Column
          padding="16 24 24 24"
          backgroundColor={Theme.Colors.whiteBackgroundColor}>
          <Button
            testID="confirmReplaceCredential"
            type="gradient"
            title={t('errors.replaceCredential.confirm')}
            // Mirrors the machine's `hasSelectedDuplicates` guard, so the button cannot be
            // pressed into a transition that would be refused anyway.
            disabled={selectedKeys.length === 0}
            onPress={controller.CONFIRM_REPLACE}
          />
          <Button
            testID="cancelReplaceCredential"
            type="clear"
            title={t('common:cancel')}
            onPress={controller.CANCEL_REPLACE}
          />
        </Column>
      </Column>
    </Modal>
  );
};
