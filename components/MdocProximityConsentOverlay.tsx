import React, {useEffect, useState} from 'react';
import {
  Modal,
  ScrollView,
  StyleSheet,
  TouchableOpacity,
  View,
} from 'react-native';
import {Icon} from 'react-native-elements';
import {useTranslation} from 'react-i18next';
import {useSafeAreaInsets} from 'react-native-safe-area-context';
import {Button, Column, Row, Text} from './ui';
import {Header} from './ui/Header';
import {Theme} from './ui/styleUtils';
import {MdocPresentmentConsentElement} from '../shared/mdoc/iso18013PresentmentInterop';

function formatElementLabel(element: string): string {
  return element
    .split('_')
    .filter(Boolean)
    .map(part => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

function getInitials(name: string | undefined): string {
  const words = (name ?? '').trim().split(/\s+/).filter(Boolean);
  if (words.length === 0) {
    return '?';
  }
  if (words.length === 1) {
    return words[0].slice(0, 2).toUpperCase();
  }
  return (words[0][0] + words[1][0]).toUpperCase();
}

/**
 * `requestInfo` is JSON.parse'd from a string handed across the native BLE bridge
 * (see iso18013PresentmentInterop.ts) — it is not runtime-validated against the
 * TypeScript shape, and comes from an external, untrusted verifier device. A field
 * typed as `boolean` can still arrive as the string "false" (truthy in JS!), "1", a
 * number, or be missing — so `is_required` must be normalized rather than trusted.
 */
function isRequiredFlag(value: unknown): boolean {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    return value !== 0;
  }
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    return normalized === 'true' || normalized === '1';
  }
  return false;
}

/**
 * Stable per-purpose identity for tracking (de)selection. Falls back through id -> name
 * -> index so a verifier sending duplicate or missing names can't make two distinct
 * purposes share one toggle state.
 */
function purposeKey(p: {id?: string; name?: string}, index: number): string {
  return p.id || p.name || `purpose-${index}`;
}

/**
 * Full-screen consent page shown when a proximity verifier sends a DeviceRequest and before
 * the wallet builds/sends a DeviceResponse.
 *
 * Displays verifier identity, purpose (from deviceRequestInfo.purposeHints),
 * credential, and requested attributes — Share continues presentment; Cancel rejects.
 */
export const MdocProximityConsentOverlay: React.FC<
  MdocProximityConsentOverlayProps
> = props => {
  const {t} = useTranslation('VcDetails');
  const insets = useSafeAreaInsets();
  // requestInfo.verifier_name comes from the same untrusted, unvalidated JSON blob as
  // purposes/is_required (see the note above isRequiredFlag) — it's the primary source
  // per the verifier's own request, with the top-level verifierName (readerAuth / trust
  // metadata) as a fallback for requests that don't set it.
  const verifier =
    props.requestInfo?.verifier_name?.trim() ||
    props.verifierName?.trim() ||
    t('mdocConsent.unknownVerifier');
  const purpose = props.requestInfo?.purpose
    ? formatElementLabel(props.requestInfo.purpose)
    : props.purpose?.trim() || t('mdocConsent.defaultPurpose');

  const purposesList = props.requestInfo?.purposes;
  const [unselectedPurposes, setUnselectedPurposes] = useState<Set<string>>(
    new Set(),
  );
  // This component stays mounted across multiple consent requests (QrCodeOverlay just
  // toggles isVisible), so selections must reset per request — otherwise a deselection
  // from a previous verifier's request could leak in and, e.g., leave Share wrongly
  // disabled if a later request happens to reuse the same purpose name.
  useEffect(() => {
    if (props.isVisible) {
      setUnselectedPurposes(new Set());
    }
  }, [props.isVisible]);

  // Required purposes are deselectable like optional ones, but Share stays disabled
  // until every required purpose is selected again.
  const allRequiredPurposesSelected =
    purposesList?.every(
      (p, index) =>
        !isRequiredFlag(p.is_required) ||
        !unselectedPurposes.has(purposeKey(p, index)),
    ) ?? true;

  const retainedCount = props.elements.filter(e => e.intentToRetain).length;

  // Split the hint copy around its literal "*" so that one character can be styled red
  // (matching the red "*" markers on required purposes) without hardcoding the sentence
  // itself into JSX — if the translation ever drops or moves the "*", this still renders
  // sensibly (just without a colored segment) instead of breaking.
  const requiredHintText = t('mdocConsent.requiredPurposeHint');
  const [requiredHintBefore, ...requiredHintRest] =
    requiredHintText.split('*');
  const requiredHintAfter = requiredHintRest.join('*');

  return (
    <Modal
      visible={props.isVisible}
      animationType="slide"
      presentationStyle="fullScreen"
      onRequestClose={props.onDeny}>
      <Column fill backgroundColor={Theme.Colors.whiteBackgroundColor}>
        <Header
          goBack={props.onDeny}
          title={t('mdocConsent.title')}
          testID="mdocConsentHeader"
        />
        <ScrollView
          style={styles.scrollView}
          contentContainerStyle={styles.content}
          showsVerticalScrollIndicator={true}
          persistentScrollbar={true}>
          <Text
            testID="mdocConsentMessage"
            size="mediumSmall"
            color={Theme.Colors.GrayIcon}
            margin="0 0 20 0">
            {t('mdocConsent.message', {verifier})}
          </Text>

          <Row crossAlign="center" style={styles.verifierCard}>
            <Column style={styles.avatar}>
              <Text weight="bold" size="medium" color={Theme.Colors.whiteText}>
                {getInitials(verifier)}
              </Text>
            </Column>
            <Column style={styles.verifierInfo}>
              <Text
                testID="mdocConsentVerifierName"
                weight="bold"
                size="medium"
                color={Theme.Colors.Details}
                numLines={2}>
                {verifier}
              </Text>
              <Text
                testID="mdocConsentCredential"
                size="small"
                color={Theme.Colors.GrayIcon}
                margin="2 0 0 0">
                {t('mdocConsent.requestingMdl')}
              </Text>
            </Column>
          </Row>

          <Text style={styles.sectionLabel}>
            {t('mdocConsent.purposeLabel')}
          </Text>

          {purposesList && purposesList.length > 0 ? (
            <Column style={styles.card}>
              {purposesList.map((p, index) => {
                const key = purposeKey(p, index);
                const isSelected = !unselectedPurposes.has(key);
                const isRequired = isRequiredFlag(p.is_required);
                // Only the description is shown — the raw `name` identifier (e.g.
                // "age_verification") is internal bookkeeping, not meant for display.
                // Every purpose entry is rendered purely off whatever this specific
                // request sent; nothing here is hardcoded to a particular use case.
                const description =
                  typeof p.description === 'string' && p.description.trim()
                    ? p.description.trim()
                    : t('mdocConsent.defaultPurpose');
                return (
                  <TouchableOpacity
                    key={key}
                    onPress={() => {
                      const newSet = new Set(unselectedPurposes);
                      if (isSelected) {
                        newSet.add(key);
                      } else {
                        newSet.delete(key);
                      }
                      setUnselectedPurposes(newSet);
                    }}
                    style={[
                      styles.purposeRow,
                      index === purposesList.length - 1 && styles.lastRow,
                    ]}>
                    <Column style={styles.purposeText}>
                      <Text
                        weight="semibold"
                        size="mediumSmall"
                        color={Theme.Colors.Details}>
                        {isRequired && (
                          <Text weight="bold" color={Theme.Colors.errorMessage}>
                            {'* '}
                          </Text>
                        )}
                        {description}
                      </Text>
                    </Column>
                    <Icon
                      name={isSelected ? 'check-box' : 'check-box-outline-blank'}
                      type="material"
                      color={isSelected ? Theme.Colors.Icon : Theme.Colors.Details}
                      size={22}
                      containerStyle={styles.purposeIcon}
                    />
                  </TouchableOpacity>
                );
              })}
            </Column>
          ) : (
            <Text
              testID="mdocConsentPurpose"
              size="mediumSmall"
              color={Theme.Colors.GrayIcon}
              style={styles.plainCard}
              margin="0 0 20 0">
              {purpose}
            </Text>
          )}

          {props.elements.length > 0 && (
            <>
              <Text style={styles.sectionLabel}>
                {t('mdocConsent.requestedData')}
              </Text>
              <Column style={styles.card}>
                {props.elements.map((item, index) => (
                  <Row
                    key={`${item.namespace}:${item.element}:${index}`}
                    crossAlign="center"
                    style={[
                      styles.elementRow,
                      index === props.elements.length - 1 && styles.lastRow,
                    ]}>
                    <Icon
                      name="check-circle"
                      type="material"
                      color={Theme.Colors.VerifiedIcon}
                      size={18}
                      containerStyle={styles.elementIcon}
                    />
                    <Column style={styles.purposeText}>
                      <Text
                        testID={`mdocConsentElement-${index}`}
                        weight="semibold"
                        size="mediumSmall"
                        color={Theme.Colors.Details}>
                        {formatElementLabel(item.element)}
                      </Text>
                      {item.intentToRetain ? (
                        <Text size="extraSmall" color={Theme.Colors.GrayIcon}>
                          {t('mdocConsent.retain')}
                        </Text>
                      ) : null}
                    </Column>
                  </Row>
                ))}
              </Column>

              <Row crossAlign="flex-start" style={styles.retentionBanner}>
                <Icon
                  name="info-outline"
                  type="material"
                  color={Theme.Colors.WarningIcon}
                  size={18}
                  containerStyle={styles.retentionIcon}
                />
                <Text
                  size="small"
                  color={'#8A6116'}
                  style={styles.retentionText}>
                  {t('mdocConsent.retentionSummary', {
                    retained: retainedCount,
                    total: props.elements.length,
                    verifier,
                  })}
                </Text>
              </Row>
              <Text
                testID="mdocConsentOnlyListed"
                size="extraSmall"
                color={Theme.Colors.GrayIcon}
                margin="10 0 0 0">
                {t('mdocConsent.onlyListedShared')}
              </Text>
            </>
          )}
        </ScrollView>

        <Column
          style={[styles.footer, {paddingBottom: Math.max(insets.bottom, 16)}]}>
          {!allRequiredPurposesSelected && (
            <View testID="mdocConsentRequiredHint" style={styles.hintWrapper}>
              <View style={styles.hintBubble}>
                <Text size="small" color={Theme.Colors.Details} align="center">
                  {requiredHintBefore}
                  {requiredHintRest.length > 0 && (
                    <Text weight="bold" color={Theme.Colors.errorMessage}>
                      {'*'}
                    </Text>
                  )}
                  {requiredHintAfter}
                </Text>
              </View>
              <View style={styles.hintArrow} />
            </View>
          )}
          <Button
            testID="mdocConsentAllow"
            type="gradient"
            title={t('mdocConsent.confirmButton')}
            disabled={!allRequiredPurposesSelected || props.isBusy}
            onPress={() => {
              const purposesResponse =
                purposesList?.map((p, index) => ({
                  id: p.id || 'NA',
                  name: p.name,
                  accepted: !unselectedPurposes.has(purposeKey(p, index)),
                })) || [];
              props.onAllow(purposesResponse);
            }}
          />
          <Button
            testID="mdocConsentDeny"
            margin={'10 0 0 0'}
            type="clear"
            title={t('mdocConsent.cancelButton')}
            disabled={props.isBusy}
            onPress={props.onDeny}
          />
        </Column>
      </Column>
    </Modal>
  );
};

const styles = StyleSheet.create({
  scrollView: {
    flex: 1,
  },
  content: {
    paddingHorizontal: 20,
    paddingTop: 12,
    paddingBottom: 24,
  },
  verifierCard: {
    backgroundColor: '#F7F7F7',
    borderRadius: 16,
    padding: 14,
    marginBottom: 24,
  },
  avatar: {
    width: 48,
    height: 48,
    borderRadius: 12,
    backgroundColor: Theme.Colors.Icon,
    justifyContent: 'center',
    alignItems: 'center',
  },
  verifierInfo: {
    flex: 1,
    marginLeft: 12,
  },
  sectionLabel: {
    fontSize: 12,
    fontWeight: '700',
    letterSpacing: 0.6,
    textTransform: 'uppercase',
    color: Theme.Colors.GrayIcon,
    marginBottom: 8,
    marginTop: 4,
  },
  card: {
    backgroundColor: '#F7F7F7',
    borderRadius: 14,
    marginBottom: 24,
    overflow: 'hidden',
  },
  plainCard: {
    backgroundColor: '#F7F7F7',
    borderRadius: 14,
    padding: 14,
  },
  purposeRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    padding: 14,
    borderBottomWidth: 1,
    borderBottomColor: '#EDEDED',
  },
  purposeText: {
    flex: 1,
  },
  purposeIcon: {
    marginLeft: 8,
    marginTop: 2,
  },
  elementRow: {
    padding: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#EDEDED',
  },
  elementIcon: {
    marginRight: 10,
  },
  hintWrapper: {
    alignItems: 'center',
    marginBottom: 8,
  },
  hintBubble: {
    backgroundColor: '#FDECEA',
    borderRadius: 10,
    borderWidth: 1,
    borderColor: '#F3B9B4',
    paddingHorizontal: 14,
    paddingVertical: 8,
  },
  hintArrow: {
    width: 0,
    height: 0,
    borderLeftWidth: 7,
    borderRightWidth: 7,
    borderTopWidth: 7,
    borderLeftColor: 'transparent',
    borderRightColor: 'transparent',
    borderTopColor: '#FDECEA',
    marginTop: -1,
  },
  retentionBanner: {
    backgroundColor: '#FFF6E5',
    borderRadius: 12,
    padding: 12,
  },
  retentionIcon: {
    marginRight: 8,
    marginTop: 1,
  },
  retentionText: {
    flex: 1,
  },
  lastRow: {
    borderBottomWidth: 0,
  },
  footer: {
    paddingHorizontal: 20,
    paddingTop: 12,
    borderTopWidth: 1,
    borderTopColor: '#EDEDED',
  },
});

export interface MdocProximityConsentOverlayProps {
  isVisible: boolean;
  docType?: string;
  credentialLabel?: string;
  verifierName?: string;
  purpose?: string;
  elements: MdocPresentmentConsentElement[];
  requestInfo?: {
    intent_to_retain?: boolean;
    verifier_name?: string;
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
  /** True while a Share/Cancel is already being processed (biometric prompt, native
   * approve/deny call) — disables both buttons so a second tap can't queue up
   * another one underneath it. */
  isBusy?: boolean;
}
