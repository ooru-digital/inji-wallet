import React from 'react';
import {StyleSheet, Text, View} from 'react-native';
import {Icon} from 'react-native-elements';
import {useTranslation} from 'react-i18next';
import {Theme} from '../../ui/styleUtils';
import {MatchingVCsResultForDcql} from '../../../shared/openID4VP/openid4vp.types';
import {
  DcqlSection,
  DcqlSelection,
  isDcqlSectionSatisfied,
  vcKeysForQuery,
} from './dcqlSelection';

const COLORS = Theme.Colors.Design;

type DcqlCredentialSetsProps = {
  result: MatchingVCsResultForDcql;
  sections: DcqlSection[];
  selection: DcqlSelection;
  /** Renders one matching card; selection state and taps are the caller's. */
  renderCard: (
    queryId: string,
    vcKey: string,
    sectionIndex: number,
  ) => React.ReactNode;
};

/**
 * The cards a DCQL verifier asked for, one block per credential set (upstream Inji Wallet
 * 1.0.0-alpha.1's CredentialSetSection, in the share screen's style). Required sets come first;
 * a set with several options shows them as alternatives separated by "or".
 */
export const DcqlCredentialSets: React.FC<DcqlCredentialSetsProps> = ({
  result,
  sections,
  selection,
  renderCard,
}) => {
  const {t} = useTranslation('SendVPScreen');

  return (
    <View testID="dcqlCredentialSets">
      {sections.map((section, position) => {
        const satisfied = isDcqlSectionSatisfied(section, selection);
        const hasOptions = section.options.length > 1;
        return (
          <View
            key={section.index}
            style={styles.section}
            testID={`dcqlSection-${section.index}`}>
            <View style={styles.header}>
              <Text style={styles.title}>
                {section.required
                  ? t('dcqlSection.mandatoryCards')
                  : t('dcqlSection.optionalCards')}
              </Text>
              {satisfied && (
                <Icon
                  name="check-circle"
                  type="material-community"
                  size={20}
                  color={COLORS.teal}
                  containerStyle={styles.satisfiedIcon}
                />
              )}
              <View
                style={[
                  styles.badge,
                  !section.required && styles.badgeOptional,
                ]}>
                <Text
                  style={[
                    styles.badgeText,
                    !section.required && styles.badgeTextOptional,
                  ]}>
                  {section.required
                    ? t('dcqlSection.required')
                    : t('dcqlSection.notRequired')}
                </Text>
              </View>
            </View>
            {sections.length > 1 && (
              <Text style={styles.step}>
                {t('dcqlSection.stepOf', {
                  current: position + 1,
                  total: sections.length,
                })}
              </Text>
            )}
            {hasOptions && (
              <Text style={styles.hint}>{t('dcqlSection.pickOneOption')}</Text>
            )}

            {section.options.map((option, optionIndex) => (
              <View key={option.join('|')}>
                {optionIndex > 0 && (
                  <View style={styles.orRow}>
                    <View style={styles.orLine} />
                    <Text style={styles.orText}>{t('dcqlSection.or')}</Text>
                    <View style={styles.orLine} />
                  </View>
                )}
                <View
                  style={
                    option.length > 1 ? styles.multiCardOption : undefined
                  }>
                  {option.length > 1 && (
                    <Text style={styles.optionLabel}>
                      {t('dcqlSection.allRequired')}
                    </Text>
                  )}
                  {option.map(queryId => {
                    const vcKeys = vcKeysForQuery(result, queryId);
                    const allowMultiple =
                      result.matchingVCs[queryId]?.allowMultipleCredentials;
                    return (
                      <View key={queryId} style={styles.query}>
                        {vcKeys.length > 1 && (
                          <Text style={styles.hint}>
                            {allowMultiple
                              ? t('dcqlSection.pickOneOrMore')
                              : t('pickOneHint')}
                          </Text>
                        )}
                        {vcKeys.map(vcKey => (
                          <React.Fragment key={`${queryId}-${vcKey}`}>
                            {renderCard(queryId, vcKey, section.index)}
                          </React.Fragment>
                        ))}
                      </View>
                    );
                  })}
                </View>
              </View>
            ))}
          </View>
        );
      })}
    </View>
  );
};

const styles = StyleSheet.create({
  section: {
    marginBottom: 14,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  title: {
    flex: 1,
    marginRight: 10,
    fontFamily: 'Montserrat_700Bold',
    fontSize: 16,
    letterSpacing: 0.5,
    color: COLORS.navy,
  },
  satisfiedIcon: {
    marginRight: 8,
  },
  badge: {
    backgroundColor: COLORS.cardBackground,
    borderRadius: 14,
    paddingHorizontal: 12,
    paddingVertical: 5,
  },
  badgeOptional: {
    backgroundColor: COLORS.mutedBackground,
  },
  badgeText: {
    fontFamily: 'Montserrat_600SemiBold',
    fontSize: 12,
    color: COLORS.link,
  },
  badgeTextOptional: {
    color: COLORS.bodyText,
  },
  step: {
    marginTop: 4,
    fontFamily: 'Montserrat_500Medium',
    fontSize: 12,
    color: COLORS.bodyText,
  },
  hint: {
    marginTop: 6,
    marginBottom: 8,
    fontFamily: 'Montserrat_400Regular',
    fontSize: 14,
    lineHeight: 20,
    color: COLORS.bodyText,
  },
  query: {
    marginTop: 8,
  },
  multiCardOption: {
    marginTop: 8,
    padding: 10,
    borderRadius: 18,
    borderWidth: 1,
    borderStyle: 'dashed',
    borderColor: COLORS.border,
  },
  optionLabel: {
    fontFamily: 'Montserrat_600SemiBold',
    fontSize: 12,
    color: COLORS.link,
  },
  orRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginVertical: 6,
  },
  orLine: {
    flex: 1,
    height: StyleSheet.hairlineWidth,
    backgroundColor: COLORS.border,
  },
  orText: {
    marginHorizontal: 10,
    fontFamily: 'Montserrat_600SemiBold',
    fontSize: 12,
    color: COLORS.mutedIcon,
  },
});
