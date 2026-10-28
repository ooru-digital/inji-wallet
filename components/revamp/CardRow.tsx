import React from 'react';
import {Pressable, StyleSheet, View} from 'react-native';
import {useTranslation} from 'react-i18next';
import {VCMetadata} from '../../shared/VCMetadata';
import testIDProps from '../../shared/commonUtil';
import {CheckIcon, ChevronIcon} from './Icons';
import {ScaledText} from './ScaledText';
import {CredentialCardFront, ScaledCard} from './CredentialCard';
import {validUntil} from './CredentialParts';
import {useCredentialCard} from './useCredentialCard';
import {fonts, radii} from './tokens';
import {useRevampTheme} from './useRevampTheme';

/**
 * A card in a list to choose from: its thumbnail, title, and holder · valid until. With
 * `selected` it is a checkbox (choose several); without, a row that acts on tap.
 */
export const CardRow: React.FC<{
  vcMetadata: VCMetadata;
  selected?: boolean;
  onPress: () => void;
  testID: string;
}> = ({vcMetadata, selected, onPress, testID}) => {
  const {t} = useTranslation('IssuersScreen');
  const {c} = useRevampTheme();
  const {data} = useCredentialCard(vcMetadata);
  const until = data ? validUntil(data) : undefined;
  const detail = [
    data?.holderName,
    until ? t('validUntil', {date: until}) : undefined,
  ]
    .filter(Boolean)
    .join(' · ');
  const checkbox = selected !== undefined;
  return (
    <Pressable
      {...testIDProps(testID)}
      accessibilityRole={checkbox ? 'checkbox' : 'button'}
      accessibilityState={checkbox ? {checked: selected} : undefined}
      onPress={onPress}
      style={({pressed}) => [
        styles.row,
        (selected || pressed) && {backgroundColor: c.tintAzure},
      ]}>
      <View style={[styles.thumb, {backgroundColor: c.sand}]}>
        {data ? (
          <ScaledCard width={64}>
            <CredentialCardFront data={data} />
          </ScaledCard>
        ) : null}
      </View>
      <View style={styles.text}>
        <ScaledText style={[styles.title, {color: c.ink}]}>
          {data?.title ?? vcMetadata.credentialType}
        </ScaledText>
        {detail ? (
          <ScaledText style={[styles.detail, {color: c.inkMuted}]}>
            {detail}
          </ScaledText>
        ) : null}
      </View>
      {!checkbox ? (
        <ChevronIcon color={c.inkMuted} direction="right" />
      ) : selected ? (
        <CheckIcon color={c.ink} />
      ) : (
        <View style={[styles.box, {borderColor: c.lineStrong}]} />
      )}
    </Pressable>
  );
};

const styles = StyleSheet.create({
  row: {
    minHeight: 72,
    paddingHorizontal: 16,
    paddingVertical: 12,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 14,
  },
  thumb: {width: 64, height: 40, borderRadius: 6, overflow: 'hidden'},
  text: {flex: 1, gap: 2},
  title: {fontFamily: fonts.semibold, fontSize: 15, lineHeight: 19},
  detail: {fontFamily: fonts.regular, fontSize: 12, lineHeight: 16},
  box: {width: 20, height: 20, borderRadius: radii.chip / 2, borderWidth: 1.5},
});
