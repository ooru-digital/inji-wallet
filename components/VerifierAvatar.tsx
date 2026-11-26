import React from 'react';
import {StyleSheet, View} from 'react-native';
import {Icon} from 'react-native-elements';
import {Theme} from './ui/styleUtils';
import {IssuerLogo} from './ui/svg';

const COLORS = Theme.Colors.Design;

/**
 * The verifier's logo in a teal ring, or a building icon when it has none or it fails to load.
 * IssuerLogo draws .svg logos with SvgUri (Image can't), as upstream Inji Wallet #2234 does for
 * the verifier trust screen.
 */
export const VerifierAvatar: React.FC<{logo?: string; size?: number}> = ({
  logo,
  size = 72,
}) => {
  const fallback = (
    <Icon
      name="office-building-outline"
      type="material-community"
      size={size * 0.42}
      color={COLORS.teal}
    />
  );
  return (
    <View
      style={[
        styles.circle,
        {width: size, height: size, borderRadius: size / 2},
      ]}>
      <IssuerLogo
        key={logo}
        uri={logo}
        testID="verifierLogo"
        size={size * 0.66}
        fallback={fallback}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  circle: {
    borderWidth: 3,
    borderColor: COLORS.teal,
    backgroundColor: COLORS.surface,
    alignItems: 'center',
    justifyContent: 'center',
    overflow: 'hidden',
    shadowColor: '#000',
    shadowOpacity: 0.12,
    shadowRadius: 6,
    shadowOffset: {width: 0, height: 3},
    elevation: 4,
  },
});
