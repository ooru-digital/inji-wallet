import {Dimensions} from 'react-native';
import {getDefaultHeaderHeight} from '@react-navigation/elements';
import {initialWindowMetrics} from 'react-native-safe-area-context';
import {isIOS} from './constants';

// Extends the Settings header's white bar a bit further down the screen (purely cosmetic
// spacing above Language), computed the same way the header itself derives its default height —
// screen size + safe-area top inset — so the extra space stays consistent across iOS devices
// instead of a hardcoded height clipping or overshooting on some of them.
const SETTINGS_HEADER_EXTRA_HEIGHT = 16;
const settingsHeaderHeight =
  getDefaultHeaderHeight(
    Dimensions.get('window'),
    false,
    initialWindowMetrics?.insets.top ?? 0,
  ) + SETTINGS_HEADER_EXTRA_HEIGHT;

/** Values that differ between iOS and Android, kept in one place. */
export const PLATFORM_SPECIFIC = {
  settings: {
    // 15 clips the bottom of the 26pt "Settings" title inside the iOS header.
    headerMarginTop: isIOS() ? 1 : 15,
    // undefined keeps the header's default height.
    headerHeight: isIOS() ? settingsHeaderHeight : undefined,
  },
  welcome: {
    // iOS runs the biometric unlock on the Welcome screen itself, so returning users see a
    // single unlock page. Android navigates to the separate Biometric screen, which prompts
    // automatically, and is deliberately left unchanged.
    unlocksBiometricsInPlace: isIOS(),
  },
};
