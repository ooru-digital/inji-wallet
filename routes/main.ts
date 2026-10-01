import React from 'react';
import {Dimensions} from 'react-native';
import {BottomTabNavigationOptions} from '@react-navigation/bottom-tabs';
import {getDefaultHeaderHeight} from '@react-navigation/elements';
import {initialWindowMetrics} from 'react-native-safe-area-context';
import {ScanLayout} from '../screens/Scan/ScanLayout';
import {HistoryScreen} from '../screens/History/HistoryScreen';
import i18n from '../i18n';
import {BOTTOM_TAB_ROUTES} from './routesConstants';
import {HomeScreenLayout} from '../screens/HomeScreenLayout';
import {Theme} from '../components/ui/styleUtils';
import {SettingScreen} from '../screens/Settings/SettingScreen';
import {isIOS} from '../shared/constants';

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

const home: TabScreen = {
  name: BOTTOM_TAB_ROUTES.home,
  component: HomeScreenLayout,
  icon: 'home',
  options: {
    headerTitle: '',
    headerShown: false,
  },
};
export const share: TabScreen = {
  name: BOTTOM_TAB_ROUTES.share,
  component: ScanLayout,
  icon: 'qr-code-scanner',
  options: {
    title: i18n.t('MainLayout:share'),
    headerShown: false,
  },
};

const history: TabScreen = {
  name: BOTTOM_TAB_ROUTES.history,
  component: HistoryScreen,
  icon: 'history',
  options: {
    headerTitleStyle: Theme.Styles.HistoryHeaderTitleStyle,
    title: i18n.t('MainLayout:history'),
  },
};

const settings: TabScreen = {
  name: BOTTOM_TAB_ROUTES.settings,
  component: SettingScreen,
  icon: 'settings',
  options: {
    headerTitleAlign: 'left',
    headerTitleStyle: {
      fontSize: 26,
      fontFamily: 'Montserrat_600SemiBold',
      marginTop: isIOS() ? 1 : 15, //isIOS condition to fix rendering issue of 'settings' on ios
    },
    headerStyle: isIOS() ? {height: settingsHeaderHeight} : undefined,
    title: i18n.t('MainLayout:settings'),
  },
};

export const mainRoutes: TabScreen[] = [];
mainRoutes.push(home);
mainRoutes.push(share);
mainRoutes.push(history);
mainRoutes.push(settings);

export interface TabScreen {
  name: string;
  icon: string;
  component: React.FC;
  options?: BottomTabNavigationOptions;
}
