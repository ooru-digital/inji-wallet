import {getFocusedRouteNameFromRoute} from '@react-navigation/native';
import {createNativeStackNavigator} from '@react-navigation/native-stack';
import React, {useState} from 'react';
import {useTranslation} from 'react-i18next';
import {Row, Text} from '../components/ui';
import {Header} from '../components/ui/Header';
import {Theme} from '../components/ui/styleUtils';
import {RootRouteProps} from '../routes';
import {HomeScreen} from './Home/HomeScreen';
import {IssuersScreen} from './Issuers/IssuersScreen';
import {SvgImage} from '../components/ui/svg';
import {HelpScreen} from '../components/HelpScreen';
import {I18nManager, View} from 'react-native';
import {useSafeAreaInsets} from 'react-native-safe-area-context';
import {isIOS} from '../shared/constants';
import {Copilot} from '../components/ui/Copilot';
import LinearGradient from 'react-native-linear-gradient';

/**
 * Both the logo (an opaque white rect baked into CredIssuerHorizontalLogo.svg) and the Help
 * pill (a translucent tint via LinearGradient, rendered against whatever sits behind it) rely
 * on their surroundings being opaque white — but headerLeft/headerRight render into
 * react-native-screens' native iOS header, and setting `headerStyle.backgroundColor` on that
 * header was confirmed (on-device, after a full rebuild) to still leave it translucent/blurred.
 * A plain JS View's backgroundColor is never subject to that native chrome, so this replaces
 * headerLeft/headerRight/headerStyle/headerTitle wholesale with one fully custom `header` render
 * function — same approach IssuersScreen already uses below — giving the logo and Help pill an
 * actually-opaque backdrop to sit on, on both platforms.
 */
const HomeScreenHeader: React.FC = () => {
  const {t} = useTranslation('IssuersScreen');
  const insets = useSafeAreaInsets();
  const [isRTL] = useState(I18nManager.isRTL);

  const logo = (
    <View style={Theme.Styles.injiHomeLogo}>
      {SvgImage.InjiLogo(Theme.Styles.injiLogo)}
    </View>
  );

  const help = (
    <HelpScreen
      source={'Inji'}
      triggerComponent={
        <Copilot
          title={t('copilot:helpTitle')}
          description={t('copilot:helpMessage')}
          order={1}>
          <LinearGradient
            style={{borderRadius: 8}}
            colors={Theme.Colors.GradientColorsLight}
            start={Theme.LinearGradientDirection.start}
            end={Theme.LinearGradientDirection.end}>
            {/* HelpScreenStyle.viewStyle's padding is shared with the intro-slider Help pills
                (trustedDigitalWalletIntro, backupRestoreIntro), so it's overridden to 0 here
                rather than changed at the source — this navbar instance is the only one whose
                padding read as an ugly mismatched box; the sliders' usage is unaffected. */}
            <View style={[Theme.HelpScreenStyle.viewStyle, {padding: 0}]}>
              <Row crossAlign="center" style={Theme.HelpScreenStyle.rowStyle}>
                <View testID="helpIcon" style={Theme.HelpScreenStyle.iconStyle}>
                  {SvgImage.coloredInfo()}
                </View>
                <Text
                  testID="helpText"
                  style={Theme.HelpScreenStyle.labelStyle}>
                  {t('help')}
                </Text>
              </Row>
            </View>
          </LinearGradient>
        </Copilot>
      }
    />
  );

  return (
    // A fully custom `header` opts out of every default native-stack header behaviour, not
    // just headerStyle — including headerShadowVisible's default separator under the bar, on
    // both Android and iOS. Theme.elevation(2) puts that separator back explicitly, the same
    // way Header.tsx (Issuers' own custom header, just below) already replaces it.
    <View
      style={[
        Theme.elevation(2),
        {
          borderRadius: 0,
          backgroundColor: Theme.Colors.whiteBackgroundColor,
          paddingTop: insets.top,
        },
      ]}>
      <Row
        crossAlign="center"
        align="space-between"
        style={{paddingHorizontal: 4, paddingVertical: 10}}>
        {isIOS() || !isRTL ? logo : help}
        {isIOS() || !isRTL ? help : logo}
      </Row>
    </View>
  );
};

export const HomeScreenLayout: React.FC<RootRouteProps> = props => {
  const {t} = useTranslation('IssuersScreen');
  const {Navigator, Screen} = createNativeStackNavigator();

  React.useLayoutEffect(() => {
    const routeName = getFocusedRouteNameFromRoute(props.route);
    if (routeName === 'IssuersScreen') {
      props.navigation.setOptions({tabBarStyle: {display: 'none'}});
    } else {
      props.navigation.setOptions({
        tabBarShowLabel: true,
        tabBarActiveTintColor: Theme.Colors.IconBg,
        tabBarLabelStyle: {
          fontSize: 12,
          fontFamily: 'Montserrat_600SemiBold',
        },
        tabBarStyle: {
          height: 75,
          paddingHorizontal: 10,
        },
        tabBarItemStyle: {
          height: 83,
          padding: 11,
        },
      });
    }
  }, [props.navigation, props.route]);

  const HomeScreenOptions = {
    header: () => <HomeScreenHeader />,
  };

  return (
    <Navigator>
      <Screen
        key={'HomeScreen'}
        name={'HomeScreen'}
        component={HomeScreen}
        options={HomeScreenOptions}
      />
      <Screen
        key={'Issuers'}
        name={'IssuersScreen'}
        component={IssuersScreen}
        options={{
          header: props => (
            <Header
              goBack={props.navigation.goBack}
              title={t('title')}
              testID="issuersScreenHeader"
            />
          ),
        }}
      />
    </Navigator>
  );
};
