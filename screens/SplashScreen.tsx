import {Dimensions} from 'react-native';
import {RootRouteProps} from '../routes';
import {Image} from 'react-native-elements';
import React, {useEffect} from 'react';
import {APPLICATION_THEME} from 'react-native-dotenv';
import {Column} from '../components/ui';
import {useAppLayout} from './AppLayoutController';

export const SplashScreen: React.FC<RootRouteProps> = props => {
  const imageResource =
    APPLICATION_THEME?.toLowerCase() === 'purple'
      ? require('../assets/purpleSplashScreen.png')
      : require('../assets/SplashScreen.png');
  const controller = useAppLayout();

  useEffect(() => {
    const isAuthReady =
      controller.isLanguagesetup ||
      controller.isUnAuthorized ||
      controller.isAuthorized ||
      controller.isSettingUp ||
      controller.isIntroSlider;

    if (!isAuthReady) {
      return;
    }

    const timer = setTimeout(() => {
      if (controller.isLanguagesetup) {
        props.navigation.navigate('Language');
      } else if (controller.isIntroSlider) {
        props.navigation.navigate('IntroSliders');
      } else if (
        controller.isUnAuthorized ||
        controller.isSettingUp ||
        controller.isAuthorized
      ) {
        props.navigation.navigate('Welcome');
      }
    }, 3000);

    return () => clearTimeout(timer);
  }, [
    controller.isAuthorized,
    controller.isIntroSlider,
    controller.isLanguagesetup,
    controller.isSettingUp,
    controller.isUnAuthorized,
    props.navigation,
  ]);

  return (
    <Column
      crossAlign="center"
      style={{
        flex: 1,
        justifyContent: 'center',
        backgroundColor: '#ffffff',
        height: Dimensions.get('screen').height,
        width: Dimensions.get('screen').width,
      }}>
      <Image
        resizeMode="contain"
        style={{
          width: Dimensions.get('screen').width,
          height: Dimensions.get('screen').height,
        }}
        source={imageResource}
      />
    </Column>
  );
};
