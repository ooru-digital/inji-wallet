import {useSelector} from '@xstate/react';
import {useContext} from 'react';
import {
  AuthEvents,
  selectBiometrics,
  selectLanguagesetup,
  selectPasscode,
  selectSettingUp,
} from '../machines/auth';
import {
  SettingsEvents,
  selectBiometricUnlockEnabled,
} from '../machines/settings';
import {RootRouteProps} from '../routes';
import {GlobalContext} from '../shared/GlobalContext';
import {
  getStartEventData,
  getInteractEventData,
  sendInteractEvent,
  sendStartEvent,
} from '../shared/telemetry/TelemetryUtils';
import {TelemetryConstants} from '../shared/telemetry/TelemetryConstants';
import {isIOS} from '../shared/constants';

export function useWelcomeScreen(props: RootRouteProps) {
  const {appService} = useContext(GlobalContext);
  const authService = appService.children.get('auth');
  const settingsService = appService.children.get('settings');

  const isSettingUp = useSelector(authService, selectSettingUp);
  const passcode = useSelector(authService, selectPasscode);

  const isPasscodeSet = () => !!passcode;

  const biometrics = useSelector(authService, selectBiometrics);
  const isLanguagesetup = useSelector(authService, selectLanguagesetup);
  const isBiometricUnlockEnabled = useSelector(
    settingsService,
    selectBiometricUnlockEnabled,
  );

  // iOS only: biometric unlock runs on this screen itself (see WelcomeScreen), so returning users
  // see a single unlock page. The separate Biometric screen showed a second unlock page there and
  // needed a second tap, because it never raised Face ID by itself. Android keeps navigating to
  // the Biometric screen below, which prompts automatically, and is deliberately left unchanged.
  const isBiometricUnlock =
    isIOS() && !isSettingUp && isBiometricUnlockEnabled && biometrics !== '';

  return {
    isSettingUp,
    isLanguagesetup,
    isPasscodeSet,
    isBiometricUnlock,
    NEXT: () => {
      authService.send(AuthEvents.NEXT()), props.navigation.navigate('Auth');
    },
    SELECT: (screen: any) => {
      authService.send(AuthEvents.SELECT()),
        props.navigation.navigate('IntroSliders');
    },
    BACK: () => {
      settingsService.send(SettingsEvents.BACK()),
        props.navigation.navigate('Main');
    },
    unlockPage: () => {
      // prioritize biometrics
      if (!isSettingUp && isBiometricUnlockEnabled && biometrics !== '') {
        props.navigation.navigate('Biometric', {setup: isSettingUp});
      } else if (!isSettingUp && passcode !== '') {
        sendStartEvent(getStartEventData(TelemetryConstants.FlowType.appLogin));
        sendInteractEvent(
          getInteractEventData(
            TelemetryConstants.FlowType.appLogin,
            TelemetryConstants.InteractEventSubtype.click,
            'Unlock application button',
          ),
        );
        props.navigation.navigate('Passcode', {setup: isSettingUp});
      } else {
        props.navigation.navigate('Auth');
      }
    },
  };
}
