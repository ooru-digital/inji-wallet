import {useSelector} from '@xstate/react';
import {useContext, useEffect, useState} from 'react';
import {
  AuthEvents,
  selectAuthorized,
  selectPasscode,
  selectPasscodeSalt,
  selectIsBiometricToggleFromSettings,
  selectBiometrics,
} from '../machines/auth';
import {PasscodeRouteProps} from '../routes';
import {GlobalContext} from '../shared/GlobalContext';
import {
  getEndEventData,
  getEventType,
  sendEndEvent,
} from '../shared/telemetry/TelemetryUtils';
import {TelemetryConstants} from '../shared/telemetry/TelemetryConstants';
import {SettingsEvents} from '../machines/settings';

export function usePasscodeScreen(props: PasscodeRouteProps) {
  const {appService} = useContext(GlobalContext);
  const authService = appService.children.get('auth');
  const settingsService = appService.children.get('settings');
  const isAuthorized = useSelector(authService, selectAuthorized);
  const isPasscodeSet = () => !!passcode;
  const [passcode, setPasscode] = useState('');
  const [error, setError] = useState('');
  // True when the passcode is being set from Settings to replace biometric unlock, not
  // during onboarding.
  const toggleUnlock = useSelector(
    authService,
    selectIsBiometricToggleFromSettings,
  );

  useEffect(() => {
    if (isAuthorized) {
      sendEndEvent(
        getEndEventData(
          getEventType(props.route.params?.setup),
          TelemetryConstants.EndEventStatus.success,
        ),
      );
      props.navigation.reset({
        index: 0,
        routes: [{name: 'Main'}],
      });
    }
  }, [isAuthorized]);

  // Set during onboarding after choosing biometrics, as the fallback for them.
  const biometrics = useSelector(authService!, selectBiometrics);
  const isBackupPasscode = !toggleUnlock && !!biometrics;

  return {
    isPasscodeSet,
    passcode,
    setPasscode,
    error,
    setError,

    storedPasscode: useSelector(authService, selectPasscode),
    toggleUnlock,
    isBackupPasscode,

    LOGIN: () => {
      authService.send(AuthEvents.LOGIN());
    },

    SETUP_PASSCODE: () => {
      authService.send(AuthEvents.SETUP_PASSCODE(passcode));
      // A backup passcode keeps biometric unlock on; switching to a passcode turns it off.
      // The second argument only decides whether the "you can now use passcode" banner shows.
      // It belongs to a switch from biometrics in Settings. During onboarding it put that
      // banner on the first Home screen, where it closed under the tour and pulled the tour's
      // highlight off the + button.
      if (!isBackupPasscode) {
        settingsService?.send(
          SettingsEvents.TOGGLE_BIOMETRIC_UNLOCK(false, toggleUnlock),
        );
      }
    },

    storedSalt: useSelector(authService, selectPasscodeSalt),
  };
}
