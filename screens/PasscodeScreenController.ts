import {useSelector} from '@xstate/react';
import {useContext, useEffect, useState} from 'react';
import {
  AuthEvents,
  selectAuthorized,
  selectPasscode,
  selectPasscodeSalt,
  selectIsBiometricToggleFromSettings,
} from '../machines/auth';
import {PasscodeRouteProps} from '../routes';
import {GlobalContext} from '../shared/GlobalContext';
import {
  getEndEventData,
  getEventType,
  sendEndEvent,
} from '../shared/telemetry/TelemetryUtils';
import {TelemetryConstants} from '../shared/telemetry/TelemetryConstants';
import { SettingsEvents } from '../machines/settings';
import {useHolderAuthService} from '../components/HolderAuthProvider';
import {
  selectIsCheckingHolderSession,
  selectIsHolderAuthenticated,
} from '../machines/holderAuth';
import {navigateAfterDeviceAuth} from '../shared/credissuer/navigateAfterDeviceAuth';

export function usePasscodeScreen(props: PasscodeRouteProps) {
  const {appService} = useContext(GlobalContext);
  const authService = appService.children.get('auth');
  const settingsService = appService.children.get('settings');
  const holderAuthService = useHolderAuthService();
  const isAuthorized = useSelector(authService, selectAuthorized);
  const isHolderAuthenticated = useSelector(
    holderAuthService,
    selectIsHolderAuthenticated,
  );
  const isCheckingHolderSession = useSelector(
    holderAuthService,
    selectIsCheckingHolderSession,
  );
  const isPasscodeSet = () => !!passcode;
  const [passcode, setPasscode] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    if (isAuthorized && !isCheckingHolderSession) {
      sendEndEvent(
        getEndEventData(
          getEventType(props.route.params?.setup),
          TelemetryConstants.EndEventStatus.success,
        ),
      );
      navigateAfterDeviceAuth(props.navigation, isHolderAuthenticated);
    }
  }, [isAuthorized, isHolderAuthenticated, isCheckingHolderSession]);

  return {
    isPasscodeSet,
    passcode,
    setPasscode,
    error,
    setError,

    storedPasscode: useSelector(authService, selectPasscode),
    toggleUnlock: useSelector(authService, selectIsBiometricToggleFromSettings),

    LOGIN: () => {
      authService.send(AuthEvents.LOGIN());
    },

    SETUP_PASSCODE: () => {
      authService.send(AuthEvents.SETUP_PASSCODE(passcode));
      settingsService?.send(SettingsEvents.TOGGLE_BIOMETRIC_UNLOCK(false,true))
    },

    storedSalt: useSelector(authService, selectPasscodeSalt),
  };
}
