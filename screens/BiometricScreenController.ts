import {useMachine, useSelector} from '@xstate/react';
import {useContext, useEffect, useState} from 'react';
import {Platform} from 'react-native';
import RNFingerprintChange from 'react-native-biometrics-changed';
import {
  AuthEvents,
  selectAuthorized,
  selectPasscode,
  selectPasscodeSalt,
} from '../machines/auth';
import {
  biometricsMachine,
  selectError,
  selectErrorResponse,
  selectIsAvailable,
  selectIsSuccess,
  selectIsUnenrolled,
  selectIsUnvailable,
} from '../machines/biometrics';
import {RootRouteProps} from '../routes';
import {GlobalContext} from '../shared/GlobalContext';
import {
  getStartEventData,
  getEndEventData,
  getInteractEventData,
  sendEndEvent,
  sendInteractEvent,
  sendStartEvent,
  resetRetryCount,
} from '../shared/telemetry/TelemetryUtils';
import {TelemetryConstants} from '../shared/telemetry/TelemetryConstants';

import {isAndroid} from '../shared/constants';

/**
 * `autoStart` (default true) starts biometric authentication as soon as biometrics are available,
 * which is what the Biometric screen does on arrival. The Welcome screen passes false on iOS: it
 * hosts the unlock itself and starts it only when the user taps its button, via `unlock()`.
 */
export function useBiometricScreen(
  props: RootRouteProps,
  {autoStart = true}: {autoStart?: boolean} = {},
) {
  const {appService} = useContext(GlobalContext);
  const authService = appService.children.get('auth');

  const [error, setError] = useState('');
  const [isReEnabling, setReEnabling] = useState(false);
  const [initAuthBio, updateInitAuthBio] = useState(true);
  const [, bioSend, bioService] = useMachine(biometricsMachine);

  const isAuthorized = useSelector(authService, selectAuthorized);
  const isAvailable = useSelector(bioService, selectIsAvailable);
  const isUnavailable = useSelector(bioService, selectIsUnvailable);
  const isSuccessBio = useSelector(bioService, selectIsSuccess);
  const isUnenrolled = useSelector(bioService, selectIsUnenrolled);
  const errorMsgBio = useSelector(bioService, selectError);
  const errorResponse = useSelector(bioService, selectErrorResponse);
  const passcodeSalt = useSelector(authService, selectPasscodeSalt);

  useEffect(() => {
    // Without autoStart, the login flow starts on the user's tap, and unlock() reports it there.
    if (isAvailable && autoStart) {
      sendStartEvent(getStartEventData(TelemetryConstants.FlowType.appLogin));
      sendInteractEvent(
        getInteractEventData(
          TelemetryConstants.FlowType.appLogin,
          TelemetryConstants.InteractEventSubtype.click,
          'Unlock with Biometrics button',
        ),
      );
    }
  }, [isAvailable]);

  useEffect(() => {
    if (isAuthorized) {
      sendEndEvent(
        getEndEventData(
          TelemetryConstants.FlowType.appLogin,
          TelemetryConstants.EndEventStatus.success,
        ),
      );
      props.navigation.reset({
        index: 0,
        routes: [{name: 'Main'}],
      });
      return;
    }

    if (autoStart && initAuthBio && isAvailable) {
      checkBiometricsChange();

      // so we only init authentication of biometrics just once
      updateInitAuthBio(false);
    }

    // if biometic state is success then lets send auth service BIOMETRICS
    if (isSuccessBio) {
      authService.send(AuthEvents.LOGIN());
      return;
    }

    if (errorMsgBio && !isReEnabling) {
      sendEndEvent(
        getEndEventData(
          TelemetryConstants.FlowType.appLogin,
          TelemetryConstants.EndEventStatus.failure,
          {
            errorId: errorResponse.res.error,
            errorMessage: errorResponse.res.warning,
            stackTrace: errorResponse.stacktrace,
          },
        ),
      );
    }

    if (isUnavailable || isUnenrolled) {
      props.navigation.reset({
        index: 0,
        routes: [{name: 'Passcode'}],
      });
      sendStartEvent(getStartEventData(TelemetryConstants.FlowType.appLogin));
      sendInteractEvent(
        getInteractEventData(
          TelemetryConstants.FlowType.appLogin,
          TelemetryConstants.InteractEventSubtype.click,
          'Unlock application button',
        ),
      );
    }
  }, [
    isAuthorized,
    isAvailable,
    isUnenrolled,
    isUnavailable,
    isSuccessBio,
    errorMsgBio,
  ]);

  const checkBiometricsChange = () => {
    if (isAndroid()) {
      RNFingerprintChange.hasFingerPrintChanged().then(
        async (biometricsHasChanged: boolean) => {
          //if new biometrics are added, re-enable Biometrics Authentication
          if (biometricsHasChanged) {
            setReEnabling(true);
          } else {
            bioSend({type: 'AUTHENTICATE'});
          }
        },
      );
    } else {
      // iOS has no equivalent of the fingerprint-change check above yet (TODO), so authenticate
      // directly. Previously nothing happened here, so Face ID never came up on its own.
      bioSend({type: 'AUTHENTICATE'});
    }
  };

  /**
   * Starts the unlock from a button tap. The first attempt goes through the same
   * biometrics-changed check the auto-start path uses; retries authenticate directly.
   */
  const unlock = () => {
    sendStartEvent(getStartEventData(TelemetryConstants.FlowType.appLogin));
    sendInteractEvent(
      getInteractEventData(
        TelemetryConstants.FlowType.appLogin,
        TelemetryConstants.InteractEventSubtype.click,
        'Unlock application button',
      ),
    );
    if (initAuthBio && isAvailable) {
      updateInitAuthBio(false);
      checkBiometricsChange();
    } else {
      bioSend({type: 'AUTHENTICATE'});
    }
  };

  const useBiometrics = () => {
    sendStartEvent(getStartEventData(TelemetryConstants.FlowType.appLogin));
    sendInteractEvent(
      getInteractEventData(
        TelemetryConstants.FlowType.appLogin,
        TelemetryConstants.InteractEventSubtype.click,
        'Unlock with biometrics button',
      ),
    );
    bioSend({type: 'AUTHENTICATE'});
  };

  const onSuccess = () => {
    resetRetryCount();
    bioSend({type: 'AUTHENTICATE'});
    setError('');
  };

  const onError = (value: string) => {
    setError(value);
  };

  const onDismiss = () => {
    sendEndEvent(
      getEndEventData(
        TelemetryConstants.FlowType.appLogin,
        TelemetryConstants.EndEventStatus.failure,
        {
          errorId: 'user_cancel',
          errorMessage: 'Authentication canceled',
        },
      ),
    );
    setReEnabling(false);
  };

  return {
    error,
    isReEnabling,
    isSuccessBio,
    passcodeSalt,
    storedPasscode: useSelector(authService, selectPasscode),
    useBiometrics,
    unlock,

    onSuccess,
    onError,
    onDismiss,
  };
}
