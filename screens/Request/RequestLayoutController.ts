import {NavigationProp, useNavigation} from '@react-navigation/native';
import {useSelector} from '@xstate/react';
import {useContext, useEffect} from 'react';

import {MainBottomTabParamList} from '../../routes/routeTypes';
import {GlobalContext} from '../../shared/GlobalContext';
import {
  selectIsWaitingForConnection,
  selectSenderInfo,
  selectIsDone,
  selectIsNavigatingToReceivedCards,
  selectIsNavigatingToHome,
} from '../../machines/bleShare/request/selectors';
import {
  selectIsAccepted,
  selectIsDisconnected,
  selectIsHandlingBleError,
  selectIsRejected,
  selectIsReviewing,
  selectBleError,
} from '../../machines/bleShare/commonSelectors';
import {RequestEvents} from '../../machines/bleShare/request/requestMachine';
import {
  BOTTOM_TAB_ROUTES,
  REQUEST_ROUTES,
  RequestStackParamList,
} from '../../routes/routesConstants';
import {VCSharingErrorStatusProps} from '../../components/MessageOverlay';
import {useTranslation} from 'react-i18next';

/**
 * `Main` is included because the Receive Card flow lives in the *root* stack, as a
 * sibling of `Main` — not inside the bottom tabs. Reaching a tab from here therefore
 * needs the nested form, `navigate('Main', {screen: <tab>})`.
 */
type RequestLayoutNavigation = NavigationProp<
  RequestStackParamList &
    MainBottomTabParamList & {
      Main: {screen: string};
    }
>;

export function useRequestLayout() {
  const {t} = useTranslation('RequestScreen');
  const {appService} = useContext(GlobalContext);
  const requestService = appService.children.get('request');
  const navigation = useNavigation<RequestLayoutNavigation>();

  useEffect(() => {
    const subscriptions = [
      navigation.addListener('focus', () =>
        requestService.send(RequestEvents.SCREEN_FOCUS()),
      ),
      navigation.addListener('blur', () =>
        requestService.send(RequestEvents.SCREEN_BLUR()),
      ),
    ];

    return () => {
      subscriptions.forEach(unsubscribe => unsubscribe());
    };
  }, []);

  const isReviewing = useSelector(requestService, selectIsReviewing);
  const isDone = useSelector(requestService, selectIsDone);
  const isBleError = useSelector(requestService, selectIsHandlingBleError);
  const bleError = useSelector(requestService, selectBleError);
  const isDisconnected = useSelector(requestService, selectIsDisconnected);
  const isWaitingForConnection = useSelector(
    requestService,
    selectIsWaitingForConnection,
  );
  const isNavigatingToReceivedCards = useSelector(
    requestService,
    selectIsNavigatingToReceivedCards,
  );
  const isNavigationToHome = useSelector(
    requestService,
    selectIsNavigatingToHome,
  );

  let errorStatusOverlay: Pick<
    VCSharingErrorStatusProps,
    'title' | 'message'
  > | null = null;
  if (isDisconnected) {
    errorStatusOverlay = {
      title: t('status.disconnected.title'),
      message: t('status.disconnected.message'),
    };
  } else if (isBleError) {
    errorStatusOverlay = {
      title: t(`status.bleError.${bleError.code}.title`),
      message: t(`status.bleError.${bleError.code}.message`),
    };
  }

  useEffect(() => {
    if (isNavigationToHome) {
      // Back out to Settings, which is where this flow is entered from
      // (SettingScreenController's RECEIVE_CARD). The bare `navigate('home')` this
      // replaced was never handled by any navigator: `home` is a bottom tab inside
      // `Main`, and navigate only bubbles *up* from the Request stack to the root,
      // never down into `Main`. The request machine had already left
      // `waitingForConnection` by then, so the QR unmounted and the user was left on
      // an empty screen under the Receive Card header.
      navigation.navigate('Main', {screen: BOTTOM_TAB_ROUTES.settings});
    } else if (isReviewing) {
      navigation.navigate(REQUEST_ROUTES.ReceiveVcScreen);
    } else if (isWaitingForConnection) {
      navigation.navigate(REQUEST_ROUTES.RequestScreen);
    }
  }, [isNavigationToHome, isReviewing, isWaitingForConnection]);

  return {
    senderInfo: useSelector(requestService, selectSenderInfo),

    isAccepted: useSelector(requestService, selectIsAccepted),
    isRejected: useSelector(requestService, selectIsRejected),
    isDisconnected,
    isBleError,
    bleError,
    errorStatusOverlay,
    isReviewing,
    isDone,
    isNavigatingToReceivedCards,
    DISMISS: () => requestService.send(RequestEvents.DISMISS()),
    RESET: () => requestService.send(RequestEvents.RESET()),
    GOTO_HOME: () => requestService.send(RequestEvents.GOTO_HOME()),
  };
}
