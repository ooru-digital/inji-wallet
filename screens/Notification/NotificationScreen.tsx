import messaging, {
  FirebaseMessagingTypes,
} from '@react-native-firebase/messaging';
import {Alert} from 'react-native';
import {useEffect} from 'react';
import {useMachine} from '@xstate/react';
import {IssuersMachine} from '../../machines/Issuers/IssuersMachine.ts';

// Request notification permissions
export async function requestPermission(): Promise<void> {
  const authStatus = await messaging().requestPermission();
  const enabled =
    authStatus === messaging.AuthorizationStatus.AUTHORIZED ||
    authStatus === messaging.AuthorizationStatus.PROVISIONAL;

  if (enabled) {
    console.log('Notification permission granted.');
  }
}

// Handle foreground notifications
export function useForegroundNotification(): void {
  const [state] = useMachine(IssuersMachine);

  useEffect(() => {
    requestPermission();

    const unsubscribe = messaging().onMessage(
      async (remoteMessage: FirebaseMessagingTypes.RemoteMessage) => {
        console.log(
          '🔔 Full Foreground Notification Data:',
          JSON.stringify(remoteMessage, null, 2),
        );

        const {title, body} = remoteMessage.notification || {};
        const messageText = body || 'You have received a new message.';
        const credential_issuer = remoteMessage.data || {};
        const issuerId = credential_issuer.org_code || null;

        console.log('📢 Extracted org_code:', issuerId);
        console.log('📌 Notification data:', credential_issuer);

        Alert.alert(title || 'Notification', messageText);
      },
    );

    return unsubscribe;
  }, [state]);
}

// Handle background notifications
export function useBackgroundNotification(): void {
  useEffect(() => {
    requestPermission();

    const unsubscribeBackground = messaging().onNotificationOpenedApp(
      (remoteMessage: FirebaseMessagingTypes.RemoteMessage) => {
        console.log(
          '🔔 Full Background Notification Data:',
          JSON.stringify(remoteMessage, null, 2),
        );

        const messageText =
          remoteMessage.notification?.body ||
          'You have received a new message.';
        console.log('📌 Notification opened in background:', messageText);
        Alert.alert(
          remoteMessage.notification?.title || 'Notification',
          messageText,
        );
      },
    );

    messaging()
      .getInitialNotification()
      .then(remoteMessage => {
        if (remoteMessage) {
          console.log(
            '🔔 Full Initial Notification Data:',
            JSON.stringify(remoteMessage, null, 2),
          );

          const messageText =
            remoteMessage.notification?.body ||
            'You have received a new message.';
          console.log(
            '📌 Notification received while app was quit:',
            messageText,
          );
        }
      })
      .catch(error => {
        console.error('❌ Error getting initial notification:', error);
      });

    messaging().setBackgroundMessageHandler(
      async (remoteMessage: FirebaseMessagingTypes.RemoteMessage) => {
        console.log(
          '🔔 Full Background Message Received:',
          JSON.stringify(remoteMessage, null, 2),
        );
      },
    );

    return () => {
      unsubscribeBackground();
    };
  }, []);
}
