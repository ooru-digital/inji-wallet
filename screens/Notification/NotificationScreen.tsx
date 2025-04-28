import messaging, {
  FirebaseMessagingTypes,
} from '@react-native-firebase/messaging';
import {Alert} from 'react-native';
import {useEffect} from 'react';

// Request notification permissions
export async function requestPermission(): Promise<void> {
  const authStatus = await messaging().requestPermission();
  const enabled =
    authStatus === messaging.AuthorizationStatus.AUTHORIZED ||
    authStatus === messaging.AuthorizationStatus.PROVISIONAL;

  if (enabled) {
    // Permission granted
  }
}

// Handle foreground notifications
export function useForegroundNotification(): void {
  useEffect(() => {
    requestPermission();

    const unsubscribe = messaging().onMessage(
      async (remoteMessage: FirebaseMessagingTypes.RemoteMessage) => {
        const {title, body} = remoteMessage.notification || {};
        const messageText = body || 'You have received a new message.';
        Alert.alert(title || 'Notification', messageText);
      },
    );

    return unsubscribe;
  }, []);
}

// Handle background notifications
export function useBackgroundNotification(): void {
  useEffect(() => {
    requestPermission();

    // Handle notifications when the app is in the background and opened
    const unsubscribeBackground = messaging().onNotificationOpenedApp(
      (remoteMessage: FirebaseMessagingTypes.RemoteMessage) => {
        const messageText =
          remoteMessage.notification?.body ||
          'You have received a new message.';
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
          const messageText =
            remoteMessage.notification?.body ||
            'You have received a new message.';
          // Initial notification logic (e.g., navigation) can go here
        }
      })
      .catch(error => {
        // Optionally handle the error
      });

    messaging().setBackgroundMessageHandler(
      async (remoteMessage: FirebaseMessagingTypes.RemoteMessage) => {
        // You can process the background message here if needed
      },
    );

    return () => {
      unsubscribeBackground();
    };
  }, []);
}
