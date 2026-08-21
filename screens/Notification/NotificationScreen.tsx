import {getApps} from '@react-native-firebase/app';
import messaging, {
  FirebaseMessagingTypes,
} from '@react-native-firebase/messaging';
import {Alert} from 'react-native';
import {useEffect} from 'react';

// This app flavor's applicationId has no matching client entry in
// google-services.json, so the google-services gradle plugin is disabled
// and no default Firebase app is initialized natively. Calling messaging()
// in that state throws ("No Firebase App '[DEFAULT]' has been created"),
// so every entry point below must no-op until that's registered.
const isFirebaseAvailable = (): boolean => getApps().length > 0;

// Request notification permissions
export async function requestPermission(): Promise<void> {
  if (!isFirebaseAvailable()) {
    return;
  }
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
    if (!isFirebaseAvailable()) {
      return;
    }
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
    if (!isFirebaseAvailable()) {
      return;
    }
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
