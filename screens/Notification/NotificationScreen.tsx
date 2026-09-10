import messaging, {
  FirebaseMessagingTypes,
} from '@react-native-firebase/messaging';
import {Alert} from 'react-native';
import {useEffect} from 'react';
import {
  reregisterCurrentHolderFcmToken,
  subscribeFcmTokenRefresh,
} from '../../shared/credissuer/fcmRegistration';

export async function requestPermission(): Promise<void> {
  try {
    await messaging().requestPermission();
  } catch {
    // Permission request may fail on unsupported platforms/builds
  }
}

export function useForegroundNotification(): void {
  useEffect(() => {
    let unsubscribe = () => {};
    try {
      unsubscribe = messaging().onMessage(
        async (remoteMessage: FirebaseMessagingTypes.RemoteMessage) => {
          const {title, body} = remoteMessage.notification || {};
          Alert.alert(
            title || 'Notification',
            body || 'You have received a new message.',
          );
        },
      );
    } catch {
      // Firebase messaging may be unavailable
    }
    return unsubscribe;
  }, []);
}

export function useBackgroundNotification(): void {
  useEffect(() => {
    let unsubscribeBackground = () => {};
    try {
      unsubscribeBackground = messaging().onNotificationOpenedApp(
        (remoteMessage: FirebaseMessagingTypes.RemoteMessage) => {
          Alert.alert(
            remoteMessage.notification?.title || 'Notification',
            remoteMessage.notification?.body ||
              'You have received a new message.',
          );
        },
      );
    } catch {
      // Firebase messaging may be unavailable
    }
    return () => {
      unsubscribeBackground();
    };
  }, []);
}

export function useFcmTokenRefreshRegistration(): void {
  useEffect(() => {
    return subscribeFcmTokenRefresh(() => {
      reregisterCurrentHolderFcmToken();
    });
  }, []);
}
