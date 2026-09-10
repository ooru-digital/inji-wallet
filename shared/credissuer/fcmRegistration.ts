import messaging from '@react-native-firebase/messaging';
import {getUniqueId} from 'react-native-device-info';
import {getHolderEmail} from './holderSession';
import {storeFcmToken} from './holdersApi';

async function getFcmToken(): Promise<string | null> {
  try {
    const token = await messaging().getToken();
    return token || null;
  } catch {
    return null;
  }
}

export async function registerFcmTokenForEmail(email: string): Promise<boolean> {
  let token: string | null;
  let deviceId: string;
  try {
    [token, deviceId] = await Promise.all([getFcmToken(), getUniqueId()]);
  } catch {
    return false;
  }

  if (!token || !deviceId) {
    return false;
  }

  try {
    const result = await storeFcmToken(email, token, deviceId);
    return result.ok;
  } catch {
    return false;
  }
}

export async function reregisterCurrentHolderFcmToken(): Promise<void> {
  const email = await getHolderEmail();
  if (!email) {
    return;
  }
  await registerFcmTokenForEmail(email);
}

export function subscribeFcmTokenRefresh(
  onRefresh: (token: string) => void,
): () => void {
  try {
    return messaging().onTokenRefresh(token => {
      onRefresh(token);
    });
  } catch {
    return () => {};
  }
}
