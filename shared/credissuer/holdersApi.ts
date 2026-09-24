import {CREDISSUER_APP_BASE_URL} from '../constants';

const holdersBaseUrl = () => `${CREDISSUER_APP_BASE_URL}/api/holders`;

type HoldersApiResult = {
  ok: boolean;
  data: any;
  message?: string;
};

async function postHolders(
  path: string,
  body: Record<string, unknown>,
): Promise<HoldersApiResult> {
  const response = await fetch(`${holdersBaseUrl()}${path}`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  });

  let data: any = {};
  try {
    data = await response.json();
  } catch {
    // non-JSON body
  }

  return {
    ok: response.ok,
    data,
    message: typeof data?.message === 'string' ? data.message : undefined,
  };
}

export async function sendEmailOtp(email: string) {
  return postHolders('/send-email-otp', {
    login_type: 'email_otp',
    email,
  });
}

export async function verifyEmailOtp(email: string, otp: string) {
  return postHolders('/verify-email-otp', {email, otp});
}

/** Staging/prod API requires email + token + device_id. */
export async function storeFcmToken(
  email: string,
  token: string,
  deviceId: string,
) {
  return postHolders('/store-token/fcm/', {
    email,
    token,
    device_id: deviceId,
  });
}
