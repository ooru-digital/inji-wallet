import {
  CREDISSUER_API_BASE_URL,
  CREDISSUER_API_TOKEN_VALUE,
} from '../constants';
import {getCredentialId, getIssuerQrCodeUrl} from '../qr/issuerQrCode';

const REQUEST_TIMEOUT_MS = 15000;

/**
 * The `qr_code` stored in a downloaded credential is a presigned link that expires within a day
 * (and some credentials don't carry one at all), so the current one is fetched from CredIssuer.
 * `expectedVcId` guards against the lookup ID resolving to a different person's credential.
 * Without it there is nothing to compare against, so no request is made and the caller keeps
 * the stored QR.
 */
export async function fetchIssuerQrCodeUrl(
  credentialId: string,
  expectedVcId: string | null,
): Promise<string | null> {
  if (!expectedVcId) {
    return null; // can't verify ownership, so use the stored QR
  }
  if (!CREDISSUER_API_TOKEN_VALUE) {
    return null;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(
      `${CREDISSUER_API_BASE_URL}/api/credentials/credentials/${encodeURIComponent(
        credentialId,
      )}`,
      {
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${CREDISSUER_API_TOKEN_VALUE}`,
        },
        signal: controller.signal,
      },
    );
    if (!response.ok) {
      throw new Error(
        `CredIssuer credentials API returned HTTP ${response.status}`,
      );
    }
    const body = await response.json();
    const returnedVcId = getCredentialId(body?.credential);
    if (returnedVcId !== expectedVcId) {
      return null;
    }
    return getIssuerQrCodeUrl(body?.credential);
  } finally {
    clearTimeout(timeoutId);
  }
}
