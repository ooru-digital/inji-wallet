import type {displayType} from '../../machines/Issuers/IssuersMachine';
import {getDisplayObjectForCurrentLanguage} from './Utils';

const OFFER_FETCH_TIMEOUT_MS = 5000;
export const CREDENTIAL_OFFER_SCHEME = 'openid-credential-offer://';

/**
 * Whether a scanned QR is an issuer's credential offer, rather than a verifier's request. The
 * offer is either the `openid-credential-offer://` scheme or any link carrying the offer inline
 * (`credential_offer=`) or by reference (`credential_offer_uri=`).
 */
export function isCredentialOffer(qrCode: string): boolean {
  if (qrCode.startsWith(CREDENTIAL_OFFER_SCHEME)) {
    return true;
  }
  try {
    const params = parseQueryParams(qrCode);
    return !!(params.credential_offer || params.credential_offer_uri);
  } catch {
    // A QR that isn't a link can hold a stray `%`, which decodeURIComponent rejects.
    return false;
  }
}

/**
 * The `credential_configuration_ids` of a scanned credential offer. The offer is either inline
 * (`credential_offer=`) or by reference (`credential_offer_uri=`), which is fetched again here
 * because the VCI library does not pass the ids to the trust callback. Only https links are
 * fetched, with a timeout; an issuer that allows a link to be used once makes this fetch fail.
 */
export async function getOfferedCredentialConfigurationIds(
  offer: string,
): Promise<string[]> {
  const params = parseQueryParams(offer);
  let offerObject: {credential_configuration_ids?: unknown};
  if (params.credential_offer) {
    offerObject = JSON.parse(params.credential_offer);
  } else if (params.credential_offer_uri) {
    if (!params.credential_offer_uri.startsWith('https://')) {
      return [];
    }
    offerObject = await fetchOfferUri(params.credential_offer_uri, response =>
      response.json(),
    );
  } else {
    return [];
  }
  const ids = offerObject?.credential_configuration_ids;
  return Array.isArray(ids)
    ? ids.filter((id): id is string => typeof id === 'string')
    : [];
}

/**
 * Display names, in the current language, of the given credential configurations from the
 * issuer's metadata. Configurations without a display name are left out.
 */
export function getCredentialConfigurationNames(
  issuerMetadata: {credential_configurations_supported?: object},
  configurationIds: string[],
): string[] {
  const supported = (issuerMetadata?.credential_configurations_supported ??
    {}) as Record<
    string,
    {display?: displayType[]; credential_metadata?: {display?: displayType[]}}
  >;
  return configurationIds
    .map(id => {
      const configuration = supported[id];
      const display =
        configuration?.display ?? configuration?.credential_metadata?.display;
      return display ? getDisplayObjectForCurrentLanguage(display)?.name : '';
    })
    .filter((name): name is string => !!name);
}

/**
 * Whether a by-reference offer has already been claimed: the issuer answers 409, or an
 * `invalid_offer` body under any status (CredIssuer sends it with a 200). Asked after a download
 * fails, because the VCI library drops the issuer's answer when it can't read the offer. Any doubt
 * answers false.
 */
export async function isCredentialOfferAlreadyUsed(
  offer: string,
): Promise<boolean> {
  const offerUri = parseQueryParams(offer).credential_offer_uri;
  if (!offerUri?.startsWith('https://')) {
    return false;
  }
  try {
    return await fetchOfferUri(offerUri, async response => {
      if (response.status === 409) {
        return true;
      }
      const body = await response.json().catch(() => null);
      return body?.error === 'invalid_offer';
    });
  } catch {
    return false;
  }
}

/** Fetches an offer link, giving up after OFFER_FETCH_TIMEOUT_MS including reading the body. */
async function fetchOfferUri<T>(
  uri: string,
  read: (response: Response) => Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), OFFER_FETCH_TIMEOUT_MS);
  try {
    return await read(
      await fetch(uri, {
        headers: {Accept: 'application/json'},
        signal: controller.signal,
      }),
    );
  } finally {
    clearTimeout(timer);
  }
}

function parseQueryParams(url: string): Record<string, string> {
  const queryStart = url.indexOf('?');
  if (queryStart === -1) {
    return {};
  }
  const params: Record<string, string> = {};
  url
    .slice(queryStart + 1)
    .split('&')
    .forEach(pair => {
      const separator = pair.indexOf('=');
      if (separator === -1) {
        return;
      }
      const key = decodeURIComponent(pair.slice(0, separator));
      params[key] = decodeURIComponent(
        pair.slice(separator + 1).replace(/\+/g, ' '),
      );
    });
  return params;
}
