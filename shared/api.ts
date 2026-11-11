import {request} from './request';
import {
  API_CACHED_STORAGE_KEYS,
  changeCrendetialRegistry,
  COMMON_PROPS_KEY,
  CACHE_TTL,
  updateCacheTTL,
} from './constants';
import {INITIAL_CONFIG} from './InitialConfig';
import {getItem, setItem} from '../machines/store';
import {
  getErrorEventData,
  getImpressionEventData,
  sendErrorEvent,
  sendImpressionEvent,
} from './telemetry/TelemetryUtils';
import {TelemetryConstants} from './telemetry/TelemetryConstants';
import NetInfo from '@react-native-community/netinfo';
import {createCacheObject} from './Utils';
import {
  currentApiMemoryCacheGeneration,
  inFlightCacheLookups,
  inFlightFetches,
  memoryCache,
} from './apiMemoryCache';

const isCacheValid = (cachedData: any) => {
  if (!cachedData?.cachedTime || typeof cachedData.cachedTime !== 'number') {
    return false;
  }
  const currentTime = Date.now();
  const expiryTime = Number(cachedData.cachedTime) + CACHE_TTL;
  return currentTime < expiryTime;
};

export const API_URLS: ApiUrls = {
  trustedVerifiersList: {
    method: 'GET',
    buildURL: (): `/${string}` => '/v1/mimoto/verifiers',
  },
  issuerConfig: {
    method: 'GET',
    buildURL: (issuerId: string): `/${string}` =>
      `/v1/mimoto/issuers/${issuerId}`,
  },
  issuerWellknownConfig: {
    method: 'GET',
    buildURL: (credentialIssuer: string): string =>
      `${credentialIssuer}/.well-known/openid-credential-issuer`,
  },
  authorizationServerMetadataConfig: {
    method: 'GET',
    buildURL: (authorizationServerUrl: string): string =>
      `${authorizationServerUrl}/.well-known/oauth-authorization-server`,
  },

  allProperties: {
    method: 'GET',
    buildURL: (): `/${string}` => '/v1/mimoto/allProperties',
  },
  getIndividualId: {
    method: 'POST',
    buildURL: (): `/${string}` => '/v1/mimoto/aid/get-individual-id',
  },
  reqIndividualOTP: {
    method: 'POST',
    buildURL: (): `/${string}` => '/v1/mimoto/req/individualId/otp',
  },
  walletBinding: {
    method: 'POST',
    buildURL: (): `/${string}` => '/v1/mimoto/wallet-binding',
  },
  bindingOtp: {
    method: 'POST',
    buildURL: (): `/${string}` => '/v1/mimoto/binding-otp',
  },
  requestOtp: {
    method: 'POST',
    buildURL: (): `/${string}` => '/v1/mimoto/req/otp',
  },
  credentialRequest: {
    method: 'POST',
    buildURL: (): `/${string}` => '/v1/mimoto/credentialshare/request',
  },
  credentialStatus: {
    method: 'GET',
    buildURL: (id: string): `/${string}` =>
      `/v1/mimoto/credentialshare/request/status/${id}`,
  },
  credentialDownload: {
    method: 'POST',
    buildURL: (): `/${string}` => '/v1/mimoto/credentialshare/download',
  },
  linkTransaction: {
    method: 'POST',
    buildURL: (): `/${string}` =>
      '/v1/esignet/linked-authorization/v2/link-transaction',
  },
  authenticate: {
    method: 'POST',
    buildURL: (): `/${string}` =>
      '/v1/esignet/linked-authorization/v2/authenticate',
  },
  sendConsent: {
    method: 'POST',
    buildURL: (): `/${string}` => '/v1/esignet/linked-authorization/v2/consent',
  },
  googleAccountProfileInfo: {
    method: 'GET',
    buildURL: (accessToken: string): `${string}` =>
      `https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=${accessToken}`,
  },
};

export const API = {
  fetchTrustedVerifiersList: async () => {
    const response = await request(
      API_URLS.trustedVerifiersList.method,
      API_URLS.trustedVerifiersList.buildURL(),
    );
    return response;
  },

  fetchIssuerConfig: async (issuerId: string) => {
    const response = await request(
      API_URLS.issuerConfig.method,
      API_URLS.issuerConfig.buildURL(issuerId),
    );
    return response.response;
  },
  fetchIssuerWellknownConfig: async (credentialIssuer: string) => {
    const response = await request(
      API_URLS.issuerWellknownConfig.method,
      API_URLS.issuerWellknownConfig.buildURL(credentialIssuer),
    );
    return response;
  },

  fetchAllProperties: async () => {
    const response = await request(
      API_URLS.allProperties.method,
      API_URLS.allProperties.buildURL(),
    );
    return response.response;
  },
  getGoogleAccountProfileInfo: async accessToken =>
    await request(
      API_URLS.googleAccountProfileInfo.method,
      API_URLS.googleAccountProfileInfo.buildURL(accessToken),
      undefined,
      '',
    ),
};

export const CACHED_API = {
  fetchTrustedVerifiersList: (isCachePreferred: boolean = true) =>
    generateCacheAPIFunction({
      isCachePreferred,
      cacheKey: API_CACHED_STORAGE_KEYS.fetchTrustedVerifiers,
      fetchCall: API.fetchTrustedVerifiersList,
    }),

  fetchIssuerWellknownConfig: (
    issuerCacheKey: string,
    credentialIssuer: string,
    isCachePreferred: boolean = false,
  ) =>
    generateCacheAPIFunction({
      isCachePreferred,
      cacheKey:
        API_CACHED_STORAGE_KEYS.fetchIssuerWellknownConfig(issuerCacheKey),
      fetchCall: API.fetchIssuerWellknownConfig.bind(null, credentialIssuer),
      // Cards wait for this before they draw, and it can be a megabyte from a slow server:
      // an hour-old copy is fine for laying out a card while a fresh one downloads.
      useStaleWhileRefreshing: true,
    }),

  fetchIssuerAuthorizationServerMetadata: (
    authorizationServerUrl: string,
    isCachePreferred: boolean = false,
  ) =>
    generateCacheAPIFunction({
      isCachePreferred,
      cacheKey: API_CACHED_STORAGE_KEYS.fetchIssuerAuthorizationServerMetadata(
        authorizationServerUrl,
      ),
      fetchCall: API.fetchAuthorizationServerMetadata.bind(
        null,
        authorizationServerUrl,
      ),
    }),

  getAllProperties: (isCachePreferred: boolean) =>
    generateCacheAPIFunction({
      isCachePreferred,
      cacheKey: COMMON_PROPS_KEY,
      fetchCall: API.fetchAllProperties,
      onErrorHardCodedValue: INITIAL_CONFIG.allProperties,
    }),
};

interface GenerateCacheAPIFunctionProps {
  isCachePreferred?: boolean;
  cacheKey: string;
  fetchCall: (...props: any) => Promise<any>;
  onErrorHardCodedValue?: any;
  /**
   * With isCachePreferred: return an expired cached response straight away and refresh it in
   * the background, instead of waiting for the network.
   */
  useStaleWhileRefreshing?: boolean;
}

async function generateCacheAPIFunction({
  isCachePreferred = false,
  cacheKey = '',
  fetchCall = () => Promise.resolve(),
  onErrorHardCodedValue = undefined,
  useStaleWhileRefreshing = false,
}: GenerateCacheAPIFunctionProps) {
  if (isCachePreferred) {
    return await shareInFlight(inFlightCacheLookups, cacheKey, () =>
      generateCacheAPIFunctionWithCachePreference(
        cacheKey,
        fetchCall,
        onErrorHardCodedValue,
        useStaleWhileRefreshing,
      ),
    );
  } else {
    return await generateCacheAPIFunctionWithAPIPreference(
      cacheKey,
      fetchCall,
      onErrorHardCodedValue,
    );
  }
}

function shareInFlight<T>(
  inFlight: Map<string, Promise<T>>,
  key: string,
  start: () => Promise<T>,
): Promise<T> {
  let pending = inFlight.get(key);
  if (!pending) {
    const started = start().finally(() => {
      // The cache may have been cleared, and the key reused, while this was running.
      if (inFlight.get(key) === started) inFlight.delete(key);
    });
    pending = started;
    inFlight.set(key, pending);
  }
  return pending;
}

function fetchAndCache(cacheKey: string, fetchCall: (...props: any[]) => any) {
  return shareInFlight(inFlightFetches, cacheKey, async () => {
    const generation = currentApiMemoryCacheGeneration();
    const response = await fetchCall();
    if (!response) {
      throw new Error('Received Empty response in fetch call');
    }
    const cacheObject = createCacheObject(response);
    if (generation === currentApiMemoryCacheGeneration()) {
      memoryCache.set(cacheKey, cacheObject);
    }
    setItem(cacheKey, cacheObject, '').then(() =>
      console.info('Cached response for ' + cacheKey),
    );
    return response;
  });
}

async function generateCacheAPIFunctionWithCachePreference(
  cacheKey: string,
  fetchCall: (...props: any[]) => any,
  onErrorHardCodedValue?: any,
  useStaleWhileRefreshing = false,
) {
  try {
    let cachedData = memoryCache.get(cacheKey);
    if (!cachedData) {
      const generation = currentApiMemoryCacheGeneration();
      cachedData = await getItem(cacheKey, null, '');
      if (cachedData && generation === currentApiMemoryCacheGeneration()) {
        memoryCache.set(cacheKey, cachedData);
      }
    }
    if (cachedData && isCacheValid(cachedData)) {
      console.info('Returned cached response for' + cacheKey);
      return cachedData.response;
    }
    if (useStaleWhileRefreshing && cachedData?.response) {
      fetchAndCache(cacheKey, fetchCall).catch(error =>
        console.warn(`Background refresh failed for ${cacheKey}`, error),
      );
      return cachedData.response;
    }
    return await fetchAndCache(cacheKey, fetchCall);
  } catch (error) {
    console.warn(`Failed to load due to network issue in cache preferred api call.
     cache key:${cacheKey} and has onErrorHardCodedValue:${
      onErrorHardCodedValue != undefined
    }`);
    console.log(error);

    if (onErrorHardCodedValue != undefined) {
      return onErrorHardCodedValue;
    } else {
      throw error;
    }
  }
}

async function generateCacheAPIFunctionWithAPIPreference(
  cacheKey: string,
  fetchCall: (...props: any[]) => any,
  onErrorHardCodedValue?: any,
) {
  let cacheObject;
  const generation = currentApiMemoryCacheGeneration();
  try {
    const response = await fetchCall();
    if (!response) {
      throw new Error('Received Empty response in fetch call');
    }
    if (response?.cacheTTLInMilliSeconds) {
      updateCacheTTL(Number(response.cacheTTLInMilliSeconds));
    }
    cacheObject = createCacheObject(response);
    if (generation === currentApiMemoryCacheGeneration()) {
      memoryCache.set(cacheKey, cacheObject);
    }
    setItem(cacheKey, cacheObject, '').then(() =>
      console.info('Cached response for ' + cacheKey),
    );
    return response;
  } catch (error) {
    console.warn(`Failed to load due to network issue in API preferred api call.
     cache key:${cacheKey} and has onErrorHardCodedValue:${
      onErrorHardCodedValue != undefined
    }`);
    console.error(`The error in fetching api ${cacheKey}`, error);
    let cachedData = null;
    if (!(await NetInfo.fetch()).isConnected) {
      cachedData = await getItem(cacheKey, null, '');
    }
    if (cachedData && isCacheValid(cachedData)) {
      return cachedData.response;
    } else if (onErrorHardCodedValue != undefined) {
      return onErrorHardCodedValue;
    } else {
      throw error;
    }
  }
}

export default async function getAllConfigurations(
  host = undefined,
  isCachePreferred = true,
) {
  host && changeCrendetialRegistry(host);
  return await CACHED_API.getAllProperties(isCachePreferred);
}

type Api_Params = {
  method: 'GET' | 'POST' | 'PATCH'; // Define the HTTP methods
  buildURL: (param?: string) => `/${string}`; // Define the buildURL function signature
};

type ApiUrls = {
  trustedVerifiersList: Api_Params;
  issuersList: Api_Params;
  issuerConfig: Api_Params;
  issuerWellknownConfig: Api_Params;
  authorizationServerMetadataConfig: Api_Params;
  allProperties: Api_Params;
  getIndividualId: Api_Params;
  reqIndividualOTP: Api_Params;
  walletBinding: Api_Params;
  bindingOtp: Api_Params;
  requestOtp: Api_Params;
  credentialRequest: Api_Params;
  credentialStatus: Api_Params;
  credentialDownload: Api_Params;
  linkTransaction: Api_Params;
  authenticate: Api_Params;
  sendConsent: Api_Params;
  googleAccountProfileInfo: Api_Params;
};

export interface DownloadProps {
  maxDownloadLimit: number;
  downloadInterval: number;
}
