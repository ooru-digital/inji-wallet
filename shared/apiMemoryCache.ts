/**
 * The session's copy of cached API responses (see `generateCacheAPIFunction` in api.ts), kept
 * apart from api.ts so the storage code can clear it without importing the API layer.
 */

/**
 * Every card asks for its issuer's metadata as it mounts, all at once. These let those callers
 * share one storage read and one download per cache key instead of each starting their own.
 */
export const inFlightCacheLookups = new Map<string, Promise<any>>();
export const inFlightFetches = new Map<string, Promise<any>>();

/**
 * What was last read or fetched for each cache key, kept for the session. The stored copy is
 * decrypted on every read, which is slow for a megabyte of issuer metadata, and every card asks
 * for it again each time it is drawn.
 */
export const memoryCache = new Map<string, any>();

let generation = 0;

/** Changes every time the cache is cleared; a response started before that is not kept. */
export function currentApiMemoryCacheGeneration() {
  return generation;
}

/**
 * Forgets everything held in memory. Call it wherever the stored cache is cleared, replaced or
 * restored, so the session doesn't keep serving the old copy until the app restarts.
 */
export function clearApiMemoryCache() {
  memoryCache.clear();
  inFlightCacheLookups.clear();
  inFlightFetches.clear();
  generation++;
}
