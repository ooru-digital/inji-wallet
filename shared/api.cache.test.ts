import {CACHE_TTL} from './constants';

jest.mock('../machines/store', () => ({
  getItem: jest.fn(),
  setItem: jest.fn(() => Promise.resolve()),
}));
jest.mock('./request', () => ({request: jest.fn()}));
jest.mock('./telemetry/TelemetryUtils', () => ({
  getErrorEventData: jest.fn(),
  getImpressionEventData: jest.fn(),
  sendErrorEvent: jest.fn(),
  sendImpressionEvent: jest.fn(),
}));

// A fresh module per test: the cache it keeps in memory would otherwise carry over.
let CACHED_API: typeof import('./api').CACHED_API;
let mockGetItem: jest.Mock;
let setItem: jest.Mock;
let mockRequest: jest.Mock;

const issuer = 'https://issuer.example';
const fresh = {credential_issuer: issuer, version: 'fresh'};
const old = {credential_issuer: issuer, version: 'old'};

const cached = (response: object, ageMs: number) => ({
  response,
  cachedTime: Date.now() - ageMs,
});

// Importing the module also reads unrelated settings, such as the language.
const wellknownReads = () =>
  mockGetItem.mock.calls.filter(([key]) => key.includes(issuer)).length;

const fetchWellknown = () =>
  CACHED_API.fetchIssuerWellknownConfig(issuer, issuer, true);

// Lets a refresh started in the background run to completion.
const settle = () => new Promise(resolve => setTimeout(resolve, 0));

describe('issuer well-known config, cache preferred', () => {
  beforeEach(() => {
    jest.resetModules();
    CACHED_API = require('./api').CACHED_API;
    ({getItem: mockGetItem, setItem} = require('../machines/store'));
    mockRequest = require('./request').request;
  });

  it('returns a valid cached copy without going to the network', async () => {
    mockGetItem.mockResolvedValue(cached(old, 0));

    expect(await fetchWellknown()).toEqual(old);
    expect(mockRequest).not.toHaveBeenCalled();
  });

  it('returns an expired copy at once and refreshes it in the background', async () => {
    mockGetItem.mockResolvedValue(cached(old, CACHE_TTL + 1));
    let finishDownload: (value: object) => void = () => {};
    mockRequest.mockReturnValue(
      new Promise(resolve => {
        finishDownload = resolve;
      }),
    );

    expect(await fetchWellknown()).toEqual(old);
    expect(mockRequest).toHaveBeenCalledTimes(1);

    finishDownload(fresh);
    await settle();
    expect(setItem).toHaveBeenCalledWith(
      expect.stringContaining(issuer),
      expect.objectContaining({response: fresh}),
      '',
    );
  });

  it('a failed background refresh still leaves the expired copy shown', async () => {
    mockGetItem.mockResolvedValue(cached(old, CACHE_TTL + 1));
    mockRequest.mockRejectedValue(new Error('offline'));

    expect(await fetchWellknown()).toEqual(old);
    await settle();
    expect(setItem).not.toHaveBeenCalled();
  });

  it('waits for the network when nothing is cached', async () => {
    mockGetItem.mockResolvedValue(null);
    mockRequest.mockResolvedValue(fresh);

    expect(await fetchWellknown()).toEqual(fresh);
  });

  it('cards asking at the same time share one read and one download', async () => {
    mockGetItem.mockResolvedValue(null);
    mockRequest.mockResolvedValue(fresh);

    const results = await Promise.all([
      fetchWellknown(),
      fetchWellknown(),
      fetchWellknown(),
    ]);

    expect(results).toEqual([fresh, fresh, fresh]);
    expect(wellknownReads()).toBe(1);
    expect(mockRequest).toHaveBeenCalledTimes(1);
  });

  it('reads the stored copy once, then answers from memory', async () => {
    mockGetItem.mockResolvedValue(cached(old, 0));

    await fetchWellknown();
    expect(await fetchWellknown()).toEqual(old);

    expect(wellknownReads()).toBe(1);
  });

  it('a download replaces the copy in memory', async () => {
    mockGetItem.mockResolvedValue(null);
    mockRequest.mockResolvedValue(fresh);

    await fetchWellknown();
    expect(await fetchWellknown()).toEqual(fresh);

    expect(mockRequest).toHaveBeenCalledTimes(1);
  });
});
