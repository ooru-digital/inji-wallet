import VciClient from '../../shared/vciClient/VciClient';
import {getItem, setItem} from '../store';
import {IssuersService, requestIssuerMetadata} from './IssuersService';

jest.mock('../../shared/vciClient/VciClient', () => {
  const client = {
    getIssuerMetadata: jest.fn(),
    requestCredentialByOffer: jest.fn(() => Promise.resolve({})),
  };
  return {__esModule: true, default: {getInstance: () => client}};
});
jest.mock('../store', () => ({
  getItem: jest.fn(() => Promise.resolve(null)),
  setItem: jest.fn(() => Promise.resolve()),
}));

const client = VciClient.getInstance() as unknown as {
  getIssuerMetadata: jest.Mock;
  requestCredentialByOffer: jest.Mock;
};
const issuer = 'https://issuer.example';
const metadata = {credential_issuer: issuer};

// The cached copy is looked up before the network is asked.
const cacheChecked = () => new Promise(resolve => setTimeout(resolve, 0));

const startOfferDownload = () =>
  IssuersService().downloadCredentialFromOffer({qrData: 'offer'})(jest.fn());

describe('issuer metadata during an offer download', () => {
  beforeEach(async () => {
    jest.clearAllMocks();
    client.getIssuerMetadata.mockResolvedValue(metadata);
    await startOfferDownload();
    client.getIssuerMetadata.mockClear();
  });

  it('is fetched once, however many steps ask for it', async () => {
    const service = IssuersService();
    requestIssuerMetadata(issuer);
    const cached = await service.cacheIssuerWellknown({
      credentialOfferCredentialIssuer: issuer,
    });

    expect(cached).toEqual(metadata);
    expect(client.getIssuerMetadata).toHaveBeenCalledTimes(1);
  });

  it('is fetched as soon as the issuer asks for a proof', async () => {
    let askForProof: (
      issuer: string,
      nonce: null,
      algs: null,
    ) => void = () => {};
    client.requestCredentialByOffer.mockImplementation(
      (_offer, _txCode, getSignedProofJwt) => {
        askForProof = getSignedProofJwt;
        return Promise.resolve({});
      },
    );
    await startOfferDownload();
    client.getIssuerMetadata.mockClear();

    askForProof(issuer, null, null);
    await cacheChecked();

    expect(client.getIssuerMetadata).toHaveBeenCalledWith(issuer);
  });

  it('is fetched again for the next download', async () => {
    await requestIssuerMetadata(issuer);
    await startOfferDownload();
    await requestIssuerMetadata(issuer);

    expect(client.getIssuerMetadata).toHaveBeenCalledTimes(2);
  });

  it('is asked for again after a failed request', async () => {
    client.getIssuerMetadata.mockRejectedValueOnce(new Error('offline'));
    await expect(requestIssuerMetadata(issuer)).rejects.toThrow('offline');

    await expect(requestIssuerMetadata(issuer)).resolves.toEqual(metadata);
    expect(client.getIssuerMetadata).toHaveBeenCalledTimes(2);
  });

  it('is asked for once more when it fails while the caching step waits on it', async () => {
    client.getIssuerMetadata
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce(metadata);

    const cached = await IssuersService().cacheIssuerWellknown({
      credentialOfferCredentialIssuer: issuer,
    });

    expect(cached).toEqual(metadata);
    expect(client.getIssuerMetadata).toHaveBeenCalledTimes(2);
  });

  it("keeps a newer download's request when an older one fails", async () => {
    let failOlder!: (error: Error) => void;
    client.getIssuerMetadata.mockImplementationOnce(
      () => new Promise((_, reject) => (failOlder = reject)),
    );
    const older = requestIssuerMetadata(issuer).catch(() => undefined);
    await cacheChecked();
    await startOfferDownload();
    client.getIssuerMetadata.mockClear();
    const newer = requestIssuerMetadata(issuer);
    await cacheChecked();

    failOlder(new Error('offline'));
    await older;

    expect(requestIssuerMetadata(issuer)).toBe(newer);
    expect(client.getIssuerMetadata).toHaveBeenCalledTimes(1);
  });

  it("keeps a newer download's request when an older caching step finishes", async () => {
    let finishOlder!: (value: typeof metadata) => void;
    client.getIssuerMetadata.mockImplementationOnce(
      () => new Promise(resolve => (finishOlder = resolve)),
    );
    const olderCaching = IssuersService().cacheIssuerWellknown({
      credentialOfferCredentialIssuer: issuer,
    });
    await cacheChecked();
    await startOfferDownload();
    client.getIssuerMetadata.mockClear();
    const newer = requestIssuerMetadata(issuer);
    await cacheChecked();

    finishOlder(metadata);
    await olderCaching;

    expect(requestIssuerMetadata(issuer)).toBe(newer);
    expect(client.getIssuerMetadata).toHaveBeenCalledTimes(1);
  });
});

describe('issuer metadata the wallet already has', () => {
  const store = {getItem: getItem as jest.Mock, setItem: setItem as jest.Mock};

  beforeEach(async () => {
    jest.clearAllMocks();
    client.getIssuerMetadata.mockResolvedValue(metadata);
    // Clears what an earlier download left shared.
    await startOfferDownload();
    jest.clearAllMocks();
  });

  afterEach(() =>
    store.getItem.mockImplementation(() => Promise.resolve(null)),
  );

  it('is not downloaded again when the cached copy is under an hour old', async () => {
    const cachedMetadata = {credential_issuer: issuer, cached: true};
    store.getItem.mockResolvedValue({
      response: cachedMetadata,
      cachedTime: Date.now() - 10 * 60 * 1000,
    });

    const result = await IssuersService().cacheIssuerWellknown({
      credentialOfferCredentialIssuer: issuer,
    });

    expect(result).toBe(cachedMetadata);
    expect(client.getIssuerMetadata).not.toHaveBeenCalled();
    // Saving it again would reset its time, so it would never expire.
    expect(store.setItem).not.toHaveBeenCalled();
  });

  it('is downloaded again when the cached copy is over an hour old', async () => {
    store.getItem.mockResolvedValue({
      response: {credential_issuer: issuer, cached: true},
      cachedTime: Date.now() - 2 * 60 * 60 * 1000,
    });

    const result = await IssuersService().cacheIssuerWellknown({
      credentialOfferCredentialIssuer: issuer,
    });

    expect(result).toEqual(metadata);
    expect(client.getIssuerMetadata).toHaveBeenCalledTimes(1);
    expect(store.setItem).toHaveBeenCalledTimes(1);
  });
});
