import VciClient from '../../shared/vciClient/VciClient';
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
});
