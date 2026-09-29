jest.mock('../constants', () => ({
  CREDISSUER_API_BASE_URL: 'https://api.credissuer.test',
  CREDISSUER_API_TOKEN_VALUE: 'test-token',
}));

import {fetchIssuerQrCodeUrl} from './credentialsApi';

const VC_ID = 'urn:uuid:64218a46-4d0d-4955-8d5f-1df660210c28';
const FRESH_QR =
  'https://cdn.credissuer.com/media/vc_presentation_files/UTPNID002/qr_presentation_UTPNID002.png?Expires=2';

const mockFetchResponse = (status: number, body: unknown) =>
  (global.fetch as jest.Mock).mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });

const credentialsApiBody = (id: string) => ({
  format: 'ldp_vc',
  credential: {
    id,
    credentialSubject: {credential_id: 'UTPNID002', qr_code: FRESH_QR},
  },
});

describe('fetchIssuerQrCodeUrl', () => {
  beforeEach(() => {
    global.fetch = jest.fn();
  });

  it('calls the credentials API with the bearer token and returns the fresh qr_code', async () => {
    mockFetchResponse(200, credentialsApiBody(VC_ID));

    await expect(fetchIssuerQrCodeUrl('UTPNID002', VC_ID)).resolves.toBe(
      FRESH_QR,
    );
    expect(global.fetch).toHaveBeenCalledWith(
      'https://api.credissuer.test/api/credentials/credentials/UTPNID002',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer test-token',
        }),
      }),
    );
  });

  it("ignores the QR when the API returns a different credential than the wallet's", async () => {
    mockFetchResponse(200, credentialsApiBody('urn:uuid:someone-else'));

    await expect(fetchIssuerQrCodeUrl('UTPNID002', VC_ID)).resolves.toBeNull();
  });

  it('returns null when the response has no qr_code', async () => {
    mockFetchResponse(200, {credential: {id: VC_ID, credentialSubject: {}}});

    await expect(fetchIssuerQrCodeUrl('UTPNID002', VC_ID)).resolves.toBeNull();
  });

  it('rejects on an error status so the caller keeps the stored QR', async () => {
    mockFetchResponse(404, {error: 'Credentials not found'});

    await expect(fetchIssuerQrCodeUrl('UNKNOWN', VC_ID)).rejects.toThrow(
      'HTTP 404',
    );
  });
});
