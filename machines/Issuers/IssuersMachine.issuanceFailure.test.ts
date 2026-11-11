const mockRequestCredentialByOffer = jest.fn();
jest.mock('../../shared/vciClient/VciClient', () => ({
  __esModule: true,
  default: {
    getInstance: () => ({
      requestCredentialByOffer: mockRequestCredentialByOffer,
    }),
  },
}));
jest.mock('../openID4VP/openID4VPMachine', () => ({
  createOpenID4VPMachine: jest.fn(),
  openID4VPMachine: {},
  OpenID4VPEvents: {},
}));

import {interpret} from 'xstate';
import {IssuersMachine} from './IssuersMachine';
import {
  IssuanceFailure,
  TokenRequestError,
} from '../../shared/openId4VCI/issuanceFailure';

const tokenRequestWithoutCode = {
  grantType: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
  tokenEndpoint: 'https://issuer.example/token',
  preAuthCode: 'pre-auth-code',
};

function rejection(status: number, body: object) {
  return Promise.reject(new TokenRequestError(status, JSON.stringify(body)));
}

const sendDownloadingFailedToVcMeta = jest.fn();

function startAtTokenRequest(
  sendTokenRequest: jest.Mock,
  {withTxCode = true} = {},
) {
  const service = interpret(
    IssuersMachine.withConfig({
      services: {
        downloadCredentialFromOffer: () => jest.fn(),
        sendTxCode: () => Promise.resolve(),
        sendTokenRequest,
        sendTokenResponse: () => new Promise(jest.fn()),
      },
      actions: {sendDownloadingFailedToVcMeta},
    }),
  ).start();

  service.send('SCAN_CREDENTIAL_OFFER_QR_CODE');
  service.send({type: 'QR_CODE_SCANNED', data: 'openid-credential-offer://'});
  if (withTxCode) {
    service.send({type: 'TX_CODE_REQUEST', inputMode: 'numeric', length: 6});
    service.send({type: 'TX_CODE_RECEIVED', txCode: '111111'});
  }
  service.send({
    type: 'TOKEN_REQUEST',
    tokenRequest: JSON.stringify(
      withTxCode
        ? {...tokenRequestWithoutCode, txCode: '111111'}
        : tokenRequestWithoutCode,
    ),
  });
  return service;
}

const flush = () => new Promise(resolve => setTimeout(resolve, 0));
const originalFetch = global.fetch;

beforeEach(() => {
  sendDownloadingFailedToVcMeta.mockClear();
});

describe('IssuersMachine transaction code retries', () => {
  it('keeps the code screen up after a wrong code and sends the next one with the same offer', async () => {
    const sendTokenRequest = jest
      .fn()
      .mockImplementationOnce(() =>
        rejection(400, {error: 'invalid_grant', tx_code_attempts_remaining: 2}),
      )
      .mockImplementationOnce(() =>
        Promise.resolve({access_token: 'token', c_nonce: 'nonce'}),
      );
    const service = startAtTokenRequest(sendTokenRequest);
    await flush();

    let state = service.getSnapshot();
    expect(state.matches('credentialDownloadFromOffer.reenteringTxCode')).toBe(
      true,
    );
    expect(state.context.isTransactionCodeRequested).toBe(true);
    expect(state.context.txCodeError).toBe(IssuanceFailure.INCORRECT_TX_CODE);
    expect(state.context.txCodeAttemptsRemaining).toBe(2);
    expect(state.context.txCodeInputResetKey).toBe(1);

    service.send({type: 'TX_CODE_RECEIVED', txCode: '222222'});
    await flush();

    state = service.getSnapshot();
    expect(sendTokenRequest).toHaveBeenCalledTimes(2);
    expect(state.context.tokenRequestObject).toMatchObject({
      preAuthCode: 'pre-auth-code',
      txCode: '222222',
    });
    expect(state.matches('credentialDownloadFromOffer.sendTokenResponse')).toBe(
      true,
    );
    expect(state.context.isTransactionCodeRequested).toBe(false);
    expect(state.context.txCodeError).toBe('');
  });

  it('locks the code screen once the attempts run out', async () => {
    const sendTokenRequest = jest.fn(() =>
      rejection(400, {error: 'invalid_grant', tx_code_attempts_remaining: 0}),
    );
    const service = startAtTokenRequest(sendTokenRequest);
    await flush();

    service.send({type: 'TX_CODE_RECEIVED', txCode: '222222'});
    await flush();

    const state = service.getSnapshot();
    expect(state.context.txCodeError).toBe(
      IssuanceFailure.TX_CODE_ATTEMPTS_EXHAUSTED,
    );
    expect(sendTokenRequest).toHaveBeenCalledTimes(1);
  });

  it('keeps the entered code after a rate limit and does not retry on its own', async () => {
    const sendTokenRequest = jest.fn(() =>
      rejection(429, {error: 'rate_limit_exceeded'}),
    );
    const service = startAtTokenRequest(sendTokenRequest);
    await flush();
    await flush();

    const state = service.getSnapshot();
    expect(state.matches('credentialDownloadFromOffer.reenteringTxCode')).toBe(
      true,
    );
    expect(state.context.txCodeError).toBe(IssuanceFailure.RATE_LIMITED);
    expect(state.context.txCodeInputResetKey).toBe(0);
    expect(sendTokenRequest).toHaveBeenCalledTimes(1);
  });

  it('shows the error screen when the first request is rate limited and no code was sent', async () => {
    const sendTokenRequest = jest.fn(() =>
      rejection(429, {error: 'rate_limit_exceeded'}),
    );
    const service = startAtTokenRequest(sendTokenRequest, {withTxCode: false});
    await flush();

    const state = service.getSnapshot();
    expect(state.matches('error')).toBe(true);
    expect(state.context.errorMessage).toBe('tooManyRequests');
    expect(state.context.isTransactionCodeRequested).toBe(false);
    expect(sendTokenRequest).toHaveBeenCalledTimes(1);
  });

  it('reports a failed download when the holder cancels after a wrong code', async () => {
    const sendTokenRequest = jest.fn(() =>
      rejection(400, {error: 'invalid_grant', tx_code_attempts_remaining: 2}),
    );
    const service = startAtTokenRequest(sendTokenRequest);
    await flush();

    service.send('CANCEL');

    const state = service.getSnapshot();
    expect(state.matches('selectingIssuer')).toBe(true);
    expect(sendDownloadingFailedToVcMeta).toHaveBeenCalledTimes(1);
    expect(state.context.isTransactionCodeRequested).toBe(false);
    expect(state.context.txCodeError).toBe('');
  });

  it('retries once without the code when the issuer does not expect one', async () => {
    const sendTokenRequest = jest
      .fn()
      .mockImplementationOnce(() =>
        rejection(400, {
          error: 'invalid_request',
          error_description: 'tx_code is not expected',
        }),
      )
      .mockImplementationOnce(() => Promise.resolve({access_token: 'token'}));
    const service = startAtTokenRequest(sendTokenRequest);
    await flush();
    await flush();

    const state = service.getSnapshot();
    expect(sendTokenRequest).toHaveBeenCalledTimes(2);
    expect(state.context.tokenRequestObject).not.toHaveProperty('txCode');
    expect(state.matches('credentialDownloadFromOffer.sendTokenResponse')).toBe(
      true,
    );
  });

  it('retries without the code only once, then shows the error', async () => {
    const sendTokenRequest = jest.fn(() =>
      rejection(400, {
        error: 'invalid_request',
        error_description: 'tx_code is not expected',
      }),
    );
    const service = startAtTokenRequest(sendTokenRequest);
    await flush();
    await flush();
    await flush();

    expect(sendTokenRequest).toHaveBeenCalledTimes(2);
    expect(service.getSnapshot().matches('error')).toBe(true);
  });

  it('says the offer was already used when the token endpoint answers 409', async () => {
    const sendTokenRequest = jest.fn(() =>
      rejection(409, {
        error: 'invalid_offer',
        message: 'Credential offer has already been used.',
      }),
    );
    const service = startAtTokenRequest(sendTokenRequest);
    await flush();

    const state = service.getSnapshot();
    expect(state.matches('error')).toBe(true);
    expect(state.context.errorMessage).toBe('offerAlreadyUsed');
  });

  it('asks the issuer and says the offer was already used when the library cannot read it', async () => {
    const offerUri = 'https://issuer.example/offers/123';
    mockRequestCredentialByOffer.mockRejectedValueOnce(
      new Error(
        'Download failed due to fetching credentialOffer Credential offer URL not valid java.lang.NullPointerException',
      ),
    );
    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        error: 'invalid_offer',
        message: 'Credential offer has already been used.',
      }),
    });
    global.fetch = fetchMock;

    const service = interpret(IssuersMachine).start();
    service.send('SCAN_CREDENTIAL_OFFER_QR_CODE');
    service.send({
      type: 'QR_CODE_SCANNED',
      data: `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(
        offerUri,
      )}`,
    });
    await flush();
    await flush();

    const state = service.getSnapshot();
    expect(fetchMock).toHaveBeenCalledWith(offerUri, expect.anything());
    expect(state.matches('error')).toBe(true);
    expect(state.context.errorMessage).toBe('offerAlreadyUsed');
    global.fetch = originalFetch;
  });

  it('stops on a spent offer without offering a retry of the code', async () => {
    const sendTokenRequest = jest.fn(() =>
      rejection(400, {
        error: 'invalid_grant',
        error_description: 'Pre-authorized code is expired, used or invalid.',
      }),
    );
    const service = startAtTokenRequest(sendTokenRequest);
    await flush();

    const state = service.getSnapshot();
    expect(state.matches('error')).toBe(true);
    expect(state.context.errorMessage).toBe('preAuthorizedCodeInvalid');
    expect(state.context.isTransactionCodeRequested).toBe(false);
  });
});
