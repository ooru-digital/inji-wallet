import {
  classifyTokenRequestFailure,
  IssuanceError,
  IssuanceFailure,
  TokenRequestError,
} from './issuanceFailure';

describe('classifyTokenRequestFailure', () => {
  it('treats a wrong code with attempts left as retryable', () => {
    expect(
      classifyTokenRequestFailure(400, {
        error: 'invalid_grant',
        error_description: 'Invalid transaction code.',
        tx_code_attempts_remaining: 3,
      }),
    ).toEqual({
      failure: IssuanceFailure.INCORRECT_TX_CODE,
      attemptsRemaining: 3,
    });
  });

  it('locks the code once no attempts are left', () => {
    expect(
      classifyTokenRequestFailure(400, {
        error: 'invalid_grant',
        tx_code_attempts_remaining: 0,
      }).failure,
    ).toBe(IssuanceFailure.TX_CODE_ATTEMPTS_EXHAUSTED);
  });

  it('reads the attempts count when it comes as a string', () => {
    expect(
      classifyTokenRequestFailure(400, {
        error: 'invalid_grant',
        tx_code_attempts_remaining: '2',
      }),
    ).toEqual({
      failure: IssuanceFailure.INCORRECT_TX_CODE,
      attemptsRemaining: 2,
    });
  });

  it('treats an invalid or expired code without a count as expired', () => {
    expect(
      classifyTokenRequestFailure(400, {
        error: 'invalid_grant',
        error_description: 'Invalid or expired transaction code.',
      }).failure,
    ).toBe(IssuanceFailure.TX_CODE_EXPIRED);
  });

  it('treats any other invalid_grant as a spent offer', () => {
    expect(
      classifyTokenRequestFailure(400, {
        error: 'invalid_grant',
        error_description: 'Pre-authorized code is expired, used or invalid.',
      }).failure,
    ).toBe(IssuanceFailure.PRE_AUTHORIZED_CODE_INVALID);
  });

  it('spots a missing and an unexpected tx_code', () => {
    expect(
      classifyTokenRequestFailure(400, {
        error: 'invalid_request',
        error_description: 'tx_code is required for this offer.',
      }).failure,
    ).toBe(IssuanceFailure.TX_CODE_REQUIRED);
    expect(
      classifyTokenRequestFailure(400, {
        error: 'invalid_request',
        error_description: 'tx_code is not expected for this offer.',
      }).failure,
    ).toBe(IssuanceFailure.TX_CODE_NOT_EXPECTED);
  });

  it('recognises rate limiting by status or error code', () => {
    expect(classifyTokenRequestFailure(429, null).failure).toBe(
      IssuanceFailure.RATE_LIMITED,
    );
    expect(
      classifyTokenRequestFailure(400, {error: 'rate_limit_exceeded'}).failure,
    ).toBe(IssuanceFailure.RATE_LIMITED);
  });

  it('recognises an offer that has already been used', () => {
    expect(
      classifyTokenRequestFailure(409, {
        error: 'invalid_offer',
        message: 'Credential offer has already been used.',
        claimed_at: '2026-11-05T10:00:00Z',
      }).failure,
    ).toBe(IssuanceFailure.OFFER_ALREADY_USED);
  });

  it('leaves anything else to the generic error handling', () => {
    expect(classifyTokenRequestFailure(500, null).failure).toBe(
      IssuanceFailure.OTHER,
    );
    expect(
      classifyTokenRequestFailure(400, {
        error: 'invalid_request',
        error_description: 'grant_type is missing',
      }).failure,
    ).toBe(IssuanceFailure.OTHER);
  });
});

describe('TokenRequestError', () => {
  it('keeps the old message and classifies the body', () => {
    const body = JSON.stringify({
      error: 'invalid_grant',
      tx_code_attempts_remaining: 1,
    });
    const error = new TokenRequestError(400, body);

    expect(error).toBeInstanceOf(IssuanceError);
    expect(error.message).toBe(`Token request failed: 400 ${body}`);
    expect(error.failure).toBe(IssuanceFailure.INCORRECT_TX_CODE);
    expect(error.attemptsRemaining).toBe(1);
  });

  it('copes with a body that is not JSON', () => {
    const error = new TokenRequestError(502, '<html>Bad gateway</html>');

    expect(error.failure).toBe(IssuanceFailure.OTHER);
    expect(error.attemptsRemaining).toBeNull();
  });
});
