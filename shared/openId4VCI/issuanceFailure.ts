/** Why an issuer turned down a credential offer download, in the terms the wallet can act on. */
export enum IssuanceFailure {
  /** Wrong transaction code; the holder can try again with the same offer. */
  INCORRECT_TX_CODE = 'incorrectTxCode',
  /** No attempts left; even the right code fails until the issuer resends one. */
  TX_CODE_ATTEMPTS_EXHAUSTED = 'txCodeAttemptsExhausted',
  /** The code has expired, or a newer one has been sent. */
  TX_CODE_EXPIRED = 'txCodeExpired',
  /** The offer needs a code, but the request went without one. */
  TX_CODE_REQUIRED = 'txCodeRequired',
  /** The request carried a code the offer doesn't take. */
  TX_CODE_NOT_EXPECTED = 'txCodeNotExpected',
  /** The offer itself has expired, been used, or never existed; only a new offer helps. */
  PRE_AUTHORIZED_CODE_INVALID = 'preAuthorizedCodeInvalid',
  /** The offer has already been claimed, usually because the card was already added from it. */
  OFFER_ALREADY_USED = 'offerAlreadyUsed',
  RATE_LIMITED = 'rateLimited',
  OTHER = 'other',
}

/** An issuance error the wallet has recognised; `setError` and the guards read `failure`. */
export class IssuanceError extends Error {
  failure: IssuanceFailure;
  /** From the issuer's `tx_code_attempts_remaining`; null when it didn't say. */
  attemptsRemaining: number | null;

  constructor(
    message: string,
    failure: IssuanceFailure,
    attemptsRemaining: number | null = null,
  ) {
    super(message);
    this.name = 'IssuanceError';
    this.failure = failure;
    this.attemptsRemaining = attemptsRemaining;
  }
}

/**
 * Thrown by the token request. The message keeps the old "Token request failed: <status> <body>"
 * form, since error handling elsewhere matches on it.
 */
export class TokenRequestError extends IssuanceError {
  status: number;

  constructor(status: number, responseText: string) {
    const {failure, attemptsRemaining} = classifyTokenRequestFailure(
      status,
      parseBody(responseText),
    );
    super(
      `Token request failed: ${status} ${responseText}`,
      failure,
      attemptsRemaining,
    );
    this.name = 'TokenRequestError';
    this.status = status;
  }
}

export function classifyTokenRequestFailure(
  status: number,
  body: Record<string, unknown> | null,
): {failure: IssuanceFailure; attemptsRemaining: number | null} {
  const error = typeof body?.error === 'string' ? body.error : '';
  const description = String(
    body?.error_description ?? body?.message ?? '',
  ).toLowerCase();
  const attemptsRemaining = toCount(body?.tx_code_attempts_remaining);
  const result = (failure: IssuanceFailure) => ({failure, attemptsRemaining});

  if (status === 429 || error === 'rate_limit_exceeded') {
    return result(IssuanceFailure.RATE_LIMITED);
  }
  if (status === 409 || error === 'invalid_offer') {
    return result(IssuanceFailure.OFFER_ALREADY_USED);
  }
  // inji-certify reports these under their own error codes rather than invalid_request/invalid_grant.
  if (error === 'tx_code_required') {
    return result(IssuanceFailure.TX_CODE_REQUIRED);
  }
  if (error === 'tx_code_mismatch') {
    return result(IssuanceFailure.INCORRECT_TX_CODE);
  }
  if (error === 'invalid_request') {
    if (description.includes('tx_code is required')) {
      return result(IssuanceFailure.TX_CODE_REQUIRED);
    }
    if (description.includes('tx_code is not expected')) {
      return result(IssuanceFailure.TX_CODE_NOT_EXPECTED);
    }
    return result(IssuanceFailure.OTHER);
  }
  if (error === 'invalid_grant') {
    if (attemptsRemaining !== null) {
      return result(
        attemptsRemaining > 0
          ? IssuanceFailure.INCORRECT_TX_CODE
          : IssuanceFailure.TX_CODE_ATTEMPTS_EXHAUSTED,
      );
    }
    const isAboutTxCode =
      description.includes('transaction code') ||
      description.includes('tx_code');
    return result(
      isAboutTxCode && !description.includes('pre-authorized')
        ? IssuanceFailure.TX_CODE_EXPIRED
        : IssuanceFailure.PRE_AUTHORIZED_CODE_INVALID,
    );
  }
  return result(IssuanceFailure.OTHER);
}

function parseBody(text: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

function toCount(value: unknown): number | null {
  if (typeof value === 'string' && value.trim() === '') return null;
  const count = typeof value === 'string' ? Number(value) : value;
  return typeof count === 'number' && Number.isFinite(count) && count >= 0
    ? count
    : null;
}
