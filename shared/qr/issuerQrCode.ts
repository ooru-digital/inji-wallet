function getCredentialSubjectString(
  credential: unknown,
  key: string,
): string | null {
  const value = (credential as {credentialSubject?: Record<string, unknown>})
    ?.credentialSubject?.[key];
  return typeof value === 'string' && value.trim().length > 0
    ? value.trim()
    : null;
}

export const getIssuerQrCodeUrl = (credential: unknown) =>
  getCredentialSubjectString(credential, 'qr_code');

/**
 * CredIssuer leaves `credential_id` out of some wallet-issued credentials; its templates then carry
 * the same value in one of these template-specific ID fields, checked in CredIssuer's priority order.
 */
const CREDISSUER_CREDENTIAL_ID_FIELDS = [
  'credential_id',
  'nrcNumber',
  'licenceNumber',
  'tpinNumber',
  'idNumber',
  '_credential_id',
  'NID',
];

export const getCredissuerCredentialId = (credential: unknown) => {
  for (const field of CREDISSUER_CREDENTIAL_ID_FIELDS) {
    const value = getCredentialSubjectString(credential, field);
    if (value) return value;
  }
  return null;
};

export function isCredissuerCredential(credential: unknown): boolean {
  const issuer = (credential as {issuer?: unknown})?.issuer;
  const issuerId =
    typeof issuer === 'string' ? issuer : (issuer as {id?: unknown})?.id;
  return (
    typeof issuerId === 'string' &&
    /^did:web:did\.credissuer\.com(:|$)/.test(issuerId)
  );
}

export function getCredentialId(credential: unknown): string | null {
  const id = (credential as {id?: unknown})?.id;
  return typeof id === 'string' && id.length > 0 ? id : null;
}
