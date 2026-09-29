import {
  getCredissuerCredentialId,
  getIssuerQrCodeUrl,
  isCredissuerCredential,
} from './issuerQrCode';

describe('getIssuerQrCodeUrl', () => {
  it('reads qr_code from the credential subject', () => {
    expect(
      getIssuerQrCodeUrl({
        credentialSubject: {qr_code: ' https://cdn.credissuer.com/x.png '},
      }),
    ).toBe('https://cdn.credissuer.com/x.png');
  });

  it('returns null when there is no usable qr_code', () => {
    expect(getIssuerQrCodeUrl({credentialSubject: {}})).toBeNull();
    expect(getIssuerQrCodeUrl({credentialSubject: {qr_code: '  '}})).toBeNull();
    expect(getIssuerQrCodeUrl({credentialSubject: {qr_code: 42}})).toBeNull();
    expect(getIssuerQrCodeUrl('compact-jwt')).toBeNull();
    expect(getIssuerQrCodeUrl(null)).toBeNull();
  });
});

describe('getCredissuerCredentialId', () => {
  it('reads credential_id from the credential subject', () => {
    expect(
      getCredissuerCredentialId({
        credentialSubject: {credential_id: 'NIDUT0016', nrcNumber: 'NIDUT0016'},
      }),
    ).toBe('NIDUT0016');
  });

  it('falls back to nrcNumber when credential_id is left out', () => {
    expect(
      getCredissuerCredentialId({credentialSubject: {nrcNumber: 'UTPNID002'}}),
    ).toBe('UTPNID002');
  });

  it.each([
    ['licenceNumber', 'LIC001'],
    ['tpinNumber', 'TPIN001'],
    ['idNumber', 'ID001'],
    ['_credential_id', 'CRED001'],
    ['NID', 'NID001'],
  ])('falls back to %s', (field, value) => {
    expect(
      getCredissuerCredentialId({credentialSubject: {[field]: value}}),
    ).toBe(value);
  });

  it('follows the CredIssuer priority order', () => {
    expect(
      getCredissuerCredentialId({
        credentialSubject: {NID: 'NID001', licenceNumber: 'LIC001'},
      }),
    ).toBe('LIC001');
    expect(
      getCredissuerCredentialId({
        credentialSubject: {nrcNumber: ' ', tpinNumber: 'TPIN001'},
      }),
    ).toBe('TPIN001');
  });

  it('returns null when no ID field is present', () => {
    expect(getCredissuerCredentialId({credentialSubject: {}})).toBeNull();
    expect(getCredissuerCredentialId({nameSpaces: {}})).toBeNull();
  });
});

describe('isCredissuerCredential', () => {
  it('accepts CredIssuer did:web issuers, as a string or an object', () => {
    const issuer =
      'did:web:did.credissuer.com:3e000830-3dee-4e7d-ba91-dff87afb557c';
    expect(isCredissuerCredential({issuer})).toBe(true);
    expect(isCredissuerCredential({issuer: {id: issuer}})).toBe(true);
  });

  it('rejects other issuers so their ID numbers are never sent to CredIssuer', () => {
    expect(isCredissuerCredential({issuer: 'did:web:example.com'})).toBe(false);
    expect(
      isCredissuerCredential({issuer: 'did:web:did.credissuer.com.evil.io'}),
    ).toBe(false);
    expect(isCredissuerCredential({})).toBe(false);
    expect(isCredissuerCredential('compact-jwt')).toBe(false);
  });
});
