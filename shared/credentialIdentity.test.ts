import {
  findCredentialOfSameType,
  getCredentialType,
  getDownloadedCredentialType,
  getStoredCredentialType,
} from './credentialIdentity';
import {VCFormat} from './VCFormat';

const credentialOfType = (specificType: string, extra: any = {}) => ({
  id: 'urn:uuid:8d5cc2df-f8a5-441b-9fca-8ca8b02e2681',
  type: ['VerifiableCredential', specificType],
  issuer: 'did:web:did.credissuer.com:d6171fe9-3703-4113-8a68-cb693803ca11',
  credentialSubject: {givenName: 'Nandeesh', nrcNumber: 'IND123415', ...extra},
});

const storedVc = (credential: any, format = VCFormat.ldp_vc) =>
  ({
    vcMetadata: {format},
    verifiableCredential: {credential},
  } as any);

const downloadOf = (credential: any, format = VCFormat.ldp_vc) => ({
  credentialWrapper: {format, verifiableCredential: {credential}},
});

describe('credential type identity', () => {
  it('reads the specific type, the second entry of the type array', () => {
    expect(getCredentialType(credentialOfType('NationalIDCredential'))).toBe(
      'NationalIDCredential',
    );
    expect(getCredentialType(credentialOfType('HealthIDCredential'))).toBe(
      'HealthIDCredential',
    );
  });

  it('works for a type it has never seen before, with no code change', () => {
    expect(
      getCredentialType(credentialOfType('SomeBrandNewCredential')),
    ).toBe('SomeBrandNewCredential');
  });

  it('ignores the details, so a re-download of the same card still matches', () => {
    // Everything the issuer regenerates per download — ids, proofs, signed URLs — is irrelevant
    // now that only the type is compared.
    const first = credentialOfType('NationalIDCredential');
    const second = credentialOfType('NationalIDCredential', {
      qr_code: 'https://cdn.credissuer.com/x.png?Expires=1788956015',
    });
    second.id = 'urn:uuid:99999999-0000-0000-0000-000000000000';

    expect(getDownloadedCredentialType(downloadOf(second))).toBe(
      getStoredCredentialType(storedVc(first)),
    );
  });

  describe('type arrays that cannot be read', () => {
    it('returns null when there is no specific type', () => {
      expect(getCredentialType({type: ['VerifiableCredential']})).toBeNull();
    });

    it('returns null when type is not an array', () => {
      expect(getCredentialType({type: 'VerifiableCredential'})).toBeNull();
      expect(getCredentialType({})).toBeNull();
      expect(getCredentialType(null)).toBeNull();
    });

    it('returns null when the specific type is blank', () => {
      expect(
        getCredentialType({type: ['VerifiableCredential', '   ']}),
      ).toBeNull();
    });
  });

  describe('finding the credential to offer replacing', () => {
    it('returns the stored card of the same type', () => {
      const stored = {
        a: storedVc(credentialOfType('HealthIDCredential')),
        b: storedVc(credentialOfType('NationalIDCredential')),
      };

      const match = findCredentialOfSameType(
        downloadOf(credentialOfType('NationalIDCredential')),
        stored,
      );

      expect(match).toBe(stored.b);
    });

    it('returns null when no stored card shares the type', () => {
      const stored = {a: storedVc(credentialOfType('HealthIDCredential'))};

      expect(
        findCredentialOfSameType(
          downloadOf(credentialOfType('NationalIDCredential')),
          stored,
        ),
      ).toBeNull();
    });

    it('returns null for an empty wallet', () => {
      expect(
        findCredentialOfSameType(
          downloadOf(credentialOfType('NationalIDCredential')),
          {},
        ),
      ).toBeNull();
    });

    it('does not match a stored credential whose type cannot be read', () => {
      const stored = {a: storedVc({type: ['VerifiableCredential']})};

      expect(
        findCredentialOfSameType(
          downloadOf(credentialOfType('NationalIDCredential')),
          stored,
        ),
      ).toBeNull();
    });
  });

  describe('formats this check deliberately leaves alone', () => {
    it('ignores an incoming mso_mdoc', () => {
      expect(
        getDownloadedCredentialType(
          downloadOf(credentialOfType('MobileDL'), VCFormat.mso_mdoc),
        ),
      ).toBeNull();
    });

    it('ignores a stored mso_mdoc', () => {
      expect(
        getStoredCredentialType(
          storedVc(credentialOfType('MobileDL'), VCFormat.mso_mdoc),
        ),
      ).toBeNull();
    });

    it('never offers to replace an mdoc, so mdl downloads are unaffected', () => {
      const stored = {
        a: storedVc(credentialOfType('MobileDL'), VCFormat.mso_mdoc),
      };

      expect(
        findCredentialOfSameType(
          downloadOf(credentialOfType('MobileDL'), VCFormat.mso_mdoc),
          stored,
        ),
      ).toBeNull();
    });

    it('does not match a stored mdoc against an incoming W3C card', () => {
      const stored = {
        a: storedVc(
          credentialOfType('NationalIDCredential'),
          VCFormat.mso_mdoc,
        ),
      };

      expect(
        findCredentialOfSameType(
          downloadOf(credentialOfType('NationalIDCredential')),
          stored,
        ),
      ).toBeNull();
    });
  });
});
