import {compactVcForQr, MAX_QR_FIELD_CHARS} from './compactVcForQr';

describe('compactVcForQr', () => {
  it('is a no-op for small VCs without blobs', () => {
    const vc = {
      id: 'urn:uuid:1',
      type: ['VerifiableCredential'],
      credentialSubject: {
        idNumber: 'IND123411',
        photo: 'https://media.credissuer.com/photo.jpeg',
      },
    };

    expect(JSON.parse(compactVcForQr(vc))).toEqual(vc);
  });

  it('strips data-URI and oversized blobs but leaves identity claims', () => {
    const blob = 'A'.repeat(MAX_QR_FIELD_CHARS + 10);
    const vc = {
      id: 'urn:uuid:1',
      proof: {type: 'Ed25519Signature2020', proofValue: 'zABC'},
      credentialSubject: {
        idNumber: 'IND123411',
        photo: 'https://media.credissuer.com/photo.jpeg',
        signature: `data:image/png;base64,${blob}`,
        faceImage: blob,
      },
    };

    const compacted = JSON.parse(compactVcForQr(vc));

    expect(compacted.credentialSubject.idNumber).toBe('IND123411');
    expect(compacted.credentialSubject.photo).toBe(
      'https://media.credissuer.com/photo.jpeg',
    );
    expect(compacted.credentialSubject.signature).toBeUndefined();
    expect(compacted.credentialSubject.faceImage).toBeUndefined();
    expect(compacted.proof.proofValue).toBe('zABC');
    expect(compactVcForQr(vc).length).toBeLessThan(JSON.stringify(vc).length);
  });

  it('drops renderMethod so inlined SVG is not encoded into the QR', () => {
    const vc = {
      id: 'urn:uuid:1',
      renderMethod: [{template: {id: 'data:image/svg+xml;base64,AAAA'}}],
      credentialSubject: {idNumber: 'IND1'},
    };

    const compacted = JSON.parse(compactVcForQr(vc));
    expect(compacted.renderMethod).toBeUndefined();
  });
});
