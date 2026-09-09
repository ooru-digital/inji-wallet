import {normalizeAuthorizationRequest} from './normalizeAuthorizationRequest';

// A real request from the CredIssuer verifier portal, which base64-encodes the
// whole query. Decodes to:
//   client_id=http://staging-verify.credissuer.com&presentation_definition={...}
//   &response_type=vp_token&...&nonce=GGsUVnXo/iLcwKGqSxeiLg==&...
const BASE64_QUERY =
  'Y2xpZW50X2lkPWh0dHA6Ly9zdGFnaW5nLXZlcmlmeS5jcmVkaXNzdWVyLmNvbSZyZXNwb25zZV90eXBlPXZwX3Rva2VuJm5vbmNlPUdHc1VWblhvL2lMY3dLR3FTeGVpTGc9PSZjbGllbnRfbWV0YWRhdGE9eyJuYW1lIjogIkNyZWRJc3N1ZXIgVmVyaWZpZXIgQXBwIn0=';

describe('normalizeAuthorizationRequest', () => {
  it('decodes a base64-encoded query and percent-encodes the values', () => {
    const result = normalizeAuthorizationRequest(
      'openid4vp://authorize?' + BASE64_QUERY,
    );

    expect(result).toBe(
      'openid4vp://authorize?client_id=http%3A%2F%2Fstaging-verify.credissuer.com' +
        '&response_type=vp_token' +
        '&nonce=GGsUVnXo%2FiLcwKGqSxeiLg%3D%3D' +
        '&client_metadata=%7B%22client_name%22%3A%22CredIssuer%20Verifier%20App%22%7D' +
        '&client_id_scheme=pre-registered',
    );
  });

  it('leaves an already spec-compliant request byte-for-byte unchanged', () => {
    const compliant =
      'openid4vp://authorize?client_id=did%3Aexample%3A123&nonce=ab%2Bc%3D%3D&response_type=vp_token';

    expect(normalizeAuthorizationRequest(compliant)).toBe(compliant);
  });

  it('percent-encodes a plain query carrying raw JSON', () => {
    expect(
      normalizeAuthorizationRequest(
        'openid4vp://authorize?client_id=did:example:123&client_metadata={"name": "X"}',
      ),
    ).toBe(
      'openid4vp://authorize?client_id=did%3Aexample%3A123&client_metadata=%7B%22client_name%22%3A%22X%22%7D',
    );
  });

  describe('client_id_scheme compatibility', () => {
    it('adds the pre-registered default to an encoded draft-21 request', () => {
      const draft21 =
        'openid4vp://authorize?client_id=https%3A%2F%2Fverify.example.com&response_type=vp_token';

      expect(normalizeAuthorizationRequest(draft21)).toBe(
        draft21 + '&client_id_scheme=pre-registered',
      );
    });

    it('does not override a client_id_scheme the verifier already sent', () => {
      const explicit =
        'openid4vp://authorize?client_id=https%3A%2F%2Fverify.example.com&client_id_scheme=redirect_uri';

      expect(normalizeAuthorizationRequest(explicit)).toBe(explicit);
    });

    it.each([
      ['did', 'did%3Aexample%3A123'],
      ['redirect_uri', 'redirect_uri%3Ahttps%3A%2F%2Fa.com%2Fcb'],
      ['a plain pre-registered identifier', 'verify.example.com'],
    ])('leaves a draft-22 %s client_id alone', (_label, clientId) => {
      const request = `openid4vp://authorize?client_id=${clientId}&response_type=vp_token`;

      expect(normalizeAuthorizationRequest(request)).toBe(request);
    });

    it('does nothing when there is no client_id at all', () => {
      const request = 'openid4vp://authorize?request_uri=https%3A%2F%2Fa.com%2Fr';

      expect(normalizeAuthorizationRequest(request)).toBe(request);
    });
  });

  describe('client_metadata vp_formats compatibility', () => {
    const build = (definition: string, metadata: string) =>
      'openid4vp://authorize?client_id=did%3Aexample%3A123' +
      `&presentation_definition=${encodeURIComponent(definition)}` +
      `&client_metadata=${encodeURIComponent(metadata)}`;

    const metadataOf = (request: string) =>
      JSON.parse(
        decodeURIComponent(
          /client_metadata=([^&]*)/.exec(request)![1],
        ),
      );

    it('derives vp_formats from the top-level presentation_definition format', () => {
      const result = normalizeAuthorizationRequest(
        build(
          '{"format": {"ldp_vc": {"proof_type": ["Ed25519Signature2020"]}}}',
          '{"name": "CredIssuer Verifier App"}',
        ),
      );

      expect(metadataOf(result)).toEqual({
        client_name: 'CredIssuer Verifier App',
        vp_formats: {ldp_vc: {proof_type: ['Ed25519Signature2020']}},
      });
    });

    it('also picks up formats declared on input_descriptors', () => {
      const result = normalizeAuthorizationRequest(
        build(
          '{"input_descriptors": [{"format": {"mso_mdoc": {"alg": ["ES256"]}}}]}',
          '{"name": "V"}',
        ),
      );

      expect(metadataOf(result).vp_formats).toEqual({
        mso_mdoc: {alg: ['ES256']},
      });
    });

    it('does not overwrite vp_formats the verifier already sent', () => {
      const request = build(
        '{"format": {"ldp_vc": {"proof_type": ["Ed25519Signature2020"]}}}',
        '{"vp_formats": {"jwt_vp": {"alg": ["ES256"]}}}',
      );

      expect(normalizeAuthorizationRequest(request)).toBe(request);
    });

    it('maps verifier `name` to spec `client_name` so the SDK keeps the display name', () => {
      const result = normalizeAuthorizationRequest(
        build('{"id": "pd-1"}', '{"name": "CredIssuer Verifier App"}'),
      );

      expect(metadataOf(result)).toEqual({
        client_name: 'CredIssuer Verifier App',
      });
    });

    it('does not overwrite a client_name the verifier already sent', () => {
      const request = build(
        '{"id": "pd-1"}',
        '{"client_name": "Official Name", "name": "Alias"}',
      );

      expect(normalizeAuthorizationRequest(request)).toBe(request);
    });

    it('maps name even when vp_formats is already present', () => {
      const result = normalizeAuthorizationRequest(
        build(
          '{"format": {"ldp_vc": {"proof_type": ["Ed25519Signature2020"]}}}',
          '{"name": "V", "vp_formats": {"jwt_vp": {"alg": ["ES256"]}}}',
        ),
      );

      expect(metadataOf(result)).toEqual({
        client_name: 'V',
        vp_formats: {jwt_vp: {alg: ['ES256']}},
      });
    });

    it('leaves the request alone when no format is declared anywhere and name is already client_name', () => {
      const request = build('{"id": "pd-1"}', '{"client_name": "V"}');

      expect(normalizeAuthorizationRequest(request)).toBe(request);
    });

    it('leaves a missing client_metadata missing rather than inventing one', () => {
      const request =
        'openid4vp://authorize?client_id=did%3Aexample%3A123' +
        '&presentation_definition=%7B%22format%22%3A%7B%22ldp_vc%22%3A%7B%7D%7D%7D';

      expect(normalizeAuthorizationRequest(request)).toBe(request);
    });

    it('drops format entries that are not lists of strings', () => {
      const result = normalizeAuthorizationRequest(
        build(
          '{"format": {"ldp_vc": {"proof_type": ["Ed25519Signature2020"], "bogus": 7}}}',
          '{"name": "V"}',
        ),
      );

      expect(metadataOf(result).vp_formats).toEqual({
        ldp_vc: {proof_type: ['Ed25519Signature2020']},
      });
    });

    it('leaves other parameters byte-for-byte intact while rewriting metadata', () => {
      const result = normalizeAuthorizationRequest(
        build(
          '{"format": {"ldp_vc": {"proof_type": ["Ed25519Signature2020"]}}}',
          '{"name": "V"}',
        ),
      );

      expect(result).toContain('client_id=did%3Aexample%3A123');
      expect(result).toContain(
        'presentation_definition=' +
          encodeURIComponent(
            '{"format": {"ldp_vc": {"proof_type": ["Ed25519Signature2020"]}}}',
          ),
      );
    });
  });

  it('keeps an unencoded & attached to the value it belongs to', () => {
    const result = normalizeAuthorizationRequest(
      'openid4vp://authorize?client_metadata={"name": "A & B"}&response_type=vp_token',
    );

    expect(result).toBe(
      'openid4vp://authorize?client_metadata=%7B%22client_name%22%3A%22A%20%26%20B%22%7D' +
        '&response_type=vp_token',
    );
  });

  // In a decoded base64 payload the bytes are raw, so a `+` is a literal plus
  // and has to be escaped — the SDK decodes with URLDecoder, where a bare `+`
  // would silently become a space and corrupt a base64 nonce.
  it('escapes a literal + recovered from a base64 payload', () => {
    // decodes to: client_id=did:example:123&nonce=aB+cd/ef==
    const encoded = 'Y2xpZW50X2lkPWRpZDpleGFtcGxlOjEyMyZub25jZT1hQitjZC9lZj09';

    expect(normalizeAuthorizationRequest('openid4vp://authorize?' + encoded)).toBe(
      'openid4vp://authorize?client_id=did%3Aexample%3A123&nonce=aB%2Bcd%2Fef%3D%3D',
    );
  });

  // Conversely, in an already-compliant request `+` carries its
  // x-www-form-urlencoded meaning of "space", so rewriting it to %2B would
  // change what the verifier asked for. It must be left alone.
  it('does not rewrite + in an already-compliant request', () => {
    const compliant =
      'openid4vp://authorize?client_id=did%3Aexample%3A123&purpose=a+b';

    expect(normalizeAuthorizationRequest(compliant)).toBe(compliant);
  });

  it('passes through payloads that are not authorization requests', () => {
    const cases = [
      'inji://landing?linkCode=abc',
      'openid4vp://authorize',
      'openid4vp://authorize?',
      'mdoc:owBjMS4wAYIB2BhYS6QBAiABIVgg',
    ];

    cases.forEach(input =>
      expect(normalizeAuthorizationRequest(input)).toBe(input),
    );
  });

  it('is idempotent', () => {
    const once = normalizeAuthorizationRequest(
      'openid4vp://authorize?' + BASE64_QUERY,
    );

    expect(normalizeAuthorizationRequest(once)).toBe(once);
  });
});
