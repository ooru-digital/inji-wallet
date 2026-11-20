// Wallet metadata for inji-openid4vp 0.7 (iOS, ios/Packages/inji-openid4vp-ios-swift).
export const walletMetadata = {
  response_types_supported: ['vp_token'],
  presentation_definition_uri_supported: true,
  vp_formats_supported: {
    ldp_vc: {
      alg_values_supported: [
        'Ed25519Signature2018',
        'Ed25519Signature2020',
        'RSASignature2018',
      ],
    },
    mso_mdoc: {
      alg_values_supported: ['ES256'],
    },
    'vc+sd-jwt': {
      alg_values_supported: ['EdDSA', 'ES256'],
    },
  },
  client_id_schemes_supported: ['redirect_uri', 'did', 'pre-registered'],
  request_object_signing_alg_values_supported: ['EdDSA'],
  authorization_encryption_alg_values_supported: ['ECDH-ES'],
  authorization_encryption_enc_values_supported: ['A256GCM'],
};

/**
 * Wallet config for inji-openid4vp 1.0 (Android). The same capabilities as above in 1.0's
 * shape: client_id prefixes instead of schemes, and per-format value lists. Every value must be
 * one the library's enums know (ProofType, ClientIdPrefix, SignatureAlgorithm, ...): an unknown
 * one parses to null. Trusted verifiers are added per scan, not here.
 */
export const walletConfig = {
  response_types_supported: ['vp_token'],
  vp_formats_supported: {
    ldp_vc: {
      proof_type_values: ['Ed25519Signature2020', 'JsonWebSignature2020'],
    },
    mso_mdoc: {
      issuerauth_alg_values: [-7],
      deviceauth_alg_values: [-7],
    },
    'dc+sd-jwt': {
      'sd-jwt_alg_values': ['EdDSA', 'ES256'],
      'kb-jwt_alg_values': ['ES256', 'EdDSA'],
    },
    'vc+sd-jwt': {
      'sd-jwt_alg_values': ['EdDSA', 'ES256'],
      'kb-jwt_alg_values': ['ES256', 'EdDSA'],
    },
  },
  client_id_prefixes_supported: [
    'redirect_uri',
    'decentralized_identifier',
    'pre-registered',
  ],
  request_object_signing_alg_values_supported: ['EdDSA'],
  authorization_encryption_alg_values_supported: ['ECDH-ES'],
  authorization_encryption_enc_values_supported: ['A256GCM'],
  presentation_definition_uri_supported: true,
};
