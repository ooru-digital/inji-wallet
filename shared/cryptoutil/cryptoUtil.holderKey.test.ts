/**
 * The ES256 holder key on iOS lives in the Secure Enclave: JS only gets the public key, and
 * signing goes through the native module, the same shape as Android.
 */
import {NativeModules, Platform} from 'react-native';
import {p256} from '@noble/curves/p256';
import {sha256} from '@noble/hashes/sha256';
import {Buffer} from 'buffer';

// The shared jest setup replaces cryptoUtil with a stub; this test needs the real module.
jest.unmock('./cryptoUtil');
jest.mock('../openId4VCI/Utils', () => ({hasKeyPair: jest.fn()}));
// cryptoUtil sets hash hooks on these at import; the other key types aren't under test here.
jest.mock('@noble/secp256k1', () => ({
  etc: {concatBytes: jest.fn()},
  utils: {randomPrivateKey: () => new Uint8Array(32).fill(1)},
  getPublicKey: () => new Uint8Array(65).fill(2),
}));
jest.mock('react-native-rsa-native', () => ({
  RSA: {
    generateKeys: jest
      .fn()
      .mockResolvedValue({public: 'rsa-public', private: 'rsa-private'}),
  },
}));
jest.mock('@noble/ed25519', () => ({
  etc: {concatBytes: jest.fn()},
  utils: {randomPrivateKey: () => new Uint8Array(32).fill(3)},
  getPublicKey: () => new Uint8Array(32).fill(4),
}));
jest.mock('../telemetry/TelemetryUtils', () => ({
  sendImpressionEvent: jest.fn(),
  getImpressionEventData: jest.fn(),
}));

import {
  createSignatureECR1,
  fetchKeyPair,
  generateKeyPairECR1,
  generateKeyPairsAndStoreOrder,
  isStoredAsGenericKey,
} from './cryptoUtil';
import {KeyTypes} from './KeyTypes';

const keystore = NativeModules.RNSecureKeystoreModule as Record<
  string,
  jest.Mock
>;

// A real P-256 key stands in for the Secure Enclave, so the signature can be verified.
const enclavePrivateKey = p256.utils.randomPrivateKey();
const enclavePublicKey = p256.getPublicKey(enclavePrivateKey, false);
const enclavePublicKeyBase64 = Buffer.from(enclavePublicKey).toString('base64');

function fromBase64Url(value: string): Uint8Array {
  return new Uint8Array(
    Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64'),
  );
}

describe('ES256 holder key on iOS (Secure Enclave)', () => {
  const originalOS = Platform.OS;

  beforeEach(() => {
    (Platform as {OS: string}).OS = 'ios';
    Object.assign(keystore, {
      hasBiometricsEnabled: jest.fn().mockResolvedValue(true),
      generateKeyPair: jest.fn().mockResolvedValue(enclavePublicKeyBase64),
      retrieveKey: jest.fn().mockResolvedValue(enclavePublicKeyBase64),
      retrieveGenericKey: jest.fn(),
      storeGenericKey: jest.fn().mockResolvedValue(true),
      storeData: jest.fn().mockResolvedValue(true),
      sign: jest.fn(async (_alg: string, _alias: string, data: string) => {
        const signature = p256.sign(
          sha256(new TextEncoder().encode(data)),
          enclavePrivateKey,
        );
        return Buffer.from(signature.toDERRawBytes()).toString('base64');
      }),
    });
  });

  afterAll(() => {
    (Platform as {OS: string}).OS = originalOS;
  });

  it('creates the key natively, with iOS arguments, and never returns a private key', async () => {
    const keyPair = await generateKeyPairECR1();

    expect(keystore.generateKeyPair).toHaveBeenCalledWith(
      KeyTypes.ES256,
      true,
      0,
    );
    expect(keyPair).toEqual({
      publicKey: enclavePublicKeyBase64,
      privateKey: '',
    });
  });

  it('reads only the public key, as the 65-byte point', async () => {
    const keyPair = await fetchKeyPair(KeyTypes.ES256);

    expect(keystore.retrieveKey).toHaveBeenCalledWith(KeyTypes.ES256);
    expect(keystore.retrieveGenericKey).not.toHaveBeenCalled();
    expect(Buffer.isBuffer(keyPair.publicKey)).toBe(true);
    expect((keyPair.publicKey as Buffer).length).toBe(65);
    expect(keyPair.privateKey).toBe('');
  });

  it('signs natively and returns a JWS r || s signature that verifies', async () => {
    const payload = 'header.payload';
    const signature = await createSignatureECR1('', payload);

    expect(keystore.sign).toHaveBeenCalledWith(
      KeyTypes.ES256,
      KeyTypes.ES256,
      payload,
    );
    const raw = fromBase64Url(signature);
    expect(raw.length).toBe(64);
    expect(
      p256.verify(
        raw,
        sha256(new TextEncoder().encode(payload)),
        enclavePublicKey,
      ),
    ).toBe(true);
  });

  it('never stores the ES256 key as a generic Keychain item', async () => {
    await generateKeyPairsAndStoreOrder();

    const storedAccounts = keystore.storeGenericKey.mock.calls.map(
      call => call[2],
    );
    expect(storedAccounts).not.toContain(KeyTypes.ES256);
    expect(storedAccounts).toContain(KeyTypes.RS256);
  });

  it('keeps ES256 out of generic storage on both platforms', () => {
    expect(isStoredAsGenericKey(KeyTypes.ES256)).toBe(false);
    expect(isStoredAsGenericKey(KeyTypes.RS256)).toBe(true);
    (Platform as {OS: string}).OS = 'android';
    expect(isStoredAsGenericKey(KeyTypes.ES256)).toBe(false);
    expect(isStoredAsGenericKey(KeyTypes.RS256)).toBe(false);
    expect(isStoredAsGenericKey(KeyTypes.ED25519)).toBe(true);
  });
});
