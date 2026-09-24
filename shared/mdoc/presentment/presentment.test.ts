/**
 * In-process loopback: this test plays the **reader** against our holder implementation.
 *
 * There is no Tap2iD device in CI, and the failure mode we care about is silent — a session that
 * completes locally but produces bytes a verifier rejects. So instead of asserting on our own
 * intermediate values, the test independently derives the session keys from the reader side,
 * decrypts what we send, and verifies the DeviceAuth signature the way a real verifier would.
 * If the SessionTranscript, key derivation, nonce construction or Sig_structure were wrong, the
 * signature check at the end fails.
 *
 * What this does *not* cover is the BLE transport itself (native, untestable here) and trust
 * decisions about the issuer. See `shared/mdoc/README.md`.
 */

import {p256} from '@noble/curves/p256';
import {gcm} from '@noble/ciphers/aes';
import {hkdf} from '@noble/hashes/hkdf';
import {sha256} from '@noble/hashes/sha256';
import {Buffer} from 'buffer';

import {CborRaw, CborTag24, encodeCbor} from '../cborEncodeMinimal';
import {
  asArray,
  asBytes,
  asMap,
  bytesEqual,
  decodeCbor,
  DecodedTag,
} from './cbor';
import {buildSigStructure, softwareEs256Signer} from './cose';
import {buildDeviceResponse} from './deviceResponse';
import {parseDeviceRequest, selectDocRequestForDocType} from './deviceRequest';
import {findElement, parseIssuerSignedCredential} from './issuerSigned';
import {
  buildSessionTranscriptBytes,
  deriveSessionKeys,
  MdocSessionCipher,
  parseSessionEstablishment,
  uncompressedP256ToCoseKey,
} from './sessionCrypto';

const DOC_TYPE = 'org.iso.18013.5.1.mDL';
const NAMESPACE = 'org.iso.18013.5.1';
const textEncoder = new TextEncoder();

// --- fixtures ---------------------------------------------------------------

/** One `IssuerSignedItemBytes` with deterministic contents. */
function issuerSignedItem(
  digestID: number,
  elementIdentifier: string,
  elementValue: unknown,
): Uint8Array {
  const item = encodeCbor(
    new Map<string, unknown>([
      ['digestID', digestID],
      ['random', new Uint8Array(16).fill(digestID)],
      ['elementIdentifier', elementIdentifier],
      ['elementValue', elementValue],
    ]),
  );
  return encodeCbor(new CborTag24(item));
}

/**
 * A minimal but structurally real `IssuerSigned`, base64-encoded the way the wallet stores it.
 * The issuer signature is not checked anywhere in the holder path, so a fixed 64-byte value is
 * enough — what matters is that the bytes survive round-tripping untouched.
 */
function buildCredential(): {
  compact: string;
  items: Record<string, Uint8Array>;
} {
  const items = {
    family_name: issuerSignedItem(1, 'family_name', 'Chandavarkar'),
    given_name: issuerSignedItem(2, 'given_name', 'Mayuresh'),
    birth_date: issuerSignedItem(3, 'birth_date', '1990-01-01'),
  };

  const mso = encodeCbor(
    new Map<string, unknown>([
      ['version', '1.0'],
      ['digestAlgorithm', 'SHA-256'],
      ['docType', DOC_TYPE],
    ]),
  );
  const issuerAuth = [
    encodeCbor(new Map<number, number>([[1, -7]])),
    new Map<number, unknown>(),
    encodeCbor(new CborTag24(mso)),
    new Uint8Array(64).fill(7),
  ];

  const issuerSigned = encodeCbor(
    new Map<string, unknown>([
      [
        'nameSpaces',
        new Map<string, unknown[]>([
          [NAMESPACE, Object.values(items).map(raw => new CborRaw(raw))],
        ]),
      ],
      ['issuerAuth', issuerAuth],
    ]),
  );

  return {
    compact: Buffer.from(issuerSigned).toString('base64'),
    items,
  };
}

/** A DeviceEngagement shaped like the one `deviceEngagement.ts` produces for iOS. */
function buildEngagement(devicePublicKeyUncompressed: Uint8Array): Uint8Array {
  const coseKey = uncompressedP256ToCoseKey(devicePublicKeyUncompressed);
  return encodeCbor(
    new Map<number, unknown>([
      [0, '1.0'],
      [1, [1, new CborTag24(coseKey)]],
      [
        2,
        [
          [
            2,
            1,
            new Map<number, unknown>([
              [0, true],
              [1, false],
              [10, new Uint8Array(16).fill(0xab)],
              [21, 130],
            ]),
          ],
        ],
      ],
    ]),
  );
}

/** `DeviceRequest` asking for two elements the credential has and one it does not. */
function buildDeviceRequest(): Uint8Array {
  const itemsRequest = encodeCbor(
    new Map<string, unknown>([
      ['docType', DOC_TYPE],
      [
        'nameSpaces',
        new Map<string, unknown>([
          [
            NAMESPACE,
            new Map<string, boolean>([
              ['family_name', true],
              ['given_name', false],
              ['portrait', false],
            ]),
          ],
        ]),
      ],
      ['requestInfo', new Map<string, unknown>([['purposeHints', 1]])],
    ]),
  );
  return encodeCbor(
    new Map<string, unknown>([
      ['version', '1.0'],
      [
        'docRequests',
        [
          new Map<string, unknown>([
            ['itemsRequest', new CborTag24(itemsRequest)],
          ]),
        ],
      ],
    ]),
  );
}

// --- the reader side --------------------------------------------------------

/**
 * Independent reimplementation of §9.1.1 from the reader's perspective.
 *
 * Deliberately not reusing {@link deriveSessionKeys} beyond the transcript: deriving the keys
 * here with a separate HKDF call is what makes the test meaningful — a matching pair proves both
 * sides agree, rather than proving our function equals itself.
 */
function readerDeriveKeys(
  readerPrivateKey: Uint8Array,
  devicePublicKeyUncompressed: Uint8Array,
  sessionTranscriptBytes: Uint8Array,
) {
  const zab = p256
    .getSharedSecret(readerPrivateKey, devicePublicKeyUncompressed)
    .subarray(1, 33);
  return {
    skDevice: hkdf(
      sha256,
      zab,
      sessionTranscriptBytes,
      textEncoder.encode('SKDevice'),
      32,
    ),
    skReader: hkdf(
      sha256,
      zab,
      sessionTranscriptBytes,
      textEncoder.encode('SKReader'),
      32,
    ),
  };
}

function nonce(identifierLastByte: number, counter: number): Uint8Array {
  const out = new Uint8Array(12);
  out[7] = identifierLastByte;
  out[8] = (counter >>> 24) & 0xff;
  out[9] = (counter >>> 16) & 0xff;
  out[10] = (counter >>> 8) & 0xff;
  out[11] = counter & 0xff;
  return out;
}

// --- tests ------------------------------------------------------------------

describe('ISO 18013-5 presentment (holder side)', () => {
  const devicePrivateKey = new Uint8Array(32).fill(0x11);
  const devicePublicKey = p256.getPublicKey(devicePrivateKey, false);
  const deviceAuthPrivateKey = new Uint8Array(32).fill(0x22);
  const deviceAuthPublicKey = p256.getPublicKey(deviceAuthPrivateKey, false);
  const readerPrivateKey = new Uint8Array(32).fill(0x33);
  const readerPublicKey = p256.getPublicKey(readerPrivateKey, false);

  const engagement = buildEngagement(devicePublicKey);
  const eReaderKeyBytes = encodeCbor(
    new CborTag24(uncompressedP256ToCoseKey(readerPublicKey)),
  );

  it('derives identical session keys on both sides', () => {
    const transcript = buildSessionTranscriptBytes(engagement, eReaderKeyBytes);
    const holder = deriveSessionKeys({
      ephemeralPrivateKey: devicePrivateKey,
      readerPublicKeyUncompressed: readerPublicKey,
      deviceEngagementCbor: engagement,
      eReaderKeyBytes,
    });
    const reader = readerDeriveKeys(
      readerPrivateKey,
      devicePublicKey,
      transcript,
    );

    expect(bytesEqual(holder.skDevice, reader.skDevice)).toBe(true);
    expect(bytesEqual(holder.skReader, reader.skReader)).toBe(true);
    expect(bytesEqual(holder.sessionTranscriptBytes, transcript)).toBe(true);
  });

  it('builds a SessionTranscript that embeds the engagement bytes verbatim', () => {
    const transcript = buildSessionTranscriptBytes(engagement, eReaderKeyBytes);
    const outer = decodeCbor(transcript) as DecodedTag;
    const arr = asArray(decodeCbor(outer.embeddedCbor), 'SessionTranscript');

    expect(arr).toHaveLength(3);
    // Handover is null for QR engagement.
    expect(arr[2]).toBeNull();
    expect(bytesEqual((arr[0] as DecodedTag).embeddedCbor, engagement)).toBe(
      true,
    );
  });

  it('decrypts a reader message encrypted with the reader identifier and counter 1', () => {
    const keys = deriveSessionKeys({
      ephemeralPrivateKey: devicePrivateKey,
      readerPublicKeyUncompressed: readerPublicKey,
      deviceEngagementCbor: engagement,
      eReaderKeyBytes,
    });
    const plaintext = textEncoder.encode('device request');
    const ciphertext = gcm(keys.skReader, nonce(0x00, 1)).encrypt(plaintext);

    const cipher = new MdocSessionCipher(keys);
    expect(Array.from(cipher.decrypt(ciphertext))).toEqual(
      Array.from(plaintext),
    );
  });

  it('encrypts with the device identifier, incrementing the counter per message', () => {
    const keys = deriveSessionKeys({
      ephemeralPrivateKey: devicePrivateKey,
      readerPublicKeyUncompressed: readerPublicKey,
      deviceEngagementCbor: engagement,
      eReaderKeyBytes,
    });
    const cipher = new MdocSessionCipher(keys);

    const first = cipher.encrypt(textEncoder.encode('one'));
    const second = cipher.encrypt(textEncoder.encode('two'));

    expect(
      Array.from(gcm(keys.skDevice, nonce(0x01, 1)).decrypt(first)),
    ).toEqual(Array.from(textEncoder.encode('one')));
    expect(
      Array.from(gcm(keys.skDevice, nonce(0x01, 2)).decrypt(second)),
    ).toEqual(Array.from(textEncoder.encode('two')));
  });

  it('parses SessionEstablishment and keeps the reader key bytes intact', () => {
    const encrypted = new Uint8Array(32).fill(9);
    const establishment = encodeCbor(
      new Map<string, unknown>([
        ['eReaderKey', new CborRaw(eReaderKeyBytes)],
        ['data', encrypted],
      ]),
    );
    const parsed = parseSessionEstablishment(establishment);

    expect(bytesEqual(parsed.eReaderKeyBytes, eReaderKeyBytes)).toBe(true);
    expect(
      bytesEqual(parsed.readerPublicKeyUncompressed, readerPublicKey),
    ).toBe(true);
    expect(bytesEqual(parsed.encryptedData, encrypted)).toBe(true);
  });

  it('indexes the credential and reads docType from the MSO', () => {
    const {compact} = buildCredential();
    const credential = parseIssuerSignedCredential(compact, 'fallback.docType');

    expect(credential.docType).toBe(DOC_TYPE);
    expect(credential.msoDocType).toBe(DOC_TYPE);
    expect(findElement(credential, NAMESPACE, 'family_name')).not.toBeNull();
    expect(findElement(credential, NAMESPACE, 'portrait')).toBeNull();
  });

  it('parses a DeviceRequest including intentToRetain and purpose', () => {
    const request = parseDeviceRequest(buildDeviceRequest());
    const docRequest = selectDocRequestForDocType(request, DOC_TYPE);

    expect(docRequest).not.toBeNull();
    expect(docRequest!.elements).toHaveLength(3);
    expect(
      docRequest!.elements.find(e => e.elementIdentifier === 'family_name')
        ?.intentToRetain,
    ).toBe(true);
    expect(
      docRequest!.elements.find(e => e.elementIdentifier === 'given_name')
        ?.intentToRetain,
    ).toBe(false);
    expect(docRequest!.requestInfo?.purposeHints).toBe(1);
  });

  it('produces a DeviceResponse a verifier can check end to end', async () => {
    const {compact, items} = buildCredential();
    const credential = parseIssuerSignedCredential(compact, DOC_TYPE);

    const keys = deriveSessionKeys({
      ephemeralPrivateKey: devicePrivateKey,
      readerPublicKeyUncompressed: readerPublicKey,
      deviceEngagementCbor: engagement,
      eReaderKeyBytes,
    });

    // Only what the reader asked for and the credential holds.
    const request = parseDeviceRequest(buildDeviceRequest());
    const docRequest = selectDocRequestForDocType(request, DOC_TYPE)!;
    const disclosed = docRequest.elements
      .map(e => findElement(credential, e.namespace, e.elementIdentifier))
      .filter((e): e is NonNullable<typeof e> => e !== null);
    // Order follows the reader's canonically-encoded request map, not the order written above;
    // it carries no meaning here because each IssuerSignedItem is digested independently.
    expect(disclosed.map(d => d.elementIdentifier).sort()).toEqual([
      'family_name',
      'given_name',
    ]);

    const responseBytes = await buildDeviceResponse({
      credential,
      docType: DOC_TYPE,
      disclosed,
      sessionTranscriptBytes: keys.sessionTranscriptBytes,
      signer: softwareEs256Signer(deviceAuthPrivateKey),
    });

    // ---- from here on, act purely as the verifier ----
    const response = asMap(decodeCbor(responseBytes), 'DeviceResponse');
    expect(response.get('version')).toBe('1.0');
    expect(response.get('status')).toBe(0);

    const documents = asArray(response.get('documents'), 'documents');
    expect(documents).toHaveLength(1);
    const document = asMap(documents[0], 'Document');
    expect(document.get('docType')).toBe(DOC_TYPE);

    // Disclosed items must be byte-identical to what the issuer signed, or the MSO digests
    // would no longer match and a real verifier would reject the credential as tampered.
    const issuerSigned = asMap(document.get('issuerSigned'), 'issuerSigned');
    const nameSpaces = asMap(issuerSigned.get('nameSpaces'), 'nameSpaces');
    const disclosedItems = asArray(
      nameSpaces.get(NAMESPACE),
      'namespace items',
    );
    expect(disclosedItems).toHaveLength(2);
    const disclosedRaw = disclosedItems.map(entry => (entry as DecodedTag).raw);
    expect(disclosedRaw.some(raw => bytesEqual(raw, items.family_name))).toBe(
      true,
    );
    expect(disclosedRaw.some(raw => bytesEqual(raw, items.given_name))).toBe(
      true,
    );
    // The element the credential does not hold must simply be absent.
    const identifiers = disclosedItems.map(entry => {
      const item = asMap(
        decodeCbor((entry as DecodedTag).embeddedCbor),
        'IssuerSignedItem',
      );
      return item.get('elementIdentifier');
    });
    expect(identifiers.sort()).toEqual(['family_name', 'given_name']);
    expect(identifiers).not.toContain('portrait');

    // Verify DeviceAuth exactly as a reader would: rebuild DeviceAuthentication from values the
    // verifier already has, rebuild the Sig_structure, and check the signature.
    const deviceSigned = asMap(document.get('deviceSigned'), 'deviceSigned');
    const deviceNameSpaces = deviceSigned.get('nameSpaces') as DecodedTag;
    const deviceAuth = asMap(deviceSigned.get('deviceAuth'), 'deviceAuth');
    const sign1 = asArray(deviceAuth.get('deviceSignature'), 'deviceSignature');

    // Detached payload: the COSE_Sign1 on the wire must not carry it inline.
    expect(sign1[2]).toBeNull();

    const sessionTranscript = (
      decodeCbor(keys.sessionTranscriptBytes) as DecodedTag
    ).embeddedCbor;
    const deviceAuthentication = encodeCbor([
      'DeviceAuthentication',
      new CborRaw(sessionTranscript),
      DOC_TYPE,
      new CborTag24(deviceNameSpaces.embeddedCbor),
    ]);
    const toBeSigned = buildSigStructure(
      asBytes(sign1[0], 'protected header'),
      encodeCbor(new CborTag24(deviceAuthentication)),
    );

    const verified = p256.verify(
      asBytes(sign1[3], 'signature'),
      sha256(toBeSigned),
      deviceAuthPublicKey,
    );
    expect(verified).toBe(true);
  });

  it('rejects a DeviceAuth signature bound to a different session', async () => {
    const {compact} = buildCredential();
    const credential = parseIssuerSignedCredential(compact, DOC_TYPE);
    const keys = deriveSessionKeys({
      ephemeralPrivateKey: devicePrivateKey,
      readerPublicKeyUncompressed: readerPublicKey,
      deviceEngagementCbor: engagement,
      eReaderKeyBytes,
    });

    const responseBytes = await buildDeviceResponse({
      credential,
      docType: DOC_TYPE,
      disclosed: [findElement(credential, NAMESPACE, 'family_name')!],
      sessionTranscriptBytes: keys.sessionTranscriptBytes,
      signer: softwareEs256Signer(deviceAuthPrivateKey),
    });

    const document = asMap(
      asArray(
        asMap(decodeCbor(responseBytes), 'DeviceResponse').get('documents'),
        'documents',
      )[0],
      'Document',
    );
    const sign1 = asArray(
      asMap(
        asMap(document.get('deviceSigned'), 'deviceSigned').get('deviceAuth'),
        'deviceAuth',
      ).get('deviceSignature'),
      'deviceSignature',
    );

    // A verifier in a *different* session rebuilds a different transcript, so the same signature
    // must not validate — this is what stops a captured response being replayed.
    const otherEngagement = buildEngagement(
      p256.getPublicKey(new Uint8Array(32).fill(0x44), false),
    );
    const otherTranscript = (
      decodeCbor(
        buildSessionTranscriptBytes(otherEngagement, eReaderKeyBytes),
      ) as DecodedTag
    ).embeddedCbor;
    const forged = encodeCbor(
      new CborTag24(
        encodeCbor([
          'DeviceAuthentication',
          new CborRaw(otherTranscript),
          DOC_TYPE,
          new CborTag24(encodeCbor(new Map())),
        ]),
      ),
    );

    const verified = p256.verify(
      asBytes(sign1[3], 'signature'),
      sha256(buildSigStructure(asBytes(sign1[0], 'protected'), forged)),
      deviceAuthPublicKey,
    );
    expect(verified).toBe(false);
  });
});

describe('CBOR codec', () => {
  it('round-trips the structures the presentment path depends on', () => {
    const value = new Map<unknown, unknown>([
      ['text', 'hello'],
      ['bytes', new Uint8Array([1, 2, 3])],
      ['int', 42],
      ['negative', -7],
      ['bool', true],
      ['null', null],
      ['array', [1, 'two', new Uint8Array([3])]],
      ['nested', new Map<string, unknown>([['a', 1]])],
    ]);
    const decoded = asMap(decodeCbor(encodeCbor(value)), 'round trip');

    expect(decoded.get('text')).toBe('hello');
    expect(Array.from(decoded.get('bytes') as Uint8Array)).toEqual([1, 2, 3]);
    expect(decoded.get('int')).toBe(42);
    expect(decoded.get('negative')).toBe(-7);
    expect(decoded.get('bool')).toBe(true);
    expect(decoded.get('null')).toBeNull();
    expect((decoded.get('nested') as Map<unknown, unknown>).get('a')).toBe(1);
  });

  it('preserves the exact source bytes of a tagged item', () => {
    const inner = encodeCbor(new Map<string, unknown>([['k', 'v']]));
    const tagged = encodeCbor(new CborTag24(inner));
    const decoded = decodeCbor(tagged) as DecodedTag;

    expect(decoded.tag).toBe(24);
    expect(bytesEqual(decoded.raw, tagged)).toBe(true);
    expect(bytesEqual(decoded.embeddedCbor, inner)).toBe(true);
    // Splicing the captured bytes back in must reproduce the original exactly.
    expect(bytesEqual(encodeCbor(new CborRaw(decoded.raw)), tagged)).toBe(true);
  });

  it('sorts map keys canonically regardless of insertion order', () => {
    const a = encodeCbor(
      new Map<number, string>([
        [3, 'c'],
        [1, 'a'],
        [2, 'b'],
      ]),
    );
    const b = encodeCbor(
      new Map<number, string>([
        [1, 'a'],
        [2, 'b'],
        [3, 'c'],
      ]),
    );
    expect(bytesEqual(a, b)).toBe(true);
  });

  it('rejects trailing bytes rather than silently ignoring them', () => {
    const valid = encodeCbor(42);
    const withTrailing = new Uint8Array([...valid, 0xff]);
    expect(() => decodeCbor(withTrailing)).toThrow(/trailing/);
  });

  it('decodes indefinite-length strings a third-party reader may send', () => {
    // 0x5f (indefinite bstr) + two chunks + break.
    const indefinite = new Uint8Array([
      0x5f, 0x42, 0x01, 0x02, 0x41, 0x03, 0xff,
    ]);
    expect(Array.from(decodeCbor(indefinite) as Uint8Array)).toEqual([1, 2, 3]);
  });
});
