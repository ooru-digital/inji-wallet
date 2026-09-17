import {encodeCbor} from './cborEncodeMinimal';
import {
  createMdocDeviceEngagementSession,
  generateEphemeralP256KeyPair,
  validateDeviceEngagementInteroperability,
} from './deviceEngagement';
import {
  countBleTransferMethodRowsInDeviceEngagement,
  parseBlePeripheralUuidFromDeviceEngagement,
  parseCoseEc2P256FromDeviceEngagement,
} from './cborDecodeMinimal';

describe('mDoc DeviceEngagement (ISO 18013-5 interop / Tap2ID)', () => {
  it('encodes CBOR maps in canonical key order (same bytes regardless of insertion order)', () => {
    const m1 = new Map<number | string, string>([
      [2, 'b'],
      [1, 'a'],
    ]);
    const m2 = new Map<number | string, string>([
      [1, 'a'],
      [2, 'b'],
    ]);
    const a = encodeCbor(m1);
    const b = encodeCbor(m2);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
  });

  it('produces DeviceEngagement that decodes to raw 32-byte EC2 x/y and 16-byte BLE UUID', () => {
    const kp = generateEphemeralP256KeyPair();
    const uuid = new Uint8Array(16);
    uuid.fill(0x7e);
    const session = createMdocDeviceEngagementSession({
      ephemeralPrivateKey: kp.privateKey,
      ephemeralPublicKeyUncompressed: kp.publicKeyUncompressed,
      ble: {peripheralServerUuidBytes: uuid},
      proximityPresentationProfile: 'tap2id',
    });
    const v = validateDeviceEngagementInteroperability(
      session.deviceEngagementCbor,
    );
    expect(v).toEqual({ok: true});

    const cose = parseCoseEc2P256FromDeviceEngagement(
      session.deviceEngagementCbor,
    );
    expect(cose.kty).toBe(2);
    expect(cose.crv).toBe(1);
    expect(cose.x.length).toBe(32);
    expect(cose.y.length).toBe(32);
    expect(
      Buffer.from(cose.x).equals(
        Buffer.from(kp.publicKeyUncompressed.subarray(1, 33)),
      ),
    ).toBe(true);
    expect(
      Buffer.from(cose.y).equals(
        Buffer.from(kp.publicKeyUncompressed.subarray(33, 65)),
      ),
    ).toBe(true);

    const bleUuid = parseBlePeripheralUuidFromDeviceEngagement(
      session.deviceEngagementCbor,
    );
    expect(Buffer.from(bleUuid).equals(Buffer.from(uuid))).toBe(true);
  });

  it('multipaz profile encodes two BLE transfer method rows', () => {
    const session = createMdocDeviceEngagementSession({
      proximityPresentationProfile: 'multipaz',
    });
    expect(
      countBleTransferMethodRowsInDeviceEngagement(
        session.deviceEngagementCbor,
      ),
    ).toBe(2);
  });

  it('tap2id profile encodes one BLE transfer method row', () => {
    const session = createMdocDeviceEngagementSession({
      proximityPresentationProfile: 'tap2id',
    });
    expect(
      countBleTransferMethodRowsInDeviceEngagement(
        session.deviceEngagementCbor,
      ),
    ).toBe(1);
  });

  it('uses a 3-key interop root map (0,1,2) for tap2id profile', () => {
    const session = createMdocDeviceEngagementSession({
      proximityPresentationProfile: 'tap2id',
    });
    expect(session.deviceEngagementCbor[0] & 0xe0).toBe(0xa0);
    expect(session.deviceEngagementCbor[0] & 0x1f).toBe(3);
  });

  it('passes interoperability validation for many random sessions', () => {
    for (let i = 0; i < 20; i++) {
      const session = createMdocDeviceEngagementSession();
      expect(
        validateDeviceEngagementInteroperability(session.deviceEngagementCbor),
      ).toEqual({
        ok: true,
      });
    }
  });
});
