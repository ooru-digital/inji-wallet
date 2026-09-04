/**
 * ISO/IEC 18013-5 device engagement for QR (compact payload).
 *
 * CDDL (DIS 18013-5:2020 §8.1.1.1) describes DeviceEngagement as a CBOR **array**.
 * Many verifier stacks (and sample `mdoc:` payloads) use a CBOR **map** instead:
 *   { 0: version, 1: Security, 2: TransferMethods, ?3: Options, ?4: docTypes, ?5: ApplicationSpecific }
 *
 * Security = [ cipherSuiteIdentifier, #6.24(bstr .cbor COSE_Key) ]
 * QR URI: `mdoc:` or `mDL:` + base64url-without-padding (engagement CBOR).
 */
import {Buffer} from 'buffer';
import {encode as base64urlEncode} from 'base64url-universal';
import {p256} from '@noble/curves/p256';
import {CborTag24, encodeCbor} from './cborEncodeMinimal';
import {
  parseBlePeripheralUuidFromDeviceEngagement,
  parseCoseEc2P256FromDeviceEngagement,
} from './cborDecodeMinimal';

/** Holder-facing QR prefix (ecosystem convention). */
export const MDOC_QR_URI_SCHEME = 'mdoc:';
/** Prefix from ISO/IEC 18013-5:2020 §8.1.2.3. */
export const MDL_QR_URI_SCHEME = 'mDL:';

/** Table 22 — 1 = P-256 / ECDH + AES-128-CBC-HMAC-SHA256 (typical profile). */
export const CIPHER_SUITE_P256_ECDH_AES_128 = 1;

/** BLE offline retrieval — Table 5: type 2, version 1. */
export const TRANSFER_METHOD_BLE = 2;
export const TRANSFER_METHOD_BLE_VERSION = 1;

/** ISO DIS 18013-5:2020 §8.1.1.1 `BleOptions` map keys (not 1/10/11 for flags/UUIDs). */
export const BLE_OPT_SUPPORTS_PERIPHERAL_SERVER = 0;
export const BLE_OPT_SUPPORTS_CENTRAL_CLIENT = 1;
/** UUID (16 bytes, big-endian) when acting as BLE peripheral GATT server. */
export const BLE_OPT_PERIPHERAL_SERVER_UUID = 10;
/** UUID (16 bytes, big-endian) when acting as BLE central GATT client. */
export const BLE_OPT_CENTRAL_CLIENT_UUID = 11;
/**
 * Tap2iD / working-sample `mdoc:` QRs use a **single** BLE row with key **21**.
 * Working payload observed: **130** (not 128). Multipaz dual-row samples often use **128** on the first row only.
 */
export const BLE_OPT_INTEROP_PAIRING_HINT_21 = 21;
export const BLE_OPT_INTEROP_PAIRING_HINT_21_DEFAULT = 130;
/** First-row hint when {@link MdocDeviceEngagementOptions.ble} `dualBleTransferRows` is true. */
export const BLE_OPT_INTEROP_PAIRING_HINT_21_MULTIPAZ_DEFAULT = 128;

/** How the top-level engagement value is CBOR-encoded before base64url. */
export type MdocDeviceEngagementEncoding = 'iso18013Array' | 'interopCborMap';

/** How BLE rows are shaped for proximity QR (Multipaz vs Credence Tap2iD samples). */
export type MdocProximityPresentationProfile = 'multipaz' | 'tap2id';

export interface MdocDeviceEngagementOptions {
  /**
   * **tap2id** (default): one BLE row `{0:true,1:false,10:uuid,21:130}` — same logical shape as a decoded
   * Multipaz / Tap2iD working proximity engagement (`TransferMethods` = one `[2,1,BleOptions]`).
   * **multipaz**: two BLE rows (peripheral row `21:128` + central row `11:uuid`) for labs that expect dual-row QRs.
   * Ignored if `ble.dualBleTransferRows` is set explicitly.
   */
  proximityPresentationProfile?: MdocProximityPresentationProfile;
  /**
   * `interopCborMap` (default) matches common verifier / `mdoc:` samples (uint map keys).
   * `iso18013Array` matches the CDDL array in ISO/IEC 18013-5:2020 §8.1.1.1.
   */
  deviceEngagementEncoding?: MdocDeviceEngagementEncoding;
  /**
   * When using `interopCborMap`, include map key `4` with doc types (default false = minimal 3-key map).
   */
  includeDocTypesInEngagement?: boolean;
  /** Defaults to {@link CIPHER_SUITE_P256_ECDH_AES_128}. */
  cipherSuiteIdentifier?: number;
  /** If set, QR also advertises WebAPI online retrieval (ISO §8.1.1.2). */
  webApi?: {version?: number; url: string; token: string};
  oidc?: {version?: number; url: string; token: string};
  ble?: {
    /** Reserved for future custom BLE rows; Tap2iD default ignores these. */
    supportsPeripheral?: boolean;
    supportsCentral?: boolean;
    /** 16-byte UUID for BLE peripheral server row (map key 10). Default: random. */
    peripheralServerUuidBytes?: Uint8Array;
    /** 16-byte UUID for BLE central client row (map key 11). Default: random. */
    centralClientUuidBytes?: Uint8Array;
    /**
     * Map key {@link BLE_OPT_INTEROP_PAIRING_HINT_21} on the **single** BLE row (default Tap2iD style) or on the **first** row when dual BLE is enabled.
     * Defaults: **130** (single-row Tap2iD working sample), **128** (first row of Multipaz dual-row).
     */
    interopPairingHint21?: number;
    /**
     * `true`: two `[2,1,BleOptions]` rows (Multipaz-style).
     * `false`: one BLE row (Tap2iD-style).
     * If omitted, derived from {@link MdocDeviceEngagementOptions.proximityPresentationProfile}.
     */
    dualBleTransferRows?: boolean;
  };
  /** ISO DocType strings, e.g. org.iso.18013.5.1.mDL */
  docTypes?: string[];
  applicationSpecific?: Record<string, unknown>;
  /** URI scheme prefix (include trailing semantics: no second colon). */
  uriScheme?: typeof MDOC_QR_URI_SCHEME | typeof MDL_QR_URI_SCHEME | string;
}

export interface MdocDeviceEngagementSession {
  /** Full `mdoc:...` / `mDL:...` string for the QR component. */
  mdocUri: string;
  /** Raw DeviceEngagement CBOR (not tag-24 wrapped). */
  deviceEngagementCbor: Uint8Array;
  /** Retain until presentation completes — needed for SessionTranscript / DeviceAuth. */
  ephemeralPrivateKey: Uint8Array;
  /** Uncompressed P-256 public key (0x04 || x || y), for debugging/tests. */
  ephemeralPublicKeyUncompressed: Uint8Array;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/**
 * Validates decoded DeviceEngagement (interop map) for Tap2ID-style readers:
 * COSE_Key EC2 P-256 with raw 32-byte x/y, tag 24 wrapping inner CBOR bstr only,
 * BLE row with 16-byte UUID at key 10.
 */
export function validateDeviceEngagementInteroperability(
  deviceEngagementCbor: Uint8Array,
): {ok: true} | {ok: false; error: string} {
  try {
    const cose = parseCoseEc2P256FromDeviceEngagement(deviceEngagementCbor);
    if (cose.kty !== 2 || cose.crv !== 1) {
      throw new Error(
        `COSE_Key must use kty=2 (EC2) and crv=1 (P-256); got kty=${cose.kty}, crv=${cose.crv}`,
      );
    }
    parseBlePeripheralUuidFromDeviceEngagement(deviceEngagementCbor);
    return {ok: true};
  } catch (e) {
    return {ok: false, error: e instanceof Error ? e.message : String(e)};
  }
}

function assertDeviceEngagementMatchesEphemeralKey(
  deviceEngagementCbor: Uint8Array,
  publicUncompressed: Uint8Array,
): void {
  const cose = parseCoseEc2P256FromDeviceEngagement(deviceEngagementCbor);
  if (cose.kty !== 2 || cose.crv !== 1) {
    throw new Error(
      `COSE_Key must use kty=2 (EC2) and crv=1 (P-256); got kty=${cose.kty}, crv=${cose.crv}`,
    );
  }
  const xExp = publicUncompressed.subarray(1, 33);
  const yExp = publicUncompressed.subarray(33, 65);
  if (!bytesEqual(cose.x, xExp) || !bytesEqual(cose.y, yExp)) {
    throw new Error(
      'Decoded COSE_Key x/y do not match the generated ephemeral public key (check for double CBOR wrapping)',
    );
  }
  parseBlePeripheralUuidFromDeviceEngagement(deviceEngagementCbor);
}

function logDeviceEngagementDev(deviceEngagementCbor: Uint8Array): void {
  try {
    const cose = parseCoseEc2P256FromDeviceEngagement(deviceEngagementCbor);
    const uuid =
      parseBlePeripheralUuidFromDeviceEngagement(deviceEngagementCbor);
    const hex = (u: Uint8Array) =>
      Array.from(u, byte => byte.toString(16).padStart(2, '0')).join('');
    const n = Math.min(96, deviceEngagementCbor.length);
    console.log(
      '[mDoc DeviceEngagement] CBOR length:',
      deviceEngagementCbor.length,
    );
    console.log(
      '[mDoc DeviceEngagement] CBOR hex (first',
      n,
      'bytes):',
      hex(deviceEngagementCbor.subarray(0, n)),
    );
    console.log(
      '[mDoc DeviceEngagement] COSE_Key: kty=',
      cose.kty,
      'crv=',
      cose.crv,
      'x.len=',
      cose.x.length,
      'y.len=',
      cose.y.length,
    );
    console.log('[mDoc DeviceEngagement] COSE x (hex):', hex(cose.x));
    console.log('[mDoc DeviceEngagement] COSE y (hex):', hex(cose.y));
    console.log(
      '[mDoc DeviceEngagement] BLE peripheral UUID (16 B, hex):',
      hex(uuid),
    );
    console.log(
      '[mDoc DeviceEngagement] SessionTranscript is built after BLE with the reader ephemeral key; the QR carries DeviceEngagement bytes only.',
    );
  } catch (e) {
    console.warn('[mDoc DeviceEngagement] dev log failed', e);
  }
}

function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  const cr = globalThis.crypto;
  if (!cr?.getRandomValues) {
    throw new Error(
      'crypto.getRandomValues is required for mdoc DeviceEngagement',
    );
  }
  cr.getRandomValues(out);
  return out;
}

export function generateEphemeralP256KeyPair(): {
  privateKey: Uint8Array;
  publicKeyUncompressed: Uint8Array;
} {
  const privateKey = p256.utils.randomPrivateKey();
  const publicKeyUncompressed = p256.getPublicKey(privateKey, false);
  return {privateKey, publicKeyUncompressed};
}

function coseEc2P256PublicKey(
  publicUncompressed: Uint8Array,
): Map<number, number | Uint8Array> {
  if (publicUncompressed.length !== 65 || publicUncompressed[0] !== 0x04) {
    throw new Error(
      'Expected uncompressed P-256 public key (65 bytes, 0x04 prefix)',
    );
  }
  const x = new Uint8Array(publicUncompressed.subarray(1, 33));
  const y = new Uint8Array(publicUncompressed.subarray(33, 65));
  if (x.length !== 32 || y.length !== 32) {
    throw new Error('COSE P-256 x/y must be exactly 32 raw bytes each');
  }
  return new Map<number, number | Uint8Array>([
    [1, 2],
    [-1, 1],
    [-2, x],
    [-3, y],
  ]);
}

export function inferDefaultDocTypes(
  credentialConfigurationId?: string,
): string[] {
  // Engagement QR usually omits docTypes (includeDocTypesInEngagement defaults false).
  // When present, prefer not to invent a type — empty means "not advertised in engagement".
  if (!credentialConfigurationId) {
    return [];
  }
  const id = credentialConfigurationId.toLowerCase();
  if (id.includes('mdl') || id.includes('drivers') || id.includes('license')) {
    return ['org.iso.18013.5.1.mDL'];
  }
  if (id.includes('pid') || id.includes('person')) {
    return ['eu.europa.ec.eudi.pid.1'];
  }
  // Generic mdoc config id — do not force mDL; presentment uses MSO.docType.
  return [];
}

/**
 * Build ISO 18013-5 DeviceEngagement CBOR and `mdoc:` / `mDL:` URI.
 * Does not include issuerSigned, portrait, or certificates — only engagement material.
 */
export function createMdocDeviceEngagementSession(
  options: MdocDeviceEngagementOptions & {
    ephemeralPrivateKey?: Uint8Array;
    ephemeralPublicKeyUncompressed?: Uint8Array;
  } = {},
): MdocDeviceEngagementSession {
  const kp =
    options.ephemeralPrivateKey && options.ephemeralPublicKeyUncompressed
      ? {
          privateKey: options.ephemeralPrivateKey,
          publicKeyUncompressed: options.ephemeralPublicKeyUncompressed,
        }
      : generateEphemeralP256KeyPair();

  const cipher =
    options.cipherSuiteIdentifier ?? CIPHER_SUITE_P256_ECDH_AES_128;
  const coseKey = coseEc2P256PublicKey(kp.publicKeyUncompressed);
  const eDeviceKeyCbor = encodeCbor(coseKey);
  const security = [cipher, new CborTag24(eDeviceKeyCbor)];

  let peripheralUuid: Uint8Array;
  if (
    options.ble?.peripheralServerUuidBytes &&
    options.ble.peripheralServerUuidBytes.byteLength === 16
  ) {
    peripheralUuid = new Uint8Array(options.ble.peripheralServerUuidBytes);
  } else {
    peripheralUuid = randomBytes(16);
  }

  const profile: MdocProximityPresentationProfile =
    options.proximityPresentationProfile ?? 'tap2id';
  let dualBle: boolean;
  if (options.ble?.dualBleTransferRows === true) {
    dualBle = true;
  } else if (options.ble?.dualBleTransferRows === false) {
    dualBle = false;
  } else {
    dualBle = profile === 'multipaz';
  }

  const hint21Single =
    options.ble?.interopPairingHint21 ??
    BLE_OPT_INTEROP_PAIRING_HINT_21_DEFAULT;
  const hint21DualFirst =
    options.ble?.interopPairingHint21 ??
    BLE_OPT_INTEROP_PAIRING_HINT_21_MULTIPAZ_DEFAULT;

  let transferMethods: unknown[];
  if (dualBle) {
    const centralUuid =
      options.ble?.centralClientUuidBytes &&
      options.ble.centralClientUuidBytes.byteLength === 16
        ? new Uint8Array(options.ble.centralClientUuidBytes)
        : randomBytes(16);
    const blePeripheralRow = new Map<number, boolean | number | Uint8Array>([
      [BLE_OPT_SUPPORTS_PERIPHERAL_SERVER, true],
      [BLE_OPT_SUPPORTS_CENTRAL_CLIENT, false],
      [BLE_OPT_PERIPHERAL_SERVER_UUID, peripheralUuid],
      [BLE_OPT_INTEROP_PAIRING_HINT_21, hint21DualFirst],
    ]);
    const bleCentralRow = new Map<number, boolean | number | Uint8Array>([
      [BLE_OPT_SUPPORTS_PERIPHERAL_SERVER, false],
      [BLE_OPT_SUPPORTS_CENTRAL_CLIENT, true],
      [BLE_OPT_CENTRAL_CLIENT_UUID, centralUuid],
    ]);
    transferMethods = [
      [TRANSFER_METHOD_BLE, TRANSFER_METHOD_BLE_VERSION, blePeripheralRow],
      [TRANSFER_METHOD_BLE, TRANSFER_METHOD_BLE_VERSION, bleCentralRow],
    ];
  } else {
    const bleTap2idRow = new Map<number, boolean | number | Uint8Array>([
      [BLE_OPT_SUPPORTS_PERIPHERAL_SERVER, true],
      [BLE_OPT_SUPPORTS_CENTRAL_CLIENT, false],
      [BLE_OPT_PERIPHERAL_SERVER_UUID, peripheralUuid],
      [BLE_OPT_INTEROP_PAIRING_HINT_21, hint21Single],
    ]);
    transferMethods = [
      [TRANSFER_METHOD_BLE, TRANSFER_METHOD_BLE_VERSION, bleTap2idRow],
    ];
  }

  const opts: Record<string, unknown> = {};
  if (options.webApi) {
    opts.webApi = [
      options.webApi.version ?? 1,
      options.webApi.url,
      options.webApi.token,
    ];
  }
  if (options.oidc) {
    opts.oidc = [
      options.oidc.version ?? 1,
      options.oidc.url,
      options.oidc.token,
    ];
  }

  const docTypes = options.docTypes ?? [];
  const appSpec = options.applicationSpecific;
  const hasApplicationSpecific =
    !!appSpec && Object.keys(appSpec as Record<string, unknown>).length > 0;
  const hasOpts = Object.keys(opts).length > 0;
  const encoding = options.deviceEngagementEncoding ?? 'interopCborMap';
  const includeDocTypes =
    options.includeDocTypesInEngagement === true && docTypes.length > 0;

  let deviceEngagementCbor: Uint8Array;
  if (encoding === 'iso18013Array') {
    const deviceEngagement: unknown[] = [
      '1.0',
      security,
      transferMethods,
      opts,
      docTypes,
    ];
    if (hasApplicationSpecific) {
      deviceEngagement.push(appSpec);
    }
    deviceEngagementCbor = encodeCbor(deviceEngagement);
  } else {
    const root = new Map<number, unknown>([
      [0, '1.0'],
      [1, security],
      [2, transferMethods],
    ]);
    if (hasOpts) {
      root.set(3, opts);
    }
    if (includeDocTypes) {
      root.set(4, docTypes);
    }
    if (hasApplicationSpecific) {
      root.set(5, appSpec);
    }
    deviceEngagementCbor = encodeCbor(root);
  }

  if (encoding === 'interopCborMap') {
    /* Validation expects uint-key map layout (Tap2ID / Multipaz `mdoc:` shape). */
    assertDeviceEngagementMatchesEphemeralKey(
      deviceEngagementCbor,
      kp.publicKeyUncompressed,
    );
    if (__DEV__ && process.env.NODE_ENV !== 'test') {
      logDeviceEngagementDev(deviceEngagementCbor);
    }
  }

  const scheme = options.uriScheme ?? MDOC_QR_URI_SCHEME;
  const mdocUri = `${scheme}${base64urlEncode(
    Buffer.from(deviceEngagementCbor),
  )}`;

  return {
    mdocUri,
    deviceEngagementCbor,
    ephemeralPrivateKey: kp.privateKey,
    ephemeralPublicKeyUncompressed: kp.publicKeyUncompressed,
  };
}
