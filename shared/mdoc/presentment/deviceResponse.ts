/**
 * Builds the `DeviceResponse` and its `DeviceAuth` signature (ISO 18013-5 §8.3.2.1.2.2, §9.1.3).
 *
 * ```
 * DeviceResponse        = { "version": "1.0", ?"documents": [Document], "status": uint }
 * Document              = { "docType": tstr, "issuerSigned": IssuerSigned,
 *                           "deviceSigned": DeviceSigned }
 * DeviceSigned          = { "nameSpaces": DeviceNameSpacesBytes,
 *                           "deviceAuth": { "deviceSignature": COSE_Sign1 } }
 * DeviceAuthentication  = [ "DeviceAuthentication", SessionTranscript, DocType,
 *                           DeviceNameSpacesBytes ]
 * ```
 *
 * The signature binds the response to *this* session: `SessionTranscript` contains the
 * DeviceEngagement the reader scanned and the reader's own ephemeral key, so a captured
 * response cannot be replayed into a different session.
 */

import {CborRaw, CborTag24, encodeCbor} from '../cborEncodeMinimal';
import {decodeCbor, DecodedTag} from './cbor';
import {signCoseSign1Detached, type Es256Signer} from './cose';
import {
  buildDisclosedNameSpaces,
  type IndexedIssuerSignedItem,
  type ParsedIssuerSignedCredential,
} from './issuerSigned';
import {logByteCommitment} from './sessionCrypto';

/** ISO 18013-5 §8.3.2.1.2.2 DeviceResponse status codes. */
export const DEVICE_RESPONSE_STATUS_OK = 0;
export const DEVICE_RESPONSE_STATUS_GENERAL_ERROR = 10;
export const DEVICE_RESPONSE_STATUS_CBOR_DECODING_ERROR = 11;
export const DEVICE_RESPONSE_STATUS_CBOR_VALIDATION_ERROR = 12;

/**
 * `DeviceNameSpaces` is an empty map: this wallet discloses only issuer-signed elements and
 * adds no device-signed ones. It still has to be present and byte-stable, because the very same
 * bytes appear inside `DeviceAuthentication` and inside `DeviceSigned`.
 */
const DEVICE_NAMESPACES_EMPTY = encodeCbor(new Map<string, unknown>());

function deviceNameSpacesBytes(): CborTag24 {
  return new CborTag24(DEVICE_NAMESPACES_EMPTY);
}

/**
 * `DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)`.
 *
 * `sessionTranscriptBytes` arrives already tagged, and is spliced in verbatim: it is the exact
 * byte string the session keys were derived from, and the reader recomputes it independently.
 */
export function buildDeviceAuthenticationBytes(params: {
  sessionTranscriptBytes: Uint8Array;
  docType: string;
}): Uint8Array {
  const deviceAuthentication = encodeCbor([
    'DeviceAuthentication',
    // SessionTranscriptBytes is #6.24(...); DeviceAuthentication embeds the SessionTranscript
    // itself, so the tag wrapper is stripped back off here.
    new CborRaw(unwrapTag24Payload(params.sessionTranscriptBytes)),
    params.docType,
    deviceNameSpacesBytes(),
  ]);
  return encodeCbor(new CborTag24(deviceAuthentication));
}

/**
 * Returns the inner CBOR of a `#6.24(bstr .cbor X)` as its own encodable bytes.
 *
 * `SessionTranscriptBytes` is the tagged form (that is what HKDF salts with), while
 * `DeviceAuthentication[1]` is the bare `SessionTranscript` array. Rather than rebuild the array
 * — which would risk a different serialization from the one the keys were derived from — the
 * tag wrapper is peeled off the bytes we already have.
 */
function unwrapTag24Payload(taggedBytes: Uint8Array): Uint8Array {
  const decoded = decodeCbor(taggedBytes);
  if (!(decoded instanceof DecodedTag) || decoded.tag !== 24) {
    throw new Error(
      'expected SessionTranscriptBytes to be a #6.24 tagged value',
    );
  }
  return decoded.embeddedCbor;
}

export interface BuildDeviceResponseParams {
  credential: ParsedIssuerSignedCredential;
  docType: string;
  disclosed: IndexedIssuerSignedItem[];
  sessionTranscriptBytes: Uint8Array;
  signer: Es256Signer;
}

/**
 * Assembles and signs the full `DeviceResponse`.
 *
 * Signing happens here rather than in the session loop because the signer may prompt the user
 * (biometrics on the Android path), and the response cannot be framed until it returns.
 */
export async function buildDeviceResponse(
  params: BuildDeviceResponseParams,
): Promise<Uint8Array> {
  const deviceAuthenticationBytes = buildDeviceAuthenticationBytes({
    sessionTranscriptBytes: params.sessionTranscriptBytes,
    docType: params.docType,
  });
  logByteCommitment('DeviceAuthenticationBytes', deviceAuthenticationBytes);

  const deviceSignature = await signCoseSign1Detached(
    deviceAuthenticationBytes,
    params.signer,
  );

  const issuerSigned = new Map<string, unknown>();
  const disclosedNameSpaces = buildDisclosedNameSpaces(params.disclosed);
  if (disclosedNameSpaces.size > 0) {
    issuerSigned.set('nameSpaces', disclosedNameSpaces);
  }
  issuerSigned.set(
    'issuerAuth',
    new CborRaw(params.credential.issuerAuthEncoded),
  );

  const deviceSigned = new Map<string, unknown>([
    ['nameSpaces', deviceNameSpacesBytes()],
    [
      'deviceAuth',
      new Map<string, unknown>([['deviceSignature', deviceSignature]]),
    ],
  ]);

  const document = new Map<string, unknown>([
    ['docType', params.docType],
    ['issuerSigned', issuerSigned],
    ['deviceSigned', deviceSigned],
  ]);

  const deviceResponse = new Map<string, unknown>([
    ['version', '1.0'],
    ['documents', [document]],
    ['status', DEVICE_RESPONSE_STATUS_OK],
  ]);

  const encoded = encodeCbor(deviceResponse);
  logByteCommitment('DeviceResponse', encoded);
  return encoded;
}

/** A `DeviceResponse` carrying only an error status — used when we cannot serve the request. */
export function buildErrorDeviceResponse(status: number): Uint8Array {
  return encodeCbor(
    new Map<string, unknown>([
      ['version', '1.0'],
      ['status', status],
    ]),
  );
}
