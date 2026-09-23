/**
 * Parses the reader's `DeviceRequest` (ISO 18013-5 §8.3.2.1.2) into the shape the consent UI
 * already speaks — `MdocPresentmentConsentRequest` from `../iso18013PresentmentInterop`.
 *
 * ```
 * DeviceRequest = { "version": tstr, "docRequests": [ DocRequest ] }
 * DocRequest    = { "itemsRequest": ItemsRequestBytes, ?"readerAuth": COSE_Sign1 }
 * ItemsRequest  = { "docType": tstr,
 *                   "nameSpaces": { ns => { elementId => intentToRetain(bool) } },
 *                   ?"requestInfo": { * tstr => any } }
 * ```
 *
 * This comes from a third party, so every field is treated as optional and untrusted: a
 * malformed request should end the session with a status code, never crash the app or leak a
 * partially-approved disclosure.
 */

import {
  asArray,
  asMap,
  asText,
  decodeCbor,
  decodeEmbedded,
  DecodedTag,
} from './cbor';
import {parseCoseSign1, readerCommonNameFromX5Chain} from './cose';

export interface RequestedElement {
  namespace: string;
  elementIdentifier: string;
  intentToRetain: boolean;
}

export interface ParsedDocRequest {
  docType: string;
  elements: RequestedElement[];
  /** Free-form `requestInfo`, JSON-ified for the consent overlay. */
  requestInfo: Record<string, unknown> | null;
  /** Display-only name from readerAuth's certificate chain; never a trust decision. */
  readerName: string | null;
  hasReaderAuth: boolean;
}

export interface ParsedDeviceRequest {
  version: string;
  docRequests: ParsedDocRequest[];
}

/**
 * ISO 18013-5 §10.2.5 `purposeHints` codes, mapped to the same labels Android shows.
 * Unknown codes fall through to `null` so the UI uses its generic copy instead of inventing one.
 */
export function purposeLabelFromHintCode(code: number | null): string | null {
  switch (code) {
    case 1:
      return 'Age verification';
    case 2:
      return 'Identity verification';
    case 3:
      return 'Law enforcement';
    case 4:
      return 'Account opening';
    case 5:
      return 'Access control';
    default:
      return null;
  }
}

/** CBOR values → JSON-safe values, so `requestInfo` can cross into the consent overlay. */
function toJsonSafe(value: unknown): unknown {
  if (value instanceof Uint8Array) {
    return `<${value.length} bytes>`;
  }
  if (value instanceof DecodedTag) {
    return toJsonSafe(value.value);
  }
  if (Array.isArray(value)) {
    return value.map(toJsonSafe);
  }
  if (value instanceof Map) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of value.entries()) {
      out[String(k)] = toJsonSafe(v);
    }
    return out;
  }
  if (value === undefined) {
    return null;
  }
  return value;
}

function parseItemsRequest(itemsRequest: unknown): {
  docType: string;
  elements: RequestedElement[];
  requestInfo: Record<string, unknown> | null;
} {
  const map = asMap(itemsRequest, 'ItemsRequest');
  const docType = asText(map.get('docType'), 'ItemsRequest.docType');

  const elements: RequestedElement[] = [];
  const nameSpaces = map.get('nameSpaces');
  if (nameSpaces instanceof Map) {
    for (const [nsKey, elementMap] of nameSpaces.entries()) {
      const namespace = String(nsKey);
      if (!(elementMap instanceof Map)) {
        continue;
      }
      for (const [elementKey, intentToRetain] of elementMap.entries()) {
        elements.push({
          namespace,
          elementIdentifier: String(elementKey),
          intentToRetain: intentToRetain === true,
        });
      }
    }
  }

  const requestInfoRaw = map.get('requestInfo');
  const requestInfo =
    requestInfoRaw instanceof Map
      ? (toJsonSafe(requestInfoRaw) as Record<string, unknown>)
      : null;

  return {docType, elements, requestInfo};
}

export function parseDeviceRequest(bytes: Uint8Array): ParsedDeviceRequest {
  const root = asMap(decodeCbor(bytes), 'DeviceRequest');
  const version =
    typeof root.get('version') === 'string'
      ? (root.get('version') as string)
      : '1.0';

  const docRequestsRaw = root.get('docRequests');
  const docRequests: ParsedDocRequest[] = [];
  if (docRequestsRaw !== undefined) {
    for (const entry of asArray(docRequestsRaw, 'DeviceRequest.docRequests')) {
      const docRequestMap = asMap(entry, 'DocRequest');
      const itemsRequest = decodeEmbedded(
        docRequestMap.get('itemsRequest'),
        'DocRequest.itemsRequest',
      );
      const parsed = parseItemsRequest(itemsRequest);

      let readerName: string | null = null;
      const readerAuth = docRequestMap.get('readerAuth');
      const hasReaderAuth = readerAuth !== undefined;
      if (hasReaderAuth) {
        try {
          readerName = readerCommonNameFromX5Chain(parseCoseSign1(readerAuth));
        } catch {
          // readerAuth is display-only here; an unparseable chain must not end the session.
          readerName = null;
        }
      }

      docRequests.push({
        docType: parsed.docType,
        elements: parsed.elements,
        requestInfo: parsed.requestInfo,
        readerName,
        hasReaderAuth,
      });
    }
  }

  return {version, docRequests};
}

/**
 * Picks the DocRequest this credential can answer.
 *
 * Readers routinely ask for several docTypes in one request (an mDL *and* a photo ID, say);
 * the wallet is presenting exactly one credential, so anything else is simply not ours to
 * answer. Returns `null` when none match, which the session reports as "cannot satisfy" rather
 * than sending an empty response the reader would read as a refusal.
 */
export function selectDocRequestForDocType(
  request: ParsedDeviceRequest,
  walletDocType: string,
): ParsedDocRequest | null {
  return request.docRequests.find(dr => dr.docType === walletDocType) ?? null;
}

/** Every docType the reader asked for, for the "cannot satisfy" diagnostics. */
export function requestedDocTypes(request: ParsedDeviceRequest): string[] {
  return request.docRequests.map(dr => dr.docType);
}

/**
 * Reads a purpose out of `requestInfo`.
 *
 * Two encodings are seen in the wild: a numeric `purposeHints` code (ISO §10.2.5) and free-text
 * under various keys. Numeric wins when both are present, matching Android.
 */
export function purposeFromRequestInfo(
  requestInfo: Record<string, unknown> | null,
): {purpose: string | null; purposeHintCode: number | null} {
  if (!requestInfo) {
    return {purpose: null, purposeHintCode: null};
  }
  const hint = requestInfo.purposeHints;
  let purposeHintCode: number | null = null;
  if (typeof hint === 'number') {
    purposeHintCode = hint;
  } else if (Array.isArray(hint) && typeof hint[0] === 'number') {
    purposeHintCode = hint[0] as number;
  }

  const labelled = purposeLabelFromHintCode(purposeHintCode);
  if (labelled) {
    return {purpose: labelled, purposeHintCode};
  }

  for (const key of ['purpose', 'otherInfo', 'description']) {
    const value = requestInfo[key];
    if (typeof value === 'string' && value.trim().length > 0) {
      return {purpose: value.trim(), purposeHintCode};
    }
  }
  return {purpose: null, purposeHintCode};
}

/** Verifier's own display name when it sends one, preferred over the certificate CN. */
export function verifierNameFromRequestInfo(
  requestInfo: Record<string, unknown> | null,
): string | null {
  if (!requestInfo) {
    return null;
  }
  for (const key of ['verifier_name', 'verifierName', 'readerName']) {
    const value = requestInfo[key];
    if (typeof value === 'string' && value.trim().length > 0) {
      return value.trim();
    }
  }
  return null;
}
