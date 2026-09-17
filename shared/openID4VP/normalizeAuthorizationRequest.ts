import {Buffer} from 'buffer';

/**
 * Compatibility layer between verifiers speaking OpenID4VP draft 21 or earlier
 * and the bundled inji-openid4vp SDK, which implements draft 22+.
 *
 * The SDK parses a request with
 * `URI(request).rawQuery.split("&").map { it.split("=")[1] }`, running each value
 * through `URLDecoder.decode`. Four things go wrong against an older verifier,
 * and every one of them surfaces as the same generic "Request can't be
 * processed" screen:
 *
 *  1. The query must be a real `key=value&key=value` string. A verifier that
 *     base64-encodes the whole query produces a single opaque token with no `=`
 *     in it, so `split("=")[1]` throws IndexOutOfBounds.
 *  2. Every value must be percent-encoded. Raw JSON in `presentation_definition`
 *     or `client_metadata` carries spaces, `{`, `}`, `"`, `[`, `]`, which
 *     `java.net.URI` rejects outright with a URISyntaxException.
 *  3. The client id scheme is a prefix on `client_id` in draft 22+
 *     (`did:example:123`), derived with `client_id.split(":")[0]`. Draft 21 sends
 *     a bare URL plus a separate `client_id_scheme` parameter that defaults to
 *     `pre-registered` when omitted, so the SDK reads the scheme as literally
 *     "http" and fails with "Given client_id_scheme is not supported".
 *  4. `client_metadata.vp_formats` is mandatory in draft 22+; `ClientMetadata`
 *     rejects a request without it. Draft 21 verifiers routinely omit it and
 *     declare formats only inside `presentation_definition`.
 *  5. Some verifiers (CredIssuer) send `client_metadata.name` instead of the
 *     spec field `client_name`. The SDK only deserialises `client_name`, so
 *     the display name is otherwise dropped and the UI shows "Unknown verifier".
 *
 * For 3 and 4 the correction is a restatement of what the older draft already
 * means, not an invention: `pre-registered` is that draft's documented default
 * (and the most restrictive scheme, so it routes into the wallet's
 * trusted-verifier check rather than around it), and `vp_formats` is derived
 * from the formats the verifier itself declared in its presentation definition.
 * Neither is synthesised when the verifier supplied its own value.
 *
 * This is deliberately a no-op for a well-formed request: a spec-compliant
 * verifier is passed through byte-for-byte.
 */

// Characters java.net.URI refuses to accept in a query component.
const ILLEGAL_IN_URI_QUERY = /[^A-Za-z0-9\-._~!$&'()*+,;=:@/?%]/;

const PARAM_NAME = /^[A-Za-z_][A-Za-z0-9_.-]*$/;

const CLIENT_ID = 'client_id';
const CLIENT_ID_SCHEME = 'client_id_scheme';
const CLIENT_METADATA = 'client_metadata';
const CLIENT_NAME = 'client_name';
const CLIENT_NAME_ALIAS = 'name';
const PRESENTATION_DEFINITION = 'presentation_definition';
const VP_FORMATS = 'vp_formats';
const PRE_REGISTERED = 'pre-registered';

// A bare http(s) URL as client_id is the draft-21-and-earlier shape. Anything
// else — `did:...`, `redirect_uri:...`, a plain identifier — already resolves to
// a scheme the SDK supports and must be left alone.
const BARE_HTTP_CLIENT_ID = /^https?:\/\//i;

type Pairs = [string, string][];

type PlainObject = Record<string, unknown>;

function isPlainObject(value: unknown): value is PlainObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseJson(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch (e) {
    return undefined;
  }
}

function isBase64(value: string): boolean {
  return (
    value.length > 0 &&
    value.length % 4 === 0 &&
    /^[A-Za-z0-9+/]+={0,2}$/.test(value)
  );
}

/**
 * Splits a query into key/value pairs, tolerating unencoded `&` inside a value
 * (common when a verifier drops raw JSON straight into the query). A chunk that
 * does not begin with a plausible parameter name is treated as a continuation
 * of the previous value rather than a new parameter.
 */
function splitPairs(query: string): Pairs {
  const pairs: Pairs = [];

  for (const chunk of query.split('&')) {
    const separator = chunk.indexOf('=');
    const key = separator === -1 ? '' : chunk.slice(0, separator);

    if (separator === -1 || !PARAM_NAME.test(key)) {
      if (pairs.length === 0) return [];
      pairs[pairs.length - 1][1] += '&' + chunk;
      continue;
    }
    pairs.push([key, chunk.slice(separator + 1)]);
  }
  return pairs;
}

function findValue(pairs: Pairs, key: string): string | undefined {
  return pairs.find(([name]) => name === key)?.[1];
}

/**
 * True only when the verifier omitted `client_id_scheme` *and* sent a bare
 * http(s) URL as `client_id` — the one combination the SDK cannot resolve.
 */
function needsPreRegisteredScheme(pairs: Pairs): boolean {
  if (findValue(pairs, CLIENT_ID_SCHEME) !== undefined) return false;

  const clientId = findValue(pairs, CLIENT_ID);
  return clientId !== undefined && BARE_HTTP_CLIENT_ID.test(clientId);
}

/**
 * Keeps only entries shaped like the SDK's
 * `Map<String, Map<String, List<String>>>`, so a presentation definition with an
 * unexpected format block can never turn a clear error into a confusing one.
 */
function sanitizeFormats(source: PlainObject): PlainObject | undefined {
  const formats: PlainObject = {};

  for (const [format, spec] of Object.entries(source)) {
    if (!isPlainObject(spec)) continue;

    const entries = Object.entries(spec).filter(
      ([, values]) =>
        Array.isArray(values) && values.every(v => typeof v === 'string'),
    );
    formats[format] = Object.fromEntries(entries);
  }

  return Object.keys(formats).length > 0 ? formats : undefined;
}

/**
 * Collects the formats the verifier declared in its presentation definition,
 * both the top-level `format` block and any per-input-descriptor overrides.
 */
function deriveVpFormats(presentationDefinition: string): PlainObject | undefined {
  const definition = parseJson(presentationDefinition);
  if (!isPlainObject(definition)) return undefined;

  const declared: PlainObject = {};
  if (isPlainObject(definition.format)) {
    Object.assign(declared, definition.format);
  }
  if (Array.isArray(definition.input_descriptors)) {
    for (const descriptor of definition.input_descriptors) {
      if (isPlainObject(descriptor) && isPlainObject(descriptor.format)) {
        Object.assign(declared, descriptor.format);
      }
    }
  }

  return sanitizeFormats(declared);
}

function hasNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim() !== '';
}

/**
 * Returns a replacement `client_metadata` when the verifier's payload needs a
 * spec-shaped restatement (`name` → `client_name`, or missing `vp_formats`
 * derived from the presentation definition). Undefined means leave the original
 * bytes alone. A missing `client_metadata` is left missing — that is a
 * distinct, clearer SDK error.
 */
function normalizedClientMetadata(pairs: Pairs): string | undefined {
  const raw = findValue(pairs, CLIENT_METADATA);
  if (raw === undefined) return undefined;

  const metadata = parseJson(raw);
  if (!isPlainObject(metadata)) return undefined;

  const next: PlainObject = {...metadata};
  let changed = false;

  if (!hasNonEmptyString(next[CLIENT_NAME]) && hasNonEmptyString(next[CLIENT_NAME_ALIAS])) {
    next[CLIENT_NAME] = next[CLIENT_NAME_ALIAS];
    delete next[CLIENT_NAME_ALIAS];
    changed = true;
  }

  const existing = next[VP_FORMATS];
  const hasVpFormats = isPlainObject(existing) && Object.keys(existing).length > 0;
  if (!hasVpFormats) {
    const presentationDefinition = findValue(pairs, PRESENTATION_DEFINITION);
    if (presentationDefinition !== undefined) {
      const formats = deriveVpFormats(presentationDefinition);
      if (formats !== undefined) {
        next[VP_FORMATS] = formats;
        changed = true;
      }
    }
  }

  return changed ? JSON.stringify(next) : undefined;
}

export function normalizeAuthorizationRequest(request: string): string {
  const separator = request.indexOf('?');
  if (separator === -1) return request;

  const prefix = request.slice(0, separator + 1);
  let query = request.slice(separator + 1);
  if (query === '') return request;

  // Values that already survive java.net.URI are left in their original encoded
  // form unless something actually changes, so a compliant request round-trips
  // untouched and a literal `+` never shifts meaning.
  let valuesAreEncoded = true;

  if (isBase64(query)) {
    let decoded: string;
    try {
      decoded = Buffer.from(query, 'base64').toString('utf8');
    } catch (e) {
      return request;
    }
    // Only trust the decode if it actually yields a query string; otherwise the
    // payload just happened to look like base64 and should be left alone.
    if (splitPairs(decoded).length === 0) return request;
    query = decoded;
    valuesAreEncoded = false;
  } else if (ILLEGAL_IN_URI_QUERY.test(query)) {
    valuesAreEncoded = false;
  }

  const pairs = splitPairs(query);
  if (pairs.length === 0) return request;

  let decodedPairs: Pairs;
  try {
    decodedPairs = valuesAreEncoded
      ? pairs.map(([key, value]): [string, string] => [
          key,
          decodeURIComponent(value),
        ])
      : pairs;
  } catch (e) {
    return request;
  }

  const overrides = new Map<string, string>();
  const additions: Pairs = [];

  if (needsPreRegisteredScheme(decodedPairs)) {
    additions.push([CLIENT_ID_SCHEME, PRE_REGISTERED]);
  }

  const metadata = normalizedClientMetadata(decodedPairs);
  if (metadata !== undefined) overrides.set(CLIENT_METADATA, metadata);

  const unchanged =
    valuesAreEncoded && overrides.size === 0 && additions.length === 0;
  if (unchanged) return request;

  const rendered = pairs.map(([key, value]) => {
    const override = overrides.get(key);
    if (override !== undefined) return `${key}=${encodeURIComponent(override)}`;
    // An untouched value keeps its original bytes when it was already encoded.
    return valuesAreEncoded
      ? `${key}=${value}`
      : `${key}=${encodeURIComponent(value)}`;
  });

  for (const [key, value] of additions) {
    rendered.push(`${key}=${encodeURIComponent(value)}`);
  }

  return prefix + rendered.join('&');
}
