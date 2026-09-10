import {VCFormat} from './VCFormat';

/**
 * Identifies a W3C credential by its specific type, so the wallet can spot that the user already
 * holds a credential of the same kind.
 *
 * A W3C `type` array is `["VerifiableCredential", "<TheSpecificType>"]` — the first entry is the
 * same on every credential, so the second is what actually distinguishes one kind from another:
 *
 *   "type": ["VerifiableCredential", "NationalIDCredential"]   ->  NationalIDCredential
 *   "type": ["VerifiableCredential", "HealthIDCredential"]     ->  HealthIDCredential
 *
 * Nothing is hardcoded: whatever the issuer puts in that position is the identity, so new
 * credential types work without a code change.
 *
 * Only ldp_vc is handled; mdoc/mDL downloads are left alone.
 */

/** Index of the specific type within a W3C `type` array; index 0 is always "VerifiableCredential". */
const SPECIFIC_TYPE_INDEX = 1;

function credentialOf(verifiableCredential: any): any {
  if (verifiableCredential == null) {
    return null;
  }
  // `?? verifiableCredential` would be wrong here: when `credential` is present but null, the
  // wrapper itself would be returned instead of the credential.
  return 'credential' in verifiableCredential
    ? verifiableCredential.credential
    : verifiableCredential;
}

/** The specific credential type, or null when there isn't one to read. */
export function getCredentialType(credential: any): string | null {
  const types = credential?.type;
  if (!Array.isArray(types)) {
    return null;
  }
  const specificType = types[SPECIFIC_TYPE_INDEX];
  return typeof specificType === 'string' && specificType.trim()
    ? specificType.trim()
    : null;
}

/** Type of a credential already in the wallet, or null if it cannot be read. */
export function getStoredCredentialType(vc: any): string | null {
  if (vc?.vcMetadata?.format !== VCFormat.ldp_vc) {
    return null;
  }
  return getCredentialType(credentialOf(vc?.verifiableCredential));
}

/** Type of the credential just downloaded but not yet stored, or null if it cannot be read. */
export function getDownloadedCredentialType(context: any): string | null {
  if (context?.credentialWrapper?.format !== VCFormat.ldp_vc) {
    return null;
  }
  return getCredentialType(
    credentialOf(
      context?.credentialWrapper?.verifiableCredential ??
        context?.verifiableCredential,
    ),
  );
}

/**
 * The credential already in the wallet that has the same specific type as the one being
 * downloaded, or null if there isn't one.
 *
 * Returns the matched VC rather than a boolean because the caller needs its metadata to offer
 * "replace the existing one".
 */
export function findCredentialOfSameType(
  context: any,
  storedVcs: Record<string, any>,
): any | null {
  const downloadedType = getDownloadedCredentialType(context);
  if (!downloadedType) {
    return null;
  }
  return (
    Object.values(storedVcs ?? {}).find(
      (vc: any) => getStoredCredentialType(vc) === downloadedType,
    ) ?? null
  );
}
