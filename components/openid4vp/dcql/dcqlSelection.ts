import {
  CredentialSetOption,
  MatchingVCsResultForDcql,
} from '../../../shared/openID4VP/openid4vp.types';
import {claimPathPointersToJsonPath} from '../../../shared/openID4VP/OpenID4VPHelper';

/**
 * Card selection for a DCQL request, ported from upstream Inji Wallet 1.0.0-alpha.1
 * (DcqlMatchingVcList / DcqlMatchingVcController / CredentialSetSection) without its UI.
 *
 * A request is a list of credential sets (the library makes one required set per credential
 * query when the verifier sends none). A set's options are alternatives — the holder satisfies
 * one of them — and an option lists credential queries that must all be met. Required sets come
 * first; optional ones can be skipped.
 *
 * Selection is kept as credential query id → selected card keys, the shape the share flow sends
 * on (ACCEPT_REQUEST → constructUnsignedVPToken).
 */
export type DcqlSection = CredentialSetOption & {index: number};
export type DcqlSelection = Record<string, string[]>;

/** The credential sets that still have options, required ones first. */
export function orderDcqlSections(
  result: MatchingVCsResultForDcql | null,
): DcqlSection[] {
  const sets = (result?.credentialSetOptions ?? [])
    .map((set, index) => ({...set, index}))
    .filter(set => (set.options ?? []).length > 0);
  return [...sets.filter(s => s.required), ...sets.filter(s => !s.required)];
}

export function vcKeysForQuery(
  result: MatchingVCsResultForDcql | null,
  queryId: string,
): string[] {
  return (result?.matchingVCs[queryId]?.matchingVcs ?? []).map(
    match => match.matchingVcInfo.vcKey,
  );
}

/** Each required set starts on its first option, with each query's first matching card. */
export function initialDcqlSelection(
  result: MatchingVCsResultForDcql | null,
  sections: DcqlSection[],
): DcqlSelection {
  const selection: DcqlSelection = {};
  sections
    .filter(section => section.required)
    .forEach(section => {
      section.options[0].forEach(queryId => {
        const [firstVcKey] = vcKeysForQuery(result, queryId);
        if (firstVcKey && !selection[queryId]) {
          selection[queryId] = [firstVcKey];
        }
      });
    });
  return selection;
}

const isOptionComplete = (option: string[], selection: DcqlSelection) =>
  option.every(queryId => (selection[queryId]?.length ?? 0) > 0);

/**
 * Selects or deselects a card for a credential query. A query that allows several credentials
 * toggles the card; otherwise the card replaces the query's selection (or clears it when it was
 * already the one picked). Picking a card in one option of a set clears the set's other options,
 * since a set is satisfied by exactly one of them.
 */
export function toggleDcqlCard(
  result: MatchingVCsResultForDcql | null,
  sections: DcqlSection[],
  selection: DcqlSelection,
  queryId: string,
  vcKey: string,
  sectionIndex?: number,
): DcqlSelection {
  const next: DcqlSelection = {...selection};
  const current = selection[queryId] ?? [];
  const allowMultiple = result?.matchingVCs[queryId]?.allowMultipleCredentials;

  if (current.includes(vcKey)) {
    const remaining = current.filter(key => key !== vcKey);
    if (remaining.length > 0) {
      next[queryId] = remaining;
    } else {
      delete next[queryId];
    }
    return next;
  }
  next[queryId] = allowMultiple ? [...current, vcKey] : [vcKey];

  const section =
    sections.find(s => s.index === sectionIndex) ??
    sections.find(s => s.options.some(option => option.includes(queryId)));
  if (section) {
    const chosen =
      section.options.find(
        option => option.includes(queryId) && isOptionComplete(option, next),
      ) ?? section.options.find(option => option.includes(queryId));
    section.options
      .filter(option => option !== chosen)
      .flat()
      .filter(otherQueryId => !chosen?.includes(otherQueryId))
      .forEach(otherQueryId => delete next[otherQueryId]);
  }
  return next;
}

/** Whether the set's chosen option has a card for every query. */
export function isDcqlSectionSatisfied(
  section: DcqlSection,
  selection: DcqlSelection,
): boolean {
  return section.options.some(option => isOptionComplete(option, selection));
}

/** Sharing is possible once every required set is satisfied; optional sets never block it. */
export function isDcqlSelectionComplete(
  sections: DcqlSection[],
  selection: DcqlSelection,
): boolean {
  return (
    sections.length > 0 &&
    sections
      .filter(section => section.required)
      .every(section => isDcqlSectionSatisfied(section, selection))
  );
}

/**
 * Per selected card, the JSONPaths of the claims the verifier asked for (from the library's
 * matched claims). SD-JWT cards disclose exactly these; with no claims requested they disclose
 * nothing selectively disclosable, as DCQL specifies.
 */
export function dcqlDisclosuresByVc(
  result: MatchingVCsResultForDcql | null,
  selection: DcqlSelection,
): Record<string, string[]> {
  const disclosures: Record<string, Set<string>> = {};
  Object.entries(selection).forEach(([queryId, vcKeys]) => {
    (result?.matchingVCs[queryId]?.matchingVcs ?? [])
      .filter(match => vcKeys.includes(match.matchingVcInfo.vcKey))
      .forEach(({matchingVcInfo, matchedClaims}) => {
        const paths = (disclosures[matchingVcInfo.vcKey] ??= new Set());
        matchedClaims?.forEach(claim =>
          paths.add(claimPathPointersToJsonPath(claim.path)),
        );
      });
  });
  return Object.fromEntries(
    Object.entries(disclosures).map(([vcKey, paths]) => [vcKey, [...paths]]),
  );
}
