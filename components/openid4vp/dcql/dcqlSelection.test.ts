import {
  dcqlDisclosuresByVc,
  initialDcqlSelection,
  isDcqlSelectionComplete,
  orderDcqlSections,
  toggleDcqlCard,
} from './dcqlSelection';
import {
  MatchingVCsResultForDcql,
  VCInfo,
} from '../../../shared/openID4VP/openid4vp.types';

jest.mock('../../../shared/openID4VP/OpenID4VPHelper', () => ({
  claimPathPointersToJsonPath: (path: Array<string | number | null>) =>
    path
      .map(p => (p === null ? '[*]' : typeof p === 'number' ? `[${p}]` : p))
      .join('.'),
}));

const match = (vcKey: string, claimPaths: string[][] = []) => ({
  matchingVcInfo: new VCInfo(vcKey, {} as any),
  matchedClaims: claimPaths.map(path => ({
    id: undefined,
    path,
    values: undefined,
  })),
});

const result = (
  matchingVCs: Record<string, any>,
  credentialSetOptions: MatchingVCsResultForDcql['credentialSetOptions'],
): MatchingVCsResultForDcql => ({
  matchingVCs,
  credentialSetOptions,
  success: true,
  purpose: '',
  requestedClaims: new Set(),
});

describe('dcqlSelection', () => {
  const insurance = result(
    {
      insurance: {
        matchingVcs: [match('ins-1'), match('ins-2')],
        allowMultipleCredentials: false,
      },
      pid: {matchingVcs: [match('pid-1')], allowMultipleCredentials: false},
      mdl: {matchingVcs: [match('mdl-1')], allowMultipleCredentials: false},
      extra: {
        matchingVcs: [match('extra-1'), match('extra-2')],
        allowMultipleCredentials: true,
      },
    },
    [
      {options: [['extra']], required: false},
      {options: [['insurance']], required: true},
      {options: [['pid'], ['mdl']], required: true},
    ],
  );
  const sections = orderDcqlSections(insurance);

  it('orders required credential sets before optional ones', () => {
    expect(sections.map(s => s.required)).toEqual([true, true, false]);
    expect(sections.map(s => s.index)).toEqual([1, 2, 0]);
  });

  it('drops credential sets without options', () => {
    expect(
      orderDcqlSections(result({}, [{options: [], required: true}])),
    ).toEqual([]);
  });

  it('preselects the first card of the first option of each required set only', () => {
    expect(initialDcqlSelection(insurance, sections)).toEqual({
      insurance: ['ins-1'],
      pid: ['pid-1'],
    });
  });

  it('replaces the pick for a single-credential query and clears it on a second tap', () => {
    let selection = initialDcqlSelection(insurance, sections);
    selection = toggleDcqlCard(
      insurance,
      sections,
      selection,
      'insurance',
      'ins-2',
    );
    expect(selection.insurance).toEqual(['ins-2']);
    selection = toggleDcqlCard(
      insurance,
      sections,
      selection,
      'insurance',
      'ins-2',
    );
    expect(selection.insurance).toBeUndefined();
  });

  it('adds cards to a query that allows multiple credentials', () => {
    let selection = {};
    selection = toggleDcqlCard(
      insurance,
      sections,
      selection,
      'extra',
      'extra-1',
    );
    selection = toggleDcqlCard(
      insurance,
      sections,
      selection,
      'extra',
      'extra-2',
    );
    expect(selection).toEqual({extra: ['extra-1', 'extra-2']});
  });

  it('keeps the options of a credential set mutually exclusive', () => {
    let selection = initialDcqlSelection(insurance, sections);
    selection = toggleDcqlCard(insurance, sections, selection, 'mdl', 'mdl-1');
    expect(selection.mdl).toEqual(['mdl-1']);
    expect(selection.pid).toBeUndefined();
    expect(selection.insurance).toEqual(['ins-1']);
  });

  it('is complete when every required set is satisfied, whatever the optional ones', () => {
    const selection = initialDcqlSelection(insurance, sections);
    expect(isDcqlSelectionComplete(sections, selection)).toBe(true);
    expect(
      isDcqlSelectionComplete(sections, {...selection, insurance: []}),
    ).toBe(false);
    expect(isDcqlSelectionComplete([], {})).toBe(false);
  });

  it('discloses the matched claims of selected cards only', () => {
    const sdJwt = result(
      {
        q1: {
          matchingVcs: [
            match('a', [['given_name'], ['address', 'city']]),
            match('b', [['family_name']]),
          ],
          allowMultipleCredentials: false,
        },
      },
      [{options: [['q1']], required: true}],
    );
    expect(dcqlDisclosuresByVc(sdJwt, {q1: ['a']})).toEqual({
      a: ['given_name', 'address.city'],
    });
  });
});
