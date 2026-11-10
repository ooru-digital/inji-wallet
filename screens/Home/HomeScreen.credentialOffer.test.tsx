import React, {useState} from 'react';
import {act, render} from '@testing-library/react-native';
import {HomeScreen} from './HomeScreen';

// jest-init.js stubs useState and useEffect for every test; the screen needs the real ones.
jest.unmock('react');

const mockGotoIssuers = jest.fn();
jest.mock('./HomeScreenController', () => ({
  useHomeScreen: () => ({
    GOTO_ISSUERS: mockGotoIssuers,
    haveTabsLoaded: false,
    IssuersService: undefined,
    isMinimumStorageLimitReached: false,
    tabRefs: {},
  }),
}));
jest.mock('./MyVcsTab', () => ({MyVcsTab: () => null}));
jest.mock('./ViewVcModal', () => ({ViewVcModal: () => null}));
jest.mock('../../components/BannerNotificationContainer', () => ({
  BannerNotificationContainer: () => null,
}));
jest.mock('../../components/MessageOverlay', () => ({
  ErrorMessageOverlay: () => null,
}));
jest.mock('../../machines/Issuers/IssuersMachine', () => ({
  IssuerScreenTabEvents: {},
}));
jest.mock('../../shared/openId4VCI/Utils', () => ({
  getDisplayObjectForCurrentLanguage: jest.fn(),
}));

const OFFER_URL =
  'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example.com%2Foffer';

type Params = {credentialOfferUrl?: string};

/**
 * Renders the home screen inside a stand-in for react-navigation that holds the route
 * params: `scan` sets credentialOfferUrl the way the Scan tab does, and the screen's own
 * setParams merges into them, as the navigator would.
 */
const renderHome = async () => {
  let setHostParams: React.Dispatch<React.SetStateAction<Params>> = () => {};
  const setParams = jest.fn((next: Params) =>
    setHostParams(params => ({...params, ...next})),
  );
  const Host = () => {
    const [params, setState] = useState<Params>({});
    setHostParams = setState;
    return (
      <HomeScreen
        {...({
          route: {params},
          navigation: {navigate: jest.fn(), setParams},
        } as unknown as React.ComponentProps<typeof HomeScreen>)}
      />
    );
  };
  const screen = render(<Host />);
  // Lets the launch-link check (Linking.getInitialURL) settle.
  await act(() => Promise.resolve());
  const scan = (url: string) =>
    act(async () =>
      setHostParams(params => ({...params, credentialOfferUrl: url})),
    );
  const rerender = () =>
    act(async () => setHostParams(params => ({...params})));
  return {screen, scan, rerender, setParams};
};

describe('HomeScreen: a credential offer scanned on the Scan tab', () => {
  beforeEach(() => mockGotoIssuers.mockClear());

  it('clears the param and then starts the download', async () => {
    const {scan, setParams} = await renderHome();

    await scan(OFFER_URL);

    expect(setParams).toHaveBeenCalledWith({credentialOfferUrl: undefined});
    expect(mockGotoIssuers).toHaveBeenCalledTimes(1);
    expect(setParams.mock.invocationCallOrder[0]).toBeLessThan(
      mockGotoIssuers.mock.invocationCallOrder[0],
    );
  });

  it('starts the download again when the same offer is scanned twice in a row', async () => {
    const {scan} = await renderHome();

    await scan(OFFER_URL);
    await scan(OFFER_URL);

    expect(mockGotoIssuers).toHaveBeenCalledTimes(2);
  });

  it('does not start it again when the screen re-renders without a new scan', async () => {
    const {scan, rerender} = await renderHome();

    await scan(OFFER_URL);
    await rerender();

    expect(mockGotoIssuers).toHaveBeenCalledTimes(1);
  });
});
