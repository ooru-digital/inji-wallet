/* eslint-disable @typescript-eslint/no-explicit-any */
import React from 'react';
import {Pressable, Text} from 'react-native';
import {fireEvent, render} from '@testing-library/react-native';
import {IssuersScreen} from './IssuersScreen';

// The shared jest setup stubs out useEffect and useState; this screen's flows need them.
const {useEffect, useState} = jest.requireActual('react');
Object.assign(React, {useEffect, useState});

let mockController: Record<string, any>;
const mockFetchIssuerWellknownConfig = jest.fn();

jest.mock('expo-localization', () => ({
  getLocales: () => [{languageTag: 'en-US', languageCode: 'en'}],
}));
jest.mock('react-i18next', () => ({
  initReactI18next: {type: '3rdParty', init: jest.fn()},
  useTranslation: () => ({t: (key: string) => key}),
}));
jest.mock('react-native-safe-area-context', () => ({
  useSafeAreaInsets: () => ({top: 0, bottom: 0, left: 0, right: 0}),
}));
jest.mock('@react-navigation/native', () => {
  const {useEffect} = jest.requireActual('react');
  return {useFocusEffect: (effect: () => () => void) => useEffect(effect, [])};
});
jest.mock('./IssuerScreenController', () => ({
  useIssuerScreenController: () => mockController,
}));
jest.mock('../../shared/api', () => ({
  CACHED_API: {
    fetchIssuerWellknownConfig: (...args: any[]) =>
      mockFetchIssuerWellknownConfig(...args),
  },
}));
jest.mock('../../shared/openId4VCI/Utils', () => ({
  Protocols: {OpenId4VCI: 'OpenId4VCI', OTP: 'OTP'},
  getDisplayObjectForCurrentLanguage: (display: any[]) => display[0],
  ErrorMessage: {
    GENERIC: 'generic',
    TECHNICAL_DIFFICULTIES: 'technicalDifficulty',
    CREDENTIAL_TYPE_DOWNLOAD_FAILURE: 'credentialTypeDownloadFailure',
    AUTHORIZATION_GRANT_TYPE_NOT_SUPPORTED:
      'authorizationGrantTypeNotSupported',
    NETWORK_REQUEST_FAILED: 'networkRequestFailed',
  },
}));
jest.mock('../../shared/telemetry/TelemetryUtils', () => ({
  getInteractEventData: jest.fn(),
  getStartEventData: jest.fn(),
  sendInteractEvent: jest.fn(),
  sendStartEvent: jest.fn(),
}));
jest.mock('../../shared/telemetry/TelemetryConstants', () => ({
  TelemetryConstants: {
    FlowType: {vcDownload: 'vcDownload'},
    InteractEventSubtype: {click: 'click'},
  },
}));
jest.mock('../../components/ui/svg', () => ({
  SvgImage: new Proxy({}, {get: () => () => null}),
  IssuerLogo: () => null,
}));
jest.mock('../../components/revamp/Page', () => {
  const {Pressable, View} = jest.requireActual('react-native');
  return {
    Page: (props: any) => (
      <View testID={props.testID}>
        {props.header}
        {props.children}
      </View>
    ),
    PageButton: (props: any) => (
      <Pressable testID={props.testID} onPress={props.onPress} />
    ),
    AlertSheet: () => null,
  };
});
jest.mock('../Scan/SendVPScreen', () => ({SendVPScreen: () => null}));
jest.mock('./CredentialTypeSelectionScreen', () => ({
  CredentialTypeSelectionScreen: () => null,
}));
jest.mock('./ReplaceCredentialSelectionScreen', () => ({
  ReplaceCredentialSelectionScreen: () => null,
}));
jest.mock('./TransactionCodeScreen', () => ({
  TransactionCodeModal: () => null,
}));
jest.mock('../../components/MessageOverlay', () => ({
  MessageOverlay: () => null,
}));
jest.mock('../../components/ui/Loader', () => ({
  Loader: (props: any) => <Text testID="loader">{props.title}</Text>,
}));
jest.mock('../../components/ui/processingScreen/ProcessingModal', () => ({
  ProcessingModal: () => null,
  ProgressIndicator: () => null,
}));
jest.mock('../../components/ui/Error', () => ({
  ErrorView: (props: any) => (
    <>
      <Pressable testID="errorView" onPress={props.primaryButtonEvent}>
        <Text>{props.title}</Text>
      </Pressable>
      <Pressable testID="closeError" onPress={props.onDismiss} />
    </>
  ),
}));
jest.mock('../../components/addCredential/DownloadingCard', () => ({
  DownloadingCard: (props: any) => (
    <Text testID="downloadingCard">{props.reason}</Text>
  ),
}));
jest.mock('../../components/addCredential/TrustIssuerSheet', () => ({
  TrustIssuerSheet: (props: any) =>
    props.isVisible ? (
      <Pressable testID="trustIssuerSheet" onPress={props.onCancel}>
        <Text>{`${props.name} ${props.credentialTypes.join(',')}`}</Text>
      </Pressable>
    ) : null,
}));

const baseController = () => ({
  isError: false,
  errorMessageType: '',
  verificationErrorMessage: '',
  loadingReason: null,
  isPresentationAuthorization: false,
  isSelectingIssuer: false,
  isQrScanning: false,
  isConsentRequested: false,
  isDownloadSuccess: false,
  isAuthEndpointToOpen: false,
  isSelectingCredentialType: false,
  isCredentialAlreadyExists: false,
  isSelectingCredentialsToReplace: false,
  isTxCodeRequested: false,
  isBiometricsCancelled: false,
  isFetchingIssuers: false,
  issuersFetchFailed: false,
  issuers: [],
  selectedIssuer: {},
  selectedCredentialType: {},
  issuerName: 'Ministry of Transport',
  issuerLogo: undefined,
  offeredCredentialTypeNames: ['Driving Licence'],
  trustedIssuerConsentStatus: 'idle',
  SCAN_CREDENTIAL_OFFER_QR_CODE: jest.fn(),
  QR_CODE_SCANNED: jest.fn(),
  ON_CONSENT_GIVEN: jest.fn(),
  CANCEL: jest.fn(),
  TRY_AGAIN: jest.fn(),
  RESET_ERROR: jest.fn(),
  SELECTED_ISSUER: jest.fn(),
  DOWNLOAD_ID: jest.fn(),
  FETCH_ISSUERS: jest.fn(),
});

const transport = {
  issuer_id: 'RoadTransport',
  protocol: 'OpenId4VCI',
  credential_issuer_host: 'https://transport.example',
  display: [{name: 'Road Transport Authority', logo: {url: ''}}],
};
const university = {
  issuer_id: 'NationalUniversity',
  protocol: 'OpenId4VCI',
  credential_issuer_host: 'https://university.example',
  display: [{name: 'National University', logo: {url: ''}}],
};
const wellknowns: Record<string, any> = {
  'https://transport.example': {
    credential_configurations_supported: {
      dl: {display: [{name: 'Driving Licence'}]},
      vr: {display: [{name: 'Vehicle Registration'}]},
    },
  },
  'https://university.example': {
    credential_configurations_supported: {
      degree: {display: [{name: 'Degree Certificate'}]},
    },
  },
};

describe('IssuersScreen issuer list (the wallet’s + button)', () => {
  const tabs = {setOptions: jest.fn()};
  const navigation = {
    setOptions: jest.fn(),
    getParent: () => tabs,
    goBack: jest.fn(),
    navigate: jest.fn(),
  };
  const screen = () => (
    <IssuersScreen navigation={navigation as any} route={{} as any} />
  );
  // The screen asks for the list as it opens; this answers it with `issuers`.
  const renderLoadedList = (issuers: any[]) => {
    mockController.isFetchingIssuers = true;
    const rendered = render(screen());
    mockController = {
      ...mockController,
      isFetchingIssuers: false,
      isSelectingIssuer: true,
      issuers,
    };
    rendered.rerender(screen());
    return rendered;
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockController = baseController();
    mockFetchIssuerWellknownConfig.mockImplementation((_key, host) =>
      Promise.resolve(wellknowns[host]),
    );
  });

  it('asks for the issuers once, and shows placeholder rows while they load', () => {
    mockController.isSelectingIssuer = true;

    const {getByTestId, getAllByTestId} = render(screen());

    expect(mockController.FETCH_ISSUERS).toHaveBeenCalledTimes(1);
    expect(getByTestId('issuerListPage')).toBeTruthy();
    expect(getAllByTestId('issuerSkeleton')).toHaveLength(3);
    expect(mockController.SCAN_CREDENTIAL_OFFER_QR_CODE).not.toHaveBeenCalled();
  });

  it('lists each issuer with its credential types, and picking one starts its download', async () => {
    const {findByText, getByTestId, getByText} = renderLoadedList([
      transport,
      university,
    ]);

    expect(getByText('issuerList.count')).toBeTruthy();
    expect(
      await findByText('Driving Licence · Vehicle Registration'),
    ).toBeTruthy();
    expect(getByText('2')).toBeTruthy();
    expect(getByTestId('issuersTrustNote')).toBeTruthy();

    fireEvent.press(getByTestId('RoadTransport'));
    expect(mockController.SELECTED_ISSUER).toHaveBeenCalledWith(
      'RoadTransport',
    );
  });

  it('lists the issuers again on coming back from one, without placeholders', () => {
    const {getByTestId, queryByTestId, rerender} = renderLoadedList([
      transport,
    ]);

    // An issuer is opened: its credential types replace the list.
    mockController = {
      ...mockController,
      isSelectingIssuer: false,
      isSelectingCredentialType: true,
    };
    rerender(screen());
    expect(queryByTestId('issuerListPage')).toBeNull();

    // Back from the credential types.
    mockController = {
      ...mockController,
      isSelectingIssuer: true,
      isSelectingCredentialType: false,
    };
    rerender(screen());

    expect(getByTestId('RoadTransport')).toBeTruthy();
    expect(queryByTestId('issuerSkeleton')).toBeNull();
    expect(mockController.FETCH_ISSUERS).toHaveBeenCalledTimes(1);
  });

  it('searches by credential type as well as issuer name', async () => {
    const {findByText, getByTestId, queryByTestId} = renderLoadedList([
      transport,
      university,
    ]);
    await findByText('Degree Certificate');

    fireEvent.changeText(getByTestId('issuerSearchBar'), 'degree');
    expect(queryByTestId('NationalUniversity')).toBeTruthy();
    expect(queryByTestId('RoadTransport')).toBeNull();

    fireEvent.changeText(getByTestId('issuerSearchBar'), 'passport');
    expect(getByTestId('noIssuersMatch')).toBeTruthy();
  });

  it('offers a retry when the issuers fail to load', () => {
    mockController.isSelectingIssuer = true;
    mockController.issuersFetchFailed = true;

    const {getByTestId, queryByTestId} = render(screen());
    expect(queryByTestId('issuerSkeleton')).toBeNull();
    fireEvent.press(getByTestId('retryIssuers'));

    expect(mockController.FETCH_ISSUERS).toHaveBeenCalledTimes(2);
  });

  it('goes back to the wallet from the back button', () => {
    mockController.isSelectingIssuer = true;

    const {getByTestId} = render(screen());
    fireEvent.press(getByTestId('goBack'));

    expect(navigation.goBack).toHaveBeenCalledTimes(1);
  });

  it('hides the bottom tab bar while open and brings it back on leaving', () => {
    mockController.isSelectingIssuer = true;

    const {unmount} = render(screen());
    expect(tabs.setOptions).toHaveBeenLastCalledWith({
      tabBarStyle: {display: 'none'},
    });

    unmount();
    expect(tabs.setOptions).toHaveBeenLastCalledWith({
      tabBarStyle: expect.objectContaining({display: 'flex'}),
    });
  });

  it('shows an offer’s trust sheet over the download, with no scanner', () => {
    mockController.isConsentRequested = true;
    mockController.loadingReason = 'preparingRequest';

    const {getByTestId, getByText} = render(screen());

    expect(getByTestId('downloadingCard')).toBeTruthy();
    expect(getByText('Ministry of Transport Driving Licence')).toBeTruthy();
    fireEvent.press(getByTestId('trustIssuerSheet'));
    expect(mockController.CANCEL).toHaveBeenCalledTimes(1);
  });
});

describe('IssuersScreen opened from an Add to Wallet link', () => {
  const tabs = {setOptions: jest.fn()};
  const navigation = {
    setOptions: jest.fn(),
    getParent: () => tabs,
    goBack: jest.fn(),
    navigate: jest.fn(),
  };
  const credentialOfferUrl = 'openid-credential-offer://?link';
  const route = {params: {credentialOfferUrl}} as any;
  const renderScreen = () =>
    render(<IssuersScreen navigation={navigation as any} route={route} />);
  const resetToSelectingIssuer = (
    rerender: (ui: React.ReactElement) => void,
  ) => {
    mockController = {
      ...mockController,
      isError: false,
      errorMessageType: '',
      isSelectingIssuer: true,
    };
    rerender(<IssuersScreen navigation={navigation as any} route={route} />);
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockController = baseController();
  });

  it('reads the offer without opening the scanner', () => {
    mockController.loadingReason = 'preparingRequest';

    const {getByTestId, queryByTestId} = renderScreen();

    expect(getByTestId('downloadingCard')).toBeTruthy();
    expect(queryByTestId('scanToAddScreen')).toBeNull();
    expect(mockController.SCAN_CREDENTIAL_OFFER_QR_CODE).not.toHaveBeenCalled();
  });

  it('asks to trust a new issuer without opening the scanner', () => {
    mockController.isConsentRequested = true;
    mockController.loadingReason = 'preparingRequest';

    const {getByText, queryByTestId} = renderScreen();

    expect(queryByTestId('scanToAddScreen')).toBeNull();
    expect(getByText('Ministry of Transport Driving Licence')).toBeTruthy();
  });

  it('closes instead of starting the scanner once the offer is declined or fails', () => {
    mockController.isSelectingIssuer = true;

    renderScreen();

    expect(navigation.goBack).toHaveBeenCalledTimes(1);
    expect(mockController.SCAN_CREDENTIAL_OFFER_QR_CODE).not.toHaveBeenCalled();
  });

  it('reads the same offer again on "Try again" after an error, and stays open', () => {
    mockController.isError = true;
    mockController.errorMessageType = 'networkRequestFailed';

    const {getByTestId, queryByTestId, rerender} = renderScreen();
    fireEvent.press(getByTestId('errorView'));
    expect(mockController.TRY_AGAIN).toHaveBeenCalledTimes(1);

    resetToSelectingIssuer(rerender);

    expect(navigation.goBack).not.toHaveBeenCalled();
    expect(mockController.SCAN_CREDENTIAL_OFFER_QR_CODE).toHaveBeenCalledTimes(
      1,
    );
    expect(mockController.QR_CODE_SCANNED).toHaveBeenCalledWith(
      credentialOfferUrl,
    );
    expect(queryByTestId('scanToAddScreen')).toBeNull();
  });

  it('closes when an error is dismissed', () => {
    mockController.isError = true;
    mockController.errorMessageType = 'networkRequestFailed';

    const {getByTestId, rerender} = renderScreen();
    fireEvent.press(getByTestId('closeError'));
    expect(mockController.RESET_ERROR).toHaveBeenCalledTimes(1);

    resetToSelectingIssuer(rerender);

    expect(navigation.goBack).toHaveBeenCalledTimes(1);
    expect(mockController.QR_CODE_SCANNED).not.toHaveBeenCalled();
  });

  it('closes on a later decline after a retry', () => {
    mockController.isError = true;
    mockController.errorMessageType = 'networkRequestFailed';

    const {getByTestId, rerender} = renderScreen();
    fireEvent.press(getByTestId('errorView'));
    resetToSelectingIssuer(rerender);
    expect(navigation.goBack).not.toHaveBeenCalled();

    mockController = {
      ...mockController,
      isSelectingIssuer: false,
      isConsentRequested: true,
    };
    rerender(<IssuersScreen navigation={navigation as any} route={route} />);
    mockController = {
      ...mockController,
      isConsentRequested: false,
      isSelectingIssuer: true,
    };
    rerender(<IssuersScreen navigation={navigation as any} route={route} />);

    expect(navigation.goBack).toHaveBeenCalledTimes(1);
    expect(mockController.QR_CODE_SCANNED).toHaveBeenCalledTimes(1);
  });
});
