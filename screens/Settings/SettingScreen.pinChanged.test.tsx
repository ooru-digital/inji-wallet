import React from 'react';
import {Platform, View} from 'react-native';
import {act, fireEvent, render, within} from '@testing-library/react-native';
import {SettingScreen} from './SettingScreen';

// jest-init.js stubs useState and useEffect for every test; the screen needs the real ones.
jest.unmock('react');

let mockChangePinProps: {
  isVisible: boolean;
  onDone: (changed: boolean) => void;
  onDismissed?: () => void;
};
jest.mock('./ChangePin', () => ({
  ChangePin: (props: typeof mockChangePinProps) => {
    mockChangePinProps = props;
    return null;
  },
}));
jest.mock('./SettingScreenController', () => ({
  useSettingsScreen: () => ({
    isPasscodeSet: () => true,
    isBiometricUnlockEnabled: false,
    alertMsg: '',
    hideAlert: jest.fn(),
    TOGGLE_SETTINGS: jest.fn(),
    INJI_TOUR_GUIDE: jest.fn(),
    appId: 'test',
  }),
}));
jest.mock('@react-navigation/native', () => ({
  useNavigation: () => ({navigate: jest.fn()}),
}));
jest.mock('expo-local-authentication', () => ({
  hasHardwareAsync: () => Promise.resolve(true),
  isEnrolledAsync: () => Promise.resolve(true),
}));
jest.mock('../../i18n', () => ({SUPPORTED_LANGUAGES: {}}));
jest.mock('../../components/BannerNotificationContainer', () => ({
  BannerNotificationContainer: () => null,
}));
jest.mock('../../components/MessageOverlay', () => ({
  MessageOverlay: () => null,
}));
jest.mock('../../components/LanguageSelector', () => ({
  LanguageSelector: () => null,
}));
jest.mock('../../components/EditableListItem', () => ({
  EditableListItem: () => null,
}));
jest.mock('./AboutInji', () => ({AboutInji: () => null}));
jest.mock('./InfoPage', () => ({InfoPage: () => null}));
jest.mock('./autoLock', () => ({
  AUTO_LOCK_OPTIONS: [],
  useAutoLockSetting: () => [0, jest.fn()],
}));

const renderScreen = async () => {
  const screen = render(
    <SettingScreen
      {...({} as React.ComponentProps<typeof SettingScreen>)}
      triggerComponent={<View />}
    />,
  );
  // Lets the biometrics availability check settle.
  await act(() => Promise.resolve());
  return screen;
};

/** The PIN changed dialog's title, or null while it is hidden. useTranslation's mock returns keys. */
const dialogTitle = (screen: Awaited<ReturnType<typeof renderScreen>>) =>
  screen.queryByRole('header', {name: 'pinChanged'});

describe('SettingScreen: after a PIN change', () => {
  const realOS = Platform.OS;
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => {
    jest.useRealTimers();
    Platform.OS = realOS;
  });

  it('shows the PIN changed dialog, then on Done a snackbar with the same text', async () => {
    Platform.OS = 'android';
    const screen = await renderScreen();
    expect(dialogTitle(screen)).toBeNull();

    act(() => mockChangePinProps.onDone(true));
    expect(dialogTitle(screen)).toBeTruthy();
    expect(screen.queryByRole('alert')).toBeNull();

    fireEvent.press(screen.getByText('done'));
    expect(dialogTitle(screen)).toBeNull();
    expect(
      within(screen.getByRole('alert')).getByText('pinChanged'),
    ).toBeTruthy();
  });

  it('on iOS, waits for Change PIN to finish closing before showing the dialog', async () => {
    Platform.OS = 'ios';
    const screen = await renderScreen();

    act(() => mockChangePinProps.onDone(true));
    expect(dialogTitle(screen)).toBeNull();

    act(() => mockChangePinProps.onDismissed?.());
    expect(dialogTitle(screen)).toBeTruthy();
  });

  it('shows nothing when Change PIN is closed without changing it', async () => {
    Platform.OS = 'ios';
    const screen = await renderScreen();

    act(() => {
      mockChangePinProps.onDone(false);
      mockChangePinProps.onDismissed?.();
    });
    expect(dialogTitle(screen)).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
  });
});
