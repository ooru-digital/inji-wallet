import React from 'react';
import {act, fireEvent, render} from '@testing-library/react-native';
import {Dialog, Snackbar} from './Page';

// jest-init.js stubs useState and useEffect for every test; these components need the real ones.
jest.unmock('react');

describe('Dialog', () => {
  const props = {
    isVisible: true,
    icon: () => null,
    title: 'PIN changed',
    message: 'Use your new PIN from now on.',
    button: {title: 'Done', onPress: jest.fn()},
    onRequestClose: jest.fn(),
  };

  it('shows its title and message', () => {
    const {getByText} = render(<Dialog {...props} />);
    expect(getByText('PIN changed')).toBeTruthy();
    expect(getByText('Use your new PIN from now on.')).toBeTruthy();
  });

  it('calls the button handler when the button is pressed', () => {
    const onPress = jest.fn();
    const {getByText} = render(
      <Dialog {...props} button={{title: 'Done', onPress}} />,
    );
    fireEvent.press(getByText('Done'));
    expect(onPress).toHaveBeenCalledTimes(1);
  });

  it('shows nothing while hidden', () => {
    const {queryByText} = render(<Dialog {...props} isVisible={false} />);
    expect(queryByText('PIN changed')).toBeNull();
  });
});

describe('Snackbar', () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  it('shows the message, then calls onHide once its time is up', () => {
    const onHide = jest.fn();
    const {getByText} = render(
      <Snackbar message="PIN changed" onHide={onHide} duration={3000} />,
    );
    expect(getByText('PIN changed')).toBeTruthy();

    act(() => jest.advanceTimersByTime(2900));
    expect(onHide).not.toHaveBeenCalled();

    act(() => jest.advanceTimersByTime(1000));
    expect(onHide).toHaveBeenCalledTimes(1);
  });

  it('shows nothing and never calls onHide without a message', () => {
    const onHide = jest.fn();
    const {toJSON} = render(<Snackbar message="" onHide={onHide} />);
    expect(toJSON()).toBeNull();

    act(() => jest.advanceTimersByTime(10000));
    expect(onHide).not.toHaveBeenCalled();
  });

  it('does not call onHide once unmounted', () => {
    const onHide = jest.fn();
    const {unmount} = render(
      <Snackbar message="PIN changed" onHide={onHide} duration={3000} />,
    );
    act(() => jest.advanceTimersByTime(1000));
    unmount();

    act(() => jest.advanceTimersByTime(10000));
    expect(onHide).not.toHaveBeenCalled();
  });
});
