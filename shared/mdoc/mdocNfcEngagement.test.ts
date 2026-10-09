import {DeviceEventEmitter, NativeModules, Platform} from 'react-native';
import * as nfcModule from './mdocNfcEngagement';

const discardNfcEngagement = jest.fn();
const getPendingNfcEngagement = jest.fn(() => Promise.resolve(null));

function load() {
  return nfcModule;
}

describe('a reader tapping the phone', () => {
  beforeAll(() => {
    Platform.OS = 'android';
    (NativeModules as Record<string, unknown>).MdocIso18013Presentment = {
      discardNfcEngagement,
      getPendingNfcEngagement,
    };
    nfcModule.startListeningForNfcEngagement();
  });

  beforeEach(() => {
    jest.useFakeTimers();
    nfcModule.takeNfcEngagement();
    discardNfcEngagement.mockClear();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('is waiting once native reports the tap', () => {
    const nfc = load();
    DeviceEventEmitter.emit('MdocNfcEngaged', {id: 'tap-1'});
    expect(nfc.pendingNfcEngagementId()).toBe('tap-1');
  });

  it('answers only the first card opened', () => {
    // A second card opened afterwards must fall back to its QR code, not reuse a tap that
    // native has already handed to the first session.
    const nfc = load();
    DeviceEventEmitter.emit('MdocNfcEngaged', {id: 'tap-1'});
    expect(nfc.takeNfcEngagement()).toBe('tap-1');
    expect(nfc.takeNfcEngagement()).toBeNull();
  });

  it('stops waiting when the reader would have given up', () => {
    const nfc = load();
    DeviceEventEmitter.emit('MdocNfcEngaged', {id: 'tap-1'});
    jest.advanceTimersByTime(25_000);
    expect(nfc.pendingNfcEngagementId()).toBeNull();
  });

  it('a newer tap replaces an older one', () => {
    const nfc = load();
    DeviceEventEmitter.emit('MdocNfcEngaged', {id: 'tap-1'});
    DeviceEventEmitter.emit('MdocNfcEngaged', {id: 'tap-2'});
    expect(nfc.takeNfcEngagement()).toBe('tap-2');
  });

  it('cancelling tells native to forget the tap', () => {
    const nfc = load();
    DeviceEventEmitter.emit('MdocNfcEngaged', {id: 'tap-1'});
    nfc.dismissNfcEngagement();
    expect(discardNfcEngagement).toHaveBeenCalledWith('tap-1');
    expect(nfc.pendingNfcEngagementId()).toBeNull();
  });
});
