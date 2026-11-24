import {DeviceEventEmitter, NativeModules} from 'react-native';

jest.mock('../GlobalVariables', () => ({__AppId: {getValue: () => 'app'}}));
jest.mock('../../machines/openID4VP/openID4VPServices', () => ({
  signatureSuite: 'suite',
}));

const nativeClient = {
  init: jest.fn(),
  addListener: jest.fn(),
  removeListeners: jest.fn(),
  requestCredentialByOffer: jest.fn(),
};
NativeModules.InjiVciClient = nativeClient;

// eslint-disable-next-line @typescript-eslint/no-var-requires
const VciClient = require('./VciClient').default;

function requestByOffer(getTxCode: jest.Mock) {
  return VciClient.getInstance().requestCredentialByOffer(
    'offer',
    getTxCode,
    jest.fn(),
    jest.fn(),
    jest.fn(),
    jest.fn(),
    jest.fn(),
    jest.fn(),
  );
}

describe('VciClient listeners', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('removes its listeners once the download settles', async () => {
    nativeClient.requestCredentialByOffer.mockRejectedValueOnce(
      new Error('failed'),
    );
    jest.spyOn(console, 'error').mockImplementation(jest.fn());

    await expect(requestByOffer(jest.fn())).rejects.toThrow('failed');

    expect(DeviceEventEmitter.listenerCount('onRequestTxCode')).toBe(0);
    expect(DeviceEventEmitter.listenerCount('onRequestTokenResponse')).toBe(0);
  });

  it('drops a cancelled download’s listeners when the next download starts', async () => {
    nativeClient.requestCredentialByOffer
      .mockReturnValueOnce(new Promise(jest.fn()))
      .mockResolvedValueOnce(JSON.stringify({credential: {}}));
    const cancelledTxCode = jest.fn();
    const currentTxCode = jest.fn();

    requestByOffer(cancelledTxCode);
    const current = requestByOffer(currentTxCode);
    DeviceEventEmitter.emit('onRequestTxCode', {
      inputMode: 'numeric',
      length: 6,
    });
    await current;

    expect(cancelledTxCode).not.toHaveBeenCalled();
    expect(currentTxCode).toHaveBeenCalledWith('numeric', undefined, 6);
    expect(DeviceEventEmitter.listenerCount('onRequestTxCode')).toBe(0);
  });
});
