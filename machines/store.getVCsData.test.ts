// The shared jest setup replaces the store with a stub; this test needs the real functions.
jest.unmock('./store');

const mockStored = new Map<string, string>();

jest.mock('../shared/cryptoutil/cryptoUtil', () => ({
  isHardwareKeystoreExists: false,
  AUTH_TIMEOUT: 300,
  ENCRYPTION_ID: 'enc',
  HMAC_ALIAS: 'hmac',
  encryptJson: async (_key: string, data: string) => data,
  decryptJson: async (_key: string, data: string) => data,
}));
jest.mock('../shared/storage', () => ({
  __esModule: true,
  default: {
    getItem: async (key: string) => mockStored.get(key) ?? null,
    setItem: async (key: string, data: string) => {
      mockStored.set(key, data);
    },
    removeItem: async (key: string) => {
      mockStored.delete(key);
    },
  },
  MMKV: {removeItem: jest.fn()},
}));
jest.mock('../shared/VCMetadata', () => ({
  VCMetadata: class {
    id = '';
    constructor(metadata: object) {
      Object.assign(this, metadata);
    }
    static fromVC(metadata: object) {
      return new this(metadata);
    }
    static isVCKey(key: string) {
      return key.startsWith('VC_');
    }
    getVcKey() {
      return `VC_${this.id}`;
    }
  },
}));
jest.mock('../shared/fileStorage', () => ({isVCStorageInitialised: jest.fn()}));
jest.mock('../shared/telemetry/TelemetryUtils', () => ({
  getErrorEventData: jest.fn(),
  sendErrorEvent: jest.fn(),
}));

import {getVCsData} from './store';

describe('getVCsData', () => {
  beforeEach(() => {
    mockStored.clear();
    jest.spyOn(console, 'error').mockImplementation(() => undefined);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('leaves tampered cards out of the returned card list', async () => {
    mockStored.set('myVCs', JSON.stringify([{id: 'good'}, {id: 'tampered'}]));
    mockStored.set('VC_good', JSON.stringify({credential: 'good'}));

    const {vcsData, vcsMetadata, tamperedVcsList} = await getVCsData(
      'myVCs',
      'key',
    );

    expect(Object.keys(vcsData)).toEqual(['VC_good']);
    expect(vcsMetadata.map(metadata => metadata.id)).toEqual(['good']);
    expect(tamperedVcsList.map(metadata => metadata.id)).toEqual(['tampered']);
    expect(JSON.parse(mockStored.get('myVCs')!)).toEqual([{id: 'good'}]);
  });

  it('returns an empty card list when none is stored', async () => {
    const {vcsMetadata, tamperedVcsList} = await getVCsData('myVCs', 'key');

    expect(vcsMetadata).toEqual([]);
    expect(tamperedVcsList).toEqual([]);
  });
});
