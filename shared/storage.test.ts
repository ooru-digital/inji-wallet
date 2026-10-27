const mockFiles = new Map<string, string>();
const mockKeyValues = new Map<string, string>();
const mockFileOps = {
  failMoveFile: false,
  failStoringHmac: false,
  writeDelayMs: new Map<string, number>(),
};
let mockIsIOS = false;

jest.mock('react-native-mmkv-storage', () => ({
  MMKVLoader: class {
    initialize() {
      return {
        getItem: async (key: string) => mockKeyValues.get(key) ?? null,
        setItem: async (key: string, value: string) => {
          if (mockFileOps.failStoringHmac) {
            throw new Error('killed while storing the HMAC');
          }
          mockKeyValues.set(key, value);
        },
        removeItem: (key: string) => mockKeyValues.delete(key),
        indexer: {strings: {getKeys: async () => [...mockKeyValues.keys()]}},
      };
    }
  },
}));

jest.mock('./fileStorage', () => {
  const getFilePath = (key: string) => `/vc/${key}.txt`;
  return {
    __esModule: true,
    default: {
      createDirectory: async () => undefined,
      writeFile: async (path: string, data: string) => {
        const delayMs = mockFileOps.writeDelayMs.get(data);
        if (delayMs) {
          await new Promise(resolve => setTimeout(resolve, delayMs));
        }
        mockFiles.set(path, data);
      },
      readFile: async (path: string) => {
        if (!mockFiles.has(path)) {
          throw new Error(`ENOENT: No such file or directory, open '${path}'`);
        }
        return mockFiles.get(path);
      },
      exists: async (path: string) => mockFiles.has(path),
      removeItem: async (path: string) => {
        mockFiles.delete(path);
      },
      removeItemIfExist: async (path: string) => mockFiles.delete(path),
      moveFile: async (from: string, to: string) => {
        if (mockFileOps.failMoveFile) {
          throw new Error('killed while moving the file');
        }
        if (mockIsIOS && mockFiles.has(to)) {
          throw new Error('file already exists');
        }
        mockFiles.set(to, mockFiles.get(from)!);
        mockFiles.delete(from);
      },
    },
    getFilePath,
    getPendingFilePath: (key: string) => `${getFilePath(key)}.tmp`,
    getDirectorySize: async () => 0,
    vcDirectoryPath: '/vc',
  };
});

jest.mock('./cryptoutil/cryptoUtil', () => ({
  isHardwareKeystoreExists: false,
  HMAC_ALIAS: 'hmac',
  hmacSHA: (key: string, data: string) => `hmac(${key}:${data})`,
  encryptJson: async (_key: string, data: string) => `enc(${data})`,
  decryptJson: async (_key: string, data: string) =>
    data.replace(/^enc\(/, '').replace(/\)$/, ''),
}));

jest.mock('./constants', () => ({
  androidVersion: 33,
  API_CACHED_STORAGE_KEYS: {fetchIssuerWellknownConfig: () => 'wellknown_'},
  ENOENT: 'No such file or directory',
  isAndroid: () => !mockIsIOS,
  isIOS: () => mockIsIOS,
  SETTINGS_STORE_KEY: 'settings',
}));

jest.mock('./VCMetadata', () => ({
  VCMetadata: {isVCKey: (key: string) => /^VC_[a-zA-Z0-9_-]+$/.test(key)},
}));
jest.mock('./api', () => jest.fn());
jest.mock('./backupUtils/backupData', () => ({exportData: jest.fn()}));
jest.mock('./backupUtils/restoreData', () => ({loadBackupData: jest.fn()}));
jest.mock('./GlobalVariables', () => ({__AppId: {setValue: jest.fn()}}));
jest.mock('./telemetry/TelemetryUtils', () => ({
  getErrorEventData: jest.fn(),
  sendErrorEvent: jest.fn(),
}));

import Storage from './storage';

const KEY = 'VC_card-1';
const ENCRYPTION_KEY = 'secret';
const FILE = `/vc/${KEY}.txt`;
const PENDING_FILE = `${FILE}.tmp`;

const storedHmacFor = (data: string) => `enc(hmac(${ENCRYPTION_KEY}:${data}))`;

describe('Storage: saving a card', () => {
  beforeEach(() => {
    mockFiles.clear();
    mockKeyValues.clear();
    mockFileOps.failMoveFile = false;
    mockFileOps.failStoringHmac = false;
    mockFileOps.writeDelayMs.clear();
    mockIsIOS = false;
    jest.spyOn(console, 'error').mockImplementation(() => undefined);
    jest.spyOn(console, 'debug').mockImplementation(() => undefined);
    jest.spyOn(console, 'info').mockImplementation(() => undefined);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('stores the card and its HMAC, leaving no pending file', async () => {
    await Storage.setItem(KEY, 'v1', ENCRYPTION_KEY);

    expect(mockFiles.get(FILE)).toBe('v1');
    expect(mockFiles.has(PENDING_FILE)).toBe(false);
    expect(mockKeyValues.get(KEY)).toBe(storedHmacFor('v1'));
    expect(await Storage.getItem(KEY, ENCRYPTION_KEY)).toBe('v1');
  });

  it('replaces the existing card on iOS, which cannot move onto a file', async () => {
    mockIsIOS = true;
    await Storage.setItem(KEY, 'v1', ENCRYPTION_KEY);
    await Storage.setItem(KEY, 'v2', ENCRYPTION_KEY);

    expect(await Storage.getItem(KEY, ENCRYPTION_KEY)).toBe('v2');
    expect(mockFiles.has(PENDING_FILE)).toBe(false);
  });

  describe('when the app is killed during a save', () => {
    beforeEach(async () => {
      await Storage.setItem(KEY, 'v1', ENCRYPTION_KEY);
    });

    it('keeps the previous card if killed before the HMAC is stored', async () => {
      mockFileOps.failStoringHmac = true;
      await expect(Storage.setItem(KEY, 'v2', ENCRYPTION_KEY)).rejects.toThrow();
      mockFileOps.failStoringHmac = false;

      expect(await Storage.getItem(KEY, ENCRYPTION_KEY)).toBe('v1');
      expect(mockFiles.has(PENDING_FILE)).toBe(false);
    });

    it('finishes the save if killed after the HMAC is stored', async () => {
      mockFileOps.failMoveFile = true;
      await expect(Storage.setItem(KEY, 'v2', ENCRYPTION_KEY)).rejects.toThrow();
      mockFileOps.failMoveFile = false;

      expect(await Storage.getItem(KEY, ENCRYPTION_KEY)).toBe('v2');
      expect(mockFiles.get(FILE)).toBe('v2');
      expect(mockFiles.has(PENDING_FILE)).toBe(false);
    });

    it('finishes the save if killed after iOS removed the old file', async () => {
      mockFiles.set(PENDING_FILE, 'v2');
      mockKeyValues.set(KEY, storedHmacFor('v2'));
      mockFiles.delete(FILE);

      expect(await Storage.getItem(KEY, ENCRYPTION_KEY)).toBe('v2');
      expect(mockFiles.get(FILE)).toBe('v2');
    });

    it('keeps the previous card if killed partway through writing the pending file', async () => {
      mockFiles.set(PENDING_FILE, 'v2-trunc');

      expect(await Storage.getItem(KEY, ENCRYPTION_KEY)).toBe('v1');
      expect(mockFiles.has(PENDING_FILE)).toBe(false);
    });
  });

  it('still reports a card whose data was changed as tampered', async () => {
    await Storage.setItem(KEY, 'v1', ENCRYPTION_KEY);
    mockFiles.set(FILE, 'changed');

    expect(await Storage.getItem(KEY, ENCRYPTION_KEY)).toBeNull();
  });

  it('does not accept a pending file that does not match the stored HMAC', async () => {
    await Storage.setItem(KEY, 'v1', ENCRYPTION_KEY);
    mockFiles.set(FILE, 'changed');
    mockFiles.set(PENDING_FILE, 'also changed');

    expect(await Storage.getItem(KEY, ENCRYPTION_KEY)).toBeNull();
    expect(mockFiles.has(PENDING_FILE)).toBe(false);
  });

  it('applies overlapping saves of a card in order', async () => {
    mockFileOps.writeDelayMs.set('v1', 20);
    await Promise.all([
      Storage.setItem(KEY, 'v1', ENCRYPTION_KEY),
      Storage.getItem(KEY, ENCRYPTION_KEY).catch(() => undefined),
      Storage.setItem(KEY, 'v2', ENCRYPTION_KEY),
      Storage.setItem(KEY, 'v3', ENCRYPTION_KEY),
    ]);

    expect(mockFiles.get(FILE)).toBe('v3');
    expect(mockKeyValues.get(KEY)).toBe(storedHmacFor('v3'));
    expect(await Storage.getItem(KEY, ENCRYPTION_KEY)).toBe('v3');
  });

  it('removes a pending file along with the card', async () => {
    await Storage.setItem(KEY, 'v1', ENCRYPTION_KEY);
    mockFiles.set(PENDING_FILE, 'v2');

    await Storage.removeItem(KEY);

    expect(mockFiles.has(FILE)).toBe(false);
    expect(mockFiles.has(PENDING_FILE)).toBe(false);
  });
});
