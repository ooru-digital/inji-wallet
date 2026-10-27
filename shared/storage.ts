import { NativeModules } from 'react-native';
import {
  getFreeDiskStorageOldSync,
  getFreeDiskStorageSync,
} from 'react-native-device-info';
import { MMKVLoader } from 'react-native-mmkv-storage';
import getAllConfigurations from './api';
import { exportData } from './backupUtils/backupData';
import { loadBackupData } from './backupUtils/restoreData';
import { BYTES_IN_MEGABYTE } from './commonUtil';
import {
  androidVersion,
  API_CACHED_STORAGE_KEYS,
  ENOENT,
  isAndroid,
  isIOS,
  SETTINGS_STORE_KEY
} from './constants';
import {
  decryptJson,
  encryptJson,
  HMAC_ALIAS,
  hmacSHA,
  isHardwareKeystoreExists,
} from './cryptoutil/cryptoUtil';
import FileStorage, {
  getDirectorySize,
  getFilePath,
  getPendingFilePath,
  vcDirectoryPath,
} from './fileStorage';
import { __AppId } from './GlobalVariables';
import { TelemetryConstants } from './telemetry/TelemetryConstants';
import { getErrorEventData, sendErrorEvent } from './telemetry/TelemetryUtils';
import { VCMetadata } from './VCMetadata';

export const MMKV = new MMKVLoader().initialize();
const { RNSecureKeystoreModule } = NativeModules;

async function generateHmac(
  encryptionKey: string,
  data: string,
): Promise<string> {
  if (!isHardwareKeystoreExists) {
    return hmacSHA(encryptionKey, data);
  }
  return await RNSecureKeystoreModule.generateHmacSha(HMAC_ALIAS, data);
}

const vcKeyLocks = new Map<string, Promise<unknown>>();

// A VC's file and HMAC are changed in separate steps, so operations on the same VC must not
// interleave: overlapping saves can pair one save's data with another's HMAC.
function withVcKeyLock<T>(key: string, task: () => Promise<T>): Promise<T> {
  const previous = vcKeyLocks.get(key) ?? Promise.resolve();
  const result = previous.then(task);
  const settled = result.catch(() => undefined);
  vcKeyLocks.set(key, settled);
  settled.then(() => {
    if (vcKeyLocks.get(key) === settled) {
      vcKeyLocks.delete(key);
    }
  });
  return result;
}

class Storage {

  static backupData = async (encryptionKey: string) => {
    return await exportData(encryptionKey)
  };

  static async restoreBackUpData(data: string, encryptionKey: string): Promise<any> {
    return await loadBackupData(data, encryptionKey)
  }

  static fetchAllWellknownConfig = async (encryptionKey: string) => {
    let wellknownConfigData: Record<string, Object> = {};
    const allKeysInDB = await MMKV.indexer.strings.getKeys();
    const wellknownConfigCacheKey =
      API_CACHED_STORAGE_KEYS.fetchIssuerWellknownConfig('');
    const wellknownKeys = allKeysInDB.filter(key =>
      key.includes(wellknownConfigCacheKey),
    );

    for (const wellknownKey of wellknownKeys) {
      const configData = await this.getItem(wellknownKey, encryptionKey);
      const decryptedConfigData = await decryptJson(encryptionKey, configData);
      wellknownConfigData[
        wellknownKey.substring(wellknownConfigCacheKey.length)
      ] = JSON.parse(JSON.stringify(decryptedConfigData));
    }
    return wellknownConfigData;
  };

  static setItem = async (
    key: string,
    data: string,
    encryptionKey?: string,
  ) => {
    try {
      const isSavingVC = VCMetadata.isVCKey(key);
      if (isSavingVC) {
        return await withVcKeyLock(key, () =>
          this.storeVC(key, data, encryptionKey),
        );
      }

      await MMKV.setItem(key, data);
    } catch (error) {
      console.error('Error Occurred while saving in Storage.', error);
      throw error;
    }
  };

  static getItem = async (key: string, encryptionKey?: string) => {
    try {
      const isVCKey = VCMetadata.isVCKey(key);

      if (isVCKey) {
        return await withVcKeyLock(key, () => this.readVC(key, encryptionKey));
      }

      return await MMKV.getItem(key);
    } catch (error) {
      const isVCKey = VCMetadata.isVCKey(key);

      if (isVCKey) {
        const isDownloaded = await this.isVCAlreadyDownloaded(
          key,
          encryptionKey,
        );

        if (isDownloaded && error.message.includes(ENOENT)) {
          sendErrorEvent(
            getErrorEventData(
              TelemetryConstants.FlowType.fetchData,
              TelemetryConstants.ErrorId.dataRetrieval,
              error.message,
            ),
          );
          throw new Error(ENOENT);
        }
      }
      sendErrorEvent(
        getErrorEventData(
          TelemetryConstants.FlowType.fetchData,
          TelemetryConstants.ErrorId.dataRetrieval,
          'Error Occurred while retrieving from Storage',
        ),
      );

      console.error('Error Occurred while retrieving from Storage.', error);
      throw error;
    }
  };

  static removeItem = async (key: string) => {
    if (VCMetadata.isVCKey(key)) {
      const isFileRemoved = await withVcKeyLock(key, async () => {
        await FileStorage.removeItemIfExist(getPendingFilePath(key));
        const path = getFilePath(key);
        const isFileExists = await FileStorage.exists(path);
        if (isFileExists) {
          await FileStorage.removeItem(path);
          return true;
        }
        console.warn('file not exist`s');
        return false;
      });
      if (isFileRemoved) {
        return;
      }
    }
    MMKV.removeItem(key);
  };

  static clear = async () => {
    try {
      (await FileStorage.exists(`${vcDirectoryPath}`)) &&
        (await FileStorage.removeItem(`${vcDirectoryPath}`));
      const settings = await MMKV.getItem(SETTINGS_STORE_KEY);
      const appId = JSON.parse(settings).appId;
      __AppId.setValue(appId);
      MMKV.clearStore();
      await MMKV.setItem(SETTINGS_STORE_KEY, JSON.stringify({ appId: appId }));
    } catch (e) {
      console.error('Error Occurred while Clearing Storage.', e);
    }
  };

  // A save writes the pending file, then the HMAC, then moves the pending file into place, so
  // after an interruption the HMAC matches either the pending file (finish the move) or the
  // current file (drop the pending one). Data matching neither has been tampered with.
  private static async readVC(key: string, encryptionKey: string) {
    const storedHMACofCurrentVC = await this.readHmacForDataCorruptionCheck(
      key,
      encryptionKey,
    );
    const path = getFilePath(key);
    const pendingPath = getPendingFilePath(key);

    if (await FileStorage.exists(pendingPath)) {
      const pendingData = await FileStorage.readFile(pendingPath);
      const HMACofPendingVC = await generateHmac(encryptionKey, pendingData);
      if (
        storedHMACofCurrentVC !== null &&
        HMACofPendingVC === storedHMACofCurrentVC
      ) {
        await this.replaceWithPendingFile(pendingPath, path);
        sendErrorEvent(
          getErrorEventData(
            TelemetryConstants.FlowType.fetchData,
            TelemetryConstants.ErrorId.dataRetrieval,
            'Recovered an interrupted VC save',
          ),
        );
        console.info(`Completed an interrupted save of VC - ${key}`);
        return pendingData;
      }
      await FileStorage.removeItem(pendingPath);
      sendErrorEvent(
        getErrorEventData(
          TelemetryConstants.FlowType.fetchData,
          TelemetryConstants.ErrorId.dataRetrieval,
          'Discarded an unfinished VC save',
        ),
      );
      console.info(`Discarded an unfinished save of VC - ${key}`);
    }

    const data = await this.readVCFromFile(key);
    const HMACofVC = await generateHmac(encryptionKey, data);
    const isCorrupted = HMACofVC !== storedHMACofCurrentVC;

    if (isCorrupted) {
      sendErrorEvent(
        getErrorEventData(
          TelemetryConstants.FlowType.fetchData,
          TelemetryConstants.ErrorId.tampered,
          'VC is corrupted and will be deleted from storage',
        ),
      );
      console.debug(
        '[Inji-406]: VC is corrupted and will be deleted from storage',
      );
      console.debug('[Inji-406]: VC key: ', key);
      console.debug('[Inji-406]: is Data null', data === null);
    }

    return isCorrupted ? null : data;
  }

  private static async isVCAlreadyDownloaded(
    key: string,
    encryptionKey: string,
  ) {
    try {
      const storedHMACofCurrentVC = await this.readHmacForVC(
        key,
        encryptionKey,
      );
      return storedHMACofCurrentVC !== null;
    } catch (e) {
      throw e;
    }
  }

  private static async readHmacForVC(key: string, encryptionKey: string) {
    try {
      const encryptedHMACofCurrentVC = await MMKV.getItem(key);
      if (encryptedHMACofCurrentVC) {
        return decryptJson(encryptionKey, encryptedHMACofCurrentVC);
      }
      return null;
    } catch (e) {
      console.error('error while reading Hmac for VC ', e);
      throw e;
    }
  }

  private static async readHmacForDataCorruptionCheck(
    key: string,
    encryptionKey: string,
  ) {
    try {
      const encryptedHMACofCurrentVC = await MMKV.getItem(key);
      if (encryptedHMACofCurrentVC) {
        return decryptJson(encryptionKey, encryptedHMACofCurrentVC);
      }
      return null;
    } catch (e) {
      throw e;
    }
  }

  private static async readVCFromFile(key: string) {
    return await FileStorage.readFile(getFilePath(key));
  }

  private static async storeVC(
    key: string,
    data: string,
    encryptionKey: string,
  ) {
    await FileStorage.createDirectory(vcDirectoryPath);
    const pendingPath = getPendingFilePath(key);
    await FileStorage.writeFile(pendingPath, data);
    await this.storeVcHmac(encryptionKey, data, key);
    await this.replaceWithPendingFile(pendingPath, getFilePath(key));
  }

  /**
   * Android's rename replaces the card file in one step. iOS refuses to move onto an existing
   * file, so the old file is removed first, and an interruption in between leaves only the
   * pending file. Every read of a card file must go through readVC, which finishes an
   * interrupted replace; reading getFilePath(key) directly can find no file at all.
   */
  private static async replaceWithPendingFile(
    pendingPath: string,
    path: string,
  ) {
    if (isIOS()) {
      await FileStorage.removeItemIfExist(path);
    }
    await FileStorage.moveFile(pendingPath, path);
  }

  private static async storeVcHmac(
    encryptionKey: string,
    data: string,
    key: string,
  ) {
    const HMACofVC = await generateHmac(encryptionKey, data);
    const encryptedHMACofVC = await encryptJson(encryptionKey, HMACofVC);
    await MMKV.setItem(key, encryptedHMACofVC);
  }
}

export default Storage;

export async function isMinimumLimitForBackupReached() {
  try {
    const directorySize = await getDirectorySize(vcDirectoryPath);
    const freeDiskStorageInBytes =
      isAndroid() && androidVersion < 29
        ? getFreeDiskStorageOldSync()
        : getFreeDiskStorageSync();

    return freeDiskStorageInBytes <= 2 * directorySize;
  } catch (error) {
    console.error('Error in isMinimumLimitForBackupReached:', error);
    throw error;
  }
}

export async function isMinimumLimitForBackupRestorationReached() {
  // TODO: Have two checks, one for downloading the ZIP file from the cloud &
  //  then by looking at it's metadata to check it's expanded size
  // APIs:
  // 1. CloudStorage.stat(file, context)
  // 2. getUncompressedSize()
  return await isMinimumStorageLimitReached('minStorageRequired');
}

export async function isMinimumStorageLimitReached(limitInMB: string) {
  const configurations = await getAllConfigurations();
  if (!configurations[limitInMB]) return false;

  const minimumStorageLimitInBytes =
    configurations[limitInMB] * BYTES_IN_MEGABYTE;

  const freeDiskStorageInBytes =
    isAndroid() && androidVersion < 29
      ? getFreeDiskStorageOldSync()
      : getFreeDiskStorageSync();

  return freeDiskStorageInBytes <= minimumStorageLimitInBytes;
};
