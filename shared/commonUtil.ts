import argon2 from 'react-native-argon2';
import {AnyState} from 'xstate';
import {getDeviceNameSync} from 'react-native-device-info';
import {
  GOOGLE_DRIVE_NAME,
  ICLOUD_DRIVE_NAME,
  isAndroid,
  GMAIL,
  APPLE,
  ASSETS_CDN_BASE_URL,
} from './constants';
import {generateSecureRandom} from 'react-native-securerandom';
import forge from 'node-forge';
import {CredentialSubject} from '../machines/VerifiableCredential/VCMetaMachine/vc';

export const hashData = async (
  data: string,
  salt: string,
  config: Argon2iConfig,
): Promise<string> => {
  const result = await argon2(data, salt, config);
  return result.rawHash as string;
};

export const generateRandomString = async () => {
  const randomBytes = await generateSecureRandom(64);
  const randomString = randomBytes.reduce(
    (acc, byte) => acc + byte.toString(16).padStart(2, '0'),
    '',
  );
  return randomString;
};
export const getRandomInt = (min, max) => {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1)) + min;
};
export const generateBackupEncryptionKey = (
  password: string,
  salt: string,
  iterations: number,
  length: number,
) => forge.pkcs5.pbkdf2(password, salt, iterations, length);

export interface Argon2iConfig {
  iterations: number;
  memory: number;
  parallelism: number;
  hashLength: number;
  mode: string;
}

export default function testIDProps(id: string) {
  return isAndroid()
    ? {accessible: true, accessibilityLabel: id}
    : {testID: id};
}

export const removeWhiteSpace = (str: string) => {
  return str ? str.replace(/\s/g, '') : str;
};

// CredIssuer's asset buckets don't allow public reads; their files are served by the assets CDN
// at the same path. The backend maps them the same way (credflow-api `form_cdn_url`).
const CDN_SERVED_BUCKETS = [
  'credissuer-public-assets',
  'prod-credissuer-assets',
];
const S3_URL = /^https?:\/\/([^/]+)\.s3[.-][^/]*amazonaws\.com\/(.+)$/i;

/**
 * A logo URL the app can load: CredIssuer asset-bucket URLs, which return 403, are moved to the
 * assets CDN, and spaces in file names ("IIIT Bangalore.png") are encoded, which iOS needs.
 */
export function toLogoUrl(url?: string | null): string | undefined {
  const trimmed = url?.trim();
  if (!trimmed) {
    return undefined;
  }
  const encoded = trimmed.replace(/ /g, '%20');
  // A presigned URL already grants access, and the CDN wouldn't accept its signature.
  const isPresigned = /[?&](X-Amz-|Signature=)/i.test(encoded);
  const s3 = S3_URL.exec(encoded);
  if (!isPresigned && s3 && CDN_SERVED_BUCKETS.includes(s3[1].toLowerCase())) {
    return `${ASSETS_CDN_BASE_URL}/${s3[2]}`;
  }
  return encoded;
}

export function logState(state: AnyState) {
  if (__DEV__) {
    const data = JSON.stringify(
      state.event,
      (key, value) => {
        if (key === 'type') return undefined;
        if (typeof value === 'string' && value.length >= 100) {
          return value.slice(0, 100) + '...';
        }
        return value;
      },
      2,
    );
    console.log(
      `[${getDeviceNameSync()}] ${state.machine?.id}: ${
        state.event.type
      } -> ${state.toStrings().pop()}\n${
        data.length > 300 ? data.slice(0, 300) + '...' : data
      }
      `,
    );
  }
}

export const getMaskedText = (id: string): string => {
  return '*'.repeat(id.length - 4) + id.slice(-4);
};

export const getBackupFileName = () => {
  return `backup_${Date.now()}`;
};

export const BYTES_IN_MEGABYTE = 1000 * 1000;

export const bytesToMB = (bytes: number): string => {
  if (bytes <= 0) {
    return '0';
  }

  const megabytes = bytes / BYTES_IN_MEGABYTE;
  return Number(megabytes).toFixed(3);
};

export const getAccountType = () => (isAndroid() ? GMAIL : APPLE);

export const getDriveName = () =>
  isAndroid() ? GOOGLE_DRIVE_NAME : ICLOUD_DRIVE_NAME;

export function sleep(timeInMillSeconds = 1000) {
  return new Promise(resolve => setTimeout(resolve, timeInMillSeconds));
}

export const getMosipIdentifier = (credentialSubject: CredentialSubject) => {
  return credentialSubject.UIN ? credentialSubject.UIN : credentialSubject.VID;
};

export const isTranslationKeyFound = (
  translationKey: string,
  t: (key: string) => string,
): boolean => {
  const translation = t(translationKey);
  return translation !== translationKey;
};
