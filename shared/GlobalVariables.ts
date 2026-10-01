import {getBuildNumber, getVersion} from 'react-native-device-info';
import ShortUniqueId from 'short-unique-id';
import {APP_ID_LENGTH, isIOS} from './constants';
import {NativeModules} from 'react-native';

function getTuvaliPackageDetails() {
  return isIOS() ? 'unknown' : NativeModules.VersionModule.getVersion();
}
export class __AppId {
  private static value: string;

  public static getValue(): string {
    return __AppId.value;
  }

  public static setValue(value: string) {
    this.value = value;
  }
}
export class __TuvaliVersion {
  private static packageDetails = getTuvaliPackageDetails();

  public static getpackageVersion(): string {
    return __TuvaliVersion.packageDetails;
  }

  public static getValue(): string {
    return this.getpackageVersion();
  }
}
export class __InjiVersion {
  // getVersion() -> iOS CFBundleShortVersionString / Android versionName (e.g. "1.0.0").
  // getBuildNumber() -> iOS CFBundleVersion / Android versionCode (e.g. "7"). Both read from
  // the native build config at runtime, so this stays in sync with the actual build.
  private static value = `${getVersion()}(${getBuildNumber()})`;

  public static getValue(): string {
    return __InjiVersion.value;
  }
}
export class __SessionId {
  private static value = generateSessionId();

  public static getValue(): string {
    return __SessionId.value;
  }
}

function generateSessionId() {
  const shortUUID = new ShortUniqueId({
    length: APP_ID_LENGTH,
  });
  return shortUUID.randomUUID() + Date.now();
}
