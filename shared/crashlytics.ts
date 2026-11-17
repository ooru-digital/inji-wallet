import {getApps} from '@react-native-firebase/app';

type CrashlyticsModule = typeof import('@react-native-firebase/crashlytics');

/**
 * Firebase Crashlytics. Native crashes are reported by the Firebase SDK on its own; this file
 * covers JavaScript errors.
 *
 * Firebase is configured only when the build has its config file (android/app/google-services.json,
 * ios/Inji/GoogleService-Info.plist). Without one, every function here does nothing, so the app
 * works the same before the Firebase project is set up.
 *
 * Why package.json lists `promise` (8.3.0, the version react-native depends on): Crashlytics' JS
 * crash handlers import `promise/setimmediate/rejection-tracking` without declaring `promise` as a
 * dependency, relying on react-native's copy being at the top of node_modules. Here it was nested
 * under react-native/node_modules, so Metro failed with "Unable to resolve module
 * promise/setimmediate/rejection-tracking". Remove it only if a later @react-native-firebase
 * declares the dependency itself.
 *
 * Reports are sent from release builds only (firebase.json `crashlytics_debug_enabled: false`).
 * Never pass credential data, keys or personal details to `log` or `recordError`: Crashlytics
 * stores them outside the wallet.
 */
function isFirebaseConfigured(): boolean {
  try {
    return getApps().length > 0;
  } catch {
    return false;
  }
}

/**
 * Loads @react-native-firebase/crashlytics. Only call it after isFirebaseConfigured(): the module
 * calls getApp() when it loads (25.1.0, namespaced.ts) and throws "Default App Not initialized"
 * without a config file, so a top-level import would crash the app at startup in that case.
 */
function loadCrashlytics(): CrashlyticsModule {
  return require('@react-native-firebase/crashlytics');
}

/**
 * Turns on reporting of JavaScript crashes: creating the Crashlytics instance installs its handlers
 * for uncaught errors and unhandled promise rejections. Call once, as the app starts; it never
 * throws, so Crashlytics can't stop the app from starting.
 */
export function initCrashlytics(): void {
  if (!isFirebaseConfigured()) {
    return;
  }
  try {
    loadCrashlytics().getCrashlytics();
  } catch (initError) {
    console.warn('Could not start Crashlytics', initError);
  }
}

/**
 * Reports an error the app caught and handled, so it shows in Crashlytics as non-fatal. Called from
 * the credential download and verification flows; it never throws, so reporting can't break them.
 */
export function reportError(error: unknown, context?: string): void {
  if (!isFirebaseConfigured()) {
    return;
  }
  try {
    const {getCrashlytics, log, recordError} = loadCrashlytics();
    const crashlytics = getCrashlytics();
    if (context) {
      log(crashlytics, context);
    }
    recordError(
      crashlytics,
      error instanceof Error ? error : new Error(String(error)),
    );
  } catch (reportingError) {
    console.warn('Could not report an error to Crashlytics', reportingError);
  }
}
