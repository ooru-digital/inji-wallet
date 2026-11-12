import {getApps} from '@react-native-firebase/app';
import {
  getCrashlytics,
  log,
  recordError,
} from '@react-native-firebase/crashlytics';

/**
 * Firebase Crashlytics. Native crashes are reported by the Firebase SDK on its own; this file
 * covers JavaScript errors.
 *
 * Firebase is configured only when the build has its config file (android/app/google-services.json,
 * ios/Inji/GoogleService-Info.plist). Without one, every function here does nothing, so the app
 * works the same before the Firebase project is set up.
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
 * Turns on reporting of JavaScript crashes: creating the Crashlytics instance installs its handlers
 * for uncaught errors and unhandled promise rejections. Call once, as the app starts.
 */
export function initCrashlytics(): void {
  if (isFirebaseConfigured()) {
    getCrashlytics();
  }
}

/** Reports an error the app caught and handled, so it shows in Crashlytics as non-fatal. */
export function reportError(error: unknown, context?: string): void {
  if (!isFirebaseConfigured()) {
    return;
  }
  const crashlytics = getCrashlytics();
  if (context) {
    log(crashlytics, context);
  }
  recordError(
    crashlytics,
    error instanceof Error ? error : new Error(String(error)),
  );
}
