const mockGetApps = jest.fn();
const mockGetCrashlytics = jest.fn(() => ({}));
const mockLog = jest.fn();
const mockRecordError = jest.fn();

jest.mock('@react-native-firebase/app', () => ({
  getApps: () => mockGetApps(),
}));
// Like the real module (25.1.0), loading it throws when no Firebase app is configured.
jest.mock('@react-native-firebase/crashlytics', () => {
  if (mockGetApps().length === 0) {
    throw new Error("No Firebase App '[DEFAULT]' has been created");
  }
  return {
    getCrashlytics: () => mockGetCrashlytics(),
    log: (...args: unknown[]) => mockLog(...args),
    recordError: (...args: unknown[]) => mockRecordError(...args),
  };
});

import {initCrashlytics, reportError} from './crashlytics';

describe('crashlytics', () => {
  beforeEach(() => jest.clearAllMocks());

  describe('without a Firebase config file in the build', () => {
    beforeEach(() => mockGetApps.mockReturnValue([]));

    it("does nothing, and never loads the Crashlytics module, which throws when it's unconfigured", () => {
      expect(() => {
        initCrashlytics();
        reportError(new Error('boom'), 'context');
      }).not.toThrow();

      expect(mockGetCrashlytics).not.toHaveBeenCalled();
      expect(mockRecordError).not.toHaveBeenCalled();
    });

    it('does nothing when the Firebase app module throws', () => {
      mockGetApps.mockImplementation(() => {
        throw new Error('native module missing');
      });

      expect(() => initCrashlytics()).not.toThrow();
      expect(mockGetCrashlytics).not.toHaveBeenCalled();
    });
  });

  describe('with Firebase configured', () => {
    beforeEach(() => mockGetApps.mockReturnValue([{name: '[DEFAULT]'}]));

    it('starts Crashlytics, which installs its JavaScript crash handlers', () => {
      initCrashlytics();

      expect(mockGetCrashlytics).toHaveBeenCalledTimes(1);
    });

    it('reports a handled error with its context', () => {
      const error = new Error('boom');
      reportError(error, 'downloading a card');

      expect(mockLog).toHaveBeenCalledWith({}, 'downloading a card');
      expect(mockRecordError).toHaveBeenCalledWith({}, error);
    });

    it('wraps a thrown value that is not an Error', () => {
      reportError('timeout');

      expect(mockLog).not.toHaveBeenCalled();
      expect(mockRecordError).toHaveBeenCalledWith({}, new Error('timeout'));
    });

    it('never throws, so a reporting failure cannot break the flow that called it', () => {
      mockRecordError.mockImplementationOnce(() => {
        throw new Error('native module failed');
      });

      expect(() => reportError(new Error('boom'))).not.toThrow();
    });
  });
});
