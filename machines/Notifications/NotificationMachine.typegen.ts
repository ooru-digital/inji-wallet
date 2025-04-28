// This file was automatically generated. Edits will be overwritten

export interface Typegen0 {
  '@@xstate/typegen': true;
  internalEvents: {
    '': {type: ''};
    'done.invoke.checkInternet': {
      type: 'done.invoke.checkInternet';
      data: unknown;
      __tip: 'See the XState TS docs to learn how to strongly type this.';
    };
    'done.invoke.downloadIssuers': {
      type: 'done.invoke.downloadIssuers';
      data: unknown;
      __tip: 'See the XState TS docs to learn how to strongly type this.';
    };
    'done.invoke.notificationMachine.checkKeyPair:invocation[0]': {
      type: 'done.invoke.notificationMachine.checkKeyPair:invocation[0]';
      data: unknown;
      __tip: 'See the XState TS docs to learn how to strongly type this.';
    };
    'done.invoke.notificationMachine.downloadCredentialTypes:invocation[0]': {
      type: 'done.invoke.notificationMachine.downloadCredentialTypes:invocation[0]';
      data: unknown;
      __tip: 'See the XState TS docs to learn how to strongly type this.';
    };
    'done.invoke.notificationMachine.downloadCredentials:invocation[0]': {
      type: 'done.invoke.notificationMachine.downloadCredentials:invocation[0]';
      data: unknown;
      __tip: 'See the XState TS docs to learn how to strongly type this.';
    };
    'done.invoke.notificationMachine.downloadIssuerWellknown:invocation[0]': {
      type: 'done.invoke.notificationMachine.downloadIssuerWellknown:invocation[0]';
      data: unknown;
      __tip: 'See the XState TS docs to learn how to strongly type this.';
    };
    'done.invoke.notificationMachine.generateKeyPair:invocation[0]': {
      type: 'done.invoke.notificationMachine.generateKeyPair:invocation[0]';
      data: unknown;
      __tip: 'See the XState TS docs to learn how to strongly type this.';
    };
    'done.invoke.notificationMachine.performAuthorization.getKeyPairFromKeystore:invocation[0]': {
      type: 'done.invoke.notificationMachine.performAuthorization.getKeyPairFromKeystore:invocation[0]';
      data: unknown;
      __tip: 'See the XState TS docs to learn how to strongly type this.';
    };
    'done.invoke.notificationMachine.performAuthorization.setSelectedKey:invocation[0]': {
      type: 'done.invoke.notificationMachine.performAuthorization.setSelectedKey:invocation[0]';
      data: unknown;
      __tip: 'See the XState TS docs to learn how to strongly type this.';
    };
    'done.invoke.notificationMachine.performAuthorization:invocation[0]': {
      type: 'done.invoke.notificationMachine.performAuthorization:invocation[0]';
      data: unknown;
      __tip: 'See the XState TS docs to learn how to strongly type this.';
    };
    'done.invoke.notificationMachine.storing:invocation[0]': {
      type: 'done.invoke.notificationMachine.storing:invocation[0]';
      data: unknown;
      __tip: 'See the XState TS docs to learn how to strongly type this.';
    };
    'done.invoke.notificationMachine.verifyingCredential:invocation[0]': {
      type: 'done.invoke.notificationMachine.verifyingCredential:invocation[0]';
      data: unknown;
      __tip: 'See the XState TS docs to learn how to strongly type this.';
    };
    'error.platform.checkInternet': {
      type: 'error.platform.checkInternet';
      data: unknown;
    };
    'error.platform.downloadIssuers': {
      type: 'error.platform.downloadIssuers';
      data: unknown;
    };
    'error.platform.notificationMachine.checkKeyPair:invocation[0]': {
      type: 'error.platform.notificationMachine.checkKeyPair:invocation[0]';
      data: unknown;
    };
    'error.platform.notificationMachine.downloadCredentialTypes:invocation[0]': {
      type: 'error.platform.notificationMachine.downloadCredentialTypes:invocation[0]';
      data: unknown;
    };
    'error.platform.notificationMachine.downloadCredentials:invocation[0]': {
      type: 'error.platform.notificationMachine.downloadCredentials:invocation[0]';
      data: unknown;
    };
    'error.platform.notificationMachine.downloadIssuerWellknown:invocation[0]': {
      type: 'error.platform.notificationMachine.downloadIssuerWellknown:invocation[0]';
      data: unknown;
    };
    'error.platform.notificationMachine.performAuthorization.getKeyPairFromKeystore:invocation[0]': {
      type: 'error.platform.notificationMachine.performAuthorization.getKeyPairFromKeystore:invocation[0]';
      data: unknown;
    };
    'error.platform.notificationMachine.performAuthorization.setSelectedKey:invocation[0]': {
      type: 'error.platform.notificationMachine.performAuthorization.setSelectedKey:invocation[0]';
      data: unknown;
    };
    'error.platform.notificationMachine.performAuthorization:invocation[0]': {
      type: 'error.platform.notificationMachine.performAuthorization:invocation[0]';
      data: unknown;
    };
    'error.platform.notificationMachine.verifyingCredential:invocation[0]': {
      type: 'error.platform.notificationMachine.verifyingCredential:invocation[0]';
      data: unknown;
    };
    'xstate.after(10)#notificationMachine.selectingIssuer': {
      type: 'xstate.after(10)#notificationMachine.selectingIssuer';
    };
    'xstate.init': {type: 'xstate.init'};
  };
  invokeSrcNameMap: {
    checkInternet: 'done.invoke.checkInternet';
    downloadCredential: 'done.invoke.notificationMachine.downloadCredentials:invocation[0]';
    downloadCredentialTypes: 'done.invoke.notificationMachine.downloadCredentialTypes:invocation[0]';
    downloadIssuerWellknown: 'done.invoke.notificationMachine.downloadIssuerWellknown:invocation[0]';
    downloadIssuersList: 'done.invoke.downloadIssuers';
    generateKeyPair: 'done.invoke.notificationMachine.generateKeyPair:invocation[0]';
    getKeyOrderList: 'done.invoke.notificationMachine.performAuthorization.setSelectedKey:invocation[0]';
    getKeyPair: 'done.invoke.notificationMachine.performAuthorization.getKeyPairFromKeystore:invocation[0]';
    getSelectedKey: 'done.invoke.notificationMachine.checkKeyPair:invocation[0]';
    invokeAuthorization: 'done.invoke.notificationMachine.performAuthorization:invocation[0]';
    isUserSignedAlready: 'done.invoke.notificationMachine.storing:invocation[0]';
    verifyCredential: 'done.invoke.notificationMachine.verifyingCredential:invocation[0]';
  };
  missingImplementations: {
    actions:
      | 'loadKeyPair'
      | 'logDownloaded'
      | 'resetError'
      | 'resetIsVerified'
      | 'resetLoadingReason'
      | 'resetSelectedCredentialType'
      | 'resetVerificationErrorMessage'
      | 'sendBackupEvent'
      | 'sendDownloadingFailedToVcMeta'
      | 'sendErrorEndEvent'
      | 'sendImpressionEvent'
      | 'sendSuccessEndEvent'
      | 'setCredentialTypeListDownloadFailureError'
      | 'setCredentialWrapper'
      | 'setError'
      | 'setFetchWellknownError'
      | 'setIsVerified'
      | 'setIssuers'
      | 'setLoadingReasonAsDisplayIssuers'
      | 'setLoadingReasonAsDownloadingCredentials'
      | 'setLoadingReasonAsSettingUp'
      | 'setMetadataInCredentialData'
      | 'setNoInternet'
      | 'setOIDCConfigError'
      | 'setPrivateKey'
      | 'setPublicKey'
      | 'setSelectedCredentialType'
      | 'setSelectedIssuerId'
      | 'setSelectedIssuers'
      | 'setSelectedKey'
      | 'setSupportedCredentialTypes'
      | 'setTokenResponse'
      | 'setVCMetadata'
      | 'setVerifiableCredential'
      | 'setWalletFailure'
      | 'storeKeyPair'
      | 'storeVcMetaContext'
      | 'storeVcsContext'
      | 'storeVerifiableCredentialData'
      | 'storeVerifiableCredentialMeta'
      | 'updateIssuerFromWellknown'
      | 'updateSelectedIssuerWellknownResponse'
      | 'updateVerificationErrorMessage';
    delays: never;
    guards:
      | 'canSelectIssuerAgain'
      | 'hasKeyPair'
      | 'hasUserCancelledBiometric'
      | 'isCustomSecureKeystore'
      | 'isGenericError'
      | 'isInternetConnected'
      | 'isKeyTypeNotFound'
      | 'isOIDCConfigError'
      | 'isOIDCflowCancelled'
      | 'isSignedIn'
      | 'isVerificationPendingBecauseOfNetworkIssue'
      | 'shouldFetchIssuersAgain';
    services:
      | 'checkInternet'
      | 'downloadCredential'
      | 'downloadCredentialTypes'
      | 'downloadIssuerWellknown'
      | 'downloadIssuersList'
      | 'generateKeyPair'
      | 'getKeyOrderList'
      | 'getKeyPair'
      | 'getSelectedKey'
      | 'invokeAuthorization'
      | 'isUserSignedAlready'
      | 'verifyCredential';
  };
  eventsCausingActions: {
    loadKeyPair: 'done.invoke.notificationMachine.performAuthorization.getKeyPairFromKeystore:invocation[0]';
    logDownloaded:
      | 'done.invoke.notificationMachine.verifyingCredential:invocation[0]'
      | 'error.platform.notificationMachine.verifyingCredential:invocation[0]';
    resetError:
      | 'RESET_ERROR'
      | 'TRY_AGAIN'
      | 'error.platform.notificationMachine.performAuthorization:invocation[0]';
    resetIsVerified: 'error.platform.notificationMachine.verifyingCredential:invocation[0]';
    resetLoadingReason:
      | 'RESET_ERROR'
      | 'done.invoke.checkInternet'
      | 'done.invoke.downloadIssuers'
      | 'error.platform.notificationMachine.downloadCredentialTypes:invocation[0]'
      | 'error.platform.notificationMachine.downloadCredentials:invocation[0]'
      | 'error.platform.notificationMachine.downloadIssuerWellknown:invocation[0]'
      | 'error.platform.notificationMachine.performAuthorization.getKeyPairFromKeystore:invocation[0]'
      | 'error.platform.notificationMachine.performAuthorization.setSelectedKey:invocation[0]'
      | 'error.platform.notificationMachine.performAuthorization:invocation[0]'
      | 'error.platform.notificationMachine.verifyingCredential:invocation[0]';
    resetSelectedCredentialType:
      | 'CANCEL'
      | 'error.platform.notificationMachine.downloadCredentials:invocation[0]'
      | 'error.platform.notificationMachine.performAuthorization.getKeyPairFromKeystore:invocation[0]'
      | 'error.platform.notificationMachine.performAuthorization.setSelectedKey:invocation[0]'
      | 'error.platform.notificationMachine.performAuthorization:invocation[0]';
    resetVerificationErrorMessage: 'RESET_VERIFY_ERROR';
    sendBackupEvent: 'done.invoke.notificationMachine.storing:invocation[0]';
    sendDownloadingFailedToVcMeta:
      | 'error.platform.notificationMachine.downloadCredentials:invocation[0]'
      | 'error.platform.notificationMachine.performAuthorization.getKeyPairFromKeystore:invocation[0]'
      | 'error.platform.notificationMachine.performAuthorization.setSelectedKey:invocation[0]'
      | 'error.platform.notificationMachine.performAuthorization:invocation[0]';
    sendErrorEndEvent: 'error.platform.notificationMachine.verifyingCredential:invocation[0]';
    sendImpressionEvent: 'done.invoke.downloadIssuers';
    sendSuccessEndEvent: 'done.invoke.notificationMachine.verifyingCredential:invocation[0]';
    setCredentialTypeListDownloadFailureError: 'error.platform.notificationMachine.downloadCredentialTypes:invocation[0]';
    setCredentialWrapper: 'done.invoke.notificationMachine.downloadCredentials:invocation[0]';
    setError:
      | 'error.platform.notificationMachine.downloadCredentials:invocation[0]'
      | 'error.platform.notificationMachine.performAuthorization.getKeyPairFromKeystore:invocation[0]'
      | 'error.platform.notificationMachine.performAuthorization.setSelectedKey:invocation[0]'
      | 'error.platform.notificationMachine.performAuthorization:invocation[0]';
    setFetchWellknownError: 'error.platform.notificationMachine.downloadIssuerWellknown:invocation[0]';
    setIsVerified: 'done.invoke.notificationMachine.verifyingCredential:invocation[0]';
    setIssuers: 'done.invoke.downloadIssuers';
    setLoadingReasonAsDisplayIssuers: 'TRY_AGAIN';
    setLoadingReasonAsDownloadingCredentials:
      | 'TRY_AGAIN'
      | 'done.invoke.notificationMachine.generateKeyPair:invocation[0]'
      | 'done.invoke.notificationMachine.performAuthorization.getKeyPairFromKeystore:invocation[0]'
      | 'error.platform.notificationMachine.performAuthorization.getKeyPairFromKeystore:invocation[0]';
    setLoadingReasonAsSettingUp:
      | 'TRY_AGAIN'
      | 'done.invoke.notificationMachine.performAuthorization:invocation[0]'
      | 'xstate.after(10)#notificationMachine.selectingIssuer';
    setMetadataInCredentialData:
      | 'done.invoke.notificationMachine.verifyingCredential:invocation[0]'
      | 'error.platform.notificationMachine.verifyingCredential:invocation[0]';
    setNoInternet: 'done.invoke.checkInternet';
    setOIDCConfigError: 'error.platform.notificationMachine.performAuthorization:invocation[0]';
    setPrivateKey: 'done.invoke.notificationMachine.generateKeyPair:invocation[0]';
    setPublicKey: 'done.invoke.notificationMachine.generateKeyPair:invocation[0]';
    setSelectedCredentialType: '';
    setSelectedIssuerId: 'xstate.after(10)#notificationMachine.selectingIssuer';
    setSelectedIssuers: 'xstate.after(10)#notificationMachine.selectingIssuer';
    setSelectedKey: 'done.invoke.notificationMachine.performAuthorization.setSelectedKey:invocation[0]';
    setSupportedCredentialTypes: 'done.invoke.notificationMachine.downloadCredentialTypes:invocation[0]';
    setTokenResponse: 'done.invoke.notificationMachine.performAuthorization:invocation[0]';
    setVCMetadata:
      | 'done.invoke.notificationMachine.verifyingCredential:invocation[0]'
      | 'error.platform.notificationMachine.verifyingCredential:invocation[0]';
    setVerifiableCredential: 'done.invoke.notificationMachine.downloadCredentials:invocation[0]';
    setWalletFailure: 'error.platform.downloadIssuers';
    storeKeyPair: 'done.invoke.notificationMachine.generateKeyPair:invocation[0]';
    storeVcMetaContext:
      | 'done.invoke.notificationMachine.verifyingCredential:invocation[0]'
      | 'error.platform.notificationMachine.verifyingCredential:invocation[0]';
    storeVcsContext:
      | 'done.invoke.notificationMachine.verifyingCredential:invocation[0]'
      | 'error.platform.notificationMachine.verifyingCredential:invocation[0]';
    storeVerifiableCredentialData:
      | 'done.invoke.notificationMachine.verifyingCredential:invocation[0]'
      | 'error.platform.notificationMachine.verifyingCredential:invocation[0]';
    storeVerifiableCredentialMeta:
      | 'done.invoke.notificationMachine.verifyingCredential:invocation[0]'
      | 'error.platform.notificationMachine.verifyingCredential:invocation[0]';
    updateIssuerFromWellknown: 'done.invoke.notificationMachine.downloadIssuerWellknown:invocation[0]';
    updateSelectedIssuerWellknownResponse: 'done.invoke.notificationMachine.downloadIssuerWellknown:invocation[0]';
    updateVerificationErrorMessage: 'error.platform.notificationMachine.verifyingCredential:invocation[0]';
  };
  eventsCausingDelays: {};
  eventsCausingGuards: {
    canSelectIssuerAgain: 'TRY_AGAIN';
    hasKeyPair: 'done.invoke.notificationMachine.checkKeyPair:invocation[0]';
    hasUserCancelledBiometric:
      | 'error.platform.notificationMachine.downloadCredentials:invocation[0]'
      | 'error.platform.notificationMachine.performAuthorization.getKeyPairFromKeystore:invocation[0]';
    isCustomSecureKeystore: 'done.invoke.notificationMachine.generateKeyPair:invocation[0]';
    isGenericError: 'error.platform.notificationMachine.downloadCredentials:invocation[0]';
    isInternetConnected: 'done.invoke.checkInternet';
    isKeyTypeNotFound: 'error.platform.notificationMachine.performAuthorization.getKeyPairFromKeystore:invocation[0]';
    isOIDCConfigError: 'error.platform.notificationMachine.performAuthorization:invocation[0]';
    isOIDCflowCancelled: 'error.platform.notificationMachine.performAuthorization:invocation[0]';
    isSignedIn: 'done.invoke.notificationMachine.storing:invocation[0]';
    isVerificationPendingBecauseOfNetworkIssue: 'error.platform.notificationMachine.verifyingCredential:invocation[0]';
    shouldFetchIssuersAgain: 'TRY_AGAIN';
  };
  eventsCausingServices: {
    checkInternet:
      | ''
      | 'done.invoke.notificationMachine.downloadCredentialTypes:invocation[0]';
    downloadCredential: 'done.invoke.notificationMachine.generateKeyPair:invocation[0]';
    downloadCredentialTypes: 'done.invoke.notificationMachine.downloadIssuerWellknown:invocation[0]';
    downloadIssuerWellknown:
      | 'TRY_AGAIN'
      | 'xstate.after(10)#notificationMachine.selectingIssuer';
    downloadIssuersList:
      | 'CANCEL'
      | 'RESET_ERROR'
      | 'error.platform.notificationMachine.checkKeyPair:invocation[0]'
      | 'error.platform.notificationMachine.downloadCredentials:invocation[0]'
      | 'error.platform.notificationMachine.performAuthorization.getKeyPairFromKeystore:invocation[0]'
      | 'error.platform.notificationMachine.performAuthorization.setSelectedKey:invocation[0]'
      | 'error.platform.notificationMachine.performAuthorization:invocation[0]';
    generateKeyPair: 'done.invoke.notificationMachine.checkKeyPair:invocation[0]';
    getKeyOrderList: 'done.invoke.notificationMachine.performAuthorization:invocation[0]';
    getKeyPair:
      | 'TRY_AGAIN'
      | 'done.invoke.notificationMachine.performAuthorization.setSelectedKey:invocation[0]';
    getSelectedKey:
      | 'done.invoke.notificationMachine.performAuthorization.getKeyPairFromKeystore:invocation[0]'
      | 'error.platform.notificationMachine.performAuthorization.getKeyPairFromKeystore:invocation[0]';
    invokeAuthorization: '' | 'done.invoke.checkInternet';
    isUserSignedAlready:
      | 'done.invoke.notificationMachine.verifyingCredential:invocation[0]'
      | 'error.platform.notificationMachine.verifyingCredential:invocation[0]';
    verifyCredential: 'done.invoke.notificationMachine.downloadCredentials:invocation[0]';
  };
  matchesStates:
    | 'checkInternet'
    | 'checkKeyPair'
    | 'completed'
    | 'downloadCredentialTypes'
    | 'downloadCredentials'
    | 'downloadCredentials.idle'
    | 'downloadCredentials.userCancelledBiometric'
    | 'downloadIssuerWellknown'
    | 'downloadingIssuers'
    | 'error'
    | 'generateKeyPair'
    | 'handleVCVerificationFailure'
    | 'idle'
    | 'performAuthorization'
    | 'performAuthorization.getKeyPairFromKeystore'
    | 'performAuthorization.idle'
    | 'performAuthorization.setSelectedKey'
    | 'performAuthorization.userCancelledBiometric'
    | 'redirecting'
    | 'selectingCredentialType'
    | 'selectingIssuer'
    | 'storing'
    | 'verifyingCredential'
    | {
        downloadCredentials?: 'idle' | 'userCancelledBiometric';
        performAuthorization?:
          | 'getKeyPairFromKeystore'
          | 'idle'
          | 'setSelectedKey'
          | 'userCancelledBiometric';
      };
  tags: never;
}
