import {isSignedInResult} from '../../shared/CloudBackupAndRestoreUtils';
import {ErrorMessage, OIDCErrors} from '../../shared/openId4VCI/Utils';
import {BiometricCancellationError} from '../../shared/error/BiometricCancellationError';
import {VerificationErrorType} from '../../shared/vcjs/verifyCredential';
import {AuthorizationType} from '../../shared/constants';
import {IssuanceFailure} from '../../shared/openId4VCI/issuanceFailure';

export const IssuersGuards = () => {
  return {
    /**
     * True when the wallet already holds a credential of the same specific type. The lookup itself
     * happens in the `setDuplicateCredentials` action, which records every matched card so
     * "replace" can list them for the user to choose from.
     */
    hasCredentialOfSameType: (context: any) =>
      context.duplicateVcMetadatas.length > 0,

    /** Guards the replace confirmation, so "Replace" cannot delete nothing. */
    hasSelectedDuplicates: (context: any) =>
      context.selectedDuplicateVcKeys.length > 0,

    isVerificationPendingBecauseOfNetworkIssue: (_context, event) =>
      (event.data as Error).message == VerificationErrorType.NETWORK_ERROR,
    isSignedIn: (_: any, event: any) =>
      (event.data as isSignedInResult).isSignedIn,
    hasKeyPair: (context: any) => {
      return !!context.publicKey;
    },
    isKeyTypeNotFound: (context: any) => {
      return context.keyType == '';
    },
    isInternetConnected: (_: any, event: any) => !!event.data.isConnected,
    canSelectIssuerAgain: (context: any) => {
      return (
        context.errorMessage.includes(OIDCErrors.OIDC_CONFIG_ERROR_PREFIX) ||
        context.errorMessage.includes(ErrorMessage.REQUEST_TIMEDOUT)
      );
    },
    hasUserCancelledBiometric: (_: any, event: any) =>
      event.data instanceof BiometricCancellationError,
    isCredentialOfferFlow: (context: any) => {
      return context.isCredentialOfferFlow;
    },
    isIssuerIdInTrustedIssuers: (_: any, event: any) => {
      return event.data;
    },
    isPresentationAuthorization: (context: any) => {
      return (
        context.authorizationType === AuthorizationType.OPENID4VP_PRESENTATION
      );
    },
    /** The token request failed over the transaction code, so the holder goes back to the code screen. */
    shouldReenterTxCode: (context: any, event: any) => {
      switch (event.data?.failure) {
        case IssuanceFailure.INCORRECT_TX_CODE:
        case IssuanceFailure.TX_CODE_ATTEMPTS_EXHAUSTED:
        case IssuanceFailure.TX_CODE_EXPIRED:
        case IssuanceFailure.TX_CODE_REQUIRED:
          return true;
        case IssuanceFailure.RATE_LIMITED:
          return !!context.tokenRequestObject?.txCode;
        default:
          return false;
      }
    },
    // Only when a code was sent, so the retry without one can't loop.
    isTxCodeNotExpected: (context: any, event: any) =>
      event.data?.failure === IssuanceFailure.TX_CODE_NOT_EXPECTED &&
      !!context.tokenRequestObject?.txCode,
    canSubmitTxCode: (context: any) =>
      context.txCodeError !== IssuanceFailure.TX_CODE_ATTEMPTS_EXHAUSTED,
  };
};
