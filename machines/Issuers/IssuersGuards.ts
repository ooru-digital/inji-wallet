import {isSignedInResult} from '../../shared/CloudBackupAndRestoreUtils';
import {ErrorMessage, OIDCErrors} from '../../shared/openId4VCI/Utils';
import {BiometricCancellationError} from '../../shared/error/BiometricCancellationError';
import {VerificationErrorType} from '../../shared/vcjs/verifyCredential';
import {AuthorizationType} from '../../shared/constants';

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
  };
};
