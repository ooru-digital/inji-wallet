import {
  ErrorMessage,
  Issuers_Key_Ref,
  selectCredentialRequestKey,
} from '../../shared/openId4VCI/Utils';
import {
  MY_VCS_STORE_KEY,
  NETWORK_REQUEST_FAILED,
  REQUEST_TIMEOUT,
  isIOS,
} from '../../shared/constants';
import {assign, send} from 'xstate';
import {StoreEvents} from '../store';
import {BackupEvents} from '../backupAndRestore/backup';
import {getVCMetadata, VCMetadata} from '../../shared/VCMetadata';
import {isHardwareKeystoreExists} from '../../shared/cryptoutil/cryptoUtil';
import {ActivityLogEvents} from '../activityLog';
import {
  getEndEventData,
  getImpressionEventData,
  sendEndEvent,
  sendImpressionEvent,
} from '../../shared/telemetry/TelemetryUtils';
import {TelemetryConstants} from '../../shared/telemetry/TelemetryConstants';
import {NativeModules} from 'react-native';
import {KeyTypes} from '../../shared/cryptoutil/KeyTypes';
import {VCActivityLog} from '../../components/ActivityLogEvent';

const {RNSecureKeystoreModule} = NativeModules;
export const NotificationActions = (model: any) => {
  return {
    storeOriginalEventData: (context, event) => {
      const { org_code, certificate_type } = event.data;

      context.originalEventData = event.data;
    
    },
    setIsVerified: assign({
      vcMetadata: (context: any) => {
        const updatedMetadata = new VCMetadata({
          ...context.vcMetadata,
          isVerified: true,
        });
        return updatedMetadata;
      },
    }),

    resetIsVerified: assign({
      vcMetadata: (context: any) =>
        new VCMetadata({
          ...context.vcMetadata,
          isVerified: false,
        }),
    }),
    setIssuers: model.assign({
      issuers: (_: any, event: any) => event.data,
    }),
    setNoInternet: model.assign({
      errorMessage: () => ErrorMessage.NO_INTERNET,
    }),
    setLoadingReasonAsDisplayIssuers: model.assign({
      loadingReason: 'displayIssuers',
    }),
    setLoadingReasonAsDownloadingCredentials: model.assign({
      loadingReason: 'downloadingCredentials',
    }),
    setLoadingReasonAsSettingUp: model.assign({
      loadingReason: 'settingUp',
    }),
    resetLoadingReason: model.assign({
      loadingReason: null,
    }),
    setSelectedCredentialType: model.assign({
      selectedCredentialType: (context: any) => context.selectedCredentialType, 
      wellknownKeyTypes: (context: any) => {
        if (!context.selectedCredentialType) {
          console.warn('selectedCredentialType is undefined!');
          return [KeyTypes.RS256]; // Fallback value
        }

        const proofTypesSupported =
          context.selectedCredentialType.proof_types_supported;
        if (proofTypesSupported?.jwt) {
          return proofTypesSupported.jwt
            .proof_signing_alg_values_supported as string[];
        } else {
          return [KeyTypes.RS256];
        }
      },
    }),
    setSupportedCredentialTypes: model.assign({
      supportedCredentialTypes: (_: any, event: any) => {
        return event.data;
      },
    }),
    resetSelectedCredentialType: model.assign({
      selectedCredentialType: {},
    }),
    setFetchWellknownError: model.assign({
      errorMessage: (_: any, event: any) => {
        const error = event.data.message;
        if (error.includes(NETWORK_REQUEST_FAILED)) {
          return ErrorMessage.NO_INTERNET;
        }
        return ErrorMessage.TECHNICAL_DIFFICULTIES;
      },
    }),
    setCredentialTypeListDownloadFailureError: model.assign({
      errorMessage: (_: any, event: any) => {
        const error = event.data.message;
        if (error.includes(NETWORK_REQUEST_FAILED)) {
          return ErrorMessage.NO_INTERNET;
        }
        return ErrorMessage.CREDENTIAL_TYPE_DOWNLOAD_FAILURE;
      },
    }),

    setError: model.assign({
      errorMessage: (_: any, event: any) => {
        console.error('Error occurred ', event.data.message);
        const error = event.data.message;
        if (error.includes(NETWORK_REQUEST_FAILED)) {
          return ErrorMessage.NO_INTERNET;
        }
        if (error.includes(REQUEST_TIMEOUT)) {
          return ErrorMessage.REQUEST_TIMEDOUT;
        }
        return ErrorMessage.GENERIC;
      },
    }),
    setOIDCConfigError: model.assign({
      errorMessage: (_: any, event: any) => event.data.toString(),
    }),
    resetError: model.assign({
      errorMessage: '',
    }),

    loadKeyPair: assign({
      publicKey: (_, event: any) => event.data?.publicKey as string,
      privateKey: (context: any, event: any) =>
        event.data?.privateKey
          ? event.data.privateKey
          : (context.privateKey as string),
    }),
    getKeyPairFromStore: send(StoreEvents.GET(Issuers_Key_Ref), {
      to: (context: any) => context.serviceRefs.store,
    }),
    sendBackupEvent: send(BackupEvents.DATA_BACKUP(true), {
      to: (context: any) => context.serviceRefs?.backup,
    }),
    storeKeyPair: async (context: any) => {
      const keyType = context.keyType;

      if ((keyType != 'ES256' && keyType != 'RS256') || isIOS()) {
        await RNSecureKeystoreModule.storeGenericKey(
          context.publicKey,
          context.privateKey,
          keyType,
        );
      }
    },

    storeVerifiableCredentialMeta: send(
      context =>
        StoreEvents.PREPEND(
          MY_VCS_STORE_KEY,
          getVCMetadata(context, context.keyType),
        ),
      {
        to: (context: any) => context.serviceRefs?.store,
      },
    ),

    setMetadataInCredentialData: (context: any) => {
      context.credentialWrapper = {
        ...context.credentialWrapper,
        vcMetadata: context.vcMetadata,
      };
    },

    setVCMetadata: assign({
      vcMetadata: (context: any) => {
        const metadata = getVCMetadata(context, context.keyType);
        return metadata;
      },
    }),

    storeVerifiableCredentialData: send(
      (context: any) => {
        const vcMetadata = getVCMetadata(context, context.keyType);
        const {
          verifiableCredential: {
            processedCredential,
            ...filteredVerifiableCredential
          },
          ...rest
        } = context.credentialWrapper;
        const storableData = {
          ...rest,
          verifiableCredential: filteredVerifiableCredential,
        };
        return StoreEvents.SET(vcMetadata.getVcKey(), {
          ...storableData,
          vcMetadata: vcMetadata,
        });
      },
      {
        to: (context: any) => context.serviceRefs?.store,
      },
    ),

    storeVcMetaContext: send(
      context => {
        const vcMetadata = getVCMetadata(context, context.keyType);
        return {
          type: 'VC_ADDED',
          vcMetadata,
        };
      },
      {
        to: (context: any) => context.serviceRefs?.vcMeta,
      },
    ),

    storeVcsContext: send(
      (context: any) => {
        const metadata = getVCMetadata(context, context.keyType);
        return {
          type: 'VC_DOWNLOADED',
          vcMetadata: metadata,
          vc: context.credentialWrapper,
        };
      },
      {
        to: context => context.serviceRefs?.vcMeta,
      },
    ),

    setSelectedKey: model.assign({
      keyType: (context: any, event: any) => {
        if (!context.wellknownKeyTypes) {
          context.wellknownKeyTypes = [];
        }
        if (!context.wellknownKeyTypes.includes('RS256')) {
          context.wellknownKeyTypes.push('RS256');
        }

        const keyType = selectCredentialRequestKey(
          context.wellknownKeyTypes,
          event.data,
        );

        return keyType;
      },
    }),

    setSelectedIssuers: model.assign({
      selectedIssuer: (context: any) => {
        const selectedIssuer = context.issuers.find(
          issuer =>
            issuer.credential_issuer === context.originalEventData?.org_code,
        );
        return selectedIssuer;
      },
    }),

    updateIssuerFromWellknown: model.assign({
      selectedIssuer: (context: any, event: any) => ({
        ...context.selectedIssuer,
        credential_audience: event.data.credential_issuer,
        credential_endpoint: event.data.credential_endpoint,
        credential_configurations_supported:
          event.data.credential_configurations_supported,
        authorization_servers: event.data.authorization_servers,
      }),
    }),

    updateSelectedIssuerWellknownResponse: model.assign({
      selectedIssuerWellknownResponse: (_: any, event: any) => event.data,
    }),
    setSelectedIssuerId: model.assign({
      selectedIssuerId: (context: any) => {
        return context.originalEventData.org_code;
      },
    }),

    setTokenResponse: model.assign({
      tokenResponse: (_: any, event: any) => event.data,
    }),

    setVerifiableCredential: model.assign({
      verifiableCredential: (_: any, event: any) => event.data.verifiableCredential,
    }),

    setCredentialWrapper: model.assign({
      credentialWrapper: (_: any, event: any) => event.data,
    }),

    setPublicKey: assign({
      publicKey: (_, event: any) => {
        if (!isHardwareKeystoreExists) {
          return event.data.publicKey as string;
        }
        return event.data.publicKey as string;
      },
    }),

    setPrivateKey: assign({
      privateKey: (_, event: any) => event.data.privateKey as string,
    }),

    logDownloaded: send(
      context => {
        const vcMetadata = getVCMetadata(context, context.keyType);
        const logEntry = VCActivityLog.getLogFromObject({
          _vcKey: vcMetadata.getVcKey(),
          type: 'VC_DOWNLOADED',
          id: vcMetadata.displayId,
          timestamp: Date.now(),
          deviceName: '',
          issuer: context.selectedIssuerId,
          credentialConfigurationId: context.selectedCredentialType?.id,
        });

        return ActivityLogEvents.LOG_ACTIVITY(
          logEntry,
          context.selectedIssuerWellknownResponse,
        );
      },
      {
        to: (context: any) => context.serviceRefs?.activityLog,
      },
    ),

    sendSuccessEndEvent: (context: any) => {
      sendEndEvent(
        getEndEventData(
          TelemetryConstants.FlowType.vcDownload,
          TelemetryConstants.EndEventStatus.success,
          {'VC Key': context.keyType},
        ),
      );
    },

    sendErrorEndEvent: (context: any) => {
      sendEndEvent(
        getEndEventData(
          TelemetryConstants.FlowType.vcDownload,
          TelemetryConstants.EndEventStatus.failure,
          {'VC Key': context.keyType},
        ),
      );
    },
    sendImpressionEvent: () => {
      sendImpressionEvent(
        getImpressionEventData(
          TelemetryConstants.FlowType.vcDownload,
          TelemetryConstants.Screens.issuerList,
        ),
      );
    },

    updateVerificationErrorMessage: assign({
      verificationErrorMessage: (_, event: any) =>
        (event.data as Error).message,
    }),

    resetVerificationErrorMessage: model.assign({
      verificationErrorMessage: () => '',
    }),

    sendDownloadingFailedToVcMeta: send(
      (_: any) => ({
        type: 'VC_DOWNLOADING_FAILED',
      }),
      {
        to: context => context.serviceRefs.vcMeta,
      },
    ),
  };
};
