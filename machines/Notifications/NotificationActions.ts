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
        console.log('🔹 Previous vcMetadata:>>>>>>>', context.vcMetadata);

        const updatedMetadata = new VCMetadata({
          ...context.vcMetadata,
          isVerified: true,
        });

        console.log(
          '✅ Updated vcMetadata (isVerified set to true):>>>>>>>>>',
          updatedMetadata,
        );

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
      selectedCredentialType: (context: any) => context.selectedCredentialType, // ✅ Use full object from context
      wellknownKeyTypes: (context: any) => {
        console.log(
          '🔹 Extracting well-known key types from:',
          context.selectedCredentialType,
        );
      
        if (!context.selectedCredentialType) {
          console.warn('⚠️ selectedCredentialType is undefined!');
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
        console.log('Event data received:', event);

        const error = event.data.message;
        console.log('Extracted error message:', error);

        if (error.includes(NETWORK_REQUEST_FAILED)) {
          console.log(
            'Network request failed. Returning NO_INTERNET error message.',
          );

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
      console.log('🔑 Storing Key Pair...');
      console.log('📌 Context keyType:', context.keyType);
      console.log('🔐 Public Key:', context.publicKey);
      console.log('🔑 Private Key:', context.privateKey);
      console.log('📱 is iOS:', isIOS());

      const keyType = context.keyType;

      if ((keyType != 'ES256' && keyType != 'RS256') || isIOS()) {
        console.log('✅ Storing key in RNSecureKeystoreModule...');
        await RNSecureKeystoreModule.storeGenericKey(
          context.publicKey,
          context.privateKey,
          keyType,
        );
        console.log('🔒 Key successfully stored!');
      } else {
        console.log('⚠️ Key storage skipped for keyType:', keyType);
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
        console.log('🔹 Fetching VC Metadata with keyType:', context.keyType);

        const metadata = getVCMetadata(context, context.keyType);

        console.log('✅ Retrieved VC Metadata:', metadata);

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
        console.log('📩 Storing VC Metadata...');
        console.log('🔹 Current keyType:', context.keyType);
        
        const vcMetadata = getVCMetadata(context, context.keyType);
        console.log('✅ Retrieved VC Metadata:', vcMetadata);

        return {
          type: 'VC_ADDED',
          vcMetadata,
        };
      },
      {
        to: (context: any) => {
          console.log(
            '🎯 Sending VC_ADDED event to:',
            context.serviceRefs?.vcMeta,
          );
          return context.serviceRefs?.vcMeta;
        },
      },
    ),

    storeVcsContext: send(
      (context: any) => {
        console.log('📩 Sending VC_DOWNLOADED event...');
        console.log('🔹 Current keyType:', context.keyType);
        console.log('🔹 Current credentialWrapper:', context.credentialWrapper);

        const metadata = getVCMetadata(context, context.keyType);
        console.log('✅ Retrieved VC Metadata:', metadata);

        return {
          type: 'VC_DOWNLOADED',
          vcMetadata: metadata,
          vc: context.credentialWrapper,
        };
      },
      {
        to: context => {
          console.log('🎯 Sending event to:>>>>>>', context.serviceRefs);
          console.log('🎯 Sending event to:', context.serviceRefs?.vcMeta);
          return context.serviceRefs?.vcMeta;
        },
      },
    ),

    setSelectedKey: model.assign({
      keyType: (context: any, event: any) => {
        console.log(
          '🚀 Context wellknownKeyTypes:',
          context.wellknownKeyTypes || 'undefined',
        );
        console.log('📩 Event data:', event.data);

        // Ensure wellknownKeyTypes is defined before using it
        if (!context.wellknownKeyTypes) {
          console.log(
            '⚠️ wellknownKeyTypes is undefined! Initializing it now.',
          );
          context.wellknownKeyTypes = []; // ✅ Initialize as an array
        }

        // Ensure wellknownKeyTypes contains "RS256"
        if (!context.wellknownKeyTypes.includes('RS256')) {
          console.log('⚠️ RS256 is missing, adding it now!');
          context.wellknownKeyTypes.push('RS256');
        }

        const keyType = selectCredentialRequestKey(
          context.wellknownKeyTypes,
          event.data,
        );

        console.log('✅ Selected KeyType:', keyType);
        return keyType;
      },
    }),

    setSelectedIssuers: model.assign({
      selectedIssuer: (context: any, event: any) => {
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
      selectedIssuerId: (context: any, event: any) => {
        return context.originalEventData.org_code;
      },
    }),

    setTokenResponse: model.assign({
      tokenResponse: (_: any, event: any) => event.data,
    }),
    setVerifiableCredential: model.assign({
      verifiableCredential: (_: any, event: any) => {
        return event.data.verifiableCredential;
      },
    }),
    setCredentialWrapper: model.assign({
      credentialWrapper: (_: any, event: any) => {
        return event.data;
      },
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
        console.log('📩 Logging VC_DOWNLOADED event...');
        console.log('🔹 Current keyType:', context.keyType);
        console.log('🔹 Selected Issuer ID:', context.selectedIssuerId);
        console.log(
          '🔹 Selected Credential Type:',
          context.selectedCredentialType,
        );

        const vcMetadata = getVCMetadata(context, context.keyType);
        console.log('✅ Retrieved VC Metadata:', vcMetadata);

        const logEntry = VCActivityLog.getLogFromObject({
          _vcKey: vcMetadata.getVcKey(),
          type: 'VC_DOWNLOADED',
          id: vcMetadata.displayId,
          timestamp: Date.now(),
          deviceName: '',
          issuer: context.selectedIssuerId,
          credentialConfigurationId: context.selectedCredentialType?.id,
        });

        console.log('📝 Activity Log Entry Created:', logEntry);

        return ActivityLogEvents.LOG_ACTIVITY(
          logEntry,
          context.selectedIssuerWellknownResponse,
        );
      },
      {
        to: (context: any) => {
          console.log(
            '🎯 Sending log event to:',
            context.serviceRefs?.activityLog,
          );
          return context.serviceRefs?.activityLog;
        },
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
