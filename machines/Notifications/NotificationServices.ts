import Cloud from '../../shared/CloudBackupAndRestoreUtils';
import {CACHED_API} from '../../shared/api';
import {authorize} from 'react-native-app-auth';
import NetInfo from '@react-native-community/netinfo';
import {
  getImpressionEventData,
  sendImpressionEvent,
} from '../../shared/telemetry/TelemetryUtils';
import {TelemetryConstants} from '../../shared/telemetry/TelemetryConstants';
import {
  fetchKeyPair,
  generateKeyPair,
} from '../../shared/cryptoutil/cryptoUtil';
import {
  constructAuthorizationConfiguration,
  constructIssuerMetaData,
  constructProofJWT,
  hasKeyPair,
  updateCredentialInformation,
  vcDownloadTimeout,
} from '../../shared/openId4VCI/Utils';
import {VciClient} from '../../shared/vciClient/VciClient';
import {isMockVC} from '../../shared/Utils';
import {VCFormat} from '../../shared/VCFormat';
import {
  VerificationErrorMessage,
  VerificationErrorType,
  verifyCredential,
} from '../../shared/vcjs/verifyCredential';
import {NativeModules} from 'react-native';

export const NotificationServices = () => ({
  isUserSignedAlready: () => async () => {
    return await Cloud.isSignedInAlready();
  },

  // Fetch issuers list
  downloadIssuersList: async () => {
    let issuers = await CACHED_API.fetchIssuers();
    return issuers;
  },

  downloadIssuerWellknown: async (context: any) => {
    const wellknownResponse = await CACHED_API.fetchIssuerWellknownConfig(
      context.selectedIssuerId,
    );
    return wellknownResponse;
  },

  downloadCredentialTypes: async (context: any) => {
    const credentialTypes = [];
    for (const key in context.selectedIssuer
      .credential_configurations_supported) {
      credentialTypes.push({
        id: key,
        ...context.selectedIssuer.credential_configurations_supported[key],
      });
    }
    if (credentialTypes.length == 0)
      throw new Error(
        `No credential type found for issuer ${context.selectedIssuer.credential_issuer}`,
      );
    return credentialTypes;
  },

  downloadCredential: async (context: any) => {
    const downloadTimeout = await vcDownloadTimeout();
    const accessToken: string = context.tokenResponse?.accessToken;
    const proofJWT = await constructProofJWT(
      context.publicKey,
      context.privateKey,
      accessToken,
      context.selectedIssuer,
      context.keyType,
    );

    let credential = await VciClient.downloadCredential(
      constructIssuerMetaData(
        context.selectedIssuer,
        context.selectedCredentialType,
        downloadTimeout,
      ),
      proofJWT,
      accessToken,
    );

    console.info(`VC download via ${context.selectedIssuerId} is successful`);
    return await updateCredentialInformation(context, credential);
  },

  // Add to Wallet Service
  addToWalletService: async (context, event) => {
    return {};
  },

  checkInternet: async () => await NetInfo.fetch(),

  invokeAuthorization: async (context: any) => {
    sendImpressionEvent(
      getImpressionEventData(
        TelemetryConstants.FlowType.vcDownload,
        context.selectedIssuer.credential_issuer +
          TelemetryConstants.Screens.webViewPage,
      ),
    );

    let accessToken = await authorize(
      constructAuthorizationConfiguration(
        context.selectedIssuer,
        context.selectedCredentialType.scope,
      ),
    );
    return accessToken;
  },

  getKeyOrderList: async () => {
    const {RNSecureKeystoreModule} = NativeModules;
    const keyOrder = JSON.parse(
      (await RNSecureKeystoreModule.getData('keyPreference'))[1],
    );
    return keyOrder;
  },

  generateKeyPair: async (context: any) => {
    const keypair = await generateKeyPair(context.keyType);
    return keypair;
  },

  getKeyPair: async (context: any) => {
    if (context.keyType === '') {
      throw new Error('key type not found');
    } else if (!!(await hasKeyPair(context.keyType))) {
      return await fetchKeyPair(context.keyType);
    }
  },

  getSelectedKey: async (context: any) => {
    return context.keyType;
  },

  verifyCredential: async (context: any) => {
    //TODO: Remove bypassing verification of mock VCs once mock VCs are verifiable
    if (
      context.selectedCredentialType.format === VCFormat.mso_mdoc ||
      !isMockVC(context.selectedIssuerId)
    ) {
      const verificationResult = await verifyCredential(
        context.verifiableCredential?.credential,
        context.selectedCredentialType.format,
      );
      if (!verificationResult.isVerified) {
        throw new Error(verificationResult.verificationErrorCode);
      }
    } else {
      return {
        isVerified: true,
        verificationMessage: VerificationErrorMessage.NO_ERROR,
        verificationErrorCode: VerificationErrorType.NO_ERROR,
      };
    }
  },
});
