import {EventFrom, send, assign, sendParent, spawn} from 'xstate';
import {NotificationServices} from './NotificationServices';
import {NotificationActions} from './NotificationActions';
import {NotificationEvents} from './NotificationEvents';
import {NotificationModel} from './NotificationModel';
import {NotificationGuards} from './NotificationGuards';
import {storeMachine} from '../store';

const model = NotificationModel;

export const notificationMachine = model.createMachine(
  {
    predictableActionArguments: true,
    preserveActionOrder: true,
    schema: {
      context: model.initialContext,
      events: {} as EventFrom<typeof model>,
    },
    id: 'notificationMachine',
    initial: 'idle',
    tsTypes: {} as import('./NotificationMachine.typegen').Typegen0,
    context: model.initialContext,
    states: {
      idle: {
        entry: assign({
          serviceRefs: context => ({
            ...context.serviceRefs,
            store: spawn(storeMachine, {name: 'store'}),
          }),
        }),
        on: {
          [NotificationEvents.ADD_TO_WALLET]: {
            target: 'downloadingIssuers',
            actions: 'storeOriginalEventData',
          },
        },
      },
      downloadingIssuers: {
        invoke: {
          id: 'downloadIssuers',
          src: 'downloadIssuersList',
          onDone: {
            actions: [
              'sendImpressionEvent',
              'setIssuers',
              'resetLoadingReason',
            ],
            target: 'selectingIssuer',
          },
          onError: {
            target: 'error',
            actions: 'setWalletFailure',
          },
        },
      },
      error: {
        description: 'reaches here when any error happens',
        on: {
          TRY_AGAIN: [
            {
              description: 'not fetched issuers yet',
              cond: 'shouldFetchIssuersAgain',
              actions: ['setLoadingReasonAsDisplayIssuers', 'resetError'],
              target: 'idle',
            },
            {
              description:
                'error is OIDC_CONFIG_ERROR_PREFIX or REQUEST_TIMEDOUT',
              cond: 'canSelectIssuerAgain',
              actions: 'resetError',
              target: 'selectingIssuer',
            },
            {
              description:
                'issuers config is available and downloading credentials is retriable',
              actions: ['setLoadingReasonAsSettingUp', 'resetError'],
              target: 'downloadIssuerWellknown',
            },
          ],
          RESET_ERROR: {
            actions: 'resetError',
            target: 'selectingIssuer',
          },
        },
      },
      selectingIssuer: {
        description:
          'Automatically selects the issuer without user interaction',
        entry: assign(context => {
          return {
            selectedIssuerId: context.originalEventData.org_code, // Set from previous step
          };
        }),
        after: {
          10: {
            // Delay to allow state transition (optional)
            actions: [
              'setSelectedIssuerId',
              'setLoadingReasonAsSettingUp',
              'setSelectedIssuers',
            ],
            target: 'downloadIssuerWellknown',
          },
        },
      },
      downloadIssuerWellknown: {
        description: 'fetches the wellknown of the selected issuer',
        invoke: {
          src: 'downloadIssuerWellknown',
          onDone: {
            actions: [
              'updateIssuerFromWellknown',
              'updateSelectedIssuerWellknownResponse',
            ],
            target: 'downloadCredentialTypes',
          },
          onError: {
            actions: ['setFetchWellknownError', 'resetLoadingReason'],
            target: 'error',
          },
        },
      },
      downloadCredentialTypes: {
        description:
          'downloads the credentials supported from the selected issuer',
        invoke: {
          src: 'downloadCredentialTypes',
          onDone: [
            {
              actions: ['setSupportedCredentialTypes'],

              target: 'selectingCredentialType',
            },
            {
              target: 'checkInternet',
            },
          ],
          onError: {
            actions: [
              'setCredentialTypeListDownloadFailureError',
              'resetLoadingReason',
            ],
            target: 'error',
          },
        },
      },
      selectingCredentialType: {
        description:
          'Automatically selects credential type without UI interaction',
        entry: assign(context => {
          // Find the full credential object
          const selectedCredential = context.supportedCredentialTypes?.find(
            cred => cred.id === context.originalEventData.credType,
          );

          return {
            selectedCredentialType: selectedCredential,
          };
        }),
        always: {
          target: 'checkInternet',
          actions: ['setSelectedCredentialType'],
        },
      },
      checkInternet: {
        description: 'checks internet before opening the web view',
        invoke: {
          src: 'checkInternet',
          id: 'checkInternet',
          onDone: [
            {
              cond: 'isInternetConnected',
              target: 'performAuthorization',
            },
            {
              actions: ['setNoInternet', 'resetLoadingReason'],
              target: 'error',
            },
          ],
          onError: {
            actions: () =>
              console.error('Error Occurred while checking Internet'),
            target: 'error',
          },
        },
      },
      redirecting: {
        entry: 'redirectToWalletScreen',
        always: 'performAuthorization',
      },
      performAuthorization: {
        description:
          'invokes the issuers authorization endpoint and gets the access token',
        invoke: {
          src: 'invokeAuthorization',
          onDone: {
            actions: ['setTokenResponse', 'setLoadingReasonAsSettingUp'],
            target: '.setSelectedKey',
          },
          onError: [
            {
              cond: 'isOIDCflowCancelled',
              actions: [
                'resetSelectedCredentialType',
                'resetError',
                'resetLoadingReason',
              ],
              target: 'downloadingIssuers',
            },
            {
              cond: 'isOIDCConfigError',
              actions: ['setOIDCConfigError'],
              target: 'error',
            },
            {
              actions: [
                'resetSelectedCredentialType',
                () => {
                  console.log('Action: resetSelectedCredentialType triggered.');
                },
                'setError',
                () => {
                  console.log('Action: setError triggered.');
                },
                'resetLoadingReason',
                () => {
                  console.log('Action: resetLoadingReason triggered.');
                },
                'sendDownloadingFailedToVcMeta',
                (_, event) =>
                  console.error(
                    'Error Occurred while invoking Auth - ',
                    event.data,
                  ),
              ],
              target: 'downloadingIssuers',
            },
          ],
        },
        initial: 'idle',
        states: {
          idle: {},
          setSelectedKey: {
            invoke: {
              src: 'getKeyOrderList',
              onDone: {
                actions: 'setSelectedKey',
                target: 'getKeyPairFromKeystore',
              },
              onError: {
                actions: [
                  'resetSelectedCredentialType',
                  'setError',
                  'resetLoadingReason',
                  'sendDownloadingFailedToVcMeta',
                  (_, event) =>
                    console.error(
                      'Error Occurred while invoking Auth - ',
                      event.data,
                    ),
                ],
                target: '#notificationMachine.downloadingIssuers',
              },
            },
          },
          getKeyPairFromKeystore: {
            invoke: {
              src: 'getKeyPair',
              onDone: {
                actions: ['loadKeyPair'],
                target: '#notificationMachine.checkKeyPair',
              },
              onError: [
                {
                  cond: 'hasUserCancelledBiometric',
                  target: 'userCancelledBiometric',
                },
                {
                  cond: 'isKeyTypeNotFound',
                  actions: [
                    'resetSelectedCredentialType',
                    'setError',
                    'resetLoadingReason',
                    'sendDownloadingFailedToVcMeta',
                    (_, event) =>
                      console.error(
                        'Error Occurred while invoking Auth - ',
                        event.data,
                      ),
                  ],
                  target: '#notificationMachine.downloadingIssuers',
                },
                {
                  target: '#notificationMachine.checkKeyPair',
                },
              ],
            },
          },
          userCancelledBiometric: {
            on: {
              TRY_AGAIN: [
                {
                  target: 'getKeyPairFromKeystore',
                },
              ],
              RESET_ERROR: {
                actions: 'resetLoadingReason',
                target: '#notificationMachine.downloadingIssuers',
              },
            },
          },
        },
      },
      checkKeyPair: {
        description: 'checks whether key pair is generated',
        entry: ['setLoadingReasonAsDownloadingCredentials'],
        invoke: {
          src: 'getSelectedKey',
          onDone: [
            {
              cond: 'hasKeyPair',
              target: 'generateKeyPair',
            },
            {
              target: 'generateKeyPair',
            },
          ],

          onError: [
            {
              target: 'downloadingIssuers',
            },
          ],
        },
      },
      generateKeyPair: {
        description:
          'if keypair is not generated, new one is created and stored',
        invoke: {
          src: 'generateKeyPair',
          onDone: [
            {
              actions: [
                'setPublicKey',
                'setPrivateKey',
                'setLoadingReasonAsDownloadingCredentials',
                'storeKeyPair',
              ],
              cond: 'isCustomSecureKeystore',
              target: 'downloadCredentials',
            },
            {
              actions: [
                // to be decided
                'setPublicKey',
                'setLoadingReasonAsDownloadingCredentials',
                'setPrivateKey',
                'storeKeyPair',
              ],
              target: 'downloadCredentials',
            },
          ],
        },
      },
      downloadCredentials: {
        description: 'credential is downloaded from the selected issuer',
        invoke: {
          src: 'downloadCredential',
          onDone: {
            actions: ['setVerifiableCredential', 'setCredentialWrapper'],
            target: 'verifyingCredential',
          },
          onError: [
            {
              cond: 'hasUserCancelledBiometric',
              target: '.userCancelledBiometric',
            },
            {
              cond: 'isGenericError',
              target: 'downloadingIssuers',
              actions: [
                'resetSelectedCredentialType',
                'setError',
                'resetLoadingReason',
                'sendDownloadingFailedToVcMeta',
              ],
            },
            {
              actions: ['setError', 'resetLoadingReason'],
              target: 'error',
            },
          ],
        },
        on: {
          CANCEL: {
            target: 'downloadingIssuers',
            actions: 'resetSelectedCredentialType',
          },
        },
        initial: 'idle',
        states: {
          idle: {},
          userCancelledBiometric: {
            on: {
              TRY_AGAIN: [
                {
                  actions: ['setLoadingReasonAsDownloadingCredentials'],
                  target: '#notificationMachine.downloadCredentials',
                },
              ],
              RESET_ERROR: {
                actions: 'resetLoadingReason',
                target: '#notificationMachine.downloadingIssuers',
              },
            },
          },
        },
      },
      verifyingCredential: {
        description:
          'once the credential is downloaded, it is verified before saving',
        invoke: {
          src: 'verifyCredential',
          onDone: [
            {
              actions: ['sendSuccessEndEvent', 'setIsVerified'],
              target: 'storing',
            },
          ],
          onError: [
            {
              cond: 'isVerificationPendingBecauseOfNetworkIssue',
              actions: ['resetLoadingReason', 'resetIsVerified'],
              target: 'storing',
            },
            {
              actions: [
                'resetLoadingReason',
                'sendErrorEndEvent',
                'updateVerificationErrorMessage',
              ],
              target: 'handleVCVerificationFailure',
            },
          ],
        },
      },

      handleVCVerificationFailure: {
        on: {
          RESET_VERIFY_ERROR: {
            actions: ['resetVerificationErrorMessage'],
          },
        },
      },

      storing: {
        description: 'all the verified credential is stored.',
        entry: [
          'setVCMetadata',
          'setMetadataInCredentialData',
          'storeVerifiableCredentialMeta',
          'storeVerifiableCredentialData',
          'storeVcsContext',
          'storeVcMetaContext',
          'logDownloaded',
        ],
        invoke: {
          src: 'isUserSignedAlready',
          onDone: {
            cond: 'isSignedIn',
            actions: ['sendBackupEvent'],
          },
        },
      },
      completed: {
        entry: 'redirectToHome',
        type: 'final',
      },
    },
  },
  {
    actions: NotificationActions(model),
    services: NotificationServices(),
    guards: NotificationGuards(),
  },
);

export interface logoType {
  url: string;
  alt_text: string;
}

export interface displayType {
  name: string;
  locale: string;
  language: string;
  logo: logoType;
  background_color: string;
  background_image: string;
  text_color: string;
  title: string;
  description: string;
}

export interface issuerType {
  authorization_servers: [string];
  credential_issuer: string;
  protocol: string;
  client_id: string;
  '.well-known': string;
  redirect_uri: string;
  token_endpoint: string;
  proxy_token_endpoint: string;
  credential_endpoint: string;
  credential_audience: string;
  credential_configurations_supported: object;
  display: [displayType];
  credentialTypes: [CredentialTypes];
}
