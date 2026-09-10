import {createModel} from 'xstate/lib/model';
import {
  CredentialTypes,
  CredentialWrapper,
  IssuerWellknownResponse,
  VerifiableCredential,
} from '../VerifiableCredential/VCMetaMachine/vc';
import {AppServices} from '../../shared/GlobalContext';
import {VCMetadata} from '../../shared/VCMetadata';
import {IssuersEvents} from './IssuersEvents';
import {issuerType} from './IssuersMachine';
import {ActorRefFrom} from 'xstate';
import {openID4VPMachine} from '../openID4VP/openID4VPMachine';
import {AuthorizationType} from '../../shared/constants';

export const IssuersModel = createModel(
  {
    OpenId4VPRef: {} as ActorRefFrom<typeof openID4VPMachine>,
    authorizationType: AuthorizationType.IMPLICIT,
    issuers: [] as issuerType[],
    selectedIssuerId: '' as string,
    qrData: '' as string,
    selectedIssuer: {} as issuerType,
    selectedIssuerWellknownResponse: {} as IssuerWellknownResponse,
    authorizationSuccess: false as boolean,
    tokenResponse: {} as object,
    errorMessage: '' as string,
    loadingReason: 'displayIssuers' as string,
    verifiableCredential: null as VerifiableCredential | null,
    selectedCredentialType: {} as CredentialTypes,
    supportedCredentialTypes: [] as CredentialTypes[],
    credentialWrapper: {} as CredentialWrapper,
    serviceRefs: {} as AppServices,
    verificationErrorMessage: '',
    publicKey: '',
    privateKey: '',
    vcMetadata: {} as VCMetadata,
    // The credential already in the wallet with the same specific type as the one being
    // downloaded, if any. Held so "replace" knows which card to delete.
    duplicateVcMetadata: null as VCMetadata | null,
    keyType: 'RS256' as string,
    wellknownKeyTypes: [] as string[],
    authEndpointToOpen: false as boolean,
    isTransactionCodeRequested: false as boolean,
    authEndpoint: '' as string,
    accessToken: '' as string,
    txCode: '' as string,
    cNonce: '' as string,
    isConsentRequested: false as boolean,
    issuerLogo: '' as string,
    issuerName: '' as string,
    txCodeInputMode: '' as string,
    txCodeDescription: '' as string,
    txCodeLength: null as number | null,
    isCredentialOfferFlow: false as boolean,
    credentialOfferCredentialIssuer: {} as string,
    tokenRequestObject: {} as object,
    credentialConfigurationId: '' as string,
    trustedIssuerConsentStatus: 'idle' as 'idle' | 'success' | 'loading',
  },
  {
    events: IssuersEvents,
  },
);
