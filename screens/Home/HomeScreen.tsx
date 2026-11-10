// To bring back the Add to Wallet sheet, uncomment every block marked "Add to Wallet sheet"
// below and add `useState` back to this import.
import React, {useEffect, useRef} from 'react';
import {Column} from '../../components/ui';
import {Theme} from '../../components/ui/styleUtils';
import {HomeRouteProps} from '../../routes/routeTypes';
import {MyVcsTab} from './MyVcsTab';
import {ViewVcModal} from './ViewVcModal';
import {useHomeScreen} from './HomeScreenController';
import {TabRef} from './HomeScreenMachine';
import {ActorRefFrom} from 'xstate';
import {ErrorMessageOverlay} from '../../components/MessageOverlay';
import {Linking} from 'react-native';
import {BannerNotificationContainer} from '../../components/BannerNotificationContainer';
import {VCItemMachine} from '../../machines/VerifiableCredential/VCItemMachine/VCItemMachine';
import {VerifiableCredential} from '../../machines/VerifiableCredential/VCMetaMachine/vc';
import {IssuerScreenTabEvents} from '../../machines/Issuers/IssuersMachine';
import type {IssuersScreenParams} from '../Issuers/IssuersScreen';
import {BOTTOM_TAB_ROUTES} from '../../routes/routesConstants';
import {CREDENTIAL_OFFER_SCHEME} from '../../shared/openId4VCI/credentialOffer';
// Add to Wallet sheet:
// import {AddToWalletSheet} from '../../components/addCredential/AddToWalletSheet';

// getInitialURL keeps returning the launch link for the life of the process, and HomeScreen
// remounts after a logout, so the launch link must only be handled once.
let isInitialUrlHandled = false;

export const HomeScreen: React.FC<HomeRouteProps> = props => {
  const controller = useHomeScreen(props);
  const pendingCredentialOffer = useRef('');

  // Add to Wallet sheet:
  // const [isAddToWalletVisible, setIsAddToWalletVisible] = useState(false);
  // const shouldScanAfterSheetCloses = useRef(false);
  //
  // const startScanToAdd = () => {
  //   shouldScanAfterSheetCloses.current = true;
  //   setIsAddToWalletVisible(false);
  // };
  //
  // const onAddToWalletClosed = () => {
  //   if (shouldScanAfterSheetCloses.current) {
  //     shouldScanAfterSheetCloses.current = false;
  //     controller.GOTO_ISSUERS();
  //   }
  // };

  const startCredentialOfferDownload = (url: string) => {
    pendingCredentialOffer.current = url;
    controller.GOTO_ISSUERS();
  };

  useEffect(() => {
    const onLink = (url: string | null) => {
      if (url?.startsWith(CREDENTIAL_OFFER_SCHEME)) {
        startCredentialOfferDownload(url);
      }
    };

    if (!isInitialUrlHandled) {
      isInitialUrlHandled = true;
      Linking.getInitialURL().then(onLink);
    }
    const subscription = Linking.addEventListener('url', ({url}) =>
      onLink(url),
    );
    return () => subscription.remove();
  }, []);

  const scannedCredentialOffer = props.route.params?.credentialOfferUrl;
  useEffect(() => {
    if (!scannedCredentialOffer) return;
    props.navigation.setParams({credentialOfferUrl: undefined});
    startCredentialOfferDownload(scannedCredentialOffer);
  }, [scannedCredentialOffer]);

  useEffect(() => {
    if (controller.IssuersService) {
      const credentialOfferUrl = pendingCredentialOffer.current || undefined;
      if (credentialOfferUrl) {
        controller.IssuersService.send(
          IssuerScreenTabEvents.SCAN_CREDENTIAL_OFFER_QR_CODE(),
        );
        controller.IssuersService.send(
          IssuerScreenTabEvents.QR_CODE_SCANNED(credentialOfferUrl),
        );
        pendingCredentialOffer.current = '';
      }
      navigateToIssuers(credentialOfferUrl);
    }
  }, [controller.IssuersService]);

  useEffect(() => {
    if (controller.isMinimumStorageLimitReached) {
      pendingCredentialOffer.current = '';
    }
  }, [controller.isMinimumStorageLimitReached]);

  const navigateToIssuers = (credentialOfferUrl?: string) => {
    const params: IssuersScreenParams = {
      service: controller.IssuersService,
      credentialOfferUrl,
    };
    props.navigation.navigate('IssuersScreen', params);
  };

  return (
    <React.Fragment>
      <BannerNotificationContainer />
      <Column fill backgroundColor={Theme.Colors.lightGreyBackgroundColor}>
        {controller.haveTabsLoaded && (
          <Column fill>
            <MyVcsTab
              isVisible={controller.activeTab === 0}
              // Add to Wallet sheet: use this instead of the line below.
              // onAddCredential={() => setIsAddToWalletVisible(true)}
              onAddCredential={() =>
                props.navigation.navigate(BOTTOM_TAB_ROUTES.share)
              }
              service={controller.tabRefs.myVcs}
              vcItemActor={controller.selectedVc}
              isViewingVc={controller.isViewingVc}
              openVcKey={props.route.params?.openVcKey}
              onVcOpened={() =>
                props.navigation.setParams({openVcKey: undefined})
              }
              highlightVcKey={props.route.params?.highlightVcKey}
              onHighlightTaken={() =>
                props.navigation.setParams({highlightVcKey: undefined})
              }
            />
          </Column>
        )}
      </Column>

      {/* Add to Wallet sheet:
      <AddToWalletSheet
        isVisible={isAddToWalletVisible}
        onScanToAdd={startScanToAdd}
        onCancel={() => setIsAddToWalletVisible(false)}
        onClosed={onAddToWalletClosed}
      /> */}

      <ErrorMessageOverlay
        translationPath={'MyVcsTab'}
        isVisible={controller.isMinimumStorageLimitReached}
        error={'errors.storageLimitReached'}
        onDismiss={controller.DISMISS}
      />
      {controller.selectedVc && (
        <ViewVcModal
          isVisible={controller.isViewingVc}
          onDismiss={controller.DISMISS_MODAL}
          vcItemActor={controller.selectedVc}
          activeTab={controller.activeTab}
          flow="downloadedVc"
        />
      )}
    </React.Fragment>
  );
};

export interface HomeScreenTabProps {
  isViewingVc: any;
  isVisible: boolean;
  service: TabRef;
  vcItemActor: ActorRefFrom<typeof VCItemMachine>;
  vc: VerifiableCredential | Credential;
  onAddCredential?: () => void;
  /** Opens this credential's detail view as soon as its card has loaded. */
  openVcKey?: string;
  onVcOpened?: () => void;
  /** A just-downloaded credential, marked as new on the wallet home. */
  highlightVcKey?: string;
  /** Called once the home has taken it up, so it isn't applied again. */
  onHighlightTaken?: () => void;
}
