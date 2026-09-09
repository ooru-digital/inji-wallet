import {useContext, useEffect} from 'react';
import {useNavigation} from '@react-navigation/native';
import {useSelector} from '@xstate/react';
import {GlobalContext} from '../../shared/GlobalContext';
import {Theme} from '../../components/ui/styleUtils';
import {VCShareFlowType} from '../../shared/Utils';
import {SCAN_ROUTES} from '../../routes/routesConstants';
import {
  selectFlowType,
  selectIsScanning,
  selectOpenID4VPFlowType,
} from '../../machines/bleShare/scan/scanSelectors';
import {selectIsAccepted, selectIsReviewing} from '../../machines/bleShare/commonSelectors';

// Same signature ScanLayoutController.ts's own copy of this function uses — Theme.BottomTabBarStyle
// itself declares tabBarStyle.display as literally "flex" only, so neither a wider `string` nor a
// narrower "flex" | "none" param type actually satisfies it; that's a pre-existing gap in the
// Theme type, not something to paper over here.
const changeTabBarVisible = (visible: string) => {
  Theme.BottomTabBarStyle.tabBarStyle.display = visible;
};

/**
 * Pushes ScanStack.Navigator to the screen (ScanScreen / SendVcScreen / SendVPScreen) that
 * matches the scan machine's current state.
 *
 * This has to be called from a component that is itself inside <ScanStack.Navigator> — it used
 * to live in ScanLayoutController.ts's single big effect, called from ScanLayout.tsx, which sits
 * *above* <ScanStack.Navigator> in the tree (ScanLayout renders that navigator, but reads its own
 * useNavigation() before doing so). That put useNavigation() there in the tab navigator's scope,
 * not the nested stack's, so a plain navigate('SendVPScreen') had to be resolved by drilling down
 * into ScanStack's *own* registered routes from outside it — and that resolution reads whichever
 * routes ScanStack's internal useNavigationBuilder has already committed into the shared
 * navigation-state tree, a commit that (per @react-navigation/core's own useScheduleUpdate) is
 * separately scheduled from this effect's own firing. No fixed delay reliably outlasts that: the
 * "NAVIGATE ... was not handled by any navigator" warnings survived even a setTimeout defer.
 *
 * Calling useNavigation() from inside ScanScreen (a screen *of* ScanStack) sidesteps the whole
 * problem rather than out-waiting it: the navigation object it returns belongs to ScanStack
 * itself, so navigate() to a sibling screen in the same stack is resolved by that stack's own
 * router directly, off routeNames it recomputes synchronously from its own <Screen> children on
 * every render — no cross-navigator commit to wait on.
 *
 * Only the three ScanStack-internal targets moved here. GOTO_HOME/GOTO_HISTORY in
 * ScanLayoutController.ts navigate to routes the *tab* navigator owns directly, which is exactly
 * the scope useNavigation() already has where it's called — that was never the broken case.
 */
export function useScanStackScreenSwitcher() {
  const {appService} = useContext(GlobalContext);
  const scanService = appService.children.get('scan')!!;
  const navigation = useNavigation();

  const isReviewing = useSelector(scanService, selectIsReviewing);
  const flowType = useSelector(scanService, selectFlowType);
  const isAccepted = useSelector(scanService, selectIsAccepted);
  const openID4VPFlowType = useSelector(scanService, selectOpenID4VPFlowType);
  const isScanning = useSelector(scanService, selectIsScanning);

  useEffect(() => {
    if (
      isReviewing &&
      flowType === VCShareFlowType.SIMPLE_SHARE &&
      !isAccepted
    ) {
      changeTabBarVisible('none');
      navigation.navigate(SCAN_ROUTES.SendVcScreen as never);
    } else if (openID4VPFlowType === VCShareFlowType.OPENID4VP) {
      changeTabBarVisible('none');
      navigation.navigate(SCAN_ROUTES.SendVPScreen as never);
    } else if (isScanning) {
      changeTabBarVisible('flex');
      navigation.navigate(SCAN_ROUTES.ScanScreen as never);
    }
  }, [isReviewing, flowType, isAccepted, openID4VPFlowType, isScanning, navigation]);
}
