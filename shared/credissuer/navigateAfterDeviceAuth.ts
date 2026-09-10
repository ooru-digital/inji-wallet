import {NavigationProp} from '@react-navigation/native';
import {RootStackParamList} from '../../routes';

type Nav = NavigationProp<RootStackParamList>;

/**
 * After device unlock/setup succeeds, send the user to Main if they already
 * have a holder session, otherwise to HolderLogin.
 */
export function navigateAfterDeviceAuth(
  navigation: Nav,
  isHolderAuthenticated: boolean,
) {
  navigation.reset({
    index: 0,
    routes: [{name: isHolderAuthenticated ? 'Main' : 'HolderLogin'}],
  });
}
