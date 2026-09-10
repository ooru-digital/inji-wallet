import {useSelector} from '@xstate/react';
import {useContext} from 'react';
import {
  selectAuthorized,
  selectLanguagesetup,
  selectUnauthorized,
} from '../machines/auth';
import {selectIsHolderAuthenticated} from '../machines/holderAuth';
import {GlobalContext} from '../shared/GlobalContext';
import {useHolderAuthService} from '../components/HolderAuthProvider';

export function useAppLayout() {
  const {appService} = useContext(GlobalContext);
  const authService = appService.children.get('auth');
  const holderAuthService = useHolderAuthService();
  const isAuthorized = useSelector(authService, selectAuthorized);
  const isHolderAuthenticated = useSelector(
    holderAuthService,
    selectIsHolderAuthenticated,
  );

  return {
    isAuthorized,
    isUnAuthorized: useSelector(authService, selectUnauthorized),
    isLanguagesetup: useSelector(authService, selectLanguagesetup),
    canEnterMain: isAuthorized && isHolderAuthenticated,
  };
}
