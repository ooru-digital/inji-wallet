import {useSelector} from '@xstate/react';
import {useContext} from 'react';
import {
  selectAuthorized,
  selectIntroSlider,
  selectLanguagesetup,
  selectSettingUp,
  selectUnauthorized,
} from '../machines/auth';
import {GlobalContext} from '../shared/GlobalContext';

export function useAppLayout() {
  const {appService} = useContext(GlobalContext);
  const authService = appService.children.get('auth');

  return {
    isAuthorized: useSelector(authService, selectAuthorized),
    isUnAuthorized: useSelector(authService, selectUnauthorized),
    isSettingUp: useSelector(authService, selectSettingUp),
    isLanguagesetup: useSelector(authService, selectLanguagesetup),
    isIntroSlider: useSelector(authService, selectIntroSlider),
  };
}
