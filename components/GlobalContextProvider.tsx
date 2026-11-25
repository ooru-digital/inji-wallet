import React, {useEffect} from 'react';
import {useInterpret} from '@xstate/react';
import {appMachine} from '../machines/app';

import {GlobalContext} from '../shared/GlobalContext';
import {logState} from '../shared/commonUtil';

export const GlobalContextProvider: React.FC = props => {
  const appService = useInterpret(appMachine, {devTools: __DEV__});

  useEffect(() => {
    if (__DEV__) {
      return appService.subscribe(logState).unsubscribe;
    }
  }, [appService]);

  return (
    <GlobalContext.Provider value={{appService}}>
      {props.children}
    </GlobalContext.Provider>
  );
};
