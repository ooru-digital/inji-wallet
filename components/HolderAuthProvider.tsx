import React, {createContext, useContext, useEffect} from 'react';
import {useInterpret} from '@xstate/react';
import {holderAuthMachine, HolderAuthService} from '../machines/holderAuth';
import {logState} from '../shared/commonUtil';

type HolderAuthContextValue = {
  holderAuthService: HolderAuthService;
};

const HolderAuthContext = createContext<HolderAuthContextValue>(
  {} as HolderAuthContextValue,
);

export const HolderAuthProvider: React.FC<{children: React.ReactNode}> = ({
  children,
}) => {
  const holderAuthService = useInterpret(holderAuthMachine, {
    devTools: __DEV__,
  });

  useEffect(() => {
    if (!__DEV__) {
      return;
    }
    const subscription = holderAuthService.subscribe(logState);
    return () => subscription.unsubscribe();
  }, [holderAuthService]);

  return (
    <HolderAuthContext.Provider value={{holderAuthService}}>
      {children}
    </HolderAuthContext.Provider>
  );
};

export function useHolderAuthService() {
  const ctx = useContext(HolderAuthContext);
  if (!ctx?.holderAuthService) {
    throw new Error(
      'useHolderAuthService must be used within HolderAuthProvider',
    );
  }
  return ctx.holderAuthService;
}
