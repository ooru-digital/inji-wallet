import {assign, createMachine, InterpreterFrom, StateFrom} from 'xstate';
import {
  clearHolderSession,
  getHolderEmail,
  setHolderSession,
} from '../shared/credissuer/holderSession';
import {sendEmailOtp, verifyEmailOtp} from '../shared/credissuer/holdersApi';
import {registerFcmTokenForEmail} from '../shared/credissuer/fcmRegistration';

export type HolderAuthContext = {
  email: string;
  otp: string;
  error: string;
};

export const holderAuthMachine = createMachine(
  {
    id: 'holderAuth',
    predictableActionArguments: true,
    context: {
      email: '',
      otp: '',
      error: '',
    } as HolderAuthContext,
    initial: 'checkingSession',
    states: {
      checkingSession: {
        invoke: {
          src: 'loadSession',
          onDone: [
            {
              cond: 'hasEmail',
              target: 'authenticated',
              actions: 'setEmailFromSession',
            },
            {target: 'enteringEmail'},
          ],
          onError: {target: 'enteringEmail'},
        },
      },
      enteringEmail: {
        entry: 'clearOtpAndError',
        on: {
          SEND_OTP: {
            target: 'prepareSendOtp',
            actions: 'setEmailFromEvent',
          },
        },
      },
      prepareSendOtp: {
        always: [
          {cond: 'hasContextEmail', target: 'sendingOtp'},
          {target: 'enteringEmail', actions: 'setMissingEmailError'},
        ],
      },
      sendingOtp: {
        entry: 'clearError',
        invoke: {
          src: 'sendOtp',
          onDone: {target: 'enteringOtp'},
          onError: {
            target: 'enteringEmail',
            actions: 'setErrorFromEvent',
          },
        },
      },
      enteringOtp: {
        on: {
          SET_OTP: {actions: 'setOtp'},
          VERIFY_OTP: {
            target: 'prepareVerifyOtp',
            actions: 'setOtpFromEvent',
          },
          BACK_TO_EMAIL: 'enteringEmail',
          SEND_OTP: {
            target: 'prepareSendOtp',
            actions: 'setEmailFromEvent',
          },
        },
      },
      prepareVerifyOtp: {
        always: [
          {cond: 'hasContextOtp', target: 'verifying'},
          {target: 'enteringOtp', actions: 'setMissingOtpError'},
        ],
      },
      verifying: {
        entry: 'clearError',
        invoke: {
          src: 'verifyAndRegister',
          onDone: {
            target: 'authenticated',
            actions: 'setAuthenticated',
          },
          onError: {
            target: 'enteringOtp',
            actions: 'setErrorFromEvent',
          },
        },
      },
      authenticated: {
        on: {
          LOGOUT: {
            target: 'enteringEmail',
            actions: ['clearSession', 'clearContext'],
          },
        },
      },
    },
  },
  {
    guards: {
      hasEmail: (_context, event: any) => !!(event.data && event.data.email),
      hasContextEmail: (context: HolderAuthContext) => !!context.email.trim(),
      hasContextOtp: (context: HolderAuthContext) =>
        context.otp.trim().length === 6,
    },
    actions: {
      setEmailFromEvent: assign({
        email: (context: HolderAuthContext, event: any) =>
          String(event.email || context.email || '').trim(),
      }) as any,
      setOtp: assign({
        otp: (_context, event: any) => String(event.otp || ''),
      }) as any,
      setOtpFromEvent: assign({
        otp: (context: HolderAuthContext, event: any) =>
          String(event.otp || context.otp || ''),
      }) as any,
      setEmailFromSession: assign({
        email: (_context, event: any) => String(event.data?.email || ''),
        error: () => '',
        otp: () => '',
      }) as any,
      setAuthenticated: assign({
        email: (_context, event: any) => String(event.data?.email || ''),
        otp: () => '',
        error: () => '',
      }) as any,
      clearOtpAndError: assign({
        otp: () => '',
        error: () => '',
      }) as any,
      clearError: assign({
        error: () => '',
      }) as any,
      clearContext: assign({
        email: () => '',
        otp: () => '',
        error: () => '',
      }) as any,
      setMissingEmailError: assign({
        error: () => 'Please enter a valid email address.',
      }) as any,
      setMissingOtpError: assign({
        error: () => 'Please enter a 6-digit OTP.',
      }) as any,
      setErrorFromEvent: assign({
        error: (_context, event: any) =>
          String(
            event.data?.message || event.data || 'Something went wrong',
          ),
      }) as any,
      clearSession: () => {
        clearHolderSession();
      },
    },
    services: {
      loadSession: async () => {
        const email = await getHolderEmail();
        return {email};
      },
      sendOtp: async (context: HolderAuthContext) => {
        const email = context.email.trim();
        if (!email) {
          throw new Error('Please enter a valid email address.');
        }
        const result = await sendEmailOtp(email);
        if (!result.ok) {
          throw new Error(
            result.message || 'Could not send OTP. Please try again.',
          );
        }
        return result;
      },
      verifyAndRegister: async (context: HolderAuthContext) => {
        const email = context.email.trim();
        const otp = context.otp.trim();
        if (otp.length !== 6) {
          throw new Error('Please enter a 6-digit OTP.');
        }
        const result = await verifyEmailOtp(email, otp);
        if (!result.ok) {
          throw new Error(
            result.message || 'Incorrect OTP. Please try again.',
          );
        }
        await setHolderSession(email);
        await registerFcmTokenForEmail(email);
        return {email};
      },
    },
  },
);

export type HolderAuthService = InterpreterFrom<typeof holderAuthMachine>;
export type HolderAuthState = StateFrom<typeof holderAuthMachine>;

export function selectIsHolderAuthenticated(state: HolderAuthState) {
  return state.matches('authenticated');
}

export function selectIsCheckingHolderSession(state: HolderAuthState) {
  return state.matches('checkingSession');
}

export function selectHolderEmail(state: HolderAuthState) {
  return state.context.email;
}

export function selectHolderError(state: HolderAuthState) {
  return state.context.error;
}

export function selectIsEnteringOtp(state: HolderAuthState) {
  return (
    state.matches('enteringOtp') ||
    state.matches('prepareVerifyOtp') ||
    state.matches('verifying')
  );
}

export function selectIsHolderBusy(state: HolderAuthState) {
  return (
    state.matches('sendingOtp') ||
    state.matches('verifying') ||
    state.matches('checkingSession') ||
    state.matches('prepareSendOtp') ||
    state.matches('prepareVerifyOtp')
  );
}
