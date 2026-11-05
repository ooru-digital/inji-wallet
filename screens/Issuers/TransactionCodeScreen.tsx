import React, {useEffect, useRef, useState} from 'react';
import {
  ModalProps,
  Pressable,
  ScrollView,
  StyleSheet,
  TextInput,
  View,
} from 'react-native';
import {TFunction} from 'i18next';
import {useTranslation} from 'react-i18next';
import {PinInput} from '../../components/PinInput';
import {
  AlertSheet,
  FieldError,
  Page,
  PageModal,
  PageButton,
  PageHeader,
  PageHeading,
} from '../../components/revamp/Page';
import {WarningIcon} from '../../components/revamp/Icons';
import {ScaledText} from '../../components/revamp/ScaledText';
import {fonts, radii} from '../../components/revamp/tokens';
import {useRevampTheme} from '../../components/revamp/useRevampTheme';
import {IssuanceFailure} from '../../shared/openId4VCI/issuanceFailure';

/** Asks for the code an issuer sends (by email or SMS) before it releases the card. */
export const TransactionCodeModal: React.FC<ExtendedModalProps> = props => {
  const {t} = useTranslation('transactionCodeScreen');
  const cancelT = useTranslation('cancelDownloadModal').t;
  const {c} = useRevampTheme();
  const [transactionCode, setTransactionCode] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const [showCancelConfirm, setShowCancelConfirm] = useState(false);
  const [showCode, setShowCode] = useState(false);
  const [touched, setTouched] = useState(false);
  const isShortNumeric =
    (!props.inputMode || props.inputMode === 'numeric') &&
    !!props.length &&
    props.length <= 6;
  const isLocked = props.failure === IssuanceFailure.TX_CODE_ATTEMPTS_EXHAUSTED;
  const firstResetKey = useRef(props.inputResetKey);

  useEffect(() => {
    if (props.inputResetKey === firstResetKey.current) return;
    setTransactionCode('');
    setErrorMessage('');
    setTouched(false);
  }, [props.inputResetKey]);

  const validateCode = (code: string): string => {
    if (!code.trim()) return t('emptyCodeError');
    if (!/^[a-zA-Z0-9]+$/.test(code)) return t('invalidCharacters');
    return '';
  };

  const verify = (code: string) => {
    if (isLocked || props.verifying) return;
    const error = validateCode(code);
    if (error) {
      setErrorMessage(error);
      return;
    }
    setErrorMessage('');
    props.onVerify?.(code);
  };

  const handleChange = (text: string) => {
    // The PIN boxes report '' again when they're cleared after a rejected code.
    if (text === transactionCode) return;
    if (!touched) setTouched(true);
    setTransactionCode(text);
    setErrorMessage(touched ? validateCode(text) : '');
  };

  return (
    <PageModal
      visible={props.visible ?? false}
      onRequestClose={() => setShowCancelConfirm(true)}>
      <Page
        testID="transactionCode"
        header={
          <PageHeader
            title={t('pageTitle')}
            onClose={() => setShowCancelConfirm(true)}
          />
        }
        footer={
          isLocked ? (
            <PageButton
              testID="closeTransactionCode"
              title={t('close')}
              onPress={() => props.onDismiss?.()}
            />
          ) : (
            <PageButton
              testID="verifyTransactionCode"
              title={t('continue')}
              disabled={transactionCode.length === 0}
              loading={props.verifying}
              onPress={() => verify(transactionCode)}
            />
          )
        }>
        <ScrollView
          keyboardShouldPersistTaps="always"
          contentContainerStyle={styles.content}>
          <PageHeading
            testID="transactionCodeTitle"
            size="medium"
            title={t('title')}
            body={props.description || t('description')}
          />
          {isShortNumeric ? (
            <View
              style={[styles.pins, isLocked && styles.locked]}
              pointerEvents={isLocked ? 'none' : 'auto'}>
              <PinInput
                testID="pinInput"
                length={props.length!}
                autosubmit={false}
                clearKey={props.inputResetKey}
                onChange={handleChange}
                onDone={verify}
              />
            </View>
          ) : (
            <View
              style={[
                styles.field,
                {borderColor: c.lineStrong, backgroundColor: c.card},
                isLocked && styles.locked,
              ]}>
              <TextInput
                testID="transactionCodeInput"
                autoFocus
                editable={!isLocked}
                style={[styles.input, {color: c.ink}]}
                placeholder={t('placeholder')}
                placeholderTextColor={c.inkMuted}
                maxLength={props.length ?? 30}
                secureTextEntry={!showCode}
                value={transactionCode}
                keyboardType={
                  props.inputMode === 'numeric' ? 'numeric' : 'default'
                }
                onChangeText={handleChange}
              />
              <Pressable
                accessibilityRole="button"
                hitSlop={8}
                onPress={() => setShowCode(shown => !shown)}>
                <ScaledText style={[styles.show, {color: c.azureInk}]}>
                  {showCode ? t('hide') : t('show')}
                </ScaledText>
              </Pressable>
            </View>
          )}
          <FieldError
            testID="otpVerificationError"
            message={
              errorMessage ||
              props.error ||
              failureMessage(t, props.failure, props.attemptsRemaining)
            }
          />
        </ScrollView>
      </Page>
      <AlertSheet
        testID="cancelDownload"
        isVisible={showCancelConfirm}
        tone="warn"
        icon={colour => <WarningIcon color={colour} />}
        title={cancelT('heading')}
        message={cancelT('subHeading')}
        primary={{
          testID: 'cancelDownloadModalNoButton',
          title: cancelT('cancel'),
          onPress: () => setShowCancelConfirm(false),
        }}
        secondary={{
          testID: 'cancelDownloadModalYesButton',
          title: cancelT('confirm'),
          destructive: true,
          onPress: () => {
            setShowCancelConfirm(false);
            props.onDismiss?.();
          },
        }}
        onRequestClose={() => setShowCancelConfirm(false)}
      />
    </PageModal>
  );
};

function failureMessage(
  t: TFunction,
  failure: ExtendedModalProps['failure'],
  attemptsRemaining: ExtendedModalProps['attemptsRemaining'],
): string {
  switch (failure) {
    case IssuanceFailure.INCORRECT_TX_CODE:
      return attemptsRemaining != null
        ? t('incorrectCodeAttemptsLeft', {count: attemptsRemaining})
        : t('incorrectCode');
    case IssuanceFailure.TX_CODE_ATTEMPTS_EXHAUSTED:
      return t('attemptsExhausted');
    case IssuanceFailure.TX_CODE_EXPIRED:
      return t('codeExpired');
    case IssuanceFailure.RATE_LIMITED:
      return t('tooManyAttempts');
    default:
      return '';
  }
}

interface ExtendedModalProps extends ModalProps {
  onVerify?: (transactionCode: string) => void;
  error?: string;
  description?: string;
  inputMode?: 'text' | 'numeric';
  length?: number;
  /** Why the issuer turned down the last code, if it did. */
  failure?: IssuanceFailure | '';
  attemptsRemaining?: number | null;
  /** Changing it empties the input. */
  inputResetKey?: number;
  /** The code has been sent and the issuer hasn't answered yet. */
  verifying?: boolean;
}

const styles = StyleSheet.create({
  content: {paddingTop: 16, paddingBottom: 24, gap: 24},
  pins: {alignItems: 'center', marginTop: 8},
  field: {
    height: 56,
    borderRadius: radii.card,
    borderWidth: 1,
    paddingHorizontal: 16,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  input: {flex: 1, fontFamily: fonts.regular, fontSize: 17},
  show: {fontFamily: fonts.semibold, fontSize: 14},
  locked: {opacity: 0.5},
});
