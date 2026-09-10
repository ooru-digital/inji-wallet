import React, {useEffect, useRef, useState} from 'react';
import {
  ActivityIndicator,
  KeyboardAvoidingView,
  Platform,
  TextInput,
  View,
} from 'react-native';
import {useSelector} from '@xstate/react';
import {useNavigation} from '@react-navigation/native';
import {useTranslation} from 'react-i18next';
import {Button, Column, Row, Text} from '../../components/ui';
import {Theme} from '../../components/ui/styleUtils';
import {useHolderAuthService} from '../../components/HolderAuthProvider';
import {
  selectHolderEmail,
  selectHolderError,
  selectIsEnteringOtp,
  selectIsHolderAuthenticated,
  selectIsHolderBusy,
} from '../../machines/holderAuth';

export const HolderLoginScreen: React.FC = () => {
  const {t} = useTranslation('HolderLogin');
  const navigation = useNavigation();
  const holderAuthService = useHolderAuthService();

  const email = useSelector(holderAuthService, selectHolderEmail);
  const error = useSelector(holderAuthService, selectHolderError);
  const isOtpStep = useSelector(holderAuthService, selectIsEnteringOtp);
  const isBusy = useSelector(holderAuthService, selectIsHolderBusy);
  const isAuthenticated = useSelector(
    holderAuthService,
    selectIsHolderAuthenticated,
  );

  const [emailInput, setEmailInput] = useState(email || '');
  const [otpDigits, setOtpDigits] = useState(['', '', '', '', '', '']);
  const otpRefs = useRef<Array<TextInput | null>>([]);

  useEffect(() => {
    if (isAuthenticated) {
      navigation.reset({
        index: 0,
        routes: [{name: 'Main' as never}],
      });
    }
  }, [isAuthenticated, navigation]);

  useEffect(() => {
    if (email) {
      setEmailInput(email);
    }
  }, [email]);

  const handleOtpChange = (index: number, value: string) => {
    if (!/^\d?$/.test(value)) {
      return;
    }
    const updated = [...otpDigits];
    updated[index] = value;
    setOtpDigits(updated);
    holderAuthService.send({type: 'SET_OTP', otp: updated.join('')});

    if (value && index < 5) {
      otpRefs.current[index + 1]?.focus();
    }
  };

  const onPrimaryPress = () => {
    if (isOtpStep) {
      holderAuthService.send({
        type: 'VERIFY_OTP',
        otp: otpDigits.join(''),
      });
      return;
    }

    holderAuthService.send({
      type: 'SEND_OTP',
      email: emailInput.trim(),
    });
  };

  return (
    <KeyboardAvoidingView
      style={{flex: 1, backgroundColor: Theme.Colors.whiteBackgroundColor}}
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
      <Column fill padding="24" align="flex-start" crossAlign="center">
        <Text
          testID="holderLoginTitle"
          weight="bold"
          style={{
            fontSize: 22,
            marginBottom: 8,
            marginTop: 48,
            textAlign: 'center',
          }}>
          {t('title')}
        </Text>
        <Text
          testID="holderLoginSubtitle"
          color={Theme.Colors.GrayText}
          style={{textAlign: 'center', marginBottom: 28}}>
          {isOtpStep ? t('otpSubtitle', {email}) : t('emailSubtitle')}
        </Text>

        {!isOtpStep ? (
          <TextInput
            testID="holderEmailInput"
            style={{
              width: '100%',
              borderBottomWidth: 1,
              borderColor: '#ccc',
              paddingVertical: 12,
              marginBottom: 16,
              fontSize: 16,
            }}
            placeholder={t('emailPlaceholder')}
            value={emailInput}
            onChangeText={setEmailInput}
            keyboardType="email-address"
            autoCapitalize="none"
            autoCorrect={false}
            editable={!isBusy}
          />
        ) : (
          <Row
            align="space-between"
            style={{width: '100%', marginBottom: 16, paddingHorizontal: 8}}>
            {otpDigits.map((digit, index) => (
              <TextInput
                key={index}
                ref={ref => {
                  otpRefs.current[index] = ref;
                }}
                testID={`holderOtpDigit${index}`}
                style={{
                  borderBottomWidth: 1,
                  borderColor: '#000',
                  width: 40,
                  height: 48,
                  textAlign: 'center',
                  fontSize: 20,
                }}
                value={digit}
                onChangeText={text => handleOtpChange(index, text)}
                maxLength={1}
                keyboardType="number-pad"
                editable={!isBusy}
              />
            ))}
          </Row>
        )}

        {!!error && (
          <Text
            testID="holderLoginError"
            color={Theme.Colors.errorMessage}
            style={{marginBottom: 12, textAlign: 'center'}}>
            {error}
          </Text>
        )}

        {isBusy ? (
          <ActivityIndicator style={{marginVertical: 16}} />
        ) : (
          <View style={{width: '100%'}}>
            <Button
              testID="holderLoginPrimary"
              type="gradient"
              title={isOtpStep ? t('verify') : t('sendOtp')}
              onPress={onPrimaryPress}
              disabled={
                isOtpStep
                  ? otpDigits.join('').length !== 6
                  : !emailInput.trim()
              }
            />
            {isOtpStep && (
              <Row margin="16 0 0 0" align="space-evenly">
                <Button
                  testID="holderLoginBack"
                  type="clear"
                  title={t('changeEmail')}
                  onPress={() => {
                    setOtpDigits(['', '', '', '', '', '']);
                    holderAuthService.send({type: 'BACK_TO_EMAIL'});
                  }}
                />
                <Button
                  testID="holderLoginResend"
                  type="clear"
                  title={t('resendOtp')}
                  onPress={() => {
                    setOtpDigits(['', '', '', '', '', '']);
                    holderAuthService.send({
                      type: 'SEND_OTP',
                      email: emailInput.trim() || email,
                    });
                  }}
                />
              </Row>
            )}
          </View>
        )}
      </Column>
    </KeyboardAvoidingView>
  );
};
