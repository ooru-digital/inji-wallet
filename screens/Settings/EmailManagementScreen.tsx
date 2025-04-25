import React, {useState, useEffect, useRef} from 'react';
import {useTranslation} from 'react-i18next';
import {
  TouchableOpacity,
  BackHandler,
  View,
  Modal,
  TextInput,
  Alert,
  ScrollView,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import {ListItem, Icon} from 'react-native-elements';
import {Text, Button} from '../../components/ui';
import {Theme} from '../../components/ui/styleUtils';
import {NotificationHelpScreen} from '../../components/NotificationHelpScreen';
import {BackButton} from '../../components/ui/backButton/BackButton';
import {useNavigation, useRoute, RouteProp} from '@react-navigation/native';
import messaging from '@react-native-firebase/messaging';

export const EmailManagementScreen: React.FC<EmailManagementScreenProps> = () => {
  const {t} = useTranslation('SetupEmail');
  const navigation = useNavigation();
  const route =
    useRoute<RouteProp<{params: EmailManagementScreenProps}, 'params'>>();
  const {controller, isClosed} = route.params;

  const [modalVisible, setModalVisible] = useState(false);
  const [modalStep, setModalStep] = useState<'email' | 'otp'>('email');
  const [email, setEmail] = useState('');
  const [otpDigits, setOtpDigits] = useState(['', '', '', '', '', '']);
  const [registeredEmails, setRegisteredEmails] = useState<string[]>([]);
  const otpRefs = useRef<Array<TextInput | null>>([]);

  useEffect(() => {
    const backAction = () => {
      controller.SET_EMAIL_MANAGEMENT_TOUR_GUIDE_EXPLORED();
      navigation.goBack();
      return true;
    };

    const backHandler = BackHandler.addEventListener(
      'hardwareBackPress',
      backAction,
    );

    return () => backHandler.remove();
  }, []);

  useEffect(() => {
    loadEmails();
  }, []);

  const loadEmails = async () => {
    try {
      const storedEmails = await AsyncStorage.getItem('registeredEmails');
      if (storedEmails) {
        setRegisteredEmails(JSON.parse(storedEmails));
      }
    } catch (error) {
      console.error('Error loading emails:', error);
    }
  };

  const saveEmails = async (emails: string[]) => {
    try {
      await AsyncStorage.setItem('registeredEmails', JSON.stringify(emails));
    } catch (error) {
      console.error('Error saving emails:', error);
    }
  };

  const addEmailToList = async () => {
    if (email.trim()) {
      if (registeredEmails.includes(email)) {
        Alert.alert('This email address is already registered.');
      } else {
        try {
          const response = await fetch(
            'https://app.credissuer.com/api/holders/send-email-otp',
            {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({login_type: 'email_otp', email}),
            },
          );

          const data = await response.json();

          if (response.ok) {
            Alert.alert('OTP Sent', 'We’ve sent a 6-digit code to your email. Please enter it  to continue.');
            setModalStep('otp');
          } else {
            Alert.alert('Error', data.message || 'We couldn’t send the OTP. Please try again.');
          }
        } catch (error) {
          console.error('Error sending OTP:', error);
          Alert.alert('Something Went Wrong', 'We couldn’t reach our servers. Please check your internet connection and try again.');
        }
      }
    } else {
      Alert.alert('Email Required', 'Please enter a valid email address before continuing.');
    }
  };

  const handleOtpChange = (index: number, value: string) => {
    if (/^\d?$/.test(value)) {
      const updatedOtp = [...otpDigits];
      updatedOtp[index] = value;
      setOtpDigits(updatedOtp);

      if (value && index < 5) {
        otpRefs.current[index + 1]?.focus();
      }
    }
  };

  const verifyOtp = async () => {
    const otp = otpDigits.join('');
    if (otp.length === 6) {
      try {
        const response = await fetch(
          'https://app.credissuer.com/api/holders/verify-email-otp',
          {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email, otp}),
          },
        );

        const data = await response.json();

        if (response.ok) {
          Alert.alert('Success', 'Your email has been verified successfully.');
          const fcmToken = await messaging().getToken();
          await storeFCMToken(email, fcmToken);

          setRegisteredEmails(prevEmails => {
            const updatedEmails = [...prevEmails, email];
            saveEmails(updatedEmails);
            return updatedEmails;
          });

          setModalVisible(false);
          setModalStep('email');
          setEmail('');
          setOtpDigits(['', '', '', '', '', '']);
        } else {
          Alert.alert('Incorrect OTP', data.message || 'The code you entered is incorrect. Please try again.');
          setModalStep('email');
          setOtpDigits(['', '', '', '', '', '']);
        }
      } catch (error) {
        console.error('Error verifying OTP:', error);
        Alert.alert('Something Went Wrong', 'Failed to verify OTP. Please check your internet and try again.');
        setModalStep('email');
        setOtpDigits(['', '', '', '', '', '']);
      }
    } else {
      Alert.alert('Invalid Code', 'Please enter a 6-digit OTP to proceed.');
    }
  };

  const storeFCMToken = async (email: string, token: string) => {
    try {
      const response = await fetch(
        'https://app.credissuer.com/api/holders/store-token/fcm/',
        {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({email, token}),
        },
      );

      const data = await response.json();

      if (response.ok) {
        Alert.alert('FCM Registered', 'You’ll now receive notifications to this email.');
      } else {
        Alert.alert('Partial Success', 'Email verified, but we couldn’t register for notifications.');
      }
    } catch (error) {
      console.error('Error storing FCM Token:', error);
      Alert.alert('Error', 'Could not store notification token. Try again later.');
    }
  };

  const removeEmail = (emailToRemove: string) => {
    Alert.alert(
      'Confirm Delete',
      `Are you sure you want to remove ${emailToRemove}?`,
      [
        {
          text: 'No',
          style: 'cancel',
        },
        {
          text: 'Yes',
          onPress: () => {
            setRegisteredEmails(prevEmails => {
              const updatedEmails = prevEmails.filter(email => email !== emailToRemove);
              saveEmails(updatedEmails);
              return updatedEmails;
            });
          },
          style: 'destructive',
        },
      ],
      { cancelable: true },
    );
  };
  return (
    <View style={{flex: 1, backgroundColor: '#ffffff'}}>
      <View style={Theme.KeyManagementScreenStyle.outerViewStyle}>
        <TouchableOpacity onPress={isClosed}>
          <BackButton
            onPress={() => {
              controller.SET_EMAIL_MANAGEMENT_TOUR_GUIDE_EXPLORED();
              navigation.goBack();
            }}
          />
        </TouchableOpacity>
        <Text
          testID="emailManagementHeadingSettingsScreen"
          style={[
            Theme.KeyManagementScreenStyle.heading,
            {textAlign: 'center'},
          ]}>
          {t('Registered Emails')}
        </Text>
        <NotificationHelpScreen
          source={'mailManagement'}
          triggerComponent={
            <Icon
              testID="mailManagementHelpIcon"
              accessible={true}
              name="question"
              type="font-awesome"
              size={21}
              style={Theme.Styles.IconContainer}
              color={Theme.Colors.Icon}
            />
          }
        />
      </View>

      <ScrollView contentContainerStyle={{paddingBottom: 80}}>
        {registeredEmails.map((item, index) => (
          <ListItem key={index} bottomDivider>
            <ListItem.Content>
              <ListItem.Title>{item}</ListItem.Title>
            </ListItem.Content>
            <TouchableOpacity
              onPress={() => removeEmail(item)}
              style={{padding: 5, backgroundColor: '#2A2DA4', borderRadius: 5}}>
              <Text style={{color: 'white', fontSize: 12}}>Remove</Text>
            </TouchableOpacity>
          </ListItem>
        ))}
      </ScrollView>

      <View style={{position: 'absolute', bottom: 20, left: 20, right: 20}}>
        <Button
          testID="saveEmailOrderingPreference"
          type="gradient"
          title={t('Add New Email')}
          onPress={() => setModalVisible(true)}
        />
      </View>

      <Modal
        visible={modalVisible}
        transparent
        animationType="slide"
        onRequestClose={() => setModalVisible(false)}>
        <View
          style={{
            flex: 1,
            justifyContent: 'center',
            alignItems: 'center',
            backgroundColor: 'rgba(0, 0, 0, 0.5)',
          }}>
          <View
            style={{
              width: '80%',
              backgroundColor: 'white',
              padding: 20,
              borderRadius: 10,
              alignItems: 'center',
            }}>
            <View
              style={{
                flexDirection: 'row',
                justifyContent: 'space-between',
                width: '100%',
                alignItems: 'center',
              }}>
              <Text style={{fontSize: 18, fontWeight: 'bold', flex: 1}}>
                {modalStep === 'email' ? t('Enter your Email') : t('Enter OTP')}
              </Text>
              <TouchableOpacity onPress={() => setModalVisible(false)}>
                <Icon name="close" type="material" color="black" size={30} />
              </TouchableOpacity>
            </View>

            {modalStep === 'email' ? (
              <TextInput
                style={{
                  width: '100%',
                  borderBottomWidth: 1,
                  borderColor: '#ccc',
                  padding: 10,
                  marginTop: 15,
                  marginBottom: 20,
                }}
                placeholder={t('Enter your email')}
                value={email}
                onChangeText={setEmail}
                keyboardType="email-address"
              />
            ) : (
              <View
                style={{
                  flexDirection: 'row',
                  justifyContent: 'space-between',
                  width: '100%',
                  marginVertical: 20,
                }}>
                {Array(6)
                  .fill(0)
                  .map((_, index) => (
                    <TextInput
                      key={index}
                      ref={ref => (otpRefs.current[index] = ref)}
                      style={{
                        borderBottomWidth: 1,
                        borderColor: '#000',
                        width: 30,
                        height: 40,
                        textAlign: 'center',
                        fontSize: 20,
                      }}
                      value={otpDigits[index]}
                      onChangeText={text => handleOtpChange(index, text)}
                      maxLength={1}
                      keyboardType="number-pad"
                    />
                  ))}
              </View>
            )}

            <Button
              title={modalStep === 'email' ? t('Send OTP') : t('Verify')}
              testID="sendotp"
              type="gradient"
              onPress={modalStep === 'email' ? addEmailToList : verifyOtp}
            />
          </View>
        </View>
      </Modal>
    </View>
  );
};
