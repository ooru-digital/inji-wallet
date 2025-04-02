import React, { useState, useEffect } from 'react';
import {
  FlatList,
  Pressable,
  SafeAreaView,
  View,
  Alert,
  Image,
  StyleSheet,
  ToastAndroid,
  Platform,
  TouchableOpacity
} from 'react-native';
import Clipboard from '@react-native-clipboard/clipboard';
import messaging, { FirebaseMessagingTypes } from '@react-native-firebase/messaging';
import { Modal } from './ui/Modal';
import { Column, Text } from './ui';
import { Theme } from './ui/styleUtils';
import { BannerNotificationContainer } from './BannerNotificationContainer';
import {Button} from './ui';



// Request notification permission
async function requestPermission(): Promise<void> {
  const authStatus = await messaging().requestPermission();
  const enabled =
    authStatus === messaging.AuthorizationStatus.AUTHORIZED ||
    authStatus === messaging.AuthorizationStatus.PROVISIONAL;

  if (enabled) {
    console.log('Notification permission granted.');
  }
}

export const NotificationScreen: React.FC<NotificationScreenProps> = ({
  triggerComponent,
}) => {
  const [showNotificationPage, setShowNotificationPage] = useState(false);
  const [notifications, setNotifications] = useState<any[]>([]);
  const [selectedNotification, setSelectedNotification] = useState<any | null>(
    null,
  );
  const [showDetailsModal, setShowDetailsModal] = useState(false);

  // Listen for foreground notifications
  useEffect(() => {
    requestPermission();

    const unsubscribe = messaging().onMessage(
      async (remoteMessage: FirebaseMessagingTypes.RemoteMessage) => {
        console.log('New FCM Notification:', remoteMessage);

        const newNotification = {
          title: remoteMessage.notification?.title || 'New Notification',
          message:
            remoteMessage.notification?.body || 'You have a new message.',
          credential_id: remoteMessage.data?.credential_id || 'N/A',
          org_code: remoteMessage.data?.org_code || 'N/A',
          org_name: remoteMessage.data?.org_name || 'N/A',
        };

        setNotifications(prevNotifications => [
          newNotification,
          ...prevNotifications,
        ]);

        // Show an alert
        Alert.alert(newNotification.title, newNotification.message);
      },
    );

    return () => unsubscribe();
  }, []);

  // Handle background and quit state notifications
  useEffect(() => {
    messaging()
      .getInitialNotification()
      .then(remoteMessage => {
        if (remoteMessage) {
          console.log(
            'Notification received while app was quit:',
            remoteMessage,
          );

          const newNotification = {
            title: remoteMessage.notification?.title || 'New Notification',
            message:
              remoteMessage.notification?.body || 'You have a new message.',
            credential_id: remoteMessage.data?.credential_id || 'N/A',
            org_code: remoteMessage.data?.org_code || 'N/A',
            org_name: remoteMessage.data?.org_name || 'N/A',
          };

          setNotifications(prevNotifications => [
            newNotification,
            ...prevNotifications,
          ]);
        }
      });

    const unsubscribe = messaging().onNotificationOpenedApp(remoteMessage => {
      console.log('Notification opened from background:', remoteMessage);

      const newNotification = {
        title: remoteMessage.notification?.title || 'New Notification',
        message: remoteMessage.notification?.body || 'You have a new message.',
        credential_id: remoteMessage.data?.credential_id || 'N/A',
        org_code: remoteMessage.data?.org_code || 'N/A',
        org_name: remoteMessage.data?.org_name || 'N/A',
      };

      setNotifications(prevNotifications => [
        newNotification,
        ...prevNotifications,
      ]);
    });

    return () => unsubscribe();
  }, []);

  const handleNotificationPress = (notification: any) => {
    setSelectedNotification(notification);
    setShowDetailsModal(true);
  };

  const copyToClipboard = (text: string) => {
    Clipboard.setString(text);
    if (Platform.OS === 'android') {
      ToastAndroid.show('Copied to clipboard!', ToastAndroid.SHORT);
    } else {
      Alert.alert('Copied!', 'Credential ID has been copied to clipboard.');
    }
  };

  return (
    <>
      <Pressable onPress={() => setShowNotificationPage(!showNotificationPage)}>
        {triggerComponent}
      </Pressable>
      <Modal
        isVisible={showNotificationPage}
        headerTitle="Notifications"
        onDismiss={() => setShowNotificationPage(false)}>
        <BannerNotificationContainer />
        <SafeAreaView style={{ flex: 1 }}>
          <Column fill padding="10">
            <FlatList
              keyExtractor={(item, index) => 'Notification' + index.toString()}
              renderItem={({ item }) => (
                <View style={styles.notificationItem}>
                  <Pressable onPress={() => handleNotificationPress(item)}>
                    <Text style={Theme.TextStyles.helpHeader}>
                      {item.title}
                    </Text>
                    <Text style={Theme.TextStyles.helpDetails}>
                      {item.message}
                    </Text>
                  </Pressable>
                </View>
              )}
              data={notifications}
            />
          </Column>
        </SafeAreaView>
      </Modal>

      <Modal
        isVisible={showDetailsModal}
        headerTitle="Certificate Details"
        onDismiss={() => setShowDetailsModal(false)}>
        <SafeAreaView style={{ padding: 20, alignItems: 'center' }}>
          <View style={styles.card}>
            <Image
              source={require('../assets/certificate.png')}
              style={styles.cardImage}
              resizeMode="contain"
            />
            <View style={styles.cardContent}>
              <View style={styles.copyContainer}>
                <Text style={Theme.TextStyles.helpDetails}>
                  Credential ID: {selectedNotification?.credential_id}
                </Text>
                <TouchableOpacity onPress={() => copyToClipboard(selectedNotification?.credential_id || '')}>
                  <Image
                    source={require('../assets/copy.png')}
                    style={styles.copyIcon}
                  />
                </TouchableOpacity>
              </View>
              <Text style={Theme.TextStyles.helpDetails}>
                Issued by: {selectedNotification?.org_name}
              </Text>
                   
            </View>
            
          </View>
          
        </SafeAreaView>
        <View style={{position: 'absolute', bottom: 20, left: 20, right: 20}}>
                     <Button
                       testID="addToWallet"
                       type="gradient"
                       title={('Add to Wallet')}
                     />
                   </View>
        
      </Modal>
    </>
  );
};

const styles = StyleSheet.create({
  notificationItem: {
    padding: 10,
    borderBottomWidth: 1,
    borderBottomColor: '#ccc',
  },
  card: {
    width: '100%',
    borderRadius: 8,
    backgroundColor: '#fff',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
    overflow: 'hidden',
  },
  cardImage: {
    width: '100%',
    height: 200,
  },
  cardContent: {
    padding: 15,
  },
  copyContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  copyIcon: {
    width: 40,
    height: 40,
    marginLeft: -100,
  },
});

interface NotificationScreenProps {
  triggerComponent: React.ReactElement;
}

export default NotificationScreen;
