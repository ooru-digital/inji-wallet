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
  TouchableOpacity,
} from 'react-native';
import Clipboard from '@react-native-clipboard/clipboard';
import messaging, { FirebaseMessagingTypes } from '@react-native-firebase/messaging';
import { useMachine } from '@xstate/react';
import { notificationMachine } from '../machines/Notifications/NotificationMachine';
import { Modal } from './ui/Modal';
import { Column, Text } from './ui';
import { Theme } from './ui/styleUtils';
import { BannerNotificationContainer } from './BannerNotificationContainer';
import { Button } from './ui';
import { CopyButton } from './CopyButton';
import { NotificationEvents } from '../machines/Notifications/NotificationEvents';
import AsyncStorage from '@react-native-async-storage/async-storage';

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
  const [unreadCount, setUnreadCount] = useState(0);

  const [state, send] = useMachine(notificationMachine);

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

  const handleAddToWallet = () => {
    if (!selectedNotification) {
      console.log('No notification selected. Aborting add to wallet.');
      return;
    }

    console.log('Adding to wallet with the following data:', selectedNotification);
    send({ type: NotificationEvents.ADD_TO_WALLET, data: selectedNotification });

    setShowDetailsModal(false);
    setShowNotificationPage(false);
  };

  // Load stored notifications on app start
  useEffect(() => {
    const loadStoredNotifications = async () => {
      try {
        const stored = await AsyncStorage.getItem('notifications');
        if (stored) {
          setNotifications(JSON.parse(stored));
        }
      } catch (error) {
        console.error('Failed to load notifications from storage:', error);
      }
    };

    requestPermission();
    loadStoredNotifications();

    const unsubscribe = messaging().onMessage(
      async (remoteMessage: FirebaseMessagingTypes.RemoteMessage) => {
        const newNotification = {
          title: remoteMessage.notification?.title || 'New Notification',
          message: remoteMessage.notification?.body || 'You have a new message.',
          credential_id: remoteMessage.data?.credential_id || 'N/A',
          org_code: remoteMessage.data?.org_code || 'N/A',
          org_name: remoteMessage.data?.org_name || 'N/A',
          certificate_url: remoteMessage.data?.certificate_url || 'N/A',
          credType: remoteMessage.data?.certificate_type || 'N/A',
          time: new Date().toLocaleTimeString(),
        };

        setNotifications(prev => {
          const updated = [newNotification, ...prev];
          AsyncStorage.setItem('notifications', JSON.stringify(updated)).catch(console.error);
          return updated;
        });

        setUnreadCount(prev => prev + 1);
        Alert.alert(newNotification.title, newNotification.message);
      },
    );

    // Background message handler
    messaging().setBackgroundMessageHandler(
      async (remoteMessage: FirebaseMessagingTypes.RemoteMessage) => {
        const newNotification = {
          title: remoteMessage.notification?.title || 'New Notification',
          message: remoteMessage.notification?.body || 'You have a new message.',
          credential_id: remoteMessage.data?.credential_id || 'N/A',
          org_code: remoteMessage.data?.org_code || 'N/A',
          org_name: remoteMessage.data?.org_name || 'N/A',
          certificate_url: remoteMessage.data?.certificate_url || 'N/A',
          credType: remoteMessage.data?.certificate_type || 'N/A',
          time: new Date().toLocaleTimeString(),
        };

        setNotifications(prev => {
          const updated = [newNotification, ...prev];
          AsyncStorage.setItem('notifications', JSON.stringify(updated)).catch(console.error);
          return updated;
        });

        setUnreadCount(prev => prev + 1);
        // Optionally, you could trigger a local notification or other actions here.
      },
    );

    return () => unsubscribe();
  }, []);

  return (
    <>
      <Pressable
        onPress={() => {
          setShowNotificationPage(true);
          setUnreadCount(0);
        }}
        style={{ position: 'relative' }}>
        {triggerComponent}
        {unreadCount > 0 && (
          <View style={styles.badge}>
            <Text style={styles.badgeText}>{unreadCount}</Text>
          </View>
        )}
      </Pressable>

      <Modal
        animationType="fade"
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
                    <Text style={Theme.TextStyles.helpHeader}>{item.title}</Text>
                    <Text style={Theme.TextStyles.helpDetails}>{item.message}</Text>
                  </Pressable>
                </View>
              )}
              data={notifications}
            />
          </Column>
        </SafeAreaView>
      </Modal>

      <Modal
        animationType="fade"
        isVisible={showDetailsModal}
        headerTitle="Certificate Details"
        onDismiss={() => setShowDetailsModal(false)}>
        <SafeAreaView style={{ padding: 20, alignItems: 'center' }}>
          <View style={styles.card}>
            <View style={styles.cardImageContainer}>
              <Image
                source={{ uri: selectedNotification?.certificate_url }}
                style={styles.cardImage}
                resizeMode="contain"
              />
            </View>
            <View style={styles.cardContent}>
              <View style={styles.copyContainer}>
                <Text style={Theme.TextStyles.helpDetails}>
                  Credential ID: {selectedNotification?.credential_id}
                </Text>
                <CopyButton content={selectedNotification?.credential_id || ''} />
              </View>
              <Text style={Theme.TextStyles.helpDetails}>
                Issued by: {selectedNotification?.org_name}
              </Text>
            </View>
          </View>
        </SafeAreaView>
        <View style={{ position: 'absolute', bottom: 20, left: 20, right: 20 }}>
          <Button
            testID="addToWallet"
            type="gradient"
            title="Add to Wallet"
            onPress={handleAddToWallet}
            disabled={state.matches('addingToWallet')}
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
  cardImageContainer: {
    width: '100%',
    height: 200,
    backgroundColor: '#f9f9f9',
    justifyContent: 'center',
    alignItems: 'center',
  },
  cardImage: {
    width: '100%',
    height: '100%',
  },
  cardContent: {
    padding: 15,
    backgroundColor: '#f1f1f1',
    borderTopWidth: 1,
    borderTopColor: '#ddd',
  },
  copyContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  badge: {
    position: 'absolute',
    top: -4,
    right: -4,
    backgroundColor: '#2A2DA4',
    borderRadius: 10,
    width: 18,
    height: 18,
    justifyContent: 'center',
    alignItems: 'center',
    zIndex: 999,
  },
  badgeText: {
    color: 'white',
    fontSize: 10,
    fontWeight: 'bold',
  },
});
