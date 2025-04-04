import React, {useEffect} from 'react';
import {View, Text, ActivityIndicator, StyleSheet} from 'react-native';
import {useMachine} from '@xstate/react';
import {notificationMachine} from '../machines/Notifications/NotificationMachine';

const WalletStatusScreen = ({route, navigation}) => {
  const [state, send] = useMachine(notificationMachine, {
    context: {navigation},
  });

  useEffect(() => {
    send({type: 'ADD_TO_WALLET', data: route.params?.data});
  }, []);

  return (
    <View style={styles.container}>
      {state.matches('addingToWallet') && (
        <>
          <ActivityIndicator size="large" color="blue" />
          <Text style={styles.message}>Adding to wallet...</Text>
        </>
      )}
      {state.matches('added') && (
        <Text style={styles.successMessage}>✅ Added successfully!</Text>
      )}
      {state.matches('error') && (
        <Text style={styles.errorMessage}>❌ Failed to add to wallet!</Text>
      )}
    </View>
  );
};

const styles = StyleSheet.create({
  container: {flex: 1, justifyContent: 'center', alignItems: 'center'},
  message: {fontSize: 18, marginTop: 10},
  successMessage: {fontSize: 20, color: 'green', fontWeight: 'bold'},
  errorMessage: {fontSize: 20, color: 'red', fontWeight: 'bold'},
});

export default WalletStatusScreen;
