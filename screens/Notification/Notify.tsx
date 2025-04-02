import React from 'react';
import {View, Text, StyleSheet} from 'react-native';
import {useTranslation} from 'react-i18next';
import {useNavigation} from '@react-navigation/native';
import {Header} from '../../components/ui/Header';

const Notify: React.FC = () => {
  const {t} = useTranslation('NotifyScreen');
  const navigation = useNavigation();

  return (
    <View style={styles.container}>
      <Header
        goBack={navigation.goBack}
        title={t('notifyTitle')}
        testID="notifyScreenHeader"
      />
      <Text style={styles.text}>{t('notifyMessage')}</Text>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    padding: 20,
    backgroundColor: '#fff',
  },
  text: {
    fontSize: 16,
    color: '#333',
    textAlign: 'center',
  },
});

export default Notify;
