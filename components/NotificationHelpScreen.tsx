import React, {useEffect, useRef, useState} from 'react';
import {useTranslation} from 'react-i18next';
import {FlatList, Linking, Pressable, SafeAreaView, View} from 'react-native';
import {Modal} from './ui/Modal';
import {Column, Text} from './ui';
import {Theme} from './ui/styleUtils';
import {BannerNotificationContainer} from './BannerNotificationContainer';
import getAllConfigurations from '../shared/api';

export const NotificationHelpScreen: React.FC<HelpScreenProps> = props => {
  const {t} = useTranslation('NotificationHelpScreen');
  const [showHelpPage, setShowHelpPage] = useState(false);
  const listingRef = useRef();

  // Firebase Cloud Messaging Documentation URL
  const firebaseHelpUrl = 'https://firebase.google.com/docs/cloud-messaging';

  useEffect(() => {
    if (props.source === 'BackUp') {
      setTimeout(() => {
        if (listingRef?.current != null) {
          listingRef.current.scrollToIndex({
            index: 15,
            animated: true,
          });
        }
      }, 2000);
    }
  }, [showHelpPage]);

  const getTextField = (value: string, component?: React.ReactElement) => {
    return (
      <Text style={Theme.TextStyles.helpDetails}>
        {value} {component}
      </Text>
    );
  };

  const getLinkedText = (link: string, linkText: string) => {
    return (
      <Text
        style={Theme.TextStyles.urlLinkText}
        onPress={() => {
          Linking.openURL(link);
        }}>
        {linkText}
      </Text>
    );
  };

  const NotificationFaqMap = [
    {
      title: t('questions.notification.one'),
      data: (
        <React.Fragment>
          {getTextField(
            t('answers.notification.one'),
            getLinkedText(firebaseHelpUrl, 'here') // Updated link here
          )}
        </React.Fragment>
      ),
    },
  ];

  return (
    <React.Fragment>
      <Pressable
        accessible={false}
        onPress={() => {
          setShowHelpPage(!showHelpPage);
        }}>
        {props.triggerComponent}
      </Pressable>
      <Modal
        testID="notificationhelpScreen"
        isVisible={showHelpPage}
        headerTitle={t('header')}
        headerElevation={2}
        onDismiss={() => {
          setShowHelpPage(!showHelpPage);
        }}>
        <BannerNotificationContainer />
        <SafeAreaView style={{flex: 1}}>
          <Column fill padding="10" align="space-between">
            <FlatList
              ref={listingRef}
              keyExtractor={(item, index) => 'FAQ' + index.toString()}
              renderItem={({item}) => (
                <View>
                  <Text style={Theme.TextStyles.helpHeader}>{item.title}</Text>
                  {item.data}
                </View>
              )}
              data={[...NotificationFaqMap]}
              onScrollToIndexFailed={info => {
                const wait = new Promise(resolve => setTimeout(resolve, 500));
                wait.then(() => {
                  listingRef.current?.scrollToIndex({
                    index: info.index,
                    animated: true,
                  });
                });
              }}
            />
          </Column>
        </SafeAreaView>
      </Modal>
    </React.Fragment>
  );
};

interface HelpScreenProps {
  source: 'Inji' | 'BackUp';
  triggerComponent: React.ReactElement;
}
