import React, {useTransition} from 'react';
import {Pressable,View} from 'react-native';
import {ListItem, Icon} from 'react-native-elements';
import {Row} from '../../components/ui';
import testIDProps from '../../shared/commonUtil';
import {Theme} from '../../components/ui/styleUtils';
import {Text} from '../../components/ui';
import {NavigationProp, useNavigation} from '@react-navigation/native';
import {
  SETTINGS_ROUTES,
  SettingsStackParamList,
} from '../../routes/routesConstants';
import {useTranslation} from 'react-i18next';

type SettingsNavigation = NavigationProp<SettingsStackParamList>;

export const SettingsEmailManagementScreen: React.FC<
  SettingsEmailManagementScreenProps
> = props => {
  const navigation = useNavigation<SettingsNavigation>();
  const {t} = useTranslation('SetupKey');
  return (
    <React.Fragment>
      <Pressable
        accessible={false}
        {...testIDProps('keyManagement')}
        onPress={() => {
          props.controller.SET_KEY_MANAGEMENT_EXPLORED();
          navigation.navigate(SETTINGS_ROUTES.EmailManagement, {
            controller: props.controller,
          });
        }}>
      <ListItem topDivider bottomDivider>
  <View style={{ flexDirection: 'row', alignItems: 'center', flex: 1 }}>
    <Icon
      name="email"
      color={Theme.Colors.Icon}
      style={{ marginRight: 13 }}
    />
    <ListItem.Content>
      <ListItem.Title
        accessible={false}
        {...testIDProps('keyManagementText')}>
        <View style={{ flexDirection: 'row', alignItems: 'center' }}>
          <Text
            testID="keyManagementText"
            weight="semibold"
            color={Theme.Colors.settingsLabel}
            style={[Theme.KeyManagementScreenStyle.textStyle,{ paddingTop:1}]}>
            {t('Email')}
          </Text>
          {!props.controller.isKeyManagementExplored && (
            <Text
              testID="newLabel"
              style={[Theme.Styles.newLabel]}
              color={Theme.Colors.whiteText}>
              {t('NEW')}
            </Text>
          )}
        </View>
      </ListItem.Title>
    </ListItem.Content>
  </View>

  <Icon
    name="chevron-right"
    size={21}
    {...testIDProps('keyManagementChevronRight')}
    color={Theme.Colors.chevronRightColor}
    style={Theme.KeyManagementScreenStyle.iconStyle}
  />
</ListItem>
      </Pressable>
    </React.Fragment>
  );
};

export interface SettingsEmailManagementScreenProps {
  controller: any;
}
