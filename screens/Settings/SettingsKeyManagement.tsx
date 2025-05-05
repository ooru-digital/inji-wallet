import React, {useTransition} from 'react';
import {Pressable} from 'react-native';
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

export const SettingsKeyManagementScreen: React.FC<
  SettingsKeyManagementScreenProps
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
          navigation.navigate(SETTINGS_ROUTES.KeyManagement, {
            controller: props.controller,
          });
        }}>
       <ListItem topDivider bottomDivider containerStyle={{ paddingVertical: 12 }}>
  <Row style={{ alignItems: 'center', justifyContent: 'space-between', flex: 1 }}>
    <Row style={{ alignItems: 'center', flexShrink: 1 }}>
      <Icon
        name="vpn-key"
        color={Theme.Colors.Icon}
        style={{ marginRight: 13,paddingTop:2 }}
      />
      <Row style={{ alignItems: 'center', flexShrink: 1 }}>
        <Text
          testID="keyManagementText"
          weight="semibold"
          color={Theme.Colors.settingsLabel}
          style={[
            Theme.KeyManagementScreenStyle.textStyle,
            { marginTop: -10, flexShrink: 1 }
          ]}
        >
          {t('header')}
        </Text>
        {!props.controller.isKeyManagementExplored && (
          <Text
            testID="newLabel"
            style={Theme.Styles.newLabel}
            color={Theme.Colors.whiteText}
          >
            {t('NEW')}
          </Text>
        )}
      </Row>
    </Row>

    <Icon
      name="chevron-right"
      size={21}
      {...testIDProps('keyManagementChevronRight')}
      color={Theme.Colors.chevronRightColor}
      style={Theme.KeyManagementScreenStyle.iconStyle}
    />
  </Row>
</ListItem>
      </Pressable>
    </React.Fragment>
  );
};

export interface SettingsKeyManagementScreenProps {
  controller: any;
}
