import React from 'react';
import {useTranslation} from 'react-i18next';
import {Button, HorizontallyCentered, Column} from '../components/ui';
import {Theme} from '../components/ui/styleUtils';
import {RootRouteProps} from '../routes';
import {useWelcomeScreen} from './WelcomeScreenController';
import {SvgImage} from '../components/ui/svg';
import {useSafeAreaInsets} from 'react-native-safe-area-context';

export const WelcomeScreen: React.FC<RootRouteProps> = props => {
  const {t} = useTranslation('WelcomeScreen');
  const controller = useWelcomeScreen(props);
  const insets = useSafeAreaInsets();
  return (
    <Column
      fill
      padding="32 32 0"
      backgroundColor={Theme.Colors.whiteBackgroundColor}>
      <HorizontallyCentered fill>
        {SvgImage.InjiLogo(Theme.Styles.welcomeLogo)}
      </HorizontallyCentered>
      <Button
        testID="unlockApplication"
        margin={`0 0 ${32 + insets.bottom}`}
        type="gradient"
        title={t('unlockApplication')}
        onPress={controller.unlockPage}
      />
    </Column>
  );
};
