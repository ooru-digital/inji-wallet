import React from 'react';
import {useTranslation} from 'react-i18next';
import {Button, HorizontallyCentered, Column} from '../components/ui';
import {Theme} from '../components/ui/styleUtils';
import {RootRouteProps} from '../routes';
import {useWelcomeScreen} from './WelcomeScreenController';
// Rendered directly (rather than via SvgImage.InjiLogo/Theme.HomeScreenLogo) because that
// theme key now points at the horizontal icon+wordmark lockup used in the Home header, while
// this unlock screen keeps the icon-only mark.
import InjiHomeLogo from '../assets/InjiHomeLogo.svg';

export const WelcomeScreen: React.FC<RootRouteProps> = props => {
  const {t} = useTranslation('WelcomeScreen');
  const controller = useWelcomeScreen(props);
  return (
    <Column
      fill
      padding="32 32 0"
      backgroundColor={Theme.Colors.whiteBackgroundColor}>
      <HorizontallyCentered fill>
        <InjiHomeLogo {...Theme.Styles.welcomeLogo} />
      </HorizontallyCentered>
      <Button
        testID="unlockApplication"
        margin="0 0 32"
        type="gradient"
        title={t('unlockApplication')}
        onPress={controller.unlockPage}
      />
    </Column>
  );
};
