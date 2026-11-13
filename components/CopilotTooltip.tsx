import React from 'react';
import {Pressable, StyleSheet, Text, View} from 'react-native';
import {useTranslation} from 'react-i18next';
import {UseCopilotTooltip} from './CopilotTooltipController';
import testIDProps from '../shared/commonUtil';
import {ArrowRightIcon} from './revamp/Icons';
import {useRevampTheme} from './revamp/useRevampTheme';
import {fonts, radii, shadows} from './revamp/tokens';
import {COPILOT_FINAL_STEP, COPILOT_PRE_FINAL_STEP} from '../shared/constants';
import {useSettingsScreen} from '../screens/Settings/SettingScreenController';

export const CopilotTooltip = () => {
  const {t} = useTranslation('copilot');
  const {c} = useRevampTheme();
  const controller = UseCopilotTooltip();
  const settingsController = useSettingsScreen();

  controller.copilotEvents.on('stop', () => {
    controller.SET_TOUR_GUIDE(false);
    if (
      controller.CURRENT_STEP <= COPILOT_PRE_FINAL_STEP &&
      controller.isOnboarding
    ) {
      controller.ONBOARDING_DONE();
    }
    if (
      controller.CURRENT_STEP === COPILOT_FINAL_STEP &&
      controller.isInitialDownloading
    ) {
      controller.INITIAL_DOWNLOAD_DONE();
    }
    settingsController.BACK();
  });

  const {showPrevious, isDoneStep, isQuickTip} = controller;

  // The dots follow the same count as the "n of total" label.
  const dotCount = controller.stepTotal;
  const activeDot = controller.stepNumber - 1;

  return (
    <View>
      <View style={styles.topRow}>
        <Text
          {...testIDProps(`${controller.CURRENT_STEP}stepCount`)}
          style={[styles.stepCount, {color: c.azureInk}]}>
          {isQuickTip
            ? t('quickTip')
            : `${t('quickTour')} · ${controller.stepCount}`}
        </Text>
        {!isQuickTip && (
          <View
            style={styles.dots}
            accessibilityElementsHidden
            importantForAccessibility="no-hide-descendants">
            {Array.from({length: dotCount}, (_, index) => (
              <View
                key={index}
                style={[
                  styles.dot,
                  index === activeDot
                    ? [styles.dotActive, {backgroundColor: c.primary}]
                    : {backgroundColor: c.line},
                ]}
              />
            ))}
          </View>
        )}
      </View>

      <Text
        {...testIDProps(controller.titleTestID)}
        style={[styles.title, {color: c.ink}]}
        accessibilityRole="header">
        {controller.currentStepTitle}
      </Text>
      <Text
        {...testIDProps(controller.descriptionTestID)}
        style={[styles.description, {color: c.inkMuted}]}>
        {controller.currentStepDescription}
      </Text>

      <View style={styles.actions}>
        {isQuickTip ? (
          // Keeps "Got it" right-aligned.
          <View />
        ) : showPrevious ? (
          <Pressable
            {...testIDProps('copilot-prev-action')}
            accessibilityRole="button"
            onPress={controller.goToPrev}
            style={({pressed}) => [
              styles.secondaryButton,
              {backgroundColor: c.sand},
              pressed && styles.pressed,
            ]}>
            <Text style={[styles.secondaryButtonLabel, {color: c.primary}]}>
              {t('previous')}
            </Text>
          </Pressable>
        ) : !isDoneStep ? (
          <Pressable
            {...testIDProps('copilot-skip-action')}
            accessibilityRole="button"
            onPress={controller.stop}
            style={({pressed}) => [
              styles.secondaryButton,
              {backgroundColor: c.sand},
              pressed && styles.pressed,
            ]}>
            <Text style={[styles.secondaryButtonLabel, {color: c.primary}]}>
              {t('skipTour')}
            </Text>
          </Pressable>
        ) : (
          <View />
        )}

        <Pressable
          {...testIDProps('copilot-next-action')}
          accessibilityRole="button"
          onPress={isDoneStep ? controller.stop : controller.goToNext}
          style={({pressed}) => [
            styles.primaryButton,
            shadows.raised,
            {backgroundColor: c.primary},
            pressed && styles.pressed,
          ]}>
          <Text style={[styles.primaryButtonLabel, {color: c.onPrimary}]}>
            {isQuickTip ? t('gotIt') : isDoneStep ? t('done') : t('next')}
          </Text>
          {!isDoneStep && !isQuickTip && (
            <View style={styles.primaryButtonIcon}>
              <ArrowRightIcon color={c.onPrimary} size={18} strokeWidth={2.4} />
            </View>
          )}
        </Pressable>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  topRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  stepCount: {
    fontFamily: fonts.semibold,
    fontSize: 13,
  },
  dots: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  dot: {
    width: 7,
    height: 7,
    borderRadius: 4,
    marginLeft: 6,
  },
  dotActive: {
    width: 26,
  },
  title: {
    marginTop: 12,
    fontFamily: fonts.bold,
    fontSize: 24,
  },
  description: {
    marginTop: 10,
    fontFamily: fonts.regular,
    fontSize: 15,
    lineHeight: 23,
  },
  actions: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 12,
    marginTop: 22,
  },
  // Previous and Skip tour: a pill like Next, in the quieter colours, so they read as buttons.
  // It gives way to Next on a narrow screen: a long translation wraps inside it instead.
  secondaryButton: {
    flexShrink: 1,
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: 48,
    paddingHorizontal: 20,
    paddingVertical: 6,
    borderRadius: radii.pill,
  },
  secondaryButtonLabel: {
    fontFamily: fonts.semibold,
    fontSize: 16,
    textAlign: 'center',
  },
  primaryButton: {
    flexShrink: 0,
    flexDirection: 'row',
    alignItems: 'center',
    minHeight: 48,
    paddingHorizontal: 24,
    borderRadius: radii.pill,
  },
  primaryButtonLabel: {
    fontFamily: fonts.semibold,
    fontSize: 16,
  },
  primaryButtonIcon: {
    marginLeft: 8,
  },
  pressed: {
    opacity: 0.8,
  },
});
