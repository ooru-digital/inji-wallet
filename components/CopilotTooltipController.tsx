import {useCopilot} from 'react-native-copilot';
import {COPILOT_FINAL_STEP, KEY_MANAGEMENT_STEP} from '../shared/constants';
import {useContext, useEffect, useRef} from 'react';
import {GlobalContext} from '../shared/GlobalContext';
import {
  AuthEvents,
  selectIsInitialDownload,
  selectIsOnboarding,
  selectIsTourGuide,
} from '../machines/auth';
import {useSelector} from '@xstate/react';
import {copilotTestID} from '../shared/constants';

// How many frames in a row the highlighted element must stay put before the highlight is
// re-measured, and how long after a step appears to keep watching it.
const SETTLE_FRAMES = 8;
const SETTLE_WATCH_MS = 2000;

type Rect = {x: number; y: number; width: number; height: number};
const sameRect = (a: Rect, b: Rect) =>
  Math.abs(a.x - b.x) < 1 &&
  Math.abs(a.y - b.y) < 1 &&
  Math.abs(a.width - b.width) < 1 &&
  Math.abs(a.height - b.height) < 1;

/**
 * The tour measures a step's element once, when the step is shown. If the page moves while
 * the step is up (for example a banner above the Home header closing), the highlight stays
 * where the element was until Next then Previous measures it again. This does that
 * re-measure itself: it watches the element for a short while and, each time it comes to
 * rest, re-targets the step. Re-targeting an element that never moved changes nothing.
 */
const useKeepHighlightOnTarget = () => {
  const {currentStep, currentStepNumber, visible, goToNth} = useCopilot();
  const stepNumberRef = useRef(currentStepNumber);
  stepNumberRef.current = currentStepNumber;

  useEffect(() => {
    const step = currentStep as
      | {measure: () => Promise<Rect>; wrapperRef: {current: unknown}}
      | undefined;
    if (!visible || !step) {
      return;
    }
    let cancelled = false;
    let last: Rect | null = null;
    let stillFrames = 0;
    let retargeted = false;
    const deadline = Date.now() + SETTLE_WATCH_MS;

    const check = async () => {
      // step.measure() retries forever while the element is unmounted, so skip the frame.
      if (step.wrapperRef.current != null) {
        const rect = await step.measure();
        if (cancelled) {
          return;
        }
        if (last && sameRect(last, rect)) {
          stillFrames += 1;
        } else {
          stillFrames = 0;
          retargeted = false;
        }
        last = rect;
        if (!retargeted && stillFrames >= SETTLE_FRAMES) {
          retargeted = true;
          void goToNth(stepNumberRef.current);
        }
      }
      if (!cancelled && Date.now() < deadline) {
        requestAnimationFrame(check);
      }
    };
    requestAnimationFrame(check);
    return () => {
      cancelled = true;
    };
  }, [currentStep, visible]);
};

export const UseCopilotTooltip = () => {
  const {
    goToNext,
    goToPrev,
    stop,
    currentStep,
    currentStepNumber,
    isFirstStep,
    isLastStep,
    totalStepsNumber,
    copilotEvents,
  } = useCopilot();
  useKeepHighlightOnTarget();

  const {appService} = useContext(GlobalContext);
  const authService = appService.children.get('auth');
  const ONBOARDING_DONE = () => authService?.send(AuthEvents.ONBOARDING_DONE());
  const INITIAL_DOWNLOAD_DONE = () =>
    authService?.send(AuthEvents.INITIAL_DOWNLOAD_DONE());
  const SET_TOUR_GUIDE = set =>
    authService?.send(AuthEvents.SET_TOUR_GUIDE(set));
  const isOnboarding = useSelector(authService, selectIsOnboarding);
  const isInitialDownloading = useSelector(
    authService,
    selectIsInitialDownload,
  );
  const isTourGuide = useSelector(authService, selectIsTourGuide);

  const CURRENT_STEP = currentStep?.order;
  const currentStepTitle = currentStep?.name;
  const currentStepDescription = currentStep?.text;
  const titleTestID = `${copilotTestID[CURRENT_STEP?.toString()]}Title`;
  const descriptionTestID = `${
    copilotTestID[CURRENT_STEP?.toString()]
  }Description`;

  // A step shown on its own rather than as part of the tour. Outside a replay from Settings,
  // the card step only ever runs alone: it highlights a card that was just downloaded.
  const isStandalone =
    (CURRENT_STEP === COPILOT_FINAL_STEP && !isTourGuide) ||
    CURRENT_STEP === KEY_MANAGEMENT_STEP;

  // The step's position among the steps on screen, not its `order`: orders can have
  // gaps (a step whose element isn't rendered), which made the counter skip numbers
  // and run past the total. The library can report no step between steps, hence `?? 1`.
  const stepNumber = isStandalone ? 1 : currentStepNumber ?? 1;
  const stepTotal = isStandalone ? 1 : totalStepsNumber ?? 1;
  const stepCount = stepNumber + ' of ' + stepTotal;

  const isFinalStep = CURRENT_STEP === COPILOT_FINAL_STEP;

  // A standalone step has nothing to go back to.
  const showPrevious = !(isFirstStep || isStandalone);
  // The step whose primary button ends the tour ("Done") instead of moving on ("Next").
  const isDoneStep = isLastStep || isStandalone;

  return {
    goToNext,
    goToPrev,
    stop,
    CURRENT_STEP,
    currentStepNumber,
    currentStepTitle,
    currentStepDescription,
    isFirstStep,
    isLastStep,
    isFinalStep,
    totalStepsNumber,
    copilotEvents,
    stepCount,
    stepNumber,
    stepTotal,
    isStandalone,
    showPrevious,
    isDoneStep,
    isOnboarding,
    isInitialDownloading,
    titleTestID,
    descriptionTestID,
    INITIAL_DOWNLOAD_DONE,
    ONBOARDING_DONE,
    SET_TOUR_GUIDE,
  };
};
