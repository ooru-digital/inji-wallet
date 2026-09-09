import {Animated} from 'react-native';

// react-native-copilot's default svgMaskPath cuts a sharp-cornered rectangle
// out of the dimmed overlay to highlight the target element. This variant
// draws the same cutout with rounded corners so the highlight box matches
// the app's rounded UI (e.g. the bottom tab bar icons).
const MASK_CORNER_RADIUS = 10;

interface SvgMaskPathParams {
  size: {x: Animated.Value; y: Animated.Value};
  position: {x: Animated.Value; y: Animated.Value};
  canvasSize: {x: number; y: number};
}

export const roundedSvgMaskPath = ({
  size,
  position,
  canvasSize,
}: SvgMaskPathParams): string => {
  // @ts-ignore _value is a private field on Animated.Value, matching the
  // access pattern used by react-native-copilot's own defaultSvgMaskPath.
  const positionX = position.x._value;
  // @ts-ignore
  const positionY = position.y._value;
  // @ts-ignore
  const sizeX = size.x._value;
  // @ts-ignore
  const sizeY = size.y._value;

  const radius = Math.min(MASK_CORNER_RADIUS, sizeX / 2, sizeY / 2);

  const left = positionX;
  const top = positionY;
  const right = positionX + sizeX;
  const bottom = positionY + sizeY;

  const roundedRect =
    `M${left + radius},${top}` +
    `H${right - radius}` +
    `Q${right},${top} ${right},${top + radius}` +
    `V${bottom - radius}` +
    `Q${right},${bottom} ${right - radius},${bottom}` +
    `H${left + radius}` +
    `Q${left},${bottom} ${left},${bottom - radius}` +
    `V${top + radius}` +
    `Q${left},${top} ${left + radius},${top}Z`;

  return `M0,0H${canvasSize.x}V${canvasSize.y}H0V0Z${roundedRect}`;
};
