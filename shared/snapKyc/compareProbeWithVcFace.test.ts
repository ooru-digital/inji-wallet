import {compareProbeWithVcFace} from './compareProbeWithVcFace';
import {hasSdkFaceMatch, matchFaceWithSdk} from './SnapKycLiveness';

jest.mock('./SnapKycLiveness', () => ({
  hasSdkFaceMatch: jest.fn(),
  matchFaceWithSdk: jest.fn(),
}));

const JPEG = Buffer.from([0xff, 0xd8, 0xff, 1, 2, 3]).toString('base64');
const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3]).toString('base64');
const NOT_AN_IMAGE = Buffer.from('hello').toString('base64');

const sdkResult = (isMatch: boolean) => ({
  isMatch,
  cosine: isMatch ? 0.8 : 0.1,
  l2: isMatch ? 0.6 : 1.4,
  cosineThreshold: 0.363,
  l2Threshold: 1.128,
  durationMs: 120,
});

describe('compareProbeWithVcFace', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    jest.spyOn(console, 'log').mockImplementation(() => undefined);
  });

  describe('with the liveness SDK face match', () => {
    beforeEach(() => {
      (hasSdkFaceMatch as jest.Mock).mockReturnValue(true);
    });

    it('matches through the SDK', async () => {
      (matchFaceWithSdk as jest.Mock).mockResolvedValue(sdkResult(true));

      await expect(compareProbeWithVcFace(JPEG, [PNG])).resolves.toBe('match');

      expect(matchFaceWithSdk).toHaveBeenCalledWith(JPEG, PNG);
    });

    it('reports a different person as a mismatch', async () => {
      (matchFaceWithSdk as jest.Mock).mockResolvedValue(sdkResult(false));

      await expect(compareProbeWithVcFace(JPEG, [PNG])).resolves.toBe(
        'mismatch',
      );
    });

    it('treats an SDK error as a mismatch, never as no photo', async () => {
      (matchFaceWithSdk as jest.Mock).mockRejectedValue(
        Object.assign(new Error('No face'), {code: 'NO_FACE_IN_GALLERY'}),
      );

      await expect(compareProbeWithVcFace(JPEG, [PNG])).resolves.toBe(
        'mismatch',
      );
    });

    it('tries the next portrait when one does not match', async () => {
      (matchFaceWithSdk as jest.Mock)
        .mockResolvedValueOnce(sdkResult(false))
        .mockResolvedValueOnce(sdkResult(true));

      await expect(compareProbeWithVcFace(JPEG, [PNG, JPEG])).resolves.toBe(
        'match',
      );
      expect(matchFaceWithSdk).toHaveBeenCalledTimes(2);
    });

    it('is unusable when no portrait is an image', async () => {
      await expect(compareProbeWithVcFace(JPEG, [NOT_AN_IMAGE])).resolves.toBe(
        'unusable',
      );
      expect(matchFaceWithSdk).not.toHaveBeenCalled();
    });
  });

  it('fails closed when the native module has no SDK face match', async () => {
    (hasSdkFaceMatch as jest.Mock).mockReturnValue(false);

    await expect(compareProbeWithVcFace(JPEG, [PNG])).rejects.toThrow(
      'The liveness SDK face match is not available',
    );
    expect(matchFaceWithSdk).not.toHaveBeenCalled();
  });
});
