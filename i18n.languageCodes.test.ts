import i18next from 'i18next';
import {getClientNameForCurrentLanguage} from './i18n';

// The server labels text with ISO 639-3 codes; each app language must find its own.
describe('three-letter language codes', () => {
  const names = {
    eng: 'English name',
    ara: 'Arabic name',
    hin: 'Hindi name',
    kan: 'Kannada name',
    tam: 'Tamil name',
    fil: 'Filipino name',
    '@none': 'Default name',
  };

  it.each([
    ['en', 'English name'],
    ['ar', 'Arabic name'],
    ['hi', 'Hindi name'],
    ['kn', 'Kannada name'],
    ['ta', 'Tamil name'],
    ['fil', 'Filipino name'],
  ])('%s picks %s', async (language, expected) => {
    await i18next.changeLanguage(language);
    expect(getClientNameForCurrentLanguage(names)).toBe(expected);
  });
});
