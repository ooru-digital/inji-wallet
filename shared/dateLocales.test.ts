import {format} from 'date-fns';
import {DATE_FNS_LOCALES} from './dateLocales';
import {SUPPORTED_LANGUAGES} from '../i18n';

describe('DATE_FNS_LOCALES', () => {
  it('has a locale for every language the app supports', () => {
    expect(Object.keys(DATE_FNS_LOCALES).sort()).toEqual(
      Object.keys(SUPPORTED_LANGUAGES).sort(),
    );
  });

  it.each([
    ['en', 'en-US'],
    ['fil', 'fil'],
    ['ar', 'ar'],
    ['hi', 'hi'],
    ['kn', 'kn'],
    ['ta', 'ta'],
  ])('%s uses date-fns locale %s', (language, code) => {
    expect(DATE_FNS_LOCALES[language].code).toBe(code);
  });

  it('formats in the chosen language', () => {
    const date = new Date(2026, 0, 15);
    expect(format(date, 'MMMM', {locale: DATE_FNS_LOCALES.en})).toBe('January');
    expect(format(date, 'MMMM', {locale: DATE_FNS_LOCALES.ta})).not.toBe(
      'January',
    );
  });
});
