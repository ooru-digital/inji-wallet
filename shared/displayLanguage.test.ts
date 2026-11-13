import i18next from 'i18next';
import {displayInAppLanguage} from './displayLanguage';

describe('an issuer display entry in the app language', () => {
  beforeAll(() => i18next.init({lng: 'hi', resources: {}}));

  it('matches the language whatever its region', () => {
    const display = [
      {locale: 'en', name: 'National ID'},
      {locale: 'hi-IN', name: 'राष्ट्रीय पहचान पत्र'},
    ];
    expect(displayInAppLanguage(display)?.name).toBe('राष्ट्रीय पहचान पत्र');
  });

  it('falls back to English in any region', () => {
    const display = [
      {locale: 'fr', name: 'Carte'},
      {locale: 'en-GB', name: 'Card'},
    ];
    expect(displayInAppLanguage(display)?.name).toBe('Card');
  });

  it('falls back to the first entry without English', () => {
    const display = [
      {locale: 'fr', name: 'Carte'},
      {locale: 'de', name: 'Karte'},
    ];
    expect(displayInAppLanguage(display)?.name).toBe('Carte');
  });

  it('reads the older {language} entries too', () => {
    const display = [
      {language: 'en', value: 'Card'},
      {language: 'hi', value: 'कार्ड'},
    ];
    expect(displayInAppLanguage(display)?.value).toBe('कार्ड');
  });

  it('has nothing to pick from an empty list', () => {
    expect(displayInAppLanguage([])).toBeUndefined();
    expect(displayInAppLanguage(undefined)).toBeUndefined();
  });
});
