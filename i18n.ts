import i18next from 'i18next';
import * as Localization from 'expo-localization';
import {initReactI18next} from 'react-i18next';

import en from './locales/en.json';
import fil from './locales/fil.json';
import ar from './locales/ara.json';
import hi from './locales/hin.json';
import kn from './locales/kan.json';
import ta from './locales/tam.json';

import {iso6393To1} from 'iso-639-3';

import {getItem} from './machines/store';
import {LocalizedField} from './machines/VerifiableCredential/VCMetaMachine/vc';

const resources = {en, fil, ar, hi, kn, ta};
// Localization.locale (a single BCP-47 string) was removed in expo-localization's SDK 53 API in
// favor of getLocales(), which returns the device's ranked locale list. getLocales() can in
// principle return [] (documented edge case, not just a type nicety), so this falls back to
// 'en-US' to preserve the old API's guarantee of always returning a non-empty string —
// getLanguageCode() below has no undefined-handling of its own.
const locale = Localization.getLocales()[0]?.languageTag ?? 'en-US';
const languageCodeMap = {} as {[key: string]: string};

export const SUPPORTED_LANGUAGES = {
  en: 'English',
  fil: 'Filipino',
  ar: 'عربى',
  hi: 'हिंदी',
  kn: 'ಕನ್ನಡ',
  ta: 'தமிழ்',
};

i18next
  .use(initReactI18next)
  .init({
    compatibilityJSON: 'v3',
    resources,
    lng: getLanguageCode(locale),
    fallbackLng: getLanguageCode,
    supportedLngs: Object.keys(SUPPORTED_LANGUAGES),
  })
  .then(async () => {
    // languageCodeMap is a plain lookup built from the fixed SUPPORTED_LANGUAGES list, so it has
    // no dependency on changeLanguage. Previously it was only populated as a side effect of one of
    // the two changeLanguage calls below, leaving it empty ({}) whenever neither fired — and then
    // getValueForCurrentLanguage/getClientNameForCurrentLanguage always missed and fell back to
    // the default value instead of the current language's.
    populateLanguageCodeMap();

    const language = await getItem('language', null, '');

    // On a fresh install nothing is stored yet and getItem's default (null) comes back, so
    // `language !== i18next.language` was always true and this fired `changeLanguage(null)` —
    // a meaningless language change, since there is no preference to apply yet. Only apply a
    // *stored* preference.
    if (language && language !== i18next.language) {
      i18next.changeLanguage(language);
    }
    if (!Object.keys(SUPPORTED_LANGUAGES).includes(i18next.language)) {
      i18next.changeLanguage('en');
    }
  });

export default i18next;

export function getLanguageCode(code: string) {
  const [language] = code.split('-');
  return language;
}

export function getValueForCurrentLanguage(
  localizedData: LocalizedField[] | Object,
  defaultLanguage = '@none',
) {
  const currentLanguage = i18next.language;
  const currentLanguageCode = languageCodeMap[currentLanguage];
  if (Array.isArray(localizedData)) {
    const valueForCurrentLanguage = localizedData.filter(
      obj => obj.language === currentLanguageCode,
    );

    return valueForCurrentLanguage[0]?.value
      ? valueForCurrentLanguage[0].value
      : localizedData[0]?.value;
  } else {
    return localizedData?.value;
  }
}

export function getClientNameForCurrentLanguage(
  localizedData: Object,
  defaultLanguage = '@none',
) {
  const currentLanguage = i18next.language;
  const currentLanguageCode = languageCodeMap[currentLanguage];
  const localizedDataObject = localizedData as {[key: string]: string};
  return localizedDataObject.hasOwnProperty(currentLanguageCode)
    ? localizedDataObject[currentLanguageCode]
    : localizedDataObject[defaultLanguage];
}

// This method gets the value from iso-639-3 package, which contains key value pairs of three letter language codes[key] and two letter langugae code[value]. These values are according to iso standards.
// The response received from the server is three letter language code and the value in the inji code base is two letter language code. Hence the conversion is done.
function getThreeLetterLanguageCode(twoLetterLanguageCode: string) {
  return iso6393To1
    ? Object.keys(iso6393To1).find(
        key => iso6393To1[key] === twoLetterLanguageCode,
      )
    : null;
}

function populateLanguageCodeMap() {
  const supportedLanguages = Object.keys(SUPPORTED_LANGUAGES);
  supportedLanguages.forEach(languageCode => {
    let threeLetterLanguageCode = languageCode;

    if (isTwoLetterLanguageCode(languageCode)) {
      threeLetterLanguageCode = getThreeLetterLanguageCode(languageCode);
    }
    languageCodeMap[languageCode] = threeLetterLanguageCode;
  });
}

export function getLocalizedField(
  rawField: string | LocalizedField[] | Object,
) {
  if (typeof rawField === 'string') {
    return rawField;
  }

  if (Array.isArray(rawField)) {
    try {
      if (rawField.length == 1) return rawField[0]?.value;
      return getValueForCurrentLanguage(rawField);
    } catch (e) {
      return '';
    }
  }

  try {
    if (Object.keys(rawField).length === 1) {
      return Object.values(rawField)[0];
    }

    return getValueForCurrentLanguage(rawField);
  } catch (e) {
    return '';
  }
}

function isTwoLetterLanguageCode(languageCode: string) {
  return languageCode.length == 2;
}
