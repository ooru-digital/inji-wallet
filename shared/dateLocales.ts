import type {Locale} from 'date-fns';
import ar from 'date-fns/locale/ar';
import enUS from 'date-fns/locale/en-US';
import fil from 'date-fns/locale/fil';
import hi from 'date-fns/locale/hi';
import kn from 'date-fns/locale/kn';
import ta from 'date-fns/locale/ta';

/**
 * date-fns locales for the app's languages, keyed by i18n language code. Imported one by one:
 * `date-fns/locale` pulls in all 92 of date-fns's locales.
 */
export const DATE_FNS_LOCALES: Record<string, Locale> = {
  en: enUS,
  fil,
  ar,
  hi,
  kn,
  ta,
};
