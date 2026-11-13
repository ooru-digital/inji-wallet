import i18next from 'i18next';

/**
 * The redesigned wallet's text, from the `Wallet` section of the locale files. Plain functions use
 * it as it is; a memoised component also calls `useTranslation('Wallet')` so that it draws again
 * when the language changes.
 */
export const wt = (key: string, options?: Record<string, unknown>): string =>
  i18next.t(`Wallet:${key}`, options);
