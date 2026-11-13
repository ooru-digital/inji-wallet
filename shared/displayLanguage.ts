import i18next from 'i18next';

/** The language of a language tag, without its region: "hi-IN" and "hi" are both "hi". */
const baseLanguage = (tag: unknown): string =>
  typeof tag === 'string' ? tag.toLowerCase().split(/[-_]/)[0] : '';

/**
 * An issuer's display entry (`{locale, name, ...}`, or `{language, ...}`) in the app's language,
 * any region of it ("hi-IN" for "hi"), else in English (any region), else its first one.
 */
export function displayInAppLanguage<T extends object>(
  display: T[] | null | undefined,
): T | undefined {
  if (!display || display.length === 0) return undefined;
  const key = 'language' in display[0] ? 'language' : 'locale';
  const inLanguage = (language: string) =>
    display.find(
      entry =>
        baseLanguage((entry as Record<string, unknown>)[key]) === language,
    );
  return (
    inLanguage(baseLanguage(i18next.language)) ?? inLanguage('en') ?? display[0]
  );
}
