import i18next from 'i18next';

/** The language of a language tag, without its region: "hi-IN" and "hi" are both "hi". */
const baseLanguage = (tag: unknown): string =>
  typeof tag === 'string' ? tag.toLowerCase().split(/[-_]/)[0] : '';

/**
 * An issuer's display entry (`{locale, name, ...}`, or `{language, ...}`) in the app's language:
 * the exact tag, else any region of it ("hi-IN" for "hi"); else English the same way; else its
 * first one.
 */
export function displayInAppLanguage<T extends object>(
  display: T[] | null | undefined,
): T | undefined {
  const entries = (display ?? []).filter(
    entry => entry && typeof entry === 'object',
  );
  if (entries.length === 0) return undefined;
  const key = 'language' in entries[0] ? 'language' : 'locale';
  const tagOf = (entry: T) => (entry as Record<string, unknown>)[key];
  const inLanguage = (tag: string) =>
    entries.find(
      entry =>
        typeof tagOf(entry) === 'string' &&
        (tagOf(entry) as string).toLowerCase() === tag.toLowerCase(),
    ) ??
    entries.find(entry => baseLanguage(tagOf(entry)) === baseLanguage(tag));
  return inLanguage(i18next.language ?? '') ?? inLanguage('en') ?? entries[0];
}
