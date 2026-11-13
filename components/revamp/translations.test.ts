import fs from 'fs';
import path from 'path';
import i18next from 'i18next';
import en from '../../locales/en.json';
import fil from '../../locales/fil.json';
import ar from '../../locales/ara.json';
import hi from '../../locales/hin.json';
import kn from '../../locales/kan.json';
import ta from '../../locales/tam.json';
import {displayDate} from './credentialClaims';

type Tree = {[key: string]: string | Tree};

const flatten = (tree: Tree, prefix = ''): Record<string, string> =>
  Object.entries(tree).reduce(
    (all, [key, value]) =>
      typeof value === 'string'
        ? {...all, [prefix + key]: value}
        : {...all, ...flatten(value, `${prefix}${key}.`)},
    {} as Record<string, string>,
  );

const placeholders = (text: string) =>
  (text.match(/\{\{\s*\w+\s*\}\}/g) ?? [])
    .map(p => p.replace(/\s/g, ''))
    .sort();

const english = flatten(en.Wallet as Tree);

describe('the redesigned wallet in every language', () => {
  it.each([
    ['fil', fil],
    ['ar', ar],
    ['hi', hi],
    ['kn', kn],
    ['ta', ta],
  ])('%s has every piece of text, with the same placeholders', (_, locale) => {
    const translated = flatten((locale as {Wallet: Tree}).Wallet);
    expect(Object.keys(translated).sort()).toEqual(Object.keys(english).sort());
    for (const [key, text] of Object.entries(translated)) {
      expect({key, empty: text.trim() === ''}).toEqual({key, empty: false});
      expect({key, placeholders: placeholders(text)}).toEqual({
        key,
        placeholders: placeholders(english[key]),
      });
    }
  });

  it('writes dates with the month names of the app language', async () => {
    await i18next.init({
      lng: 'hi',
      resources: {en: {Wallet: en.Wallet}, hi: {Wallet: hi.Wallet}},
    });
    expect(displayDate('2026-11-06')).toBe(`06 ${hi.Wallet.months['11']} 2026`);
    await i18next.changeLanguage('en');
    expect(displayDate('2026-11-06')).toBe('06 Nov 2026');
  });

  // Text a holder sees comes from the locale files: English written into a screen stays English
  // whatever the language.
  it('has no English written into its screens', () => {
    const dir = __dirname;
    const found: string[] = [];
    // Between a tag's > and the next tag's <, not an arrow (=>) or a comparison (a < b).
    const jsxText =
      /(?<!=)>\s*([^<>{}\n]*[A-Za-z]{2,}[^<>{}\n]*?)\s*<(?=[/A-Za-z])/g;
    const textProp =
      /\b(label|title|message|subtitle|placeholder|description|hint|accessibilityLabel|accessibilityHint)=["'`][^"'`]*[A-Za-z]{2,}/g;
    for (const file of fs.readdirSync(dir)) {
      if (!file.endsWith('.tsx') || file.includes('.test.')) continue;
      const source = fs.readFileSync(path.join(dir, file), 'utf8');
      for (const match of source.matchAll(jsxText)) {
        const text = match[1].trim();
        // A JSX expression (a && b, f(x)), not text.
        if (/&&|\|\||[();=]/.test(text)) continue;
        found.push(`${file}: ${text}`);
      }
      for (const match of source.matchAll(textProp)) {
        found.push(`${file}: ${match[0]}`);
      }
    }
    expect(found).toEqual([]);
  });
});
