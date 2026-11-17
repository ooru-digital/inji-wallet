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
  // Between a tag's > and the next tag's <, not an arrow (=>) or a comparison (a < b).
  const jsxText =
    /(?<!=)>\s*([^<>{}\n]*[A-Za-z]{2,}[^<>{}\n]*?)\s*<(?=[/A-Za-z])/g;
  // A text prop given a string: label="Pin", label={'Pin'}, label={`Open ${x}`}, or one side of
  // a choice, label={pinned ? 'Unpin' : 'Pin'}; in .ts files, the same names as keys with a
  // capitalised value (lower-case values are translation keys).
  const props =
    'label|title|message|subtitle|placeholder|description|hint|accessibilityLabel|accessibilityHint';
  const quote = '["\'`]';
  const notQuote = '[^"\'`]';
  const textProp = new RegExp(
    String.raw`\b(${props})=\{?\s*${quote}${notQuote}*[A-Za-z]{2,}` +
      String.raw`|\b(${props})=\{[^}]*?[?:]\s*${quote}[A-Z]${notQuote}*${quote}` +
      String.raw`|\b(${props})\s*:\s*${quote}[A-Z]${notQuote}*${quote}`,
    'g',
  );
  const englishIn = (source: string) => {
    const found: string[] = [];
    for (const match of source.matchAll(jsxText)) {
      const text = match[1].trim();
      // A JSX expression (a && b, f(x)), not text.
      if (!/&&|\|\||[();=]/.test(text)) found.push(text);
    }
    for (const match of source.matchAll(textProp)) found.push(match[0]);
    return found;
  };

  it('finds English written into a screen', () => {
    for (const source of [
      '<Text>Pinned</Text>',
      'label="Pin"',
      "label={'Pin'}",
      'accessibilityLabel={`Open ${title} details`}',
      "label={pinned ? 'Unpin' : 'Pin'}",
      "{label: 'Share', icon}",
    ]) {
      expect({source, found: englishIn(source).length > 0}).toEqual({
        source,
        found: true,
      });
    }
    expect(englishIn("{label: 'home', icon}")).toEqual([]);
    expect(englishIn("label={wt('home.pin')}")).toEqual([]);
  });

  it('has no English written into its screens', () => {
    const found: string[] = [];
    for (const file of fs.readdirSync(__dirname)) {
      if (!/\.tsx?$/.test(file) || file.includes('.test.')) continue;
      const source = fs.readFileSync(path.join(__dirname, file), 'utf8');
      found.push(...englishIn(source).map(text => `${file}: ${text}`));
    }
    expect(found).toEqual([]);
  });
});
