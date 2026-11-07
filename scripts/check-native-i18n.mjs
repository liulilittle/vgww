#!/usr/bin/env node
// check-native-i18n.mjs - batch19 R4-P0 native resource gate.
//
// Verifies the generated M1 resource (src/ui/i18n_gen.bin) against the live
// native string source (src/ui/i18n.cpp):
//   * magic/version/format of the compact UTF-8 resource;
//   * every language block holds exactly kTableSize strings;
//   * every string decodes byte-for-byte to its source literal;
//   * no empty entry; per-key '{' placeholder count equals the en table.
//
// Negative proof: `--bin <path>` checks a different file, so a deliberately
// corrupted copy must FAIL (used for the red anchor).
//
// Usage: node scripts/check-native-i18n.mjs <repo-root> [--bin <path>]
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const root = process.argv[2];
let binPathArg = null;
for (let i = 3; i < process.argv.length; i++) {
  if (process.argv[i] === '--bin' && i + 1 < process.argv.length) binPathArg = process.argv[++i];
}
if (!root) {
  console.error('FAIL native-i18n: missing <repo-root> argument');
  process.exit(1);
}
const repo = resolve(root);
function fail(d) { console.error(`FAIL native-i18n: ${d}`); process.exit(1); }

function skipBalanced(text, i) {
  const pairs = { '{': '}', '(': ')', '[': ']' };
  const closer = pairs[text[i]];
  let depth = 1, j = i + 1;
  while (j < text.length) {
    const c = text[j];
    if (c === '/' && text[j + 1] === '/') { const nl = text.indexOf('\n', j); j = nl < 0 ? text.length : nl + 1; continue; }
    if (c === '/' && text[j + 1] === '*') { const e = text.indexOf('*/', j + 2); j = e < 0 ? text.length : e + 2; continue; }
    if (c === '"' || c === "'" || c === '`') { j += 1; while (j < text.length && !(text[j] === c && text[j - 1] !== '\\')) j++; j++; continue; }
    if (c === closer) { depth--; if (depth === 0) return j + 1; j++; continue; }
    if (Object.prototype.hasOwnProperty.call(pairs, c)) { j = skipBalanced(text, j); continue; }
    j++;
  }
  throw new Error('unbalanced');
}

const cpp = readFileSync(join(repo, 'src', 'ui', 'i18n.cpp'), 'utf8');
// batch310: the enum lives in i18n.h; the tables live in i18n.cpp. A key
// added/removed on ONE side only must fail here, not at compile time.
const header = readFileSync(join(repo, 'src', 'ui', 'i18n.h'), 'utf8');
function extractArray(name) {
  const at = cpp.indexOf(`${name}[] = {`);
  if (at < 0) fail(`cannot find ${name}[]`);
  const open = cpp.indexOf('{', at);
  const close = skipBalanced(cpp, open);
  const body = cpp.slice(open + 1, close - 1);
  const out = [];
  const re = /L"((?:[^"\\]|\\.)*)"/g;
  let m;
  while ((m = re.exec(body)) !== null) out.push(m[1].replace(/\\(.)/g, (_, c) => (c === 'n' ? '\n' : c === 't' ? '\t' : c === 'r' ? '\r' : c)));
  return out;
}
const zh = extractArray('kStringsZh');
const en = extractArray('kStringsEn');
if (zh.length !== en.length) fail('zh/en length mismatch');
const keyCount = en.length;
// batch206: counting '{' only proves two strings use the SAME NUMBER of
// placeholders - not the same ones. Every native string here is indexed
// ("{0}m {1}s"), so a translation that writes "{1}m {0}s" has the identical
// count and was silently accepted (measured with the .bin regenerated: the gate
// printed OK), while the UI then reads 30 minutes 5 seconds for 5 min 30 s.
// Compare the ordered placeholder SEQUENCE instead.
const braces = (s) => (s.match(/\{/g) || []).length;
const placeholders = (s) => (String(s).match(/\{\d+\}/g) || []);
/// A translated string is consistent with the en original when it names the
/// same placeholders, in the same order. A translation may reorder the WORDS
/// around them; it may not reorder or rename the placeholders themselves.
function placeholderMismatch(translated, original) {
  const want = placeholders(original);
  const have = placeholders(translated);
  if (want.length === 0) return null;   // the en side has no placeholders to match
  if (have.length === 0) return `no placeholders at all (en has ${want.join(' ')})`;
  for (let i = 0; i < Math.max(want.length, have.length); i++) {
    if (want[i] !== have[i]) {
      const h = have[i] === undefined ? '(absent)' : have[i];
      const w = want[i] === undefined ? '(absent)' : want[i];
      return `placeholder #${i + 1} is ${h}, en has ${w}`;
    }
  }
  return null;
}

const binPath = binPathArg ? resolve(binPathArg) : join(repo, 'src', 'ui', 'i18n_gen.bin');
const buf = readFileSync(binPath);
if (buf.length < 12) fail('resource too small');
if (buf.toString('latin1', 0, 4) !== 'VGI1') fail('bad magic (expected VGI1)');
const version = buf.readUInt32LE(4);
if (version !== 1) fail(`unsupported version ${version}`);
const langCount = buf.readUInt32LE(8);
const dir = [];
let p = 12;
for (let i = 0; i < langCount; i++) {
  if (p + 2 > buf.length) fail('directory truncated');
  const codeLen = buf.readUInt8(p); p += 1;
  const rtl = buf.readUInt8(p) === 1; p += 1;
  if (p + codeLen + 8 > buf.length) fail('directory entry truncated');
  const code = buf.toString('utf8', p, p + codeLen); p += codeLen;
  const off = buf.readUInt32LE(p); p += 4;
  const len = buf.readUInt32LE(p); p += 4;
  if (off > buf.length || len > buf.length || off + len > buf.length) fail(`block out of range (${code})`);
  dir.push({ code, rtl, off, len });
}
function readBlock(off, len) {
  if (off < 0 || len < 0 || off + len > buf.length) fail(`block out of range (off=${off} len=${len} size=${buf.length})`);
  let q = off;
  const count = buf.readUInt32LE(q); q += 4;
  if (count > 100000) fail(`implausible string count ${count}`);
  const out = [];
  for (let i = 0; i < count; i++) {
    if (q + 4 > buf.length) fail('truncated block');
    const bl = buf.readUInt32LE(q); q += 4;
    if (q + bl > buf.length) fail('truncated string body');
    out.push(buf.toString('utf8', q, q + bl)); q += bl;
  }
  if (q - off !== len) fail(`block length mismatch (off=${off} len=${len} consumed=${q - off})`);
  return out;
}
const byCode = new Map(dir.map((d) => [d.code, d]));
for (const need of ['en', 'zh-CN']) if (!byCode.has(need)) fail(`resource missing language "${need}"`);

// The catalog must be the full www set (461 for batch19).
const EXPECTED_LANGS = 461;
if (langCount !== EXPECTED_LANGS) fail(`language blocks=${langCount}, expected ${EXPECTED_LANGS}`);

const problems = [];
// batch310: enum/table length parity. i18n.cpp's static_assert catches a
// mismatch when the tree is built, but this gate must never print OK for a
// tree that cannot build (measured: adding TimeJustNow to the enum only kept
// this gate green).
{
  const at = header.indexOf('enum class Str');
  if (at < 0) fail('cannot find enum class Str');
  const open = header.indexOf('{', at);
  // The enum body carries comments that mention `_Count`, so locate the real
  // closing brace (skipBalanced skips comments/strings) instead of searching
  // for the first `_Count` token.
  const close = skipBalanced(header, open);
  const body = header.slice(open + 1, close - 1);
  // One entry per line, name first, comma after (a trailing ///< comment may
  // follow). Splitting on commas loses the entries that carry a same-line
  // comment, so match line starts instead.
  const entry = /^[ \t]*([A-Za-z_]\w*)[ \t]*,/gm;
  let enumCount = 0;
  let em;
  while ((em = entry.exec(body)) !== null) {
    if (em[1] !== '_Count') enumCount++;
  }
  if (enumCount !== keyCount) {
    problems.push(
      `enum Str has ${enumCount} entries but the kStrings tables have ${keyCount} (a key was added/removed on one side only)`);
  }
}
let fallbackTotal = 0;
for (const d of dir) {
  const strings = readBlock(d.off, d.len);
  if (strings.length !== keyCount) { problems.push(`${d.code}: ${strings.length} strings != ${keyCount}`); continue; }
  if (d.code === 'en' || d.code === 'zh-CN') {
    const src = d.code === 'en' ? en : zh;
    for (let i = 0; i < keyCount; i++) {
      if (strings[i] !== src[i]) { problems.push(`${d.code}[${i}]: resource != source`); break; }
    }
  }
  for (let i = 0; i < keyCount; i++) {
    if (strings[i] === '') { problems.push(`${d.code}[${i}]: empty entry`); break; }
    // batch206: the SEQUENCE, not the count (see placeholderMismatch).
    const phProblem = placeholderMismatch(strings[i], en[i]);
    if (phProblem) {
      problems.push(`${d.code}[${i}]: ${phProblem}`);
      break;
    }
    if (d.code !== 'en' && d.code !== 'zh-CN' && strings[i] === en[i]) fallbackTotal++;
  }
}
// batch286: a zh-CN entry copied straight from the en table used to pass
// every check here - same length, same placeholders, resource == source -
// so the Chinese UI shipped English text (measured: setting NavLeases to
// "Leases" and regenerating still printed OK). Pin the core language.
const ZH_MAY_EQUAL_EN = new Set([
  // Language endonyms: every language lists itself in its own language.
  'LangZh', 'LangEn',
  // Acronyms / product tokens that are not translated in any language.
  'DashCpu', 'ColIp', 'ColMac', 'ColLan', 'ColDuid', 'FormDuid',
  'FormVlan', 'FormGroupDhcp', 'FormGroupIpv6', 'FormGroupWeb',
  // Pure placeholders / numerals / technology tokens: nothing to translate.
  'SettingsAdapterIpsFmt', 'DashAxisZero', 'ConnTypeWifi',
]);
const ZH_ALLOWLIST_SIZE = 15;
/// Every table entry carries a trailing `// Key` comment; pair each string
/// with its key so the allowlist is keyed by NAME, not by a shifted index.
function extractKeyed(name) {
  const at = cpp.indexOf(`${name}[] = {`);
  if (at < 0) fail(`cannot find ${name}[]`);
  const open = cpp.indexOf('{', at);
  const close = skipBalanced(cpp, open);
  const body = cpp.slice(open + 1, close - 1);
  const out = [];
  const re = /L"((?:[^"\\]|\\.)*)"\s*,\s*\/\/\s*([A-Za-z0-9_]+)/g;
  let m;
  while ((m = re.exec(body)) !== null) out.push({ text: m[1], key: m[2] });
  return out;
}
{
  const zhk = extractKeyed('kStringsZh');
  const enk = extractKeyed('kStringsEn');
  if (zhk.length !== keyCount || enk.length !== keyCount) {
    problems.push(
      `keyed tables: zh=${zhk.length} en=${enk.length}, expected ${keyCount}` +
      ' (every entry needs a trailing "// Key" comment)');
  } else {
    const untranslated = [];
    const identical = new Set();
    for (let i = 0; i < keyCount; i++) {
      if (zhk[i].key !== enk[i].key) {
        problems.push(`key alignment at ${i}: ${zhk[i].key} vs ${enk[i].key}`);
        break;
      }
      if (zh[i] === en[i]) {
        identical.add(zhk[i].key);
        if (!ZH_MAY_EQUAL_EN.has(zhk[i].key)) {
          untranslated.push(`${zhk[i].key} = ${JSON.stringify(en[i])}`);
        }
      }
    }
    if (untranslated.length) {
      problems.push(`zh-CN is not translated (identical to en): ${untranslated.join(', ')}`);
    }
    // The allowlist must stay honest in its own right: a stale entry (the
    // string got translated after all) is noise, and a growing list must be
    // a deliberate edit, not a quiet way to mute the check.
    for (const k of ZH_MAY_EQUAL_EN) {
      if (!identical.has(k)) problems.push(`allowlist entry "${k}" is no longer identical to en (drop it)`);
    }
    if (ZH_MAY_EQUAL_EN.size !== ZH_ALLOWLIST_SIZE) {
      problems.push(`allowlist has ${ZH_MAY_EQUAL_EN.size} entries, expected ${ZH_ALLOWLIST_SIZE}`);
    }
  }
}
if (problems.length) fail(`\n  ${problems.join('\n  ')}`);

const total = langCount * keyCount;
const pct = ((fallbackTotal / total) * 100).toFixed(2);
const strict = process.argv.includes('--strict');
if (strict && fallbackTotal > 0) {
  fail(`strict: ${fallbackTotal}/${total} (${pct}%) strings fall back to en (T2 coverage incomplete)`);
}
console.log(`OK native-i18n: ${langCount} languages x ${keyCount} keys; en fallback=${fallbackTotal}/${total} (${pct}%); src=${binPath}`);
