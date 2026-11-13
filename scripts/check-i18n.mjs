#!/usr/bin/env node
// Gate: web_i18n
// Checks the I18N table in www/index.html:
//   1. key parity    : every key of `en` must exist in every other language,
//                      unless acknowledged in scripts/i18n-missing.allowlist as
//                      `<lang>:<key>`; keys a language has but `en` lacks are
//                      reported as WARN unless acknowledged as `<lang>:!<key>`.
//   2. duplicate keys: a key defined twice inside one language block is an error.
//   3. literal keys  : keys used as literals outside the table (`t("...")`,
//                      `data-i18n*="..."`, `new Error("err.xxx")` / throw-style
//                      `"err.xxx"` strings) must exist in `en`.
//   4. RTL coverage  : every language code listed in scripts/rtl-languages.txt
//                      must have a truthy `lang.rtl` entry in its block
//                      (applyI18n maps a falsy/absent value to ltr).
//   5. 401 path      : api()'s 401 branch must throw an i18n key that exists in
//                      en and errMsg() must map that key's namespace, so a 401
//                      can never surface as raw English (S4.6-W2).
//   6. server tokens : every fixed error token the web layer can return as
//                      {"error":"<token>"} must have an `err.<token>` entry in
//                      en; api() builds that key dynamically, so a gap makes
//                      t() return the key itself ("err.binding exists") and the
//                      toast shows an internal identifier (batch143).
//
// Usage: node scripts/check-i18n.mjs <repo-root> [--update]
//        --update regenerates scripts/i18n-missing.allowlist from the current
//        tree (sorted, de-duplicated) and prints the resulting entry count.
// Exit:  0 = OK (WARNs allowed), 1 = FAIL (or missing arg / parse failure).
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const NAME = 'i18n';
const root = process.argv[2];
const update = process.argv.includes('--update');
if (!root) {
  console.error(`FAIL ${NAME}: missing <repo-root> argument (usage: node scripts/check-i18n.mjs <repo-root> [--update])`);
  process.exit(1);
}

function fail(detail) {
  console.error(`FAIL ${NAME}: ${detail}`);
  process.exit(1);
}

const htmlPath = join(resolve(root), 'www', 'index.html');
const rtlPath = join(resolve(root), 'scripts', 'rtl-languages.txt');
const allowPath = join(resolve(root), 'scripts', 'i18n-missing.allowlist');

let html;
try {
  html = readFileSync(htmlPath, 'utf8');
} catch (e) {
  fail(`cannot read ${htmlPath}: ${e.message}`);
}
let rtlCodes;
try {
  rtlCodes = readFileSync(rtlPath, 'utf8')
    .split(/\r?\n/)
    .map((l) => l.replace(/#.*$/, '').trim())
    .filter((l) => l !== '');
} catch (e) {
  fail(`cannot read ${rtlPath}: ${e.message}`);
}

// ---------------------------------------------------------------- JS scanning
// Skip a JS string literal (single/double quote; template literals are scanned
// with ${...} nesting) starting at text[i]; returns index just past the literal.
function skipString(text, i) {
  const q = text[i];
  let j = i + 1;
  while (j < text.length) {
    const c = text[j];
    if (c === '\\') { j += 2; continue; }
    if (q === '`' && c === '$' && text[j + 1] === '{') {
      j = skipBalanced(text, j + 1); // skip the { ... } interpolation
      continue;
    }
    if (c === q) return j + 1;
    j++;
  }
  throw new Error(`unterminated string literal at offset ${i}`);
}

// text[i] must be one of ({[; returns index just past the matching closer.
function skipBalanced(text, i) {
  const pairs = { '{': '}', '(': ')', '[': ']' };
  const closer = pairs[text[i]];
  if (!closer) throw new Error(`internal: skipBalanced on '${text[i]}' at ${i}`);
  let depth = 1;
  let j = i + 1;
  while (j < text.length) {
    const c = text[j];
    if (c === '/' && text[j + 1] === '/') {
      const nl = text.indexOf('\n', j);
      if (nl < 0) return text.length;
      j = nl + 1;
      continue;
    }
    if (c === '/' && text[j + 1] === '*') {
      const end = text.indexOf('*/', j + 2);
      if (end < 0) return text.length;
      j = end + 2;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { j = skipString(text, j); continue; }
    if (c === closer) { depth--; if (depth === 0) return j + 1; j++; continue; }
    if (Object.prototype.hasOwnProperty.call(pairs, c)) { j = skipBalanced(text, j); continue; }
    j++;
  }
  throw new Error(`unbalanced '${text[i]}' starting at offset ${i}`);
}

// Split an object body on top-level commas (string/comment/nesting aware).
function splitTopLevel(body) {
  const parts = [];
  let depth = 0;
  let start = 0;
  let i = 0;
  while (i < body.length) {
    const c = body[i];
    if (c === '/' && body[i + 1] === '/') {
      const nl = body.indexOf('\n', i);
      i = nl < 0 ? body.length : nl + 1;
      continue;
    }
    if (c === '/' && body[i + 1] === '*') {
      const end = body.indexOf('*/', i + 2);
      i = end < 0 ? body.length : end + 2;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { i = skipString(body, i); continue; }
    if (c === '{' || c === '(' || c === '[') { depth++; i++; continue; }
    if (c === '}' || c === ')' || c === ']') { depth--; i++; continue; }
    if (c === ',' && depth === 0) {
      parts.push(body.slice(start, i));
      start = i + 1;
      i++;
      continue;
    }
    i++;
  }
  parts.push(body.slice(start));
  return parts.map((p) => p.trim()).filter((p) => p !== '');
}

// Parse `"key": value` entries of an object body into [{key, valueText}].
function parseEntries(body, where) {
  return splitTopLevel(body).map((part) => {
    let depth = 0;
    let colon = -1;
    let i = 0;
    while (i < part.length) {
      const c = part[i];
      if (c === '"' || c === "'" || c === '`') { i = skipString(part, i); continue; }
      if (c === '{' || c === '(' || c === '[') { depth++; i++; continue; }
      if (c === '}' || c === ')' || c === ']') { depth--; i++; continue; }
      if (c === ':' && depth === 0) { colon = i; break; }
      i++;
    }
    if (colon < 0) throw new Error(`${where}: entry without ':' -> ${JSON.stringify(part.slice(0, 60))}`);
    const keyRaw = part.slice(0, colon).trim();
    let key;
    if (keyRaw[0] === '"' || keyRaw[0] === "'") {
      const end = skipString(keyRaw, 0);
      key = keyRaw.slice(1, end - 1).replace(/\\(.)/g, '$1');
    } else {
      key = keyRaw;
    }
    return { key, valueText: part.slice(colon + 1).trim() };
  });
}

// ------------------------------------------------------------ I18N extraction
// The table lives in the inline <script>; scan script text (not raw HTML) so
// that quoting in HTML prose can never confuse the JS-aware scanner.
const scripts = [];
{
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const attrs = m[1] || '';
    if (/\bsrc\s*=/i.test(attrs)) continue;
    const tm = attrs.match(/\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
    if (tm) {
      const type = (tm[1] ?? tm[2] ?? tm[3] ?? '').trim().toLowerCase();
      if (!['', 'text/javascript', 'application/javascript', 'module', 'text/ecmascript', 'application/ecmascript'].includes(type)) continue;
    }
    scripts.push(m[2]);
  }
}
if (scripts.length === 0) fail(`no inline <script> block found in ${htmlPath}`);
const script = scripts.join('\n;\n');

const anchor = 'const I18N = {';
const anchorAt = script.indexOf(anchor);
if (anchorAt < 0) fail(`cannot find '${anchor}' in the inline script of ${htmlPath}`);
const bodyOpen = anchorAt + anchor.length - 1; // index of '{'
const bodyClose = skipBalanced(script, bodyOpen); // index just past matching '}'
const i18nBody = script.slice(bodyOpen + 1, bodyClose - 1);

let langEntries;
try {
  langEntries = parseEntries(i18nBody, 'I18N');
} catch (e) {
  fail(`cannot parse the I18N table: ${e.message}`);
}
if (langEntries.length < 2) fail(`I18N table parsed but has ${langEntries.length} language block(s) - parser is wrong, refusing to report OK`);

const keysByLang = new Map(); // lang -> Set(keys)
const valuesByLang = new Map(); // lang -> Map(key, raw value source text)
const rtlValueByLang = new Map(); // lang -> raw source text of its lang.rtl value
const duplicates = []; // "lang:key"
for (const { key: lang, valueText } of langEntries) {
  if (!valueText.startsWith('{')) fail(`language block "${lang}" is not an object literal`);
  const close = skipBalanced(valueText, 0);
  if (close - 1 !== valueText.length - 1) fail(`language block "${lang}" has trailing content after '}'`);
  let entries;
  try {
    entries = parseEntries(valueText.slice(1, close - 1), `I18N.${lang}`);
  } catch (e) {
    fail(e.message);
  }
  const seen = new Set();
  const values = new Map();
  for (const { key, valueText: v } of entries) {
    if (seen.has(key)) duplicates.push(`${lang}:${key}`);
    seen.add(key);
    values.set(key, v);
    if (key === 'lang.rtl') rtlValueByLang.set(lang, v);
  }
  keysByLang.set(lang, seen);
  valuesByLang.set(lang, values);
}

const enKeys = keysByLang.get('en');
if (!enKeys) fail('I18N table has no "en" language block (baseline missing)');
const enValues = valuesByLang.get('en') ?? new Map();

// ------------------------------------------------------------- allowlist load
const allowMissing = new Set(); // "lang:key"
const allowExtra = new Set(); // "lang:!key"
try {
  const lines = readFileSync(allowPath, 'utf8').split(/\r?\n/);
  lines.forEach((raw, n) => {
    const line = raw.replace(/#.*$/, '').trim();
    if (line === '') return;
    const m = line.match(/^([^:]+):(!?)(.+)$/);
    if (!m) fail(`${allowPath}:${n + 1}: bad allowlist entry ${JSON.stringify(raw.trim())} (expected <lang>:<key> or <lang>:!<key>)`);
    if (m[2] === '!') allowExtra.add(`${m[1]}:!${m[3]}`); else allowMissing.add(`${m[1]}:${m[3]}`);
  });
} catch (e) {
  if (e && e.code === 'ENOENT') fail(`cannot read ${allowPath}: file must exist (empty file is fine)`);
  throw e;
}

// ------------------------------------------------------------------- compare
const missingPairs = []; // {lang, key}
const extraPairs = []; // {lang, key}
const unlistedMissing = [];
const unlistedExtra = [];
for (const [lang, keys] of keysByLang) {
  if (lang === 'en') continue;
  for (const key of enKeys) {
    if (keys.has(key)) continue;
    missingPairs.push(`${lang}:${key}`);
    if (!allowMissing.has(`${lang}:${key}`)) unlistedMissing.push(`${lang}:${key}`);
  }
  for (const key of keys) {
    if (enKeys.has(key)) continue;
    extraPairs.push(`${lang}:${key}`);
    if (!allowExtra.has(`${lang}:!${key}`)) unlistedExtra.push(`${lang}:${key}`);
  }
}

const rtlMissing = [];
const rtlUnknown = [];
const rtlFalsy = []; // lang.rtl present but evaluates falsy in applyI18n (dir would stay ltr)
const FALSY_LITERALS = new Set(['""', "''", '', '0', 'false', 'null', 'undefined', 'NaN']);
for (const code of rtlCodes) {
  const keys = keysByLang.get(code);
  if (!keys) { rtlUnknown.push(code); continue; }
  if (!keys.has('lang.rtl')) { rtlMissing.push(code); continue; }
  const v = (rtlValueByLang.get(code) ?? '').trim();
  if (FALSY_LITERALS.has(v)) rtlFalsy.push(`${code}=${v}`);
}

// batch205: a key that EXISTS but carries an empty value is the same defect as
// a missing key, and harder to notice: every count in this gate says the key is
// present (it is not in missingPairs), while t() returns "" and the UI paints a
// blank. Emptied `en.dash.title` left the page title as "VGWW · " and the gate
// still printed OK (measured); emptying the zh-CN copy did the same.
//
// A value counts as empty when its SOURCE TEXT is only quotes, only whitespace,
// or a literal that evaluates to nothing at all. Whitespace-only matters on its
// own: ' ' is not "missing" by any count, but it renders as an invisible label
// and reads as silence to a screen reader.
const EMPTY_LITERAL_RE = /^(?:''|""|``)$/;
const emptyValues = [];   // { lang, key, raw }
for (const [lang, values] of valuesByLang) {
  for (const [key, raw] of values) {
    const v = String(raw).trim();
    // Only string-literal values can be "empty" in a way that hides text. A
    // numeric or boolean value is a legal translation (counts, flags).
    const isString = v.startsWith('"') || v.startsWith("'") || v.startsWith('`');
    if (!isString) continue;
    const inner = v.slice(1, -1);
    if (EMPTY_LITERAL_RE.test(v) || inner.trim() === '') {
      emptyValues.push({ lang, key, raw: v });
    }
  }
}

// Core languages must be complete and must not silently show English prose.
// Technical acronyms (DHCP/IPv6/MAC/...) and sample placeholder values are
// allowed to stay identical to en; everything else that is visibly English
// defeats the localized UI (S4-W2 style regression gate for batch37).
const CORE_LANGS = ['zh-CN', 'zh-TW'];
const CORE_TECH_RE = /^(IPv6|VLAN|MAC|CPU|TCP|WLAN|DUID|TLS|HTTP|API|RA|DHCPv?[0-9]*)$/;
const CORE_ALLOW_SAME = new Set(['set.ph.adapter', 'dash.ipv6', 'set.vlan']);
const coreMissing = [];
const coreSameAsEn = [];
for (const lang of CORE_LANGS) {
  const keys = keysByLang.get(lang);
  if (!keys) {
    coreMissing.push(`${lang}:<missing language block>`);
    continue;
  }
  for (const key of enKeys) {
    if (!keys.has(key)) coreMissing.push(`${lang}:${key}`);
  }
  const values = valuesByLang.get(lang) ?? new Map();
  for (const [key, raw] of values) {
    if (CORE_ALLOW_SAME.has(key)) continue;
    if (!enKeys.has(key)) continue;
    if (raw[0] !== '"') continue;
    let enVal = null;
    try { enVal = JSON.parse(enValues.get(key) ?? '"UNPARSED"'); } catch { /* handled below */ }
    if (enVal === null) continue;
    let val = null;
    try { val = JSON.parse(raw); } catch { continue; }
    if (typeof val !== 'string') continue;
    if (val !== enVal) continue;
    if (!/^[\x20-\x7E]*$/.test(val)) continue;
    if (!/[A-Za-z]{3,}/.test(val)) continue;
    if (CORE_TECH_RE.test(val)) continue;
    coreSameAsEn.push(`${lang}:${key}="${val}"`);
  }
}

// ------------------------------------------- literal key usage (outside table)
// Prose in comments (e.g. `// ... "err.xxx") must not count as a key usage:
// matches inside line comments or /* */ blocks are skipped. The check is
// quote-aware for the line prefix, so a '//' inside a string literal does not
// hide real usages.
const outside = `${script.slice(0, bodyOpen)}\n${script.slice(bodyClose)}`;
const blockComments = [...outside.matchAll(/\/\*[\s\S]*?\*\//g)].map((c) => [c.index, c.index + c[0].length]);
function hasLineCommentStart(prefix) {
  let inS = false;
  let inD = false;
  let inT = false;
  for (let i = 0; i < prefix.length; i++) {
    const c = prefix[i];
    if (c === '\\') { i++; continue; }
    if (inS) { if (c === "'") inS = false; continue; }
    if (inD) { if (c === '"') inD = false; continue; }
    if (inT) { if (c === '`') inT = false; continue; }
    if (c === "'") { inS = true; continue; }
    if (c === '"') { inD = true; continue; }
    if (c === '`') { inT = true; continue; }
    if (c === '/' && prefix[i + 1] === '/') return true;
  }
  return false;
}
function isCommented(index) {
  if (blockComments.some(([a, b]) => index >= a && index < b)) return true;
  const lineStart = outside.lastIndexOf('\n', index - 1) + 1;
  return hasLineCommentStart(outside.slice(lineStart, index));
}

const usedLiteral = new Set();
for (const m of outside.matchAll(/\bt\(\s*"((?:[^"\\]|\\.)*)"\s*\)/g)) {
  if (isCommented(m.index)) continue;
  usedLiteral.add(m[1].replace(/\\(.)/g, '$1'));
}
// string literals that are i18n keys carried around as data (e.g. new Error("err.network")
// or new Error("auth.unauthorized")); keys ending in '.' are dynamic concatenation
// prefixes ("err." + name) - skipped by design.
let dynamicKeyPrefixes = 0;
for (const m of outside.matchAll(/"((?:err|auth)\.[^"\\]*)"/g)) {
  if (isCommented(m.index)) continue;
  if (m[1].endsWith('.')) {
    // only count real concatenation prefixes ("err." + name); a startsWith("err.")
    // guard is a comparison, not a dynamic key lookup
    if (/^\s*\+/.test(outside.slice(m.index + m[0].length))) dynamicKeyPrefixes++;
    continue;
  }
  usedLiteral.add(m[1]);
}
// keys referenced from markup via data-i18n / data-i18n-title / data-i18n-ph
let markupKeyRefs = 0;
for (const m of html.matchAll(/\bdata-i18n(?:-title|-ph|-aria)?\s*=\s*"([^"]+)"/g)) {
  usedLiteral.add(m[1]);
  markupKeyRefs++;
}
// batch168: "no unknown key" is only meaningful if the markup was actually
// read. The page carries ~180 data-i18n* attributes; if the extractor stops
// matching (attribute renamed, rewritten to a different form, or the file read
// picks up the wrong region) usedLiteral collapses to whatever the script
// literals contribute and this gate reports a cheerful zero unknown keys while
// validating almost nothing. Require real coverage.
if (markupKeyRefs === 0) {
  fail('found 0 data-i18n* attribute(s) in www/index.html - the markup key extractor is broken, refusing to report OK');
}
const unknownLiteral = [...usedLiteral].filter((k) => !enKeys.has(k)).sort();

// ------------------------------------ unlocalized prose attributes (batch149)
// The checks above only look at keys that are REFERENCED. An attribute written
// straight into the markup - `<input placeholder="LAN IP">` - references no key
// at all, so every check above is blind to it and the string stays English in
// all 461 languages. Placeholders are the visible half of a field's label, so
// they must go through data-i18n-ph like every other label. A handful of
// placeholders are TECHNICAL SAMPLES rather than prose (a protocol name, an
// address pattern); translating those would be wrong, so they are listed here
// explicitly instead of being silently tolerated.
const PLACEHOLDER_SAMPLE_OK = new Set([
  'tcp',                 // protocol name, identical in every language
  'AA:BB:CC:DD:EE:FF',   // MAC address sample: a format, not prose
]);
const unlocalizedPlaceholders = [];
for (const m of html.matchAll(/<input\b[^>]*>/gi)) {
  const tag = m[0];
  const ph = tag.match(/\bplaceholder\s*=\s*"([^"]*)"/i);
  if (!ph) continue;
  if (/\bdata-i18n-ph\s*=/i.test(tag)) continue;
  if (PLACEHOLDER_SAMPLE_OK.has(ph[1])) continue;
  const line = html.slice(0, m.index).split('\n').length;
  unlocalizedPlaceholders.push(`www/index.html:${line}: placeholder="${ph[1]}"`);
}

// ------------------------------------- unlocalized captions (batch162)
// A <caption> is the table's ACCESSIBLE NAME. Writing the text straight into
// the markup - `<caption>DHCPv4 leases</caption>` - references no key, so every
// check above is blind to it and the name stays English in all 461 languages.
// This is the same hole placeholders had: the visible-label check only looks at
// keys that are REFERENCED, and a literal attribute is not a reference. A caption
// that is empty or purely decorative is not a name and is skipped by the gate
// that audits names (web_a11y), so anything reaching here must be translated.
const unlocalizedCaptions = [];
// Scan MARKUP only. The inline <style> carries a COMMENT that mentions
// `<caption>` in prose ("a <caption> is the accessible name of a table"), and a
// plain regex over the whole file starts matching there and runs until the first
// real </caption> - reporting a CSS sentence as an untranslated table name.
// Blank out <style>/<script> contents (same length, so line numbers survive)
// before looking for elements.
const markupOnly = html.replace(/<(style|script)\b[^>]*>[\s\S]*?<\/\1\s*>/gi,
  (m) => m.replace(/[^\n]/g, ' '));
for (const m of markupOnly.matchAll(/<caption\b([^>]*)>([\s\S]*?)<\/caption\s*>/gi)) {
  const attrs = m[1];
  const text = m[2].replace(/<[^>]*>/g, '').trim();
  if (text === '') continue;                       // empty: not a name
  if (/\bdata-i18n\s*=/i.test(attrs)) continue;    // translated
  const line = html.slice(0, m.index).split('\n').length;
  unlocalizedCaptions.push(`www/index.html:${line}: caption "${text}"`);
}

// ----------------------------------- server error tokens (batch143)
// api() localizes a backend failure as t("err." + j.error). t() returns the KEY
// itself when no entry exists, so any token the web layer can emit without an
// `err.<token>` entry renders as "err.binding exists" in the toast instead of a
// sentence. That is why the dynamic prefix above cannot be left unchecked: the
// table must cover every token the server can actually return as
// {"error":"<token>"}. Both producers are scanned:
//   - Response::Error(<status>, "<token>")            (route handlers)
//   - error = "<token>";                              (ReadRequest failures)
// A non-literal argument (Response::Error(400, error)) or a concatenation
// (error = "bind failed: " + msg) is not a fixed token and is skipped by the
// patterns below.
const serverTokens = new Set();
const SERVER_TOKEN_SOURCES = ['src/web/web_api.cpp', 'src/web/http_server.cpp'];
for (const rel of SERVER_TOKEN_SOURCES) {
  let src;
  try {
    src = readFileSync(join(resolve(root), rel), 'utf8');
  } catch (e) {
    fail(`cannot read ${rel}: ${e.message}`);
  }
  for (const m of src.matchAll(/Response::Error\(\s*\d+\s*,\s*"([^"]*)"\s*\)/g)) serverTokens.add(m[1]);
  for (const m of src.matchAll(/\berror\s*=\s*"([^"]*)"\s*;/g)) serverTokens.add(m[1]);
  // A handler that needs extra fields (the config 400 carries "reason" beside
  // "error") builds the body by hand instead of calling Response::Error, so the
  // token would silently leave this gate's coverage. Match the literal
  // `\"error\":\"<token>\"` spelling too; a concatenated value
  // (`\"error\":\"" + JsonEscaped(x)`) has no closing `\"` and is skipped, the
  // same way the Response::Error pattern skips a non-literal argument.
  for (const m of src.matchAll(/\\"error\\":\\"([^"\\]*)\\"/g)) serverTokens.add(m[1]);
}
// batch168: the same zero-coverage trap as the markup extractor. If both
// producer patterns stop matching (a refactor to Response::Error(400, Status())
// or a helper that returns the token), serverTokens is empty and "every server
// token is localized" becomes vacuously true. 63 tokens are localized today.
if (serverTokens.size === 0) {
  fail('parsed 0 server error token(s) from ' + SERVER_TOKEN_SOURCES.join(' / ')
    + ' - the extractor is broken, refusing to report OK');
}
const missingServerTokens = [...serverTokens].filter((tok) => !enKeys.has(`err.${tok}`)).sort();

// ---------------------------------------------- 401 localization (S4.6-W2)
// BUG b: a 401 must surface as a localized key, not as raw English. The
// `if (r.status === 401) { ... }` branch in api() must
//   - toast a t("...") lookup,
//   - throw an Error whose argument is a string literal that exists in en,
//   - and errMsg() must map that key's namespace, otherwise the key text
//     leaks into the toast instead of a translation.
const err401 = [];
{
  const head = script.match(/if\s*\(\s*\w+\.status\s*===\s*401\s*\)\s*\{/);
  if (!head) {
    err401.push('api(): cannot find the `if (<res>.status === 401) { ... }` branch');
  } else {
    const open = script.indexOf('{', head.index);
    let block = '';
    try { block = script.slice(open, skipBalanced(script, open)); } catch { /* handled below */ }
    if (!block) err401.push('api(): cannot parse the 401 branch');
    const thrown = block.match(/throw\s+new\s+Error\(\s*"((?:[^"\\]|\\.)*)"\s*\)/);
    if (!/\bt\(/.test(block)) err401.push('api() 401 branch does not localize its toast (no t("...") call)');
    if (!thrown) {
      err401.push('api() 401 branch must throw new Error("<i18n key>") - a raw English string leaks to the UI');
    } else {
      const key = thrown[1];
      if (!enKeys.has(key)) err401.push(`api() 401 branch throws key "${key}" which is not in the en table`);
      const ns = key.split('.')[0];
      if (!/^[A-Za-z_][\w$]*\./.test(key)) {
        err401.push(`api() 401 branch throws "${key}" - expected an i18n key like "auth.unauthorized"`);
      } else {
        const fn = script.match(/function\s+errMsg\s*\(/);
        let errMsgBody = '';
        if (fn) {
          const o = script.indexOf('{', fn.index);
          try { errMsgBody = script.slice(o, skipBalanced(script, o)); } catch { /* ignore */ }
        }
        if (!errMsgBody) err401.push('cannot find the errMsg() function to verify the 401 key mapping');
        else if (!new RegExp(`startsWith\\(\\s*["']${ns}\\.`).test(errMsgBody)) {
          err401.push(`errMsg() does not map the "${ns}." key namespace thrown by the 401 branch (the key text would leak)`);
        }
      }
    }
  }
}

// ------------------------------------------------------------ allowlist stale
const liveMissing = new Set(missingPairs);
const liveExtra = new Set(extraPairs);
const staleAllow = [];
for (const e of allowMissing) if (!liveMissing.has(e)) staleAllow.push(e);
for (const e of allowExtra) if (!liveExtra.has(e.replace(':!', ':'))) staleAllow.push(e);

// ------------------------------------------------------------------- --update
if (update) {
  const header = [
    '# i18n allowlist for scripts/check-i18n.mjs - regenerated by --update.',
    '# <lang>:<key>   acknowledged missing key (key exists in en, not in <lang>)',
    '# <lang>:!<key>  acknowledged extra key   (key exists in <lang>, not in en)',
    '# Regenerate: node scripts/check-i18n.mjs <repo-root> --update',
  ];
  const allowExtraKeys = new Set([...allowExtra].map((e) => e.replace(':!', ':')));
  const all = [
    ...[...allowMissing].filter((e) => liveMissing.has(e)),
    ...[...allowExtra].filter((e) => liveExtra.has(e.replace(':!', ':'))),
    ...[...liveMissing].filter((e) => !allowMissing.has(e)),
    ...[...liveExtra].filter((e) => !allowExtraKeys.has(e)).map((e) => e.replace(':', ':!')),
  ];
  const uniq = [...new Set(all)].sort();
  writeFileSync(allowPath, `${header.join('\n')}\n${uniq.map((l) => `${l}\n`).join('')}`);
  console.log(`OK ${NAME} --update: wrote ${uniq.length} entries to ${allowPath}`);
  process.exit(0);
}

// --------------------------------------------------------------------- report
const langCount = keysByLang.size;
console.log(`${NAME}: ${langCount} language block(s); en has ${enKeys.size} key(s); rtl codes ${rtlCodes.length}`);
if (unlistedExtra.length) console.log(`WARN ${NAME}: ${unlistedExtra.length} key(s) exist in one language but not in en (acknowledge with '<lang>:!<key>' in the allowlist)`);
if (dynamicKeyPrefixes) console.log(`${NAME}: ${dynamicKeyPrefixes} dynamic key prefix literal(s) ("err." + ...) not statically checkable`);
if (staleAllow.length) console.log(`WARN ${NAME}: ${staleAllow.length} allowlist entry/entries no longer occur (run --update to clean)`);

const failLines = [];
if (duplicates.length) failLines.push(`duplicate key(s): ${duplicates.join(', ')}`);
// batch205: a key that EXISTS but carries an EMPTY value is the same defect as
// a missing key, and harder to notice: every count in this gate says the key is
// present, while t() returns "" and the UI paints a blank. Emptied
// `en.dash.title` left the page title as "VGWW · " and the gate still printed
// OK (measured); emptying the zh-CN copy did the same. Whitespace-only counts
// too: "   " is not missing by any count but renders as an invisible label.
// `en` is the baseline (t() falls back to it) so an empty value there blanks
// EVERY language. The core languages are fatal; the rest reuse the existing
// missing-key allowlist instead of a second file.
const emptyEn = emptyValues.filter((e) => e.lang === 'en');
const emptyCore = emptyValues.filter((e) => e.lang !== 'en' && CORE_LANGS.includes(e.lang));
const emptyOther = emptyValues.filter((e) => e.lang !== 'en' && !CORE_LANGS.includes(e.lang) && !allowMissing.has(`${e.lang}:${e.key}`));
if (emptyEn.length) {
  failLines.push('key(s) with an EMPTY value in en (the baseline - every language falls back to it, so the UI paints blank):');
  for (const e of emptyEn) failLines.push(`  en:${e.key} = ${e.raw}`);
}
if (emptyCore.length) {
  failLines.push(`key(s) with an EMPTY value in a core language (allowlist cannot bless ${CORE_LANGS.join('/')}):`);
  for (const e of emptyCore) failLines.push(`  ${e.lang}:${e.key} = ${e.raw}`);
}
if (emptyOther.length) {
  failLines.push('key(s) with an EMPTY value and no allowlist entry:');
  for (const e of emptyOther) failLines.push(`  ${e.lang}:${e.key} = ${e.raw}`);
}
if (unlistedMissing.length) {
  failLines.push('key(s) missing vs en without allowlist entry:');
  for (const e of unlistedMissing) failLines.push(`  ${e}`);
}
if (unknownLiteral.length) {
  failLines.push(`literal key(s) used outside the table but absent from en:`);
  for (const k of unknownLiteral) failLines.push(`  ${k}`);
}
if (missingServerTokens.length) {
  failLines.push('server error token(s) with no "err.<token>" entry in en (the toast would show the raw key):');
  for (const t of missingServerTokens) failLines.push(`  err.${t}`);
}
if (unlocalizedPlaceholders.length) {
  failLines.push('placeholder(s) with no data-i18n-ph (the string stays English in every language):');
  for (const p of unlocalizedPlaceholders) failLines.push(`  ${p}`);
}
if (unlocalizedCaptions.length) {
  failLines.push('table caption(s) with no data-i18n (the table name stays English in every language):');
  for (const p of unlocalizedCaptions) failLines.push(`  ${p}`);
}
if (rtlUnknown.length) failLines.push(`rtl-languages.txt code(s) with no I18N block: ${rtlUnknown.join(', ')}`);
if (rtlFalsy.length) failLines.push(`RTL language(s) whose lang.rtl value is falsy: ${rtlFalsy.join(', ')}`);
if (rtlMissing.length) failLines.push(`RTL language(s) missing lang.rtl: ${rtlMissing.join(', ')}`);
if (err401.length) {
  failLines.push('401 localization (api()/errMsg):');
  for (const e of err401) failLines.push(`  ${e}`);
}

if (failLines.length) {
  console.error(`FAIL ${NAME}:`);
  for (const l of failLines) console.error(`  ${l}`);
  process.exit(1);
}
if (coreMissing.length) {
  console.error(`FAIL ${NAME} core-language completeness (allowlist cannot bless ${CORE_LANGS.join('/')}):`);
  for (const e of coreMissing) console.error(`  ${e}`);
  process.exit(1);
}
if (coreSameAsEn.length) {
  console.error(`FAIL ${NAME} core-language value copied verbatim from en (silently stays English):`);
  for (const e of coreSameAsEn) console.error(`  ${e}`);
  process.exit(1);
}
console.log(`OK ${NAME} (missing=${missingPairs.length} acknowledged, extra=${extraPairs.length}, rtl=${rtlCodes.length} covered, server_tokens=${serverTokens.size} localized)`);
