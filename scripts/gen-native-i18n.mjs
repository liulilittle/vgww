#!/usr/bin/env node
// gen-native-i18n.mjs - batch19 R4-P1 generation (T1 map + T2 AI data).
//
// Produces:
//   * src/ui/i18n_languages.inc  - runtime language catalog (code/name/rtl)
//                                  from www order (en first).
//   * src/ui/i18n_gen.bin        - M1 compact-UTF-8 resource with ALL 461
//                                  languages x kTableSize native strings.
//   * logs/b19-r4/native-i18n-coverage.json - per-language mapped/t2/fallback
//                                  counts (review artifact).
//
// Per language:
//   en      -> native en array
//   zh-CN   -> native zh array
//   other   -> T2 file (scripts/native-i18n-t2/<code>.json) if present,
//              else T1 map -> www translation, else the en fallback.
// A mapped/T2 value is rejected (-> fallback) when its '{' count differs from
// the en string (placeholder safety).
//
// Usage: node scripts/gen-native-i18n.mjs <repo-root>
import { readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

const root = process.argv[2];
if (!root) { console.error('FAIL gen-native-i18n: missing <repo-root>'); process.exit(1); }
const repo = resolve(root);
function fail(d) { console.error(`FAIL gen-native-i18n: ${d}`); process.exit(1); }

function skipString(text, i) {
  const q = text[i]; let j = i + 1;
  while (j < text.length) { const c = text[j]; if (c === '\\') { j += 2; continue; } if (c === q) return j + 1; j++; }
  throw new Error('unterminated string');
}
function skipBalanced(text, i) {
  const pairs = { '{': '}', '(': ')', '[': ']' }; const closer = pairs[text[i]]; let depth = 1, j = i + 1;
  while (j < text.length) {
    const c = text[j];
    if (c === '/' && text[j + 1] === '/') { const nl = text.indexOf('\n', j); j = nl < 0 ? text.length : nl + 1; continue; }
    if (c === '/' && text[j + 1] === '*') { const e = text.indexOf('*/', j + 2); j = e < 0 ? text.length : e + 2; continue; }
    if (c === '"' || c === "'" || c === '`') { j = skipString(text, j); continue; }
    if (c === closer) { depth--; if (depth === 0) return j + 1; j++; continue; }
    if (Object.prototype.hasOwnProperty.call(pairs, c)) { j = skipBalanced(text, j); continue; }
    j++;
  }
  throw new Error('unbalanced');
}
function splitTopLevel(body) {
  const parts = []; let depth = 0, start = 0, i = 0;
  while (i < body.length) {
    const c = body[i];
    if (c === '"' || c === "'" || c === '`') { i = skipString(body, i); continue; }
    if (c === '{' || c === '(' || c === '[') { depth++; i++; continue; }
    if (c === '}' || c === ')' || c === ']') { depth--; i++; continue; }
    if (c === ',' && depth === 0) { parts.push(body.slice(start, i)); start = i + 1; i++; continue; }
    i++;
  }
  parts.push(body.slice(start));
  return parts.map((p) => p.trim()).filter((p) => p !== '');
}
function splitKey(part) {
  let depth = 0, i = 0;
  while (i < part.length) {
    const c = part[i];
    if (c === '"' || c === "'" || c === '`') { i = skipString(part, i); continue; }
    if (c === '{' || c === '(' || c === '[') { depth++; i++; continue; }
    if (c === '}' || c === ')' || c === ']') { depth--; i++; continue; }
    if (c === ':' && depth === 0) return [part.slice(0, i).trim(), part.slice(i + 1).trim()];
    i++;
  }
  return [null, part];
}
function unquote(raw) {
  if (raw[0] === '"' || raw[0] === "'") { const end = skipString(raw, 0); return raw.slice(1, end - 1).replace(/\\(.)/g, '$1'); }
  return raw;
}
const braces = (s) => (s.match(/\{/g) || []).length;

// ------------------------------------------------------------ native arrays
const cpp = readFileSync(join(repo, 'src', 'ui', 'i18n.cpp'), 'utf8');
function extractArray(name) {
  const at = cpp.indexOf(`${name}[] = {`);
  if (at < 0) fail(`cannot find ${name}[]`);
  const open = cpp.indexOf('{', at);
  const close = skipBalanced(cpp, open);
  const body = cpp.slice(open + 1, close - 1);
  const out = []; const re = /L"((?:[^"\\]|\\.)*)"/g; let m;
  while ((m = re.exec(body)) !== null) out.push(m[1].replace(/\\(.)/g, (_, c) => (c === 'n' ? '\n' : c === 't' ? '\t' : c === 'r' ? '\r' : c)));
  return out;
}
const nativeZh = extractArray('kStringsZh');
const nativeEn = extractArray('kStringsEn');
if (nativeZh.length !== nativeEn.length) fail('zh/en length mismatch');
const keyCount = nativeEn.length;

const h = readFileSync(join(repo, 'src', 'ui', 'i18n.h'), 'utf8');
const enumStart = h.indexOf('enum class Str');
let enumBody = h.slice(enumStart, h.indexOf('};', enumStart))
  .replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
enumBody = enumBody.slice(enumBody.indexOf('{') + 1).replace(/\b_Count\b/, '');
const nativeNames = enumBody.split(',').map((s) => s.trim()).filter((s) => /^[A-Za-z_]\w*$/.test(s));
if (nativeNames.length !== keyCount) fail(`native names=${nativeNames.length} strings=${keyCount}`);

// ------------------------------------------------------------- www tables
const html = readFileSync(join(repo, 'www', 'index.html'), 'utf8');
const scripts = [];
{
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi; let m;
  while ((m = re.exec(html)) !== null) {
    const attrs = m[1] || '';
    if (/\bsrc\s*=/i.test(attrs)) continue;
    const tm = attrs.match(/\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
    if (tm) { const type = (tm[1] ?? tm[2] ?? tm[3] ?? '').trim().toLowerCase(); if (!['', 'text/javascript', 'application/javascript', 'module', 'text/ecmascript', 'application/ecmascript'].includes(type)) continue; }
    scripts.push(m[2]);
  }
}
const script = scripts.join('\n;\n');
const anchor = 'const I18N = {';
const at = script.indexOf(anchor);
if (at < 0) fail('cannot find const I18N');
const bodyOpen = at + anchor.length - 1;
const bodyClose = skipBalanced(script, bodyOpen);
const www = new Map();
for (const part of splitTopLevel(script.slice(bodyOpen + 1, bodyClose - 1))) {
  const [kRaw, value] = splitKey(part);
  if (kRaw === null || !value.startsWith('{')) continue;
  const code = unquote(kRaw);
  const close = skipBalanced(value, 0);
  const m = new Map();
  const re = /"([^"]+)"\s*:\s*"((?:[^"\\]|\\.)*)"/g;
  let mm;
  const block = value.slice(1, close - 1);
  while ((mm = re.exec(block)) !== null) m.set(mm[1], mm[2].replace(/\\(.)/g, '$1'));
  www.set(code, m);
}

// -------------------------------------------------------------- catalog list
const rtlCodes = new Set(readFileSync(join(repo, 'scripts', 'rtl-languages.txt'), 'utf8')
  .split(/\r?\n/).map((l) => l.replace(/#.*$/, '').trim()).filter((l) => l !== ''));
const selAt = html.indexOf('id="langsel"');
const selEnd = html.indexOf('</select>', selAt);
const selBody = html.slice(selAt, selEnd);
const decodeEntity = (s) => s.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'");
const catalog = [];
{
  const re = /<option\s+value="([^"]*)"\s*>([\s\S]*?)<\/option>/g; let m;
  while ((m = re.exec(selBody)) !== null) catalog.push({ code: m[1], name: decodeEntity(m[2].trim()), rtl: rtlCodes.has(m[1]) });
}
if (catalog.length < 2) fail('catalog parse failed');

// ------------------------------------------------------------ T1/T2 sources
const mapFile = JSON.parse(readFileSync(join(repo, 'scripts', 'native-i18n-map.json'), 'utf8'));
const t1 = mapFile.map || {};
const t2Dir = join(repo, 'scripts', 'native-i18n-t2');
const t2 = new Map();
if (existsSync(t2Dir)) {
  for (const f of readdirSync(t2Dir)) {
    if (f.endsWith('.json')) {
      try { t2.set(f.slice(0, -5), JSON.parse(readFileSync(join(t2Dir, f), 'utf8'))); } catch { /* ignore */ }
    }
  }
}

// -------------------------------------------------------------- assemble
function assemble(code) {
  if (code === 'en') return { strings: nativeEn, mapped: keyCount, t2n: 0, untranslated: 0, enEqual: 0 };
  if (code === 'zh-CN') return { strings: nativeZh, mapped: keyCount, t2n: 0, untranslated: 0, enEqual: 0 };
  const wwwTable = www.get(code);
  const t2Table = t2.get(code);
  const strings = [];
  let mapped = 0, t2n = 0, untranslated = 0;
  for (let i = 0; i < keyCount; i++) {
    const name = nativeNames[i];
    let v;
    if (t2Table && typeof t2Table[name] === 'string' && t2Table[name] !== '') { v = t2Table[name]; if (braces(v) === braces(nativeEn[i])) { t2n++; strings.push(v); continue; } }
    const key = t1[name];
    if (key && wwwTable && wwwTable.has(key)) { const w = wwwTable.get(key); if (braces(w) === braces(nativeEn[i])) { mapped++; strings.push(w); continue; } }
    untranslated++; strings.push(nativeEn[i]);
  }
  // AUTHORITATIVE fallback metric = the string the user actually sees is the
  // en text (a mapped www translation can legitimately equal en, e.g. "LAN"/"OK").
  let enEqual = 0;
  for (let i = 0; i < keyCount; i++) { if (strings[i] === nativeEn[i]) enEqual++; }
  return { strings, mapped, t2n, untranslated, enEqual };
}

const langs = catalog.map((c) => ({ ...c, ...assemble(c.code) }));

// ----------------------------------------------------------------- write inc
const esc = (s) => s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
const inc = [
  '// AUTO-GENERATED by scripts/gen-native-i18n.mjs - DO NOT EDIT.',
  `// www language catalog: ${catalog.length} languages, www order (en first).`,
  'struct NativeLanguageEntry { const char* code; const char* name; bool rtl; };',
  'constexpr NativeLanguageEntry kLanguageCatalog[] = {',
  ...catalog.map((l) => `    {"${esc(l.code)}", "${esc(l.name)}", ${l.rtl ? 'true' : 'false'}},`),
  '};',
  `constexpr std::size_t kLanguageCatalogSize = ${catalog.length};`,
  '',
];
writeFileSync(join(repo, 'src', 'ui', 'i18n_languages.inc'), inc.join('\n'));

// ----------------------------------------------------------------- write bin
function blockFor(strings) {
  const chunks = strings.map((s) => Buffer.from(s, 'utf8'));
  let size = 4; for (const c of chunks) size += 4 + c.length;
  const buf = Buffer.alloc(size); buf.writeUInt32LE(chunks.length, 0); let off = 4;
  for (const c of chunks) { buf.writeUInt32LE(c.length, off); c.copy(buf, off + 4); off += 4 + c.length; }
  return buf;
}
const blocks = langs.map((l) => ({ code: l.code, rtl: l.rtl, buf: blockFor(l.strings) }));
let headerLen = 12;
for (const l of blocks) headerLen += 1 + 1 + Buffer.byteLength(l.code, 'utf8') + 8;
let total = headerLen; for (const l of blocks) total += l.buf.length;
const out = Buffer.alloc(total); let p = 0;
out.write('VGI1', p); p += 4; out.writeUInt32LE(1, p); p += 4; out.writeUInt32LE(blocks.length, p); p += 4;
let dataOff = headerLen;
for (const l of blocks) {
  const cb = Buffer.from(l.code, 'utf8');
  out.writeUInt8(cb.length, p); p += 1; out.writeUInt8(l.rtl ? 1 : 0, p); p += 1;
  cb.copy(out, p); p += cb.length; out.writeUInt32LE(dataOff, p); p += 4; out.writeUInt32LE(l.buf.length, p); p += 4;
  dataOff += l.buf.length;
}
for (const l of blocks) { l.buf.copy(out, p); p += l.buf.length; }
writeFileSync(join(repo, 'src', 'ui', 'i18n_gen.bin'), out);

// ------------------------------------------------------------- coverage file
const totalKeys = catalog.length * keyCount;
// Authoritative = content equals en (what the validator reports/ what a user
// sees). structural = no T1/T2 source hit. They differ when a reused www
// translation is identical to en ("LAN", "OK", ...).
const enEqualTotal = langs.reduce((a, l) => a + l.enEqual, 0);
const untranslatedTotal = langs.reduce((a, l) => a + l.untranslated, 0);
const coverage = {
  metric: 'authoritative fallback = resource string equals the en table (excludes en/zh-CN blocks)',
  languages: catalog.length, keysPerLanguage: keyCount,
  t2Languages: langs.filter((l) => l.t2n > 0).map((l) => l.code),
  authoritativeFallbackTotal: enEqualTotal,
  structuralUntranslatedTotal: untranslatedTotal,
  totalKeys,
  authoritativeFallbackPct: Number(((enEqualTotal / totalKeys) * 100).toFixed(2)),
  structuralUntranslatedPct: Number(((untranslatedTotal / totalKeys) * 100).toFixed(2)),
  perLanguage: langs.map((l) => ({ code: l.code, mapped: l.mapped, t2: l.t2n, untranslated: l.untranslated, enEqual: l.enEqual })),
};
try { writeFileSync(join(repo, 'logs', 'b19-r4', 'native-i18n-coverage.json'), JSON.stringify(coverage, null, 2)); } catch { /* dir may be absent */ }

console.log(`OK gen-native-i18n: ${catalog.length} languages x ${keyCount} keys; bin=${total}B; authoritative fallback=${enEqualTotal}/${totalKeys} (${coverage.authoritativeFallbackPct}%); structural untranslated=${untranslatedTotal} (${coverage.structuralUntranslatedPct}%)`);
