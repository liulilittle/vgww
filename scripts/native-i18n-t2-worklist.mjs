#!/usr/bin/env node
// native-i18n-t2-worklist.mjs - batch19 R4-P1 T2 batching / resume helper.
//
// The T2 data are AI-generated per language into scripts/native-i18n-t2/<code>.json
// (keyed by Str enum name). This tool drives the batched generation:
//
//   --summary            : per language, how many keys still need T2.
//   --lang <code>        : print the exact {key, en} work units for one language
//                          (feed these to the AI translator).
//   --merge <code> <file>: merge an AI-produced JSON into <code>.json and write
//                          it back (resume: existing entries are kept, new ones
//                          added; a wrong '{' count is rejected).
//   --pending            : list only languages that still have unresolved keys.
//
// Resume: presence of scripts/native-i18n-t2/<code>.json + non-empty entries is
// the progress checkpoint; gen-native-i18n.mjs consumes whatever exists.
//
// Usage: node scripts/native-i18n-t2-worklist.mjs <repo-root> <cmd> [...]
import { readFileSync, writeFileSync, existsSync, readdirSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

const root = process.argv[2];
const cmd = process.argv[3];
if (!root) { console.error('FAIL t2-worklist: missing <repo-root>'); process.exit(1); }
const repo = resolve(root);
const t2Dir = join(repo, 'scripts', 'native-i18n-t2');

function skipString(t, i) { const q = t[i]; let j = i + 1; while (j < t.length) { const c = t[j]; if (c === '\\') { j += 2; continue; } if (c === q) return j + 1; j++; } throw new Error('str'); }
function skipBalanced(t, i) { const p = { '{': '}', '(': ')', '[': ']' }; const cl = p[t[i]]; let d = 1, j = i + 1; while (j < t.length) { const c = t[j]; if (c === '/' && t[j + 1] === '/') { const nl = t.indexOf('\n', j); j = nl < 0 ? t.length : nl + 1; continue; } if (c === '/' && t[j + 1] === '*') { const e = t.indexOf('*/', j + 2); j = e < 0 ? t.length : e + 2; continue; } if (c === '"' || c === "'" || c === '`') { j = skipString(t, j); continue; } if (c === cl) { d--; if (d === 0) return j + 1; j++; continue; } if (Object.prototype.hasOwnProperty.call(p, c)) { j = skipBalanced(t, j); continue; } j++; } throw new Error('bal'); }

const cpp = readFileSync(join(repo, 'src', 'ui', 'i18n.cpp'), 'utf8');
function arr(name) { const at = cpp.indexOf(`${name}[] = {`); const o = cpp.indexOf('{', at); const c = skipBalanced(cpp, o); const b = cpp.slice(o + 1, c - 1); const out = []; const re = /L"((?:[^"\\]|\\.)*)"/g; let m; while ((m = re.exec(b)) !== null) out.push(m[1].replace(/\\(.)/g, (_, x) => (x === 'n' ? '\n' : x === 't' ? '\t' : x === 'r' ? '\r' : x))); return out; }
const en = arr('kStringsEn');
const h = readFileSync(join(repo, 'src', 'ui', 'i18n.h'), 'utf8');
const es = h.indexOf('enum class Str');
let eb = h.slice(es, h.indexOf('};', es)).replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
eb = eb.slice(eb.indexOf('{') + 1).replace(/\b_Count\b/, '');
const names = eb.split(',').map((s) => s.trim()).filter((s) => /^[A-Za-z_]\w*$/.test(s));

const mapFile = JSON.parse(readFileSync(join(repo, 'scripts', 'native-i18n-map.json'), 'utf8'));
const t1 = mapFile.map || {};
// en/zh-CN are native; T1-covered keys need no T2.
const needT2 = names.map((n, i) => ({ n, i })).filter(({ n }) => !(n in t1));
const t2Of = (code) => (existsSync(join(t2Dir, `${code}.json`)) ? JSON.parse(readFileSync(join(t2Dir, `${code}.json`), 'utf8').replace(/^\uFEFF/, '')) : {});
const inc = readFileSync(join(repo, 'src', 'ui', 'i18n_languages.inc'), 'utf8');
const codes = [...inc.matchAll(/\{"([^"]+)",/g)].map((m) => m[1]).filter((c) => c !== 'en' && c !== 'zh-CN');

if (cmd === '--summary') {
  const rows = codes.map((c) => { const d = t2Of(c); const missing = needT2.filter(({ n }) => !(typeof d[n] === 'string' && d[n] !== '')).length; return { c, missing }; });
  const done = rows.filter((r) => r.missing === 0).length;
  console.log(`T2 languages=${codes.length} complete=${done} pending=${codes.length - done}`);
  for (const r of rows) if (r.missing > 0 && r.missing < needT2.length) console.log(`  ${r.c}: ${r.missing} pending`);
} else if (cmd === '--pending') {
  for (const c of codes) { const d = t2Of(c); if (needT2.some(({ n }) => !(typeof d[n] === 'string' && d[n] !== ''))) console.log(c); }
} else if (cmd === '--lang' && process.argv[4]) {
  const code = process.argv[4];
  const d = t2Of(code);
  const units = needT2.filter(({ n }) => !(typeof d[n] === 'string' && d[n] !== '')).map(({ n, i }) => ({ key: n, en: en[i] }));
  console.log(JSON.stringify(units, null, 2));
} else if (cmd === '--merge' && process.argv[4] && process.argv[5]) {
  const code = process.argv[4];
  const incoming = JSON.parse(readFileSync(resolve(process.argv[5]), 'utf8').replace(/^\uFEFF/, ''));
  const cur = t2Of(code);
  const braces = (s) => (s.match(/\{/g) || []).length;
  let added = 0, rejected = 0;
  for (const { n, i } of needT2) {
    const v = incoming[n];
    if (typeof v !== 'string' || v === '') continue;
    if (braces(v) !== braces(en[i])) { rejected++; continue; }
    if (typeof cur[n] !== 'string' || cur[n] === '') { cur[n] = v; added++; }
  }
  if (!existsSync(t2Dir)) mkdirSync(t2Dir, { recursive: true });
  writeFileSync(join(t2Dir, `${code}.json`), JSON.stringify(cur, null, 2));
  console.log(`merge ${code}: +${added} added, ${rejected} rejected (bad placeholder count)`);
} else {
  console.error('usage: --summary | --pending | --lang <code> | --merge <code> <file>');
  process.exit(2);
}
