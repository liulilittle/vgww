#!/usr/bin/env node
// Gate: web_api_contract
// The front end (www/index.html) may only call backend routes that actually
// exist in src/web/web_api.cpp:
//   front  = literal paths of api("...") / fetch("...") starting with /api/
//            (query string and fragment stripped)
//   back   = paths of  server.Route("METHOD", "/path", ...)  (tolerates line
//            breaks and whitespace between the arguments)
//   front \ back  -> FAIL (dead call / typo)
//   back \ front  -> must be listed in scripts/api-backend-only.allowlist
//                    (routes intentionally not used by the web UI)
//   SET_FIELDS    -> every settings field whose backend counterpart is parsed
//                    with get<uint32_t>() in src/core/config.cpp must carry
//                    kind:"number" metadata and be coerced with Number() in
//                    saveSettings (BUG a regression guard, S4.6-W1).
//
// Usage: node scripts/check-api-contract.mjs <repo-root> [--update]
//        --update regenerates scripts/api-backend-only.allowlist (sorted).
// Exit:  0 = OK (WARNs allowed), 1 = FAIL (or missing arg / unreadable input /
//        zero backend routes found - the extractor itself must be right).
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const NAME = 'api-contract';
const root = process.argv[2];
const update = process.argv.includes('--update');
if (!root) {
  console.error(`FAIL ${NAME}: missing <repo-root> argument (usage: node scripts/check-api-contract.mjs <repo-root> [--update])`);
  process.exit(1);
}
function fail(detail) {
  console.error(`FAIL ${NAME}: ${detail}`);
  process.exit(1);
}

const htmlPath = join(resolve(root), 'www', 'index.html');
const cppPath = join(resolve(root), 'src', 'web', 'web_api.cpp');
const allowPath = join(resolve(root), 'scripts', 'api-backend-only.allowlist');

let html;
try { html = readFileSync(htmlPath, 'utf8'); } catch (e) { fail(`cannot read ${htmlPath}: ${e.message}`); }
let cpp;
try { cpp = readFileSync(cppPath, 'utf8'); } catch (e) { fail(`cannot read ${cppPath}: ${e.message}`); }

// front end: api("...") / api('...') / fetch("...") / fetch('...')
// batch201: the path alone is not the contract. A call to a route that only
// exists under a DIFFERENT method answers 405 and the page shows a failure -
// but the old extractor keyed on the path only, so `DELETE /api/portmap`
// rewritten as `POST /api/portmap` still passed this gate (measured: the
// gate stayed green with a route that does not exist). Record the verb.
const front = new Map(); // path -> Set("line" or call form) for reporting
const frontCalls = [];   // { method, path, line } - one entry per call site
// The URL argument is NOT always a bare literal: three delete calls build the
// query by concatenation (`api("/api/bans?id=" + id, { method: "DELETE" })`),
// so the text between the closing quote and the options object is ` + id, `,
// not `, `. A scan anchored right after the literal therefore read those as
// GETs - which is how a DELETE rewritten to POST stayed invisible. Locate the
// whole call with the parenthesis matcher instead, then read the verb out of
// its argument list.
const frontRe = /\b(api|fetch)\(\s*(["'])([^"'\\]*)\2/g;
for (const m of html.matchAll(frontRe)) {
  const raw = m[3];
  if (!raw.startsWith('/api/')) continue;
  const p = raw.split(/[?#]/)[0];
  if (!front.has(p)) front.set(p, []);
  front.get(p).push(m[1]);
  // The call opens at the '(' before the literal.
  const openParen = html.lastIndexOf('(', m.index + m[1].length);
  let callEnd = openParen >= 0 ? openParen + 1 : m.index + m[0].length;
  if (openParen >= 0) {
    try { callEnd = skipBalanced(html, openParen); } catch { callEnd = m.index + m[0].length; }
  }
  const args = html.slice(openParen >= 0 ? openParen : m.index, callEnd);
  // A call with no method option is a GET (fetch's default), which is how the
  // page reads every list.
  let method = 'GET';
  const mm = /\bmethod\s*:\s*["']([A-Za-z]+)["']/.exec(args);
  if (mm) method = mm[1].toUpperCase();
  frontCalls.push({ method: method, path: p, line: html.slice(0, m.index).split(/\r?\n/).length });
}

// back end: server.Route("METHOD", "/path" ...) - whitespace tolerant (multiline)
const back = new Set();
const backRe = /Route\s*\(\s*"([A-Za-z]+)"\s*,\s*"([^"]+)"/g;
let pairs = 0;
for (const m of cpp.matchAll(backRe)) {
  back.add(m[2].split(/[?#]/)[0]);
  pairs++;
}
if (pairs === 0) fail(`no backend routes extracted from ${cppPath} - extractor regex must match this codebase (refusing to report OK)`);

// batch167: "nothing was compared" and "everything compared matched" look the
// same in the output. If either side parses to zero routes the cross-check is
// vacuous - a renamed route prefix, a changed `api(` call form, or a Route()
// signature change would all silently turn this gate green forever.
if (front.size === 0) fail('parsed 0 front-end route(s) from www/index.html - the extractor is broken, refusing to report OK');
if (back.size === 0) fail('parsed 0 backend route(s) from src/web/web_api.cpp - the extractor is broken, refusing to report OK');

// batch201: cross-check the VERB as well as the path. `back` above is a set of
// paths (that is what the path diff reports); this is the method-aware view.
const backPairs = new Set();
for (const m of cpp.matchAll(backRe)) backPairs.add(m[1].toUpperCase() + ' ' + m[2].split(/[?#]/)[0]);
if (backPairs.size === 0) fail('parsed 0 (method, route) pair(s) from src/web/web_api.cpp - the method extractor is broken, refusing to report OK');
if (frontCalls.length === 0) fail('parsed 0 front-end call site(s) with a method - the method extractor is broken, refusing to report OK');
const verbProblems = [];
for (const call of frontCalls) {
  if (!backPairs.has(call.method + ' ' + call.path)) {
    verbProblems.push(`www/index.html:${call.line}: ${call.method} ${call.path} - the backend registers no such (method, path) pair, so this call can only answer 405`);
  }
}

const frontExtra = [...front.keys()].filter((p) => !back.has(p)).sort();
const backendOnly = [...back].filter((p) => !front.has(p)).sort();

let allow = [];
try {
  allow = readFileSync(allowPath, 'utf8')
    .split(/\r?\n/)
    .map((l) => l.replace(/#.*$/, '').trim())
    .filter((l) => l !== '');
} catch (e) {
  if (e && e.code === 'ENOENT') fail(`cannot read ${allowPath}: file must exist (empty file is fine)`);
  throw e;
}
const allowSet = new Set(allow);
const unallowedBackendOnly = backendOnly.filter((p) => !allowSet.has(p));
const stale = allow.filter((p) => !backendOnly.includes(p));

if (update) {
  const header = [
    '# Routes that exist in src/web/web_api.cpp but are intentionally not called',
    '# by www/index.html (e.g. no DHCP page yet). Regenerate with:',
    '#   node scripts/check-api-contract.mjs <repo-root> --update',
  ];
  writeFileSync(allowPath, `${header.join('\n')}\n${backendOnly.map((p) => `${p}\n`).join('')}`);
  console.log(`OK ${NAME} --update: wrote ${backendOnly.length} entr(y/ies) to ${allowPath}`);
  process.exit(0);
}

// ------------------------------------------------ SET_FIELDS number coercion
// BUG a regression guard (S4.6-W1). The settings panel GETs /api/config and
// POSTs it back as a full replacement. The backend loader is strict: fields it
// parses with get<uint32_t>() (e.g. perf.workers / perf.max_conns) reject a
// JSON string, so the front end must convert those inputs to numbers. The
// conversion decision must be per-entry metadata inside SET_FIELDS (kind/type),
// never a hardcoded path list - otherwise the next numeric field is missed
// again. Cross-checked against the loader in src/core/config.cpp.
const cfgPath = join(resolve(root), 'src', 'core', 'config.cpp');
let cfgCpp;
try { cfgCpp = readFileSync(cfgPath, 'utf8'); } catch (e) { fail(`cannot read ${cfgPath}: ${e.message} (needed for the SET_FIELDS integer cross-check)`); }

function skipBalanced(text, i) {
  const pairs = { '{': '}', '(': ')', '[': ']' };
  const closer = pairs[text[i]];
  if (!closer) throw new Error(`internal: skipBalanced at '${text[i]}'`);
  let depth = 1;
  let j = i + 1;
  while (j < text.length) {
    const c = text[j];
    if (c === '"' || c === "'" || c === '`') {
      const q = c;
      j++;
      while (j < text.length) {
        if (text[j] === '\\') { j += 2; continue; }
        if (text[j] === q) { j++; break; }
        j++;
      }
      continue;
    }
    if (c === closer) { depth--; if (depth === 0) return j + 1; j++; continue; }
    if (Object.prototype.hasOwnProperty.call(pairs, c)) { j = skipBalanced(text, j); continue; }
    j++;
  }
  throw new Error(`unbalanced '${text[i]}' at offset ${i}`);
}
function splitTopLevel(text) {
  const parts = [];
  let depth = 0;
  let start = 0;
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === '"' || c === "'" || c === '`') {
      const q = c;
      i++;
      while (i < text.length) {
        if (text[i] === '\\') { i += 2; continue; }
        if (text[i] === q) { i++; break; }
        i++;
      }
      continue;
    }
    if (c === '{' || c === '(' || c === '[') { depth++; i++; continue; }
    if (c === '}' || c === ')' || c === ']') { depth--; i++; continue; }
    if (c === ',' && depth === 0) { parts.push(text.slice(start, i)); start = i + 1; i++; continue; }
    i++;
  }
  parts.push(text.slice(start));
  return parts;
}
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const setFieldsMatch = html.match(/const\s+SET_FIELDS\s*=\s*\[([\s\S]*?)\n\s*\];/);
if (!setFieldsMatch) fail('cannot find `const SET_FIELDS = [ ... ];` in www/index.html - refusing to report OK');
const setFields = [];
for (const part of splitTopLevel(setFieldsMatch[1])) {
  if (part.trim() === '') continue;
  const kindMatch = part.match(/(?:kind|type)\s*:\s*"([^"]+)"/);
  const quoted = [...part.matchAll(/"([^"]*)"/g)].map((mm) => mm[1]);
  if (quoted.length < 2) fail(`cannot parse SET_FIELDS entry: ${part.trim().slice(0, 80)}`);
  setFields.push({
    path: quoted[0],
    id: quoted[1],
    kind: kindMatch ? kindMatch[1] : quoted.length > 2 ? quoted[2] : null,
    // The raw entry text: the range/hint cross-check below reads min/max/ph
    // from it. The quoted-string view above cannot see unquoted numbers.
    raw: part.trim(),
  });
}
if (setFields.length === 0) fail('SET_FIELDS parsed to zero entries - parser is wrong, refusing to report OK');

// The coercion statement: the SET_FIELDS.forEach(...) block in saveSettings
// (the one that reads el.value and converts before POSTing).
let coercion = null;
for (const mm of html.matchAll(/SET_FIELDS\.forEach\(/g)) {
  const open = html.indexOf('(', mm.index);
  let end;
  try { end = skipBalanced(html, open); } catch { continue; }
  const block = html.slice(open, end);
  if (/el\.value\.trim\(\)/.test(block) || /Number\s*\(/.test(block)) { coercion = block; break; }
}
if (!coercion) fail('cannot find the saveSettings SET_FIELDS.forEach coercion block in www/index.html');

const metaDriven = /\w+\s*\.\s*(kind|type)\s*===?\s*["']number["']/.test(coercion) ||
                   /switch\s*\(\s*\w+\s*\.\s*(kind|type)\s*\)/.test(coercion);
const usesNumber = /Number\s*\(/.test(coercion);

// Loader typing: scan the assignment line that mentions config.<path> plus the
// 6 lines above it. Short window on purpose - a wider one would pick up
// get<uint32_t>() calls from neighbouring Parse* functions.
//   integer     : an integer get<>() shapes this field -> the UI must POST a number
//   non-integer : get<std::string> etc. -> the UI must POST a string
//   untyped     : found, but parsed via a helper (JsonToIpv4/JsonToMac) - no constraint
//   missing     : not mentioned in src/core/config.cpp at all -> typo/renamed
// batch22 S2: a few JSON keys the Web form edits do not match the C++ member
// spelling (the config FILE keeps its own names, so the JSON path is right and
// only this cross-check needs the alias):
//   JSON dhcp.pool[]  <-> config.dhcp.pool_start / pool_end
//   JSON dhcp.lease_hours <-> config.dhcp.lease_seconds
const PATH_ALIASES = {
  'dhcp.pool.0': 'dhcp.pool_start',
  'dhcp.pool.1': 'dhcp.pool_end',
  'dhcp.lease_hours': 'dhcp.lease_seconds',
};

function backendType(path) {
  path = PATH_ALIASES[path] || path;
  const re = new RegExp(`config\\.${escapeRe(path)}\\s*[=,)]`);
  const m = re.exec(cfgCpp);
  if (!m) return 'missing';
  const lineStart = cfgCpp.lastIndexOf('\n', m.index) + 1;
  const lineEnd = cfgCpp.indexOf('\n', m.index);
  let windowStart = lineStart;
  for (let n = 0; n < 6; n++) {
    const prev = cfgCpp.lastIndexOf('\n', windowStart - 2);
    if (prev < 0) { windowStart = 0; break; }
    windowStart = prev + 1;
  }
  const windowText = cfgCpp.slice(windowStart, lineEnd < 0 ? cfgCpp.length : lineEnd);
  if (/get<\s*(?:u?int(?:8|16|32|64)_t|unsigned[^>]*|size_t|long[^>]*)\s*>/.test(windowText)) return 'integer';
  if (/get<\s*(?:std::string|bool|double|float)\s*>/.test(windowText)) return 'non-integer';
  return 'untyped';
}

const fieldIssues = [];
// Coverage of the coercion: metadata-driven (kind === "number") when the save
// code branches on the metadata, otherwise fall back to the hardcoded list /
// regex tokens actually present in the block.
function hardcodedCovered(path) {
  const leaf = path.split('.').pop();
  for (const mm of coercion.matchAll(/["']([A-Za-z_][\w.]*)["']/g)) if (mm[1] === path) return true;
  const rx = coercion.match(/\/((?:\\.|[^/\n])*)\/\s*\.test\s*\(/);
  if (rx) {
    const body = rx[1].replace(/^\^/, '').replace(/\$$/, '');
    const tokens = body.replace(/[()]/g, '').split('|').map((t) => t.replace(/\\(.)/g, '$1').trim());
    // The regex is applied to whatever expression the block passes to .test();
    // a dotted path only matches a dotted token, a leaf only matches a leaf.
    const testsLeaf = /\.test\s*\(\s*[\w.]*\.(?:split\s*\(\s*["'][^"']*["']\s*\)\s*\.pop|pop)\s*\(/.test(coercion);
    if (tokens.includes(path)) return true;
    if (testsLeaf && tokens.includes(leaf)) return true;
  }
  return false;
}
for (const f of setFields) {
  if (!f.kind) fieldIssues.push(`SET_FIELDS entry "${f.path}" has no kind/type metadata`);
  else if (f.kind !== 'number' && f.kind !== 'string' && f.kind !== 'bool' && f.kind !== 'csv') fieldIssues.push(`SET_FIELDS entry "${f.path}" has unknown kind "${f.kind}" (expected number|string|bool|csv)`);
  const type = backendType(f.path);
  if (type === 'missing') fieldIssues.push(`SET_FIELDS path "${f.path}" not found in src/core/config.cpp (typo, or the backend field was renamed)`);
  // batch22 S1: a "bool" entry is loaded/saved through the checkbox
  // (.checked) - the coercion is the boolean branch that must exist in BOTH
  // the load and save paths.
  if (f.kind === 'bool') {
    if (!/\.checked/.test(html)) {
      fieldIssues.push(`SET_FIELDS entry "${f.path}" is bool-typed but the form never reads/writes .checked`);
    }
    continue;
  }
  // batch22 S2: a csv entry maps an array field to a comma-separated string -
  // the load path must join and the save path must split.
  if (f.kind === 'csv') {
    if (!/\.split\(/.test(html)) {
      fieldIssues.push(`SET_FIELDS entry "${f.path}" is csv-typed but the save path never splits the string`);
    }
    if (!/\.join\(/.test(html)) {
      fieldIssues.push(`SET_FIELDS entry "${f.path}" is csv-typed but the load path never joins the array`);
    }
    continue;
  }
  const covered = metaDriven ? f.kind === 'number' : hardcodedCovered(f.path);
  if (type === 'integer' && !covered) fieldIssues.push(`SET_FIELDS path "${f.path}" is integer-typed in src/core/config.cpp but the save path never converts it to a JSON number (kind=${f.kind ?? 'none'})`);
  if (type === 'non-integer' && f.kind === 'number') fieldIssues.push(`SET_FIELDS path "${f.path}" is not an integer field in src/core/config.cpp but is coerced as a number`);
}
// ------------------------------------------------ GET /api/config coverage (batch206)
// The settings form is a LOAD-then-SAVE round trip: it reads the current
// document from GET /api/config, edits it, and posts the whole thing back. A
// field the form edits but the GET never emits arrives as undefined, and the
// next save writes the DEFAULT over whatever the operator had. That happened
// to perf.rx_poll_ms: persisted and validated in config.cpp, absent from the
// GET body, silently reset on every save. The SET_FIELDS list is the set of
// fields the form edits, so every one of its paths must appear as a JSON key
// inside the GET /api/config response builder.
let apiCpp = '';
try { apiCpp = readFileSync(join(resolve(root), 'src', 'web', 'web_api.cpp'), 'utf8'); } catch (e) { fail(`cannot read src/web/web_api.cpp: ${e.message} (needed for the GET /api/config coverage cross-check)`); }
// Only the GET /api/config handler body: from its Route(...) to the next Route(
// (or EOF). Scanning the whole file would match the POST parser and hide a
// missing GET field.
// Locate the GET /api/config handler. The Route call is written across lines
// ("GET", then "/api/config"), so anchor on the path literal that precedes the
// request lambda, then bound the body at the next route registration.
const getCfgPathAt = apiCpp.indexOf('"/api/config"');
const getCfgAt = getCfgPathAt < 0 ? -1 : apiCpp.lastIndexOf('"GET"', getCfgPathAt);
if (getCfgAt < 0) fail('cannot find GET /api/config route in src/web/web_api.cpp');
const getCfgNext = apiCpp.indexOf('Route(', getCfgPathAt);
const getCfgBody = apiCpp.slice(getCfgAt, getCfgNext < 0 ? apiCpp.length : getCfgNext);
for (const f of setFields) {
  const parts = f.path.split('.');
  const leaf = parts[parts.length - 1];
  // dhcp.pool.0 / dhcp.pool.1 are array elements of the "pool" key.
  const key = /^\d+$/.test(leaf) ? parts[parts.length - 2] : leaf;
  // Every emitted key appears as "\"<key>\":" inside a C++ string literal
  // that is streamed into the response (json << "..."). Match the escaped
  // form the source actually contains.
  const emitted = getCfgBody.includes(`\\"${key}\\":`);
  if (!emitted) {
    fieldIssues.push(`SET_FIELDS path "${f.path}" is edited by the settings form but GET /api/config never emits "${key}" - a save writes the default over the operator value`);
  }
}
// ---------------------------------------- ToJsonString vs GET /api/config (batch206)
// The strongest form of the round-trip contract: every key the PERSISTER emits
// (Config::ToJsonString) must also be emitted by GET /api/config, or a Web save
// silently resets it to the default. This catches fields the settings form does
// not even edit (perf.rx_flush_eager was exactly that). Secrets are exempt: the
// GET must never hand a credential back.
let cfgToJson = '';
try { cfgToJson = readFileSync(join(resolve(root), 'src', 'core', 'config.cpp'), 'utf8'); } catch (e) { fail(`cannot read src/core/config.cpp: ${e.message} (needed for the ToJsonString key cross-check)`); }
const toJsonAt = cfgToJson.indexOf('ToJsonString');
if (toJsonAt < 0) fail('cannot find Config::ToJsonString in src/core/config.cpp');
const toJsonBody = cfgToJson.slice(toJsonAt, toJsonAt + 6000);
// Keys appear either as json{{"k", v}, ...} or root["k"] = ... or [[ "k", x ]].
const persistKeys = new Set();
for (const mm of toJsonBody.matchAll(/\["([A-Za-z_][A-Za-z0-9_]*)"\]/g)) persistKeys.add(mm[1]);
for (const mm of toJsonBody.matchAll(/\{\{"([A-Za-z_][A-Za-z0-9_]*)"/g)) persistKeys.add(mm[1]);
// `{"key", perf.field}` inside a json{...} initializer (comma form).
for (const mm of toJsonBody.matchAll(/\{"([A-Za-z_][A-Za-z0-9_]*)",\s*[A-Za-z_]/g)) persistKeys.add(mm[1]);
// Root-level containers are emitted as objects; their children are checked too
// through the same scan, so only the leaf-key set matters here.
const SECRET_KEYS = new Set(['token']);  // never returned by GET
for (const key of persistKeys) {
  if (SECRET_KEYS.has(key)) continue;
  // Skip the container names themselves (perf/web/vlan/bridge/dhcp/ipv6).
  if (['root', 'json', 'perf', 'web', 'vlan', 'bridge', 'dhcp', 'ipv6',
       'dhcpv6', 'static_bindings', 'dns'].includes(key)) continue;
  const emitted = getCfgBody.includes(`\\"${key}\\":`) || getCfgBody.includes(`\\"${key}\\"`);
  if (!emitted) {
    fieldIssues.push(`Config::ToJsonString emits "${key}" but GET /api/config never does - a Web save silently resets it to the default`);
  }
}


// ------------------------------------------------- range hint agreement (batch163)
// A numeric field's min/max is the bound the form now enforces; its placeholder
// (set.ph.*) is the range the operator is TOLD. If the two disagree the UI lies:
// the hint said "1-720" for lease hours while the loader accepts up to 8760, and
// "256-65536" for the MAC table while the loader accepts 1. Only entries that
// declare a `ph` key AND whose hint is written as "A-B" are checked; a hint that
// is a sample value ("64", "1800") is not a range claim.
const enBlock = html.match(/\n\s{2}"en":\s*\{([\s\S]*?)\n\s{2}\},/);
const enHints = new Map();
if (enBlock) {
  for (const mm of enBlock[1].matchAll(/"([^"]+)":"((?:[^"\\]|\\.)*)"/g)) {
    if (mm[1].startsWith('set.ph.')) enHints.set(mm[1], mm[2]);
  }
}
for (const f of setFields) {
  if (f.kind !== 'number') continue;
  if (!/min:\s*\d+/.test(f.raw) || !/max:\s*\d+/.test(f.raw)) {
    fieldIssues.push(`SET_FIELDS entry "${f.path}" is numeric but declares no min/max - the form cannot refuse an out-of-range value`);
    continue;
  }
  const min = Number((f.raw.match(/min:\s*(\d+)/) || [])[1]);
  const max = Number((f.raw.match(/max:\s*(\d+)/) || [])[1]);
  if (!(min <= max)) fieldIssues.push(`SET_FIELDS entry "${f.path}" has min ${min} > max ${max}`);
  const phKey = (f.raw.match(/ph:\s*"([^"]+)"/) || [])[1];
  if (!phKey) continue;
  const hint = enHints.get(phKey);
  if (hint === undefined) {
    fieldIssues.push(`SET_FIELDS entry "${f.path}" names placeholder key "${phKey}" which is absent from the en table`);
    continue;
  }
  const range = hint.match(/^(\d+)\s*-\s*(\d+)$/);
  if (!range) continue;   // a sample value, not a range claim
  const hLo = Number(range[1]);
  const hHi = Number(range[2]);
  // 0 is the "off" value and is documented separately (e.g. VLAN "0 = off"),
  // so a hint never writes it into the range.
  const expectLo = min === 0 ? 1 : min;
  if (hLo !== expectLo || hHi !== max) {
    fieldIssues.push(`placeholder "${phKey}" says "${hint}" but SET_FIELDS "${f.path}" enforces [${min}, ${max}] - the hint lies about the accepted range`);
  }
}
if (!metaDriven) fieldIssues.push('saveSettings does not branch on the per-entry kind/type metadata (a hardcoded path list would miss the next numeric field)');
if (!usesNumber) fieldIssues.push('saveSettings never calls Number(...) - numeric inputs would reach the strict loader as JSON strings');

console.log(`${NAME}: front routes ${front.size}, backend routes ${back.size} (${pairs} Route call(s)); SET_FIELDS ${setFields.length} entr(y/ies), ${setFields.filter((f) => f.kind === 'number').length} number-typed`);
if (stale.length) console.log(`WARN ${NAME}: allowlist entr(y/ies) not backend-only anymore: ${stale.join(', ')}`);

if (frontExtra.length || unallowedBackendOnly.length || fieldIssues.length || verbProblems.length) {
  console.error(`FAIL ${NAME}:`);
  if (frontExtra.length) {
    console.error(`  front-end call(s) without a backend route:`);
    for (const p of frontExtra) console.error(`    ${p}`);
  }
  if (unallowedBackendOnly.length) {
    console.error(`  backend route(s) not called by the UI and not allowlisted (scripts/api-backend-only.allowlist):`);
    for (const p of unallowedBackendOnly) console.error(`    ${p}`);
  }
  if (fieldIssues.length) {
    console.error(`  SET_FIELDS number coercion:`);
    for (const s of fieldIssues) console.error(`    ${s}`);
  }
  if (verbProblems.length) {
    console.error(`  front-end call(s) whose (method, route) pair does not exist:`);
    for (const s of verbProblems) console.error(`    ${s}`);
  }
  process.exit(1);
}
console.log(`OK ${NAME} (${backendOnly.length} backend-only route(s) allowlisted; SET_FIELDS coercion metadata-driven)`);
