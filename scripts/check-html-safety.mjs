#!/usr/bin/env node
// Gate: web_html_safety
// Every `${...}` interpolation assigned to `.innerHTML` must be safe:
//   - wrapped in esc(...) or json(...), or
//   - produced by an approved helper: t(), fmt(), fmtRate() (local formatters /
//     i18n table lookups), or
//   - a literal (number/string/boolean/null) or a parameter bound by an arrow
//     function inside the same statement (loop indices such as `${i}`), or
//   - a top-level conditional whose two branches are themselves safe
//     (e.g. `${cond ? " spd" : ""}`).
// Anything else (member/index access on runtime data such as `${c[0]}`) is a
// FAIL with file:line:col. `.textContent` assignments are not scanned.
// Statements are delimited by scanning to the terminating ';' outside any
// bracket/string/template nesting, so multi-line `.map(...).join("")` chains
// are treated as one statement.
//
// Usage: node scripts/check-html-safety.mjs <repo-root> [--update]
//        --update rewrites scripts/html-safety.allowlist from the current
//        findings (one `www/index.html:<line>` per finding).
// Exit:  0 = OK (WARNs allowed), 1 = FAIL (or missing arg / unparsable input).
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const NAME = 'html-safety';
const REL = 'www/index.html';
// batch149: tableSpan(tableId) returns the table's column COUNT (a number read
// from its <thead>), so it is safe in an innerHTML interpolation and is the one
// source of truth for an "empty/error row" width.
const APPROVED_CALLEES = new Set(['esc', 'json', 't', 'fmt', 'fmtRate', 'tableSpan']);
const root = process.argv[2];
const update = process.argv.includes('--update');
if (!root) {
  console.error(`FAIL ${NAME}: missing <repo-root> argument (usage: node scripts/check-html-safety.mjs <repo-root> [--update])`);
  process.exit(1);
}
function fail(detail) {
  console.error(`FAIL ${NAME}: ${detail}`);
  process.exit(1);
}

const htmlPath = join(resolve(root), REL);
const allowPath = join(resolve(root), 'scripts', 'html-safety.allowlist');
let html;
try { html = readFileSync(htmlPath, 'utf8'); } catch (e) { fail(`cannot read ${htmlPath}: ${e.message}`); }

// ---------------------------------------------------------------- primitives
function skipString(text, i) {
  const q = text[i];
  let j = i + 1;
  while (j < text.length) {
    const c = text[j];
    if (c === '\\') { j += 2; continue; }
    if (q === '`' && c === '$' && text[j + 1] === '{') { j = skipBalanced(text, j + 1); continue; }
    if (c === q) return j + 1;
    j++;
  }
  return text.length; // unterminated: caller reports
}

function skipBalanced(text, i) {
  const pairs = { '{': '}', '(': ')', '[': ']' };
  const closer = pairs[text[i]];
  if (!closer) throw new Error(`internal: skipBalanced at '${text[i]}'`);
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
  throw new Error(`unbalanced '${text[i]}' at offset ${i}`);
}

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text[i] === '\n') line++;
  return line;
}

// Find the end of the assignment statement (first ';' at top level).
function statementEnd(text, start) {
  let depth = 0;
  let i = start;
  const limit = Math.min(text.length, start + 20000);
  while (i < limit) {
    const c = text[i];
    if (c === '/' && text[i + 1] === '/') {
      const nl = text.indexOf('\n', i);
      if (nl < 0) return -1;
      i = nl + 1;
      continue;
    }
    if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      if (end < 0) return -1;
      i = end + 2;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      const next = skipString(text, i);
      if (text[next - 1] !== c && next >= text.length) return -1; // unterminated
      i = next;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') { depth++; i++; continue; }
    if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth < 0) return -1; // left the statement without ';' - bail out
      i++;
      continue;
    }
    if (c === ';' && depth === 0) return i + 1;
    i++;
  }
  return -1;
}

// Collect `${...}` interpolations at any depth of the statement's templates.
function collectInterpolations(stmt) {
  const out = [];
  let i = 0;
  while (i < stmt.length) {
    const c = stmt[i];
    if (c === '/' && stmt[i + 1] === '/') {
      const nl = stmt.indexOf('\n', i);
      i = nl < 0 ? stmt.length : nl + 1;
      continue;
    }
    if (c === '/' && stmt[i + 1] === '*') {
      const end = stmt.indexOf('*/', i + 2);
      i = end < 0 ? stmt.length : end + 2;
      continue;
    }
    if (c === '"' || c === "'") { i = skipString(stmt, i); continue; }
    if (c === '`') {
      let j = i + 1;
      while (j < stmt.length) {
        const d = stmt[j];
        if (d === '\\') { j += 2; continue; }
        if (d === '$' && stmt[j + 1] === '{') {
          const end = skipBalanced(stmt, j + 1);
          out.push({ expr: stmt.slice(j + 2, end - 1), index: j });
          j = end;
          continue;
        }
        if (d === '`') break;
        j++;
      }
      i = j + 1;
      continue;
    }
    i++;
  }
  return out;
}

// ------------------------------------------------------------- interpolation
function completeCall(expr) {
  const m = expr.match(/^([A-Za-z_$][\w$]*)\s*\(/);
  if (!m) return null;
  const open = m[0].length - 1;
  let end;
  try { end = skipBalanced(expr, open); } catch { return null; }
  if (expr.slice(end).trim() !== '') return null;
  return { callee: m[1] };
}

function topLevelTernary(expr) {
  let depth = 0;
  let q = -1;
  for (let i = 0; i < expr.length; i++) {
    const c = expr[i];
    if (c === '"' || c === "'" || c === '`') { i = skipString(expr, i) - 1; continue; }
    if (c === '(' || c === '[' || c === '{') { depth++; continue; }
    if (c === ')' || c === ']' || c === '}') { depth--; continue; }
    if (c === '?' && depth === 0 && expr[i + 1] !== '.' && expr[i + 1] !== '?') { q = i; break; }
  }
  if (q < 0) return null;
  depth = 0;
  for (let i = q + 1; i < expr.length; i++) {
    const c = expr[i];
    if (c === '"' || c === "'" || c === '`') { i = skipString(expr, i) - 1; continue; }
    if (c === '(' || c === '[' || c === '{') { depth++; continue; }
    if (c === ')' || c === ']' || c === '}') { depth--; continue; }
    if (c === ':' && depth === 0) return { test: expr.slice(0, q), then: expr.slice(q + 1, i), otherwise: expr.slice(i + 1) };
  }
  return null;
}

function isBoundParam(stmt, id) {
  if (!/=>/.test(stmt)) return false;
  const re = new RegExp(`[(,]\\s*(?:[A-Za-z_$][\\w$]*\\s*,\\s*)*${id.replace(/\$/g, '\\$')}\\s*[,)]`);
  return re.test(stmt);
}

function classify(expr, stmt) {
  const e = expr.trim();
  if (e === '') return { ok: false, reason: 'empty interpolation' };
  const call = completeCall(e);
  if (call) {
    if (APPROVED_CALLEES.has(call.callee)) return { ok: true, kind: call.callee === 'esc' || call.callee === 'json' ? `escaped by ${call.callee}()` : `approved helper ${call.callee}()` };
    return { ok: false, reason: `call to unapproved helper ${call.callee}(...)` };
  }
  if (/^-?(\d+(\.\d+)?|\.\d+)$/.test(e)) return { ok: true, kind: 'numeric literal' };
  if (/^(['"])(?:[^\\]|\\.)*\1$/.test(e)) return { ok: true, kind: 'string literal' };
  if (/^(true|false|null|undefined)$/.test(e)) return { ok: true, kind: 'literal' };
  const cond = topLevelTernary(e);
  if (cond) {
    const a = classify(cond.then, stmt);
    const b = classify(cond.otherwise, stmt);
    if (a.ok && b.ok) return { ok: true, kind: 'conditional with safe branches' };
    return { ok: false, reason: `conditional branch not escaped: ${a.ok ? '' : `then=(${cond.then.trim()}) `}${b.ok ? '' : `else=(${cond.otherwise.trim()})`}` };
  }
  if (/^[A-Za-z_$][\w$]*$/.test(e) && isBoundParam(stmt, e)) return { ok: true, kind: `bound parameter ${e}` };
  return { ok: false, reason: 'expression not escaped - needs esc(...) or json(...)' };
}

// -------------------------------------------------------------------- detect
const findings = []; // {line, col, expr, reason}
const stmtLines = new Set();
const deadHelpers = [];
const re = /\binnerHTML\s*(\+?=)(?!=)/g;
let m;
let statements = 0;
while ((m = re.exec(html)) !== null) {
  const start = m.index + m[0].length;
  const end = statementEnd(html, start);
  if (end < 0) fail(`${REL}:${lineOf(html, m.index)}: cannot determine the end of the innerHTML assignment statement (unlikely syntax); refusing to skip it`);
  statements++;
  const stmt = html.slice(start, end);
  const startLine = lineOf(html, m.index);
  let bad = 0;
  for (const it of collectInterpolations(stmt)) {
    const r = classify(it.expr, stmt);
    if (!r.ok) {
      bad++;
      findings.push({
        line: lineOf(html, start + it.index),
        col: it.index - (stmt.lastIndexOf('\n', it.index) + 1) + 1,
        expr: it.expr.trim(),
        reason: r.reason,
      });
    }
  }
  if (bad > 0) stmtLines.add(startLine);
}

// ------------------------------------------------------------------ allowlist
let allow = new Set();
try {
  allow = new Set(
    readFileSync(allowPath, 'utf8')
      .split(/\r?\n/)
      .map((l) => l.replace(/#.*$/, '').trim())
      .filter((l) => l !== '')
      .map((l) => {
        const mm = l.match(/^(.*?):(\d+)$/);
        if (!mm) fail(`${allowPath}: bad entry ${JSON.stringify(l)} (expected <path>:<line>)`);
        return `${mm[1]}:${mm[2]}`;
      })
  );
} catch (e) {
  if (e && e.code === 'ENOENT') fail(`cannot read ${allowPath}: file must exist (empty file is fine)`);
  throw e;
}
const suppressed = findings.filter((f) => allow.has(`${REL}:${f.line}`));
const active = findings.filter((f) => !allow.has(`${REL}:${f.line}`));
const live = new Set(findings.map((f) => `${REL}:${f.line}`));
const stale = [...allow].filter((e) => !live.has(e));

if (update) {
  const header = [
    '# html-safety allowlist for scripts/check-html-safety.mjs - regenerated by --update.',
    '# <path>:<line> suppresses the finding(s) on that line; keep a trailing',
    '# comment stating why the interpolation is safe. Regenerate with:',
    '#   node scripts/check-html-safety.mjs <repo-root> --update',
  ];
  const lines = [...new Set(active.map((f) => `${REL}:${f.line}`))].sort((a, b) => Number(a.split(':').pop()) - Number(b.split(':').pop()));
  writeFileSync(allowPath, `${header.join('\n')}\n${lines.map((l) => `${l}\n`).join('')}`);
  console.log(`OK ${NAME} --update: wrote ${lines.length} entr(y/ies) to ${allowPath}`);
  process.exit(0);
}

// "Nothing was scanned" and "everything scanned was safe" are not the same
// answer. batch167: after the last innerHTML assignment was removed this gate
// printed "OK ... 0 innerHTML statement(s) scanned" - a result that looks
// identical to a clean bill of health but actually means the detector examined
// nothing at all, so a regression could never be caught again.
//
// The guard has to look at CODE, not at the raw text: the page legitimately
// mentions innerHTML in comments that explain why every assignment is gone, and
// counting those would make the guard fire on a correct page. Strip the
// comments and the string literals (same state machine the dead-helper check
// uses), then ask: does the executable code touch innerHTML at all?
// batch203: keep the script text at its ORIGINAL offsets so the findings below
// can report real file line numbers. The old join("\n") produced a synthetic
// document whose line 1 was the first script's line 1 - every reported line was
// then off by however much markup preceded the code (measured: an injection
// inserted at line 3542 was reported as line 2689). Blank out everything that is
// not script body with spaces, preserving length and newlines.
const scriptSpans = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script\s*>/gi)]
  .map((mm) => ({ text: mm[1], start: mm.index + mm[0].indexOf('>') + 1 }));
let codeOnly = html.replace(/[^\n]/g, ' ');
for (const span of scriptSpans) {
  codeOnly = codeOnly.slice(0, span.start) + span.text + codeOnly.slice(span.start + span.text.length);
}
codeOnly = stripJsComments(codeOnly);
if (/\binnerHTML\b/.test(codeOnly) && statements === 0) {
  console.error(`FAIL ${NAME}: the scripts reference innerHTML but the scanner found 0`
    + ` assignment statement(s) - the detector is not looking at the code it is meant`
    + ` to check (scan range / regex / comment stripping is wrong). Refusing to report OK.`);
  process.exit(1);
}

// batch203: innerHTML is not the only way to put markup into the document, and it
// is no longer the way this page does ANYTHING. batch166 removed the last
// assignment and deleted `esc()` with it (www/index.html:3093-3097): rows are
// built as elements and every value goes through textContent. That makes any
// markup-injection API a regression on its own, whatever it is called - yet the
// scanner only knew the literal `innerHTML`, so inserting
//
//   el.insertAdjacentHTML("beforeend", "<b>" + window.__clientList[0].ip + "</b>")
//
// left this gate printing OK (measured). There is no escaping to check here: the
// policy is zero injection points, so the presence of one is the finding.
const INJECTION_APIS = [
  'insertAdjacentHTML',       // parses markup into the DOM, same risk as innerHTML
  'outerHTML',                // replaces the element wholesale, same parsing
  'document.write',           // parses its argument into the document
  'document.writeln',
  'createContextualFragment', // builds nodes from a markup string
  'DOMParser',                // parseFromString(..., 'text/html') yields injectable nodes
  'srcdoc',                   // an iframe's entire document, as markup
];
const injectionHits = [];
for (const api of INJECTION_APIS) {
  // Dot-containing names (document.write) must not match `documentXwrite`.
  const escaped = api.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const hitRe = new RegExp('\\b' + escaped + '\\b', 'g');
  let hm;
  while ((hm = hitRe.exec(codeOnly)) !== null) {
    injectionHits.push({ api: api, line: lineOf(codeOnly, hm.index) });
  }
}
if (injectionHits.length) {
  console.error(`FAIL ${NAME}: ${injectionHits.length} markup-injection call(s) in the page -`
    + ` this page builds elements and writes textContent (www/index.html:3093), so no`
    + ` injection point may exist at all:`);
  for (const h of injectionHits) console.error(`  - ${REL}:${h.line}: ${h.api}`);
  process.exit(1);
}

if (stale.length) console.log(`WARN ${NAME}: stale allowlist entr(y/ies): ${stale.join(', ')}`);

if (active.length) {
  console.error(`FAIL ${NAME}: ${active.length} unwrapped interpolation(s) in ${stmtLines.size} innerHTML statement(s):`);
  for (const f of active) console.error(`  ${REL}:${f.line}:${f.col}: \${${f.expr}} - ${f.reason}`);
  process.exit(1);
}
// A helper that exists only so that the escape gate will approve interpolations
// is itself a lie once nothing interpolates any more. batch166: after the last
// innerHTML assignment was removed, `esc()` still sat in APPROVED_CALLEES
// while having ZERO call sites - the gate would have happily approved an
// `esc(...)` call that no longer does anything, and nothing else noticed that
// the function had become dead. A dead escape helper is worse than none: it
// reads like protection.
// Comments must be stripped before counting: this very file's history comment
// says "esc() used to live here", and a naive count read that as a call site -
// so a re-added dead helper stayed green. Strip line and block comments while
// keeping strings intact (a "//" inside a string is not a comment).
function stripJsComments(src) {
  let out = "";
  let q = "";
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (q) {
      out += c;
      if (c === '\\') { out += src[++i] || ""; continue; }
      if (c === q) q = "";
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { q = c; out += c; continue; }
    if (c === '/' && src[i + 1] === '/') {
      while (i < src.length && src[i] !== '\n') i++;
      out += '\n';
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      i += 2;
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) i++;
      i++;
      out += ' ';
      continue;
    }
    out += c;
  }
  return out;
}
// EVERY inline script, not just the first: the page has a small theme-bootstrap
// script before the main console script, and reading only the first one checked
// a region that does not contain the helpers at all (so the dead-helper check
// below could never fire).
const scriptSrc = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script\s*>/gi)]
  .map((m) => stripJsComments(m[1]))
  .join("\n");
for (const fn of APPROVED_CALLEES) {
  if (!/^[A-Za-z_$][\w$]*$/.test(fn)) continue;
  const declared = new RegExp(`function\\s+${fn}\\s*\\(`).test(scriptSrc);
  if (!declared) continue;
  // Count CALLS only. "function esc(" also matches a naive "esc(" search, so
  // the declaration has to be removed from the text before counting - without
  // that subtraction a declared-but-uncalled helper looks like it calls itself
  // and the check can never fire (which is exactly how the first version of
  // this check stayed green).
  const withoutDecls = scriptSrc.replace(new RegExp(`function\\s+${fn}\\s*\\(`, 'g'), "function ");
  const calls = [...withoutDecls.matchAll(new RegExp(`(?<![\\w$.])${fn}\\s*\\(`, 'g'))].length;
  if (calls === 0) {
    deadHelpers.push(`${REL}: escape helper "${fn}()" is declared but never called - remove it or restore its use`);
  }
}

if (deadHelpers.length) {
  console.error(`FAIL ${NAME}:`);
  for (const d of deadHelpers) console.error(`  ${d}`);
  process.exit(1);
}

// The readout must say WHY zero is acceptable. "0 statements" alone is
// indistinguishable from "the detector never ran", which is exactly the failure
// mode this batch fixed.
const coverage = statements === 0
  ? '0 innerHTML assignment(s) in the page - nothing to escape (checked: no code references innerHTML)'
  : `${statements} innerHTML assignment(s) scanned`;
console.log(`OK ${NAME} (${coverage}, ${suppressed.length} allowlisted)`);
