#!/usr/bin/env node
// Gate: web_a11y
// Every visible form control must have an ACCESSIBLE NAME from an explicit
// source, and no two controls may share one. Buttons follow the same rule, with
// an extra demand: a button RENDERED PER ROW must name its row, otherwise every
// row offers the identical "Delete" and a screen-reader user cannot tell which
// entry they are about to remove. Tables follow it too: a table with no name is
// announced as "table, 6 columns" and nothing else, and the Leases page stacks
// FOUR of them - four anonymous tables in a row.
//
// Why this gate exists: the page shipped with fourteen controls that had no
// name at all, and three of them were named by the same `title="Devices"`
// (`data-i18n-title="dev.title"`) - the filter, the sort key and the sort
// direction. A screen-reader user heard "Devices, combo box" three times in a
// row and had no way to tell which was which. `title`/`placeholder` alone are
// not accepted here:
//   * a placeholder is gone the moment the operator types, so the name
//     disappears exactly while it is needed;
//   * `title` is not surfaced by every screen reader, and it is not visible
//     while the control has focus.
// An explicit `<label for>`, an implicit `<label>` wrapper, `aria-label`,
// `data-i18n-aria` (translated at runtime like every other visible string) or
// `aria-labelledby` is required.
//
// Usage: node scripts/check-web-a11y.mjs <repo-root> [--update]
// Exit:  0 = OK (WARNs allowed), 1 = FAIL
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const NAME = 'a11y';
const root = process.argv[2];
const update = process.argv.includes('--update');
if (!root) {
  console.error(`FAIL ${NAME}: missing <repo-root> argument (usage: node scripts/check-web-a11y.mjs <repo-root>)`);
  process.exit(1);
}

const htmlPath = join(resolve(root), 'www', 'index.html');
const allowPath = join(resolve(root), 'scripts', 'web-a11y.allowlist');

function fail(detail) {
  console.error(`FAIL ${NAME}: ${detail}`);
  process.exit(1);
}

let html;
try {
  html = readFileSync(htmlPath, 'utf8');
} catch (e) {
  fail(`cannot read ${htmlPath}: ${e.message}`);
}

// Only the page body is audited; the inline script is not markup.
const bodyMatch = html.match(/<body\b[^>]*>([\s\S]*)<\/body\s*>/i);
if (!bodyMatch) fail(`no <body> block found in ${htmlPath}`);
const body = bodyMatch[1];
const bodyStart = html.indexOf(bodyMatch[1]);

function lineOf(index) {
  return html.slice(0, bodyStart + index).split('\n').length;
}

// -------------------------------------------------------------- explicit labels
// <label for="id"> ... </label>  (explicit association)
const labelFor = new Map(); // id -> { key, text }
for (const m of body.matchAll(/<label\b([^>]*)>([\s\S]*?)<\/label\s*>/gi)) {
  const attrs = m[1];
  const id = (attrs.match(/\bfor\s*=\s*"([^"]+)"/i) || [])[1];
  if (!id) continue; // the label wraps its control instead (handled below)
  const key = (attrs.match(/\bdata-i18n\s*=\s*"([^"]+)"/i) || [])[1] || '';
  labelFor.set(id, { key, text: m[2].replace(/<[^>]*>/g, '').trim() });
}

// ------------------------------------------------------------ authoritative list
// Controls that may legitimately have no name, each with a written reason.
const ALLOW = new Map([
  // (none today - an entry here must be justified: "it is a technical sample"
  // is not enough, a name is still needed for a screen reader)
]);

let allow = [];
try {
  allow = readFileSync(allowPath, 'utf8')
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s && !s.startsWith('#'));
} catch (e) {
  if (e.code !== 'ENOENT') fail(`cannot read ${allowPath}: ${e.message}`);
}
for (const tok of allow) {
  if (!ALLOW.has(tok)) fail(`allowlist entry "${tok}" has no documented reason in check-web-a11y.mjs`);
}
const allowSet = new Set(allow);

// ------------------------------------------------------------------- audit
// batch204: `aria-labelledby="x"` NAMES NOTHING unless #x exists AND carries
// text. The gate used to accept the attribute as a name on sight, so pointing
// it at a deleted (or never-written) id produced a control the screen reader
// announces as blank - and the gate still reported it as named (measured:
// retargeting #langsel from lang-label to a nonexistent id kept all 43 controls
// "named"). A dangling reference is worse than no reference: it looks handled.
//
// Resolve every id in the page once, then answer two questions per reference:
//   - does the id exist at all?
//   - does the element contain anything a screen reader would read (text, or a
//     data-i18n key that applyI18n will fill in)?
const idText = new Map(); // id -> { line, text }  ('' when the element is empty)
for (const m of body.matchAll(/<([a-zA-Z][\w-]*)\b([^>]*)>/g)) {
  const id = (m[2].match(/\bid\s*=\s*"([^"]+)"/i) || [])[1];
  if (!id || idText.has(id)) continue;
  // The element's own content: up to its closing tag when it is a simple
  // container, otherwise (a void element) nothing.
  const openEnd = m.index + m[0].length;
  const closeAt = body.indexOf('</' + m[1], openEnd);
  const inner = closeAt < 0 ? '' : body.slice(openEnd, closeAt);
  const key = (m[2].match(/\bdata-i18n\s*=\s*"([^"]+)"/i) || [])[1] ||
              (inner.match(/\bdata-i18n\s*=\s*"([^"]+)"/i) || [])[1] || '';
  let text = (key || inner.replace(/<[^>]*>/g, '')).trim();
  // batch204: a FORM CONTROL's own content is not a label. `<select id="x">`
  // contains its <option> list, so aria-labelledby="x" on itself appeared to
  // "have text" and passed (measured: retargeting #langsel at #langsel was
  // reported OK). A control cannot name itself, and its option text is the
  // choices, not the name - treat a control's inner text as empty.
  if (/^(input|select|textarea|button)$/i.test(m[1])) text = '';
  idText.set(id, { line: lineOf(m.index), text, tag: m[1].toLowerCase() });
}
/// Resolve one aria-labelledby value (whitespace-separated id list).
/// Returns null when it names something real, or a human-readable reason.
function labelledbyProblem(value) {
  const ids = String(value).trim().split(/\s+/).filter(Boolean);
  if (ids.length === 0) return 'the attribute is empty';
  const dead = ids.filter((id) => !idText.has(id));
  if (dead.length) return 'it points at ' + dead.map((d) => '#' + d).join(', ') + ' which does not exist';
  const blank = ids.filter((id) => !idText.get(id).text);
  if (blank.length) return 'it points at ' + blank.map((d) => '#' + d).join(', ') + ' which has no text to read';
  return null;
}
const controls = [];
const unnamed = [];
const danglingLabelledby = []; // batch204: aria-labelledby that resolves to nothing
const nameTokens = new Map(); // token -> [control ids]

for (const m of body.matchAll(/<(input|select|textarea)\b([^>]*)>/gi)) {
  const tag = m[1].toLowerCase();
  const attrs = m[2];
  const line = lineOf(m.index);
  const id = (attrs.match(/\bid\s*=\s*"([^"]+)"/i) || [])[1] || '';
  const type = (attrs.match(/\btype\s*=\s*"([^"]+)"/i) || [])[1] || '';
  if (type.toLowerCase() === 'hidden') continue;
  // Buttons in a form need their own text; this gate only covers value controls.
  if (type.toLowerCase() === 'submit' || type.toLowerCase() === 'button' ||
      type.toLowerCase() === 'reset') continue;

  const ariaLabel = (attrs.match(/\baria-label\s*=\s*"([^"]*)"/i) || [])[1];
  const ariaKey = (attrs.match(/\bdata-i18n-aria\s*=\s*"([^"]+)"/i) || [])[1];
  const ariaBy = (attrs.match(/\baria-labelledby\s*=\s*"([^"]+)"/i) || [])[1];
  // batch204: accepted only if the reference resolves to real text.
  const ariaByProblem = ariaBy ? labelledbyProblem(ariaBy) : null;

  // Implicit label: any <label ...> opened before this control and not yet
  // closed. That is what "wrapping a control in a label" means in HTML.
  const before = body.slice(0, m.index);
  const lastOpen = before.lastIndexOf('<label');
  const lastClose = before.lastIndexOf('</label');
  const implicit = lastOpen > lastClose;

  let token = '';
  let how = '';
  if (ariaKey) { token = 'key:' + ariaKey; how = 'data-i18n-aria'; }
  else if (ariaLabel) { token = 'text:' + ariaLabel.trim().toLowerCase(); how = 'aria-label'; }
  else if (ariaBy && !ariaByProblem) { token = 'by:' + ariaBy.trim(); how = 'aria-labelledby'; }
  else if (ariaBy && ariaByProblem) {
    danglingLabelledby.push({ line, label: id || `${tag}#${controls.length}`, value: ariaBy, why: ariaByProblem });
  }
  else if (id && labelFor.has(id)) {
    const l = labelFor.get(id);
    token = l.key ? 'key:' + l.key : 'text:' + l.text.toLowerCase();
    how = '<label for>';
  } else if (implicit) { token = 'implicit@' + line; how = '<label> wrapper'; }

  const label = id || `${tag}#${controls.length}`;
  controls.push({ tag, id: label, line, how, token });
  if (!token) {
    unnamed.push({ id: label, line, tag });
    continue;
  }
  if (allowSet.has(label)) continue;
  if (!nameTokens.has(token)) nameTokens.set(token, []);
  nameTokens.get(token).push({ id: label, line });
}

const duplicates = [...nameTokens.entries()]
  .filter(([, list]) => list.length > 1)
  .map(([token, list]) => ({ token, list }));

if (update) {
  const header = [
    '# web_a11y allowlist: controls that may have NO accessible name.',
    '# Each must also have a written reason in scripts/check-web-a11y.mjs (ALLOW).',
    '# Regenerate with --update.',
  ];
  writeFileSync(allowPath, `${header.join('\n')}\n${unnamed.map((u) => `${u.id}\n`).join('')}`);
  console.log(`OK ${NAME} --update: wrote ${unnamed.length} entr(y/ies) to ${allowPath}`);
  process.exit(0);
}

const problems = [];
for (const u of unnamed) {
  problems.push(`www/index.html:${u.line}: <${u.tag} id="${u.id}"> has NO accessible name `
    + '(need <label for>, a <label> wrapper, aria-label, data-i18n-aria or aria-labelledby; '
    + 'placeholder/title alone do not count)');
}
for (const d of duplicates) {
  problems.push(`www/index.html:${d.list.map((x) => x.line).join(',')}: ${d.list.length} controls share `
    + `the same accessible name (${d.token}) - a screen reader cannot tell them apart: `
    + d.list.map((x) => x.id).join(', '));
}

// ------------------------------------------------------------------- buttons
// A button's name is its text, so most are fine by construction. Two cases are
// not: (a) a button whose markup has no text (an icon-only button would be
// silent), and (b) a button built inside a ROW template - every row then
// exposes the identical name, and "Delete" x N is unusable with a screen
// reader. Such a button must carry an `aria-label` that interpolates the row's
// own data, so each one names its entry.
//
// The value is read up to the LAST quote before '>', not with `[^"]*`: a row
// template writes `aria-label="${t("rl.edit")} ${esc(r.mac)}"`, and a naive
// non-greedy match stops at the quote inside t("...") - it then saw `${t(`,
// concluded "there is an interpolation" and PASSED a name that was in fact the
// constant verb for every row. That is exactly the bug this check exists for,
// so the extraction has to survive the nested quotes.
function ariaLabelSource(attrs) {
  const open = attrs.search(/\baria-label\s*=\s*"/i);
  if (open < 0) return null;
  const start = attrs.indexOf('"', open) + 1;
  const lastQuote = attrs.lastIndexOf('"');
  if (lastQuote <= start) return null;   // empty value ""
  return attrs.slice(start, lastQuote);
}

// Interpolation bodies (`${...}`) of a template fragment, with quote awareness.
function interpolationBodies(src) {
  const out = [];
  for (let i = 0; i < src.length; i++) {
    if (src[i] !== '$' || src[i + 1] !== '{') continue;
    let depth = 1;
    let j = i + 2;
    let q = '';
    while (j < src.length && depth > 0) {
      const c = src[j];
      if (q) {
        if (c === '\\') { j += 2; continue; }
        if (c === q) q = '';
        j++;
        continue;
      }
      if (c === '"' || c === "'" || c === '`') { q = c; j++; continue; }
      if (c === '{') depth++;
      else if (c === '}') depth--;
      j++;
    }
    out.push(src.slice(i + 2, j - 1));
    i = j - 1;
  }
  return out;
}

// A name only identifies the row if at least one interpolation carries
// something OTHER than a translated literal - `t("rl.edit")` alone is the same
// string on every row.
const ROW_DATA = (src) => interpolationBodies(src).some((b) => !/^t\s*\(\s*["'][^"']*["']\s*\)$/.test(b.trim()));

const scriptStart = body.search(/<script\b/i);
for (const m of body.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button\s*>/gi)) {
  const attrs = m[1];
  const line = lineOf(m.index);
  const inScript = scriptStart >= 0 && m.index > scriptStart;
  const aria = ariaLabelSource(attrs);
  const ariaKey = (attrs.match(/\bdata-i18n-aria\s*=\s*"([^"]+)"/i) || [])[1];
  if (ariaKey) continue;
  const text = m[2].replace(/<[^>]*>/g, '').trim();
  if (inScript) {
    if (aria === null) {
      problems.push(`www/index.html:${line}: row button "${text}" has no aria-label - every row `
        + 'would expose the same name, so a screen reader cannot say which entry it acts on');
    } else if (!ROW_DATA(aria)) {
      problems.push(`www/index.html:${line}: row button aria-label "${aria}" does not interpolate `
        + `the row's data (only a translated literal) - all rows still get the same name`);
    }
    continue;
  }
  if (aria !== null) continue;
  if (!text) {
    problems.push(`www/index.html:${line}: button has neither text nor aria-label - it is silent`);
  }
}

// ------------------------------------------------------------------- actions
// batch165: the three action tables are built as ELEMENTS now, so their row
// buttons are no longer <button> markup in the script - they are specs
// { text, aria, cls, onclick } handed to paintActionTable. The markup check
// above therefore sees NOTHING of them, and deleting one aria spec left the
// whole gate green. The spec form is checked here instead.
//
// The rule is the same one: a name must combine the translated verb with the
// row's own data. `aria: t("rl.remove")` alone is the identical string on
// every row; `aria: t("rl.remove") + " " + r.mac` identifies the row.
// Brace-balanced slice of the function body. A lazy "up to the first \n}" is
// wrong here: the body nests blocks, and the first column-0 `}` may belong to
// an enclosing construct - the slice would then be empty and every check below
// would silently pass.
function functionBody(src, name) {
  const at = src.search(new RegExp('function\\s+' + name + '\\s*\\('));
  if (at < 0) return null;
  const open = src.indexOf('{', at);
  if (open < 0) return null;
  let depth = 0;
  let q = '';
  for (let i = open; i < src.length; i++) {
    const c = src[i];
    if (q) {
      if (c === '\\') { i++; continue; }
      if (c === q) q = '';
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { q = c; continue; }
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) return src.slice(open, i + 1); }
  }
  return null;
}
const actionTableBody = functionBody(body, 'paintActionTable');
if (!actionTableBody) {
  problems.push('www/index.html: paintActionTable is gone - the action-table row '
    + 'buttons have no named-aria check any more');
} else {
  // The specs are WRITTEN by the three load* renderers, so the scan covers the
  // whole script; the function body is only used to prove the helper applies
  // the name it is given.
  const specRegion = body.slice(body.search(/<script\b/i));
  const fnLine = lineOf(body.indexOf('function paintActionTable'));
  for (const m of specRegion.matchAll(/\baria:\s*([^,\n]+)/g)) {
    const expr = m[1].trim();
    if (expr === 'null' || expr === 'undefined') {
      problems.push(`www/index.html:${fnLine}: an action-table row button declares aria: ${expr} - `
        + 'every row would expose the same (or no) name');
      continue;
    }
    // Must contain a translated verb AND something that is not that verb.
    const hasVerb = /t\s*\(\s*["'][^"']+["']\s*\)/.test(expr);
    const rowPart = expr.split(/\+/).map((s) => s.trim())
      .filter((s) => s && !/^t\s*\(\s*["'][^"']+["']\s*\)$/.test(s));
    if (!hasVerb) {
      problems.push(`www/index.html:${fnLine}: action-table aria "${expr}" is not translated - `
        + 'a language switch would leave it in the previous language');
    }
    if (!rowPart.length) {
      problems.push(`www/index.html:${fnLine}: action-table aria "${expr}" does not interpolate the `
        + "row's data (only a translated literal) - all rows still get the same name");
    }
  }
  if (!/setAttribute\s*\(\s*["']aria-label["']\s*,\s*spec\.aria\s*\)/.test(actionTableBody)) {
    problems.push('www/index.html: paintActionTable never applies spec.aria - row buttons are unnamed');
  }
}

// -------------------------------------------------------------------- tables
// A data table needs a name of its own, or a screen reader announces "table,
// 6 columns" and the user has no idea which of the four tables on the Leases
// page they landed in. `<caption>` is the native mechanism and it is also the
// one that survives translation (`data-i18n` on the caption element).
// `aria-label`/`aria-labelledby` are accepted as equivalents.
const scriptStartTable = body.search(/<script\b/i);
const tableNames = new Map(); // token -> [line]
for (const m of body.matchAll(/<table\b([^>]*)>([\s\S]*?)<\/table\s*>/gi)) {
  const attrs = m[1];
  const line = lineOf(m.index);
  const id = (attrs.match(/\bid\s*=\s*"([^"]+)"/i) || [])[1] || `table#${line}`;
  if (scriptStartTable >= 0 && m.index > scriptStartTable) continue;
  const cap = m[2].match(/<caption\b([^>]*)>([\s\S]*?)<\/caption\s*>/i);
  const ariaLabel = (attrs.match(/\baria-label\s*=\s*"([^"]*)"/i) || [])[1];
  const ariaBy = (attrs.match(/\baria-labelledby\s*=\s*"([^"]+)"/i) || [])[1];
  let token = '';
  if (cap) {
    const key = (cap[1].match(/\bdata-i18n\s*=\s*"([^"]+)"/i) || [])[1];
    const text = cap[2].replace(/<[^>]*>/g, '').trim();
    token = key ? 'key:' + key : 'text:' + text.toLowerCase();
    if (!key && !text) token = '';
  } else if (ariaLabel) {
    token = 'text:' + ariaLabel.trim().toLowerCase();
  } else if (ariaBy && !labelledbyProblem(ariaBy)) {
    token = 'by:' + ariaBy.trim();
  } else if (ariaBy) {
    // batch204: a dangling reference is NOT a name - record it instead of
    // accepting it, so the table falls through to the "has NO accessible
    // name" branch below.
    danglingLabelledby.push({ line, label: '<table id="' + (id || '') + '">', value: ariaBy, why: labelledbyProblem(ariaBy) });
  }
  if (!token) {
    problems.push(`www/index.html:${line}: <table id="${id}"> has NO accessible name `
      + '(need a <caption data-i18n="...">, aria-label or aria-labelledby) - a screen reader '
      + 'announces only "table, N columns"');
    continue;
  }
  if (!tableNames.has(token)) tableNames.set(token, []);
  tableNames.get(token).push({ id, line });
}
for (const [token, list] of tableNames) {
  if (list.length > 1) {
    problems.push(`www/index.html:${list.map((x) => x.line).join(',')}: ${list.length} tables share `
      + `the same accessible name (${token}) - a screen reader cannot tell them apart: `
      + list.map((x) => x.id).join(', '));
  }
}

// batch167: a gate that inspected nothing is not a gate. If the extractors stop
// matching (a renamed attribute form, a restructured page, a selector change)
// every list below is empty and the run prints a cheerful "0 problems". Require
// real coverage so a broken extractor fails loudly instead of passing quietly.
// batch204: a reference that resolves to nothing must fail the gate. batch201's
// lesson: collecting is worthless until it is part of this verdict.
for (const d of danglingLabelledby) {
  problems.push(`www/index.html:${d.line}: ${d.label} has aria-labelledby="${d.value}" but ${d.why} - the control is announced with NO name`);
}

if (controls.length === 0) {
  problems.push('parsed 0 form control(s) - the control extractor is broken, so "no unnamed controls" means nothing');
}
if (tableNames.size === 0) {
  problems.push('parsed 0 table(s) - the table extractor is broken, so "no unnamed tables" means nothing');
}
if (scriptStart < 0) {
  problems.push('no inline <script> found in the page body - the row-button check has nothing to inspect');
}

if (problems.length) {
  console.error(`FAIL ${NAME}: ${problems.length} accessibility problem(s):`);
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log(`OK ${NAME} (${controls.length} form control(s) named, ${controls.length - unnamed.length} explicit, `
  + `${allow.length} allowlisted, no shared names; ${tableNames.size} named table(s), no shared names)`);
