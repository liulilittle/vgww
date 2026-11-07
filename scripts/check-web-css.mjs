#!/usr/bin/env node
// Gate: web_css
// Every class a page puts on an element must have a rule in the page's own
// stylesheet - otherwise the class is a promise nobody kept.
//
// This gate exists because two dead class names shipped: `.cl-out` (the console
// <pre>, so the log box had NO panel styling, no max-height and no scroll: 2000
// lines stretched the whole page) and `.spd` (added to a host tile when live
// throughput is above zero, so the "traffic is flowing" cue never changed
// anything). Both looked implemented - the markup said so - and no gate could
// see it, because a missing rule is not a syntax error, not a missing i18n key
// and not an unsafe interpolation.
//
// Detection surface: the set of class tokens that can reach an element.
//   * `class="..."` in markup (static)
//   * `class="...${...}..."` / `class="a " + x` in the inline script (composed)
//   * `classList.add/remove/toggle("x")` and `className = "x"` in the script
// Then every token must appear as `.token` in the inline <style>.
//
// Usage: node scripts/check-web-css.mjs <repo-root> [--update]
// Exit:  0 = OK (WARNs allowed), 1 = FAIL
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const NAME = 'css';
const root = process.argv[2];
const update = process.argv.includes('--update');
if (!root) {
  console.error(`FAIL ${NAME}: missing <repo-root> argument (usage: node scripts/check-web-css.mjs <repo-root>)`);
  process.exit(1);
}

const htmlPath = join(resolve(root), 'www', 'index.html');
const allowPath = join(resolve(root), 'scripts', 'web-css.allowlist');
const lines = [];
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

const styleMatch = html.match(/<style\b[^>]*>([\s\S]*?)<\/style\s*>/i);
if (!styleMatch) fail(`no inline <style> block found in ${htmlPath}`);
const style = styleMatch[1];

// ---------------------------------------------------------------- token use
// A class token is a CSS identifier. Anything produced by a template expression
// is unknown at build time, so only the literal parts are collected - which is
// exactly the part that has to have a rule.
const TOKEN = /^-?[A-Za-z_][A-Za-z0-9_-]*$/;
const used = new Map(); // token -> first line number
function noteToken(tok, line) {
  if (!tok || !TOKEN.test(tok)) return;
  // A literal that ends with '-' is a concatenation prefix ("toast-"), not a
  // class of its own; the assembled names are collected below.
  if (tok.endsWith('-')) return;
  if (!used.has(tok)) used.set(tok, line);
}
// Every quoted literal inside a class-name expression. A class can be decided
// at runtime (`class="card${on ? ' spd' : ''}"`), and that branch is exactly
// where a dead name hides: the branch is written, the rule is not.
function noteLiteralsIn(expr, line) {
  for (const q of expr.matchAll(/'([^']*)'|"([^"]*)"/g)) {
    for (const tok of (q[1] ?? q[2] ?? '').split(/\s+/)) noteToken(tok, line);
  }
}

const htmlLines = html.split('\n');
for (let i = 0; i < htmlLines.length; i++) {
  const line = htmlLines[i];
  // class="..." - static, or composed with ${...} / string concatenation.
  for (const m of line.matchAll(/class\s*=\s*"([^"]*)"/g)) {
    for (const part of m[1].split(/\$\{[^}]*\}/)) {
      for (const tok of part.split(/[\s'"+]+/)) noteToken(tok, i + 1);
    }
    noteLiteralsIn(m[1], i + 1);
  }
  for (const m of line.matchAll(/classList\.(?:add|remove|toggle|contains)\(\s*"([^"]+)"/g)) {
    for (const tok of m[1].split(/\s+/)) noteToken(tok, i + 1);
  }
  // className = <expression>: ONLY the quoted literals are class names. The
  // expression may be a variable (`className = cls`), and treating that
  // identifier as a class name is a false positive that would push an author to
  // allowlist a name that does not exist.
  for (const m of line.matchAll(/className\s*=\s*([^;]+)/g)) {
    noteLiteralsIn(m[1], i + 1);
  }
}
// How many tokens came from the page itself, before the hardcoded toast levels
// are added. The coverage guard below must look at THIS number: the three
// toast-* names are injected unconditionally, so `used.size === 0` can never
// become true and a guard written against it would never fire.
const usedFromMarkup = used.size;
for (const level of ['success', 'error', 'info']) noteToken(`toast-${level}`, 0);

// ------------------------------------------------------------- token define
const defined = new Set();
// batch202: a SELECTOR is not a RULE. The old collection added every `.token`
// it could find anywhere in the stylesheet, so `.spd{border-left-color:...}`
// and `.spd{}` were indistinguishable - and `.spd` is one of the two dead
// names this gate was created for (a host tile gets it when live throughput
// is above zero, so an emptied declaration list means the "traffic is
// flowing" cue silently does nothing again). Took the empty form to be the
// very defect the gate exists for and it was still reported OK (measured).
// Record each class selector together with whether its own declaration block
// has at least one declaration; a selector-only hit no longer counts.
//
// Strip comments first so a class named in a comment does not count as a rule.
const styleNoComments = style.replace(/\/\*[\s\S]*?\*\//g, '');
const emptySelectors = [];   // { token, selector } - declared nothing
// One rule at a time: everything up to the next '{' is the selector list.
for (let i = 0; i < styleNoComments.length; i++) {
  if (styleNoComments[i] !== '{') continue;
  // Walk back to the end of the previous rule (or the start of the sheet).
  let start = i - 1;
  while (start >= 0 && styleNoComments[start] !== '}' && styleNoComments[start] !== ';' &&
         styleNoComments[start] !== '{') start--;
  const selector = styleNoComments.slice(start + 1, i);
  // Match the closing brace of THIS rule, honouring nesting.
  let depth = 1;
  let j = i + 1;
  while (j < styleNoComments.length && depth > 0) {
    if (styleNoComments[j] === '{') depth++;
    else if (styleNoComments[j] === '}') depth--;
    j++;
  }
  const body = styleNoComments.slice(i + 1, depth === 0 ? j - 1 : j);
  // At-rules (@media, @font-face, ...) have their own grammar; their inner
  // rules are visited by this same loop, so skip only the at-rule HEADER.
  const isAtRule = /^\s*@/.test(selector);
  const hasDeclaration = body.trim() !== '' && !isAtRule;
  // batch202: only the LAST compound of a selector is what the rule styles.
  // `.card.spd .v{...}` styles the .v DESCENDANT - the .spd element itself gets
  // nothing from it. Counting every token in the selector let a deleted
  // `.card.spd{...}` rule hide behind that descendant rule (measured: deleting
  // the direct rule still reported OK), which is the same "cue silently does
  // nothing" failure. Split on combinators and keep the final compound.
  for (const one of selector.split(',')) {
    const compounds = one.trim().split(/\s+|>|\+|~/).filter(Boolean);
    const target = compounds.length ? compounds[compounds.length - 1] : '';
    for (const sm of target.matchAll(/\.(-?[A-Za-z_][A-Za-z0-9_-]*)/g)) {
      if (hasDeclaration) {
        defined.add(sm[1]);
      } else if (!isAtRule) {
        emptySelectors.push({ token: sm[1], selector: one.trim().slice(0, 60) });
      }
    }
  }
}

// ------------------------------------------------------------- allowlist
// Tokens that are deliberately rule-free. Every entry needs a reason: this is
// the one place where "used but unstyled" is allowed, and it must not become a
// dumping ground (the gate prints the list on every run).
const ALLOW = new Map([
  ['nav-icon', 'markup-only wrapper for the aria-hidden glyph; it is a flex item of nav a, whose gap/padding already space it'],
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
const allowSet = new Set(allow);
for (const tok of allowSet) {
  if (!ALLOW.has(tok)) fail(`allowlist entry "${tok}" has no documented reason in check-web-css.mjs`);
}

const missing = [];
for (const [tok, line] of [...used.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
  if (defined.has(tok)) continue;
  if (allowSet.has(tok)) continue;
  missing.push(`www/index.html:${line}: class "${tok}" has no rule in the inline <style> and is not allowlisted`);
}

const stale = allow.filter((tok) => !used.has(tok));
const nowDefined = allow.filter((tok) => defined.has(tok));

if (update) {
  const header = [
    '# web_css allowlist: class tokens that may appear in the page without a',
    '# rule in its inline <style>. Each must also have a documented reason in',
    '# scripts/check-web-css.mjs (ALLOW). Regenerate with --update.',
  ];
  const body = [...used.keys()].filter((t) => !defined.has(t)).sort();
  writeFileSync(allowPath, `${header.join('\n')}\n${body.map((t) => `${t}\n`).join('')}`);
  console.log(`OK ${NAME} --update: wrote ${body.length} entr(y/ies) to ${allowPath}`);
  process.exit(0);
}

// batch168: "every class has a rule" is vacuous if no class was collected.
// The extractor reads class="..." / classList.*("...") / className=... from the
// page; a markup rewrite (class: {...} style, a CSS-modules build step) would
// silently make it collect nothing and this gate would keep printing OK.
if (usedFromMarkup === 0) fail('collected 0 class token(s) from www/index.html - the extractor is broken, refusing to report OK');
if (defined.size === 0) fail('found 0 rule(s) in the inline <style> - the extractor is broken, refusing to report OK');

// batch202: a class whose only rule declares nothing is as dead as a class with
// no rule at all - that is exactly the failure mode this gate was built for.
// batch201's lesson applied here: the collection above only MATTERS once it is
// part of this verdict. An empty declaration list is always a mistake (the
// author either forgot the declarations or meant to delete the rule).
if (emptySelectors.length) {
  console.error(`FAIL ${NAME}: ${emptySelectors.length} class selector(s) with an EMPTY declaration block`);
  console.error(`  (a rule that declares nothing is indistinguishable from no rule: the cue it was written for never happens)`);
  for (const e of emptySelectors) console.error(`  - .${e.token}  in \`${e.selector}\``);
  process.exit(1);
}

if (missing.length) {
  console.error(`FAIL ${NAME}: ${missing.length} class token(s) used but never styled (dead class name = a feature that silently does nothing):`);
  for (const m of missing) console.error(`  - ${m}`);
  process.exit(1);
}
if (stale.length) {
  console.log(`WARN ${NAME}: allowlist entr(y/ies) no longer used: ${stale.join(', ')}`);
}
if (nowDefined.length) {
  console.log(`WARN ${NAME}: allowlist entr(y/ies) now styled (drop them): ${nowDefined.join(', ')}`);
}
console.log(`OK ${NAME} (${used.size} class token(s) used, ${defined.size} rule(s), ${allowSet.size} allowlisted)`);
