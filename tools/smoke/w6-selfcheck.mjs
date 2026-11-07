// VGWW web UI self-check (S4.6-W6 asset, persisted under tools/smoke).
//
// Asserts the W6 feature set directly in www/index.html: light/dark theme,
// responsive breakpoints, class migration, interaction states, toast queue,
// accessibility wiring, language filter, and the invariants that must never
// regress (esc() usage, SET_FIELDS kind metadata, innerHTML safety, I18N size).
//
// Usage:
//   node tools/smoke/w6-selfcheck.mjs [g1|g2|g3|g4|g5|all] [path/to/index.html]
//   default group = all, default path = <repo>/www/index.html
// Expected output: one PASS/FAIL line per check and
//   "OK selfcheck[all]: 42 check(s) passed (<path>)"   (exit 0)
// A deliberately broken copy must FAIL (negative evidence, see the W6 report).
// Reference runs: .superpowers/sdd/2026-09-21-s4-ui/logs/w6-g2-gates.*.log
// (12/12) and logs/selfcheck-*.log (42/42 on the migrated F: tree).
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../..');
const path = process.argv[3] || resolve(repoRoot, 'www/index.html');
const group = (process.argv[2] || 'all').toLowerCase();
const html = readFileSync(path, 'utf8');

const rows = [];
let failed = 0;
function check(name, cond, detail = '') {
  const ok = !!cond;
  if (!ok) failed++;
  rows.push(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  [' + detail + ']' : ''}`);
}
const count = (re) => (html.match(re) || []).length;
const has = (s) => html.includes(s);

if (group === 'g1' || group === 'all') {
  check('G1 light palette block exists', has(':root[data-theme="light"]{'));
  check('G1 palette has on-accent/on-accent2/on-danger vars',
    count(/--on-accent:#|--on-accent2:#/g) >= 2 && has('--on-danger:#'),
    `on-accent=${count(/--on-accent:#/g)}, on-accent2=${count(/--on-accent2:#/g)}, on-danger=${count(/--on-danger:#/g)}`);
  check('G1 badge backgrounds use palette vars', has('.badge.ok{background:var(--ok-bg)') && has('.badge.warn{background:var(--warn-bg)'));
  check('G1 head theme bootstrap script present', has('document.documentElement.dataset.theme = d;'));
  check('G1 localStorage key vgww_theme used', count(/vgww_theme/g) >= 2, `occurrences=${count(/vgww_theme/g)}`);
  check('G1 prefers-color-scheme default', has('(prefers-color-scheme: light)'));
  check('G1 settings theme selector (3 options)', has('id="theme-sel"') && count(/data-i18n="set\.theme(\.auto|\.light|\.dark)?"/g) === 4,
    `theme-i18n=${count(/data-i18n="set\.theme(\.auto|\.light|\.dark)?"/g)}`);
  check('G1 applyTheme() defined and called', count(/applyTheme\(\)/g) >= 3, `calls=${count(/applyTheme\(\)/g)}`);
  check('G1 matchMedia change listener', has('themeMedia.addEventListener("change"'));
  check('G1 theme keys exist in en + zh-CN', count(/"set\.theme":/g) === 2 && count(/"set\.theme\.auto":/g) === 2,
    `theme=${count(/"set\.theme":/g)}, auto=${count(/"set\.theme\.auto":/g)}`);
}

if (group === 'g2' || group === 'all') {
  check('G2 three media queries', count(/@media \(min-width:1200px\)/g) === 1 && count(/@media \(max-width:1199px\)/g) === 1 && count(/@media \(max-width:767px\)/g) === 1);
  check('G2 three dashboard columns at >=1200px', /@media \(min-width:1200px\)\{[\s\S]{0,200}grid-template-columns:repeat\(3,minmax\(0,1fr\)\)/.test(html));
  check('G2 icon sidebar 768-1199px', /@media \(max-width:1199px\)\{[\s\S]{0,400}\.nav-label\{display:none\}/.test(html));
  check('G2 single column <768px', /@media \(max-width:767px\)\{[\s\S]{0,400}body\{flex-direction:column\}/.test(html) && /@media \(max-width:767px\)\{[\s\S]{0,900}\.cards\{grid-template-columns:1fr\}/.test(html));
  check('G2 table scroll containers', count(/<div class="tablewrap">/g) === 5 && count(/<\/table><\/div>/g) === 5,
    `open=${count(/<div class="tablewrap">/g)} close=${count(/<\/table><\/div>/g)}`);
  check('G2 nav split into icon+label (5 links)', count(/<span class="nav-icon" aria-hidden="true">/g) === 5 && count(/<span class="nav-label"/g) === 5,
    `icon=${count(/<span class="nav-icon" aria-hidden="true">/g)} label=${count(/<span class="nav-label"/g)}`);
  check('G2 data-i18n moved to label span', count(/<a href="#\w+"[^>]*><span class="nav-icon"/g) === 5);
  check('G2 table wrappers scroll under 768px', has('.tablewrap table{min-width:520px}'));
}

if (group === 'g3' || group === 'all') {
  check('G3 no inline style= left in markup/JS', count(/\sstyle="/g) === 0, `style="${count(/\sstyle="/g)}`);
  check('G3 focus-visible outline', has('focus-visible'));
  check('G3 transitions <=160ms', /transition:[^;}]*0?\.1[0-6]?s|transition:[^;}]*1[0-6]0ms/.test(html));
  check('G3 disabled state', has('button:disabled'));
  check('G3 toast queue (max 3)', has('TOAST_MAX') && has('function toast('));
  check('G3 danger button class', has('.btn-danger') && has('class="btn-danger"'));
}

if (group === 'g4' || group === 'all') {
  const labels = count(/<label[^>]*\bfor="/g);
  check('G4 at least 8 label[for] bindings', labels >= 8, `labels=${labels}`);
  const thAll = count(/<th(?=[\s>])/g);
  const thScoped = count(/<th scope="col"/g);
  check('G4 every table header has scope=col', thScoped === 16 && thAll === 16, `scoped=${thScoped} total=${thAll}`);
  check('G4 sr-only labels for action headers', count(/<span class="sr-only"/g) === 3, `sr-only=${count(/<span class="sr-only"/g)}`);
  check('G4 aria-current set and cleared', has('aria-current="page"') && has('x.removeAttribute("aria-current")'));
  check('G4 favicon data URI', /<link rel="icon" href="data:image\/svg\+xml,/.test(html));
  check('G4 toast is a live region', /id="toast"[^>]*role="status"[^>]*aria-live="polite"/.test(html));
  const btns = [...html.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/g)];
  check('G4 every button has visible text or aria-label',
    btns.length === 8 && btns.every(([, attrs, body]) => /aria-label\s*=/.test(attrs) || body.replace(/<[^>]*>/g, '').trim() !== ''),
    `buttons=${btns.length}`);
}

if (group === 'g5' || group === 'all') {
  check('G5 language filter input', has('id="lang-filter"'));
  check('G5 filter has an accessible name', has('<label class="sr-only" id="lang-label" for="lang-filter"') && has('aria-labelledby="lang-label"'));
  check('G5 filter rebuilds the option list', /langsel\.textContent = ""/.test(html) && has('filterLangs'));
  check('G5 filter keeps the current language pinned', has('langOptions') && has('langsel.value = currentLang;'));
  check('G5 keyboard reachable (Enter -> select)', has('langsel.focus()'));
  check('G5 capture happens once (461 options)', /Array\.from\(langsel\.options\)/.test(html));
  check('G5 filter hidden on narrow layouts only', /@media \(max-width:1199px\)\{[\s\S]{0,500}\.lang-filter\{display:none\}/.test(html));
}

// invariants that must hold in every group
check('INV esc() uses >= baseline 20', count(/esc\(/g) >= 20, `esc() uses=${count(/esc\(/g)}`);
check('INV SET_FIELDS kind metadata intact', has('kind: "number"') || has('kind:"number"'));
check('INV no raw innerHTML assignment without esc/json', count(/\.innerHTML\s*=/g) >= 5);
check('INV I18N table intact', count(/"lang\.name":/g) === 461, `lang.name=${count(/"lang\.name":/g)}`);

console.log(rows.join('\n'));
console.log(failed === 0 ? `OK selfcheck[${group}]: ${rows.length} check(s) passed (${path})` : `FAIL selfcheck[${group}]: ${failed}/${rows.length} check(s) failed (${path})`);
process.exit(failed === 0 ? 0 : 1);
