#!/usr/bin/env node
// Gate: gates_selftest (meta-gate)
//
// WHY THIS EXISTS
// ---------------
// Every gate in this directory is a rule that can silently stop policing. Six
// consecutive audits found the SAME class of defect, each time by hand:
//
//   batch201  api-contract compared paths but not HTTP methods
//   batch202  web-css counted a selector as a rule even with an empty body
//   batch203  html-safety knew only `innerHTML`, not insertAdjacentHTML & co.
//   batch204  web-a11y accepted aria-labelledby without resolving the target
//   batch205  i18n compared keys but never values (an empty translation passed)
//   batch206  native-i18n counted placeholders but not their order
//
// In each case the gate printed OK while the defect it exists to catch was
// present. Hand-running one mutation per batch does not scale and does not
// regress: nothing fails when a future edit weakens a gate.
//
// This gate makes "the gate can still fail" executable. For each checked gate
// it copies the minimal input into a temp tree, injects a defect the gate is
// SUPPOSED to reject, and asserts the gate exits non-zero. If any gate stays
// green on its own known-bad input, this gate fails.
//
// It also runs every gate once on the UNMODIFIED tree and asserts it passes -
// a gate that fails on good input is broken in the other direction, and the
// negative case alone would not reveal that.
//
// Usage: node scripts/check-gates-selftest.mjs <repo-root>
// Exit:  0 = every gate both passes on good input and fails on its known-bad
//        input; 1 = some gate is toothless (or crashed / timed out).
import { readFileSync, writeFileSync, mkdtempSync, rmSync, mkdirSync, copyFileSync, existsSync, statSync, cpSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, resolve, dirname } from 'node:path';
import { tmpdir } from 'node:os';

const NAME = 'gates-selftest';
const root = process.argv[2];
if (!root) {
  console.error(`FAIL ${NAME}: missing <repo-root> argument (usage: node scripts/check-gates-selftest.mjs <repo-root>)`);
  process.exit(1);
}
const repo = resolve(root);
const node = process.execPath;
const GATE_TIMEOUT_MS = 120000;

function runGate(script, repoRoot) {
  try {
    // The gate must be the one INSIDE the temp tree when it exists there: a
    // case may mutate the gate itself (the shrunken-suite case deletes a test
    // case), and running the pristine copy would silently test the wrong file.
    const gateFile = join(repoRoot, 'scripts', script);
    const scriptPath = existsSync(gateFile) ? gateFile : join(repo, 'scripts', script);
    const out = execFileSync(node, [scriptPath, repoRoot], {
      encoding: 'utf8', stdio: 'pipe', timeout: GATE_TIMEOUT_MS,
    });
    return { code: 0, out };
  } catch (e) {
    const out = String((e.stdout || '') + (e.stderr || ''));
    // A crash is not "the gate rejected the input" - but a gate whose JOB is to
    // report syntax errors prints "SyntaxError" on purpose (check-js-syntax
    // forwards node --check's message), so keying on that word alone marked a
    // correct detection as a crash. A crash is an uncaught exception: the
    // process died WITHOUT emitting its own FAIL line.
    const reported = /^FAIL /m.test(out);
    const crash = !reported && /SyntaxError|ReferenceError|TypeError|Cannot read propert|is not a function|ENOENT/.test(out);
    return { code: e.status === undefined ? -1 : e.status, out, crash, timedOut: e.killed === true };
  }
}

// Files each gate reads, relative to the repo root. Copied so the injected
// defect cannot touch the working tree.
const NEEDED = [
  'www/index.html',
  'scripts/rtl-languages.txt',
  'scripts/i18n-missing.allowlist',
  'scripts/api-backend-only.allowlist',
  'scripts/html-safety.allowlist',
  'scripts/web-css.allowlist',
  'scripts/web-a11y.allowlist',
  'src/web/web_api.cpp',
  'src/web/http_server.cpp',
  'src/core/config.cpp',
  'src/ui/i18n.cpp',
  'src/ui/i18n_gen.bin',
  'src/ui/i18n.h',
  // (every scripts/check-*.mjs is copied by makeTree; see below)
  'scripts/gen-native-i18n.mjs',
  'scripts/native-i18n-map.json',
  'scripts/native-i18n-t2',
];

function makeTree() {
  const dir = mkdtempSync(join(tmpdir(), 'vgww-gates-'));
  for (const rel of NEEDED) {
    const src = join(repo, rel);
    if (!existsSync(src)) continue;
    const dst = join(dir, rel);
    mkdirSync(dirname(dst), { recursive: true });
    if (statSync(src).isDirectory()) {
      // A whole directory (the per-language translation store).
      cpSync(src, dst, { recursive: true });
    } else {
      copyFileSync(src, dst);
    }
  }
  // batch209: copy EVERY gate script, not just the ones a case happens to
  // list. runGate prefers the copy inside the temp tree, and a case may
  // mutate a gate itself (the shrunken-suite case deletes a test case). With
  // a hand-written list, a case whose script was omitted silently ran the
  // PRISTINE gate and passed - measured: degrading check-web-css to accept
  // every class still printed '9 gate(s) verified'.
  const scriptsDir = join(repo, 'scripts');
  if (existsSync(scriptsDir)) {
    for (const entry of readdirSync(scriptsDir)) {
      if (!/^check-.*\.mjs$/.test(entry)) continue;
      if (NEEDED.includes('scripts/' + entry)) continue;   // already copied
      mkdirSync(join(dir, 'scripts'), { recursive: true });
      copyFileSync(join(scriptsDir, entry), join(dir, 'scripts', entry));
    }
  }
  return dir;
}

function readIn(dir, rel) { return readFileSync(join(dir, rel), 'utf8'); }
function writeIn(dir, rel, text) { writeFileSync(join(dir, rel), text, 'utf8'); }

/// Each case: a gate that must PASS untouched and FAIL once `mutate` is applied.
/// `needle` is what the failure message must contain - a gate can exit non-zero
/// for an unrelated reason (the batch206 lesson: the first "red" was a stale
/// derived artifact, not the rule under test).
const CASES = [
  {
    script: 'check-js-syntax.mjs', name: 'js-syntax',
    mutate(dir) {
      const html = readIn(dir, 'www/index.html');
      // Break the inline script the way a bad merge would.
      writeIn(dir, 'www/index.html', html.replace('function detectLang() {', 'function detectLang( {'));
    },
    needle: /SyntaxError|Unexpected|Invalid or unexpected/i,
  },
  {
    script: 'check-api-contract.mjs', name: 'api-contract (method)',
    mutate(dir) {
      const html = readIn(dir, 'www/index.html');
      // A route that exists only as GET, called as POST -> 405 in production.
      writeIn(dir, 'www/index.html', html.replace(
        '  const r = await api("/api/console");',
        '  const r = await api("/api/console", { method: "PUT" });'));
    },
    needle: /405/,
  },
  {
    script: 'check-web-css.mjs', name: 'web-css (empty rule)',
    mutate(dir) {
      const html = readIn(dir, 'www/index.html');
      writeIn(dir, 'www/index.html', html.replace(
        '.card.spd{border-left-color:var(--accent2)}',
        '.card.spd{}'));
    },
    needle: /EMPTY declaration/,
  },
  {
    script: 'check-html-safety.mjs', name: 'html-safety (injection api)',
    mutate(dir) {
      const html = readIn(dir, 'www/index.html');
      writeIn(dir, 'www/index.html', html.replace(
        'function focusSlot(tbody) {',
        'function focusSlot(tbody) {\r\n  document.getElementById("x").insertAdjacentHTML("beforeend", "<b>" + window.__clientList[0].ip + "</b>");'));
    },
    needle: /markup-injection/,
  },
  {
    script: 'check-web-a11y.mjs', name: 'web-a11y (dangling labelledby)',
    mutate(dir) {
      const html = readIn(dir, 'www/index.html');
      writeIn(dir, 'www/index.html', html.replace(
        'aria-labelledby="lang-label"',
        'aria-labelledby="no-such-element"'));
    },
    needle: /does not exist/,
  },
  {
    script: 'check-i18n.mjs', name: 'i18n (empty en value)',
    mutate(dir) {
      const html = readIn(dir, 'www/index.html');
      writeIn(dir, 'www/index.html', html.replace('"dash.title":"Dashboard"', '"dash.title":""'));
    },
    needle: /EMPTY value in en/,
  },
  {
    script: 'check-native-i18n.mjs', name: 'native-i18n (placeholder order)',
    // batch208: this gate validates a DERIVED artifact against the source.
    // Mutating the source alone makes it fail with "resource != source" -
    // stale binary, not the rule. The defect is only reachable after the
    // resource is rebuilt, exactly as batch206 had to do by hand.
    rebuild: 'gen-native-i18n.mjs',
    mutate(dir) {
      const cppPath = 'src/ui/i18n.cpp';
      const cpp = readIn(dir, cppPath);
      // A translation that swaps two indexed placeholders: same count, so a
      // count-only check cannot see it, and the UI then renders the peak as
      // the current value. SparkCurrentPeakFmt is zh-CN's
      // "当前 {0} · 峰值 {1}" (batch310: the old fixture used the retired
      // TimeMinutesSecondsFmt string).
      const swapped = cpp.replace('L"当前 {0} · 峰值 {1}"',
                                  'L"当前 {1} · 峰值 {0}"');
      if (swapped === cpp) throw new Error('native-i18n: the zh placeholder fixture moved - update this case');
      writeIn(dir, cppPath, swapped);
    },
    needle: /placeholder #\d+/,
  },
  {
    script: 'check-native-i18n.mjs', name: 'native-i18n (zh-CN copied en)',
    // batch286: a core-language entry that is simply the English text used
    // to pass every structural check, so the Chinese UI shipped English.
    rebuild: 'gen-native-i18n.mjs',
    mutate(dir) {
      const cppPath = 'src/ui/i18n.cpp';
      const cpp = readIn(dir, cppPath);
      const copied = cpp.replace('L"租约",  // NavLeases', 'L"Leases",  // NavLeases');
      if (copied === cpp) throw new Error('native-i18n: the zh NavLeases fixture moved - update this case');
      writeIn(dir, cppPath, copied);
    },
    needle: /not translated \(identical to en\): NavLeases/,
  },
  {
    script: 'check-source-hygiene.mjs', name: 'source-hygiene (editor leftover)',
    // batch226: an editor backup in src/ui/pages/ made every text query about
    // the tree answer with stale code (OnIntent appeared 11 times instead of 8).
    // It compiled into nothing, so only a scanning gate can see it.
    mutate(dir) {
      // www/ is always present in the temp tree (the page gates need it), so the
      // leftover lands under a scanned root without needing a new directory.
      writeIn(dir, 'www/batch226-leftover.js.bak',
              '// an editor backup that is not a build input\n');
    },
    needle: /editor\/merge leftover/,
  },
  {
    script: 'check-web-logic.mjs', name: 'web-logic (double submit guard)',
    // The only gate that EXECUTES the page script. The defect below is valid
    // JavaScript and passes every static gate - it can only be seen by
    // driving the code: dropping the in-flight guard lets a double click fire
    // two POSTs, which is the behaviour batch39 was asked to prevent.
    mutate(dir) {
      const htmlPath = 'www/index.html';
      const html = readIn(dir, htmlPath);
      const from = '    if (btn && btn.dataset.busy === "1") return;';
      const swapped = html.replace(from, '    if (false) return;');
      if (swapped === html) throw new Error('web-logic: the noDup guard fixture moved - update this case');
      writeIn(dir, htmlPath, swapped);
    },
    needle: /double submit/,
  },
  {
    script: 'check-web-logic.mjs', name: 'web-logic (shrunken suite)',
    // A suite that can shrink silently is a suite that can reach zero while
    // every run stays green. This case deletes a whole registered case and
    // requires the gate to notice the COUNT, not just the pass/fail of what
    // is left - the two are different properties and only one was covered.
    mutate(dir) {
      const gatePath = 'scripts/check-web-logic.mjs';
      const gate = readIn(dir, gatePath);
      const marker = "cases.push(['a double submit is dropped while the first is in flight'";
      const idx = gate.indexOf(marker);
      const end = idx < 0 ? -1 : gate.indexOf('}]);', idx);
      if (idx < 0 || end < 0) throw new Error('web-logic: the case fixture moved - update this case');
      // Drop the whole case, leaving a suite that still passes.
      writeIn(dir, gatePath, gate.slice(0, idx) + gate.slice(end + 4));
    },
    needle: /at least 71|MIN_CASES/,
  },
];

const failures = [];
const notes = [];

/// batch224: the four judgements this gate makes about another gate's run, as a
/// named function so its own contract can be tested. Until now NOTHING checked
/// them: deleting any one of the four branches left this gate printing "9 gate(s)
/// verified" (measured - all four survived), which means a gate that started
/// failing for the WRONG reason, or on UNMODIFIED input, would never be noticed.
/// Returns null when the run looks right, or { why } describing the defect.
/// `dirty` may be null when the clean run already failed: the first check runs
/// first, so the later ones are never reached in that case.
function judgeRun(clean, dirty, needle) {
  if (clean.code !== 0) {
    return { why: `a gate reported a problem on UNMODIFIED input (exit ${clean.code}) - the self-test copy or the gate is wrong:\n${String(clean.out || '').trim().split('\n').slice(0, 4).join('\n')}` };
  }
  if (dirty === null) {
    return { why: 'internal: the clean run passed but no mutated run was made' };
  }
  if (dirty.code === 0) {
    return { why: 'the gate stayed GREEN on input it exists to reject - it no longer polices this rule' };
  }
  if (dirty.crash) {
    return { why: `the gate CRASHED instead of reporting (${dirty.out.trim().split('\n').slice(0, 2).join(' ')}). A crash is not a detection` };
  }
  if (!needle.test(dirty.out)) {
    return { why: `the gate failed but NOT for this rule - expected /${needle.source}/ in:\n${dirty.out.trim().split('\n').slice(0, 4).join('\n')}` };
  }
  return null;
}

// batch224: judgeRun has to reject ALL FOUR of these shapes. Driving it with
// synthetic results is the only way to test the judgements without a second
// copy of this gate: the real runs only ever exercise the "ok" path, so a
// deleted branch is invisible.
const JUDGE_CASES = [
  ['clean input failed', { code: 1, out: 'FAIL x: nope' }, null, /nope/, /UNMODIFIED input/],
  ['stayed green', { code: 0, out: 'OK' }, { code: 0, out: 'OK' }, /ANY/, /stayed GREEN/],
  ['crashed', { code: 0, out: 'OK' }, { code: 1, out: 'TypeError: boom', crash: true }, /ANY/, /CRASHED/],
  ['wrong reason', { code: 0, out: 'OK' }, { code: 1, out: 'FAIL x: something else' }, /needle-here/, /NOT for this rule/],
  ['all good', { code: 0, out: 'OK' }, { code: 1, out: 'FAIL x: needle-here found' }, /needle-here/, null],
  // Passing no mutated run alongside a PASSING clean run is a caller bug, not a
  // gate defect: judgeRun must say so instead of throwing "Cannot read
  // properties of null". The real loop never does this (it skips the run when
  // the clean pass failed), so this can only be reached by a future refactor.
  ['no mutated run', { code: 0, out: 'OK' }, null, /ANY/, /no mutated run/],
];
for (const [label, clean, dirty, needle, want] of JUDGE_CASES) {
  // A judge that THROWS has not diagnosed anything - the process would die with
  // a TypeError and the operator would see a stack trace instead of the reason.
  // Treating that as a failed self-check is the only way the "no mutated run"
  // contract can be policed without relying on the crash itself.
  let got;
  try {
    got = judgeRun(clean, dirty, needle);
  } catch (e) {
    failures.push(`judgeRun self-check (${label}): it THREW instead of reporting (${e.message}). A crash is not a diagnosis`);
    continue;
  }
  if (want === null) {
    if (got !== null) {
      failures.push(`judgeRun self-check (${label}): a correct run was reported as broken ("${got.why}")`);
    }
  } else if (got === null) {
    failures.push(`judgeRun self-check (${label}): this defect was accepted - the gate would print OK while a gate is toothless`);
  } else if (!want.test(got.why)) {
    failures.push(`judgeRun self-check (${label}): the wrong diagnosis, expected /${want.source}/ got "${got.why.split('\n')[0]}"`);
  }
}

for (const c of CASES) {
  const dir = makeTree();  try {
    // (1) untouched input must PASS
    const clean = runGate(c.script, dir);
    if (clean.code !== 0) {
      failures.push(`${c.name}: ${judgeRun(clean, null, c.needle).why}`);
      continue;
    }
    c.mutate(dir);
    // A gate over a DERIVED artifact needs the artifact rebuilt, or its
    // "resource != source" check fires instead of the rule under test.
    if (c.rebuild) {
      try {
        execFileSync(node, [join(repo, 'scripts', c.rebuild), dir], {
          encoding: 'utf8', stdio: 'pipe', timeout: GATE_TIMEOUT_MS, cwd: dir,
        });
      } catch (e) {
        failures.push(`${c.name}: the rebuild step (${c.rebuild}) failed, so the derived artifact is stale and the gate cannot be tested:\n${String((e.stdout || '') + (e.stderr || '')).trim().split('\n').slice(0, 3).join('\n')}`);
        continue;
      }
    }
    const dirty = runGate(c.script, dir);
    const verdict = judgeRun(clean, dirty, c.needle);
    if (verdict) {
      failures.push(`${c.name}: ${verdict.why}`);
      continue;
    }
    notes.push(`${c.name}: ok`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

if (failures.length) {
  console.error(`FAIL ${NAME}: ${failures.length} gate(s) do not police their own rule:`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.log(`OK ${NAME} (${CASES.length} gate(s) verified: green on clean input, red on their known defect): ${notes.join('; ')}`);
