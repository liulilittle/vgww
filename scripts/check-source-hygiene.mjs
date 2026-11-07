#!/usr/bin/env node
// Gate: source_hygiene
//
// WHY THIS EXISTS
// ---------------
// batch226: `src/ui/pages/leases.cpp.bak` sat in the source tree - an editor
// backup of a page implementation, 34 KB, 718 lines, containing an OLDER
// `LeasesPage::OnIntent`. It is not in CMakeLists (that list is explicit), so it
// never compiled and no test could see it. What it DID do is corrupt every
// question asked of the source tree with a text tool: grepping for `OnIntent`
// returned 11 hits instead of 8, and the second `LeasesPage::OnIntent` made it
// look like the page had two dispatchers. That is the same failure mode as
// batch225's false-negative regex - a stale copy silently answers questions
// about code that is not the code being built.
//
// The rule: the directories that feed the build contain only build inputs.
// Editor/merge leftovers (*.bak, *.orig, *.rej, *~, *.swp) are refused. Build
// output and vendored third-party trees are out of scope by design.
//
// Usage: node scripts/check-source-hygiene.mjs <repo-root>
// Exit:  0 = no leftovers under the scanned roots; 1 = at least one found.
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join, resolve, relative } from 'node:path';

const NAME = 'source-hygiene';
const root = process.argv[2];
if (!root) {
  console.error(`FAIL ${NAME}: missing <repo-root> argument (usage: node scripts/check-source-hygiene.mjs <repo-root>)`);
  process.exit(1);
}
const repo = resolve(root);

// Roots that feed the build. Everything here is read by the compiler, the
// gates, or the test suite - a stale copy in any of them is a wrong answer
// waiting to be found.
const ROOTS = ['src', 'tests', 'scripts', 'www', 'tools'];
// Top-level files that are build inputs in their own right.
const TOP_FILES = ['CMakeLists.txt'];

// Never descend: build output, vendored code, the evidence archive and the
// agent's own state directory are not build inputs we curate.
const SKIP_DIRS = new Set([
  'node_modules', 'build', 'build_s4', 'build_s5', '.git', 'logs',
  '.opencode', 'third_party', '.superpowers', 'out', 'dist',
]);

const LEFTOVER = /(\.bak|\.orig|\.rej|\.swp|\.swo|~)$/i;

// batch226: every suffix in the pattern above must actually be recognised. The
// regex is the whole rule, and a browser/editor can leave ANY of these behind -
// deleting one alternative narrows the rule with nothing to notice it (measured:
// dropping `.bak` left this gate printing OK with a .bak file present). Driving
// the pattern against synthetic names proves each alternative independently,
// without needing a real file of every kind on disk.
const MUST_MATCH = [
  'page.cpp.bak', 'page.cpp.orig', 'page.cpp.rej', 'page.cpp.swp',
  'page.cpp.swo', 'page.cpp~', 'src/ui/x.bak', '.hidden.bak',
];
const MUST_NOT_MATCH = [
  'page.cpp', 'page.cpp.bak.txt', 'baking.cpp', 'page.cpp.orig.keep',
  'notes.md', 'CMakeLists.txt',
];
{
  const missed = MUST_MATCH.filter((n) => !LEFTOVER.test(n));
  const over = MUST_NOT_MATCH.filter((n) => LEFTOVER.test(n));
  if (missed.length || over.length) {
    console.error(`FAIL ${NAME}: the leftover pattern is wrong - it misses ${JSON.stringify(missed)} and over-matches ${JSON.stringify(over)}. Every suffix below must be refused, and an ordinary name must not be.`);
    process.exit(1);
  }
}

// batch230: a translation unit that includes the same header twice is the
// same failure mode as a stale copy - the second block answers no question and
// silently doubles the preprocessor work. `dataplane.cpp` carried six of them
// (cstdio/algorithm/chrono/cstring/thread/vector), duplicated verbatim right
// after the first block, and every gate called the file clean.
//
// Only the DIRECTIVE LISTS at the top of a file are compared, and only for
// C/C++ sources; `#include` inside a comment or a string is not a directive,
// so the scan strips line comments and skips lines whose first non-space
// character is not `#`. The signature has to be a pure function of the text so
// the self-check below can drive it without a file on disk.
const DIRECTIVE = /^\s*#\s*include\s*([<"][^>"]+[>"])/;
function duplicateIncludes(text) {
  const seen = new Map();
  const dups = [];
  const lines = text.split(/\r?\n/);
  let inBlockComment = false;
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    if (inBlockComment) {
      const end = line.indexOf('*/');
      if (end === -1) continue;
      line = line.slice(end + 2);
      inBlockComment = false;
    }
    line = line.replace(/\/\*.*?\*\//g, '');
    const open = line.indexOf('/*');
    if (open !== -1) {
      line = line.slice(0, open);
      inBlockComment = true;
    }
    line = line.replace(/\/\/.*$/, '');
    const m = DIRECTIVE.exec(line);
    if (!m) continue;
    const header = m[1];
    if (seen.has(header)) dups.push({ header, first: seen.get(header), again: i + 1 });
    else seen.set(header, i + 1);
  }
  return dups;
}

// batch233: the same copy-paste failure produces duplicate namespace aliases.
// `udp_relay.cpp` defined `using Clock = std::chrono::steady_clock;` THREE
// times in one namespace scope - legal C++, no behaviour change, and every
// compiler and gate called it clean. It is the same signal as a duplicate
// include: a block was pasted and the author did not notice. A repeated alias
// is also a trap, because two `using X = Y;` lines make it look like the name
// resolves differently at different points.
//
// Two aliases collide only when they are in the SAME scope. Tracking the
// namespace path plus brace depth is not enough: two different functions in
// the same namespace both start at depth 1, and a `using Vec = ...;` at the top
// of each is perfectly legal (measured as a false positive on
// tests/test_driver_installer.cpp:1199 vs :1267). The scope key therefore also
// carries the nearest enclosing FUNCTION signature, so each function body is
// its own scope.
const ALIAS = /^\s*using\s+(\w+)\s*=/;
const NAMESPACE = /^\s*namespace\s+([\w:]+)\s*\{/;
// A function definition at namespace scope: `ret name(args) {` with no `;`.
const FUNC_HEAD = /^\s{0,12}[\w:<>,\s\*&]+?\b(\w+)\s*\([^;]*$/;
function duplicateAliases(text) {
  const seen = new Map();
  const dups = [];
  const lines = text.split(/\r?\n/);
  let inBlockComment = false;
  let localDepth = 0;
  let scopePath = '';
  let funcName = '';            // enclosing function, reset when its body closes
  const nsDepthStack = [];
  const funcDepthStack = [];
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    if (inBlockComment) {
      const end = line.indexOf('*/');
      if (end === -1) continue;
      line = line.slice(end + 2);
      inBlockComment = false;
    }
    line = line.replace(/\/\*.*?\*\//g, '');
    const open = line.indexOf('/*');
    if (open !== -1) {
      line = line.slice(0, open);
      inBlockComment = true;
    }
    line = line.replace(/\/\/.*$/, '');
    const ns = NAMESPACE.exec(line);
    const isNsLine = ns !== null;
    const func = (!isNsLine && line.includes('{')) ? FUNC_HEAD.exec(line) : null;
    const m = ALIAS.exec(line);
    if (m) {
      const key = scopePath + '|' + funcName + '|' + localDepth + '/' + m[1];
      if (seen.has(key)) dups.push({ name: m[1], first: seen.get(key), again: i + 1 });
      else seen.set(key, i + 1);
    }
    for (const ch of line) {
      if (ch === '{') {
        if (isNsLine && !line.slice(0, line.indexOf('{')).includes('{')) {
          nsDepthStack.push(localDepth);
          scopePath = scopePath ? scopePath + '::' + ns[1] : ns[1];
        } else {
          if (func !== null) {
            funcDepthStack.push(localDepth);
            funcName = func[1];
          }
          localDepth++;
        }
      } else if (ch === '}') {
        if (nsDepthStack.length > 0 && nsDepthStack[nsDepthStack.length - 1] === localDepth) {
          nsDepthStack.pop();
          const idx = scopePath.lastIndexOf('::');
          scopePath = idx < 0 ? '' : scopePath.slice(0, idx);
        } else {
          if (funcDepthStack.length > 0 && funcDepthStack[funcDepthStack.length - 1] === localDepth - 1) {
            funcDepthStack.pop();
            funcName = '';
          }
          localDepth = Math.max(0, localDepth - 1);
        }
      }
    }
  }
  return dups;
}

const ALIAS_CASES = [
  { name: 'no aliases', text: 'namespace a {\n}\n', want: 0 },
  { name: 'single alias', text: 'using Clock = std::chrono::steady_clock;\n', want: 0 },
  { name: 'duplicate alias', text: 'using Clock = A;\nusing Clock = A;\n', want: 1 },
  { name: 'three copies counted twice', text: 'using C = A;\nusing C = A;\nusing C = A;\n', want: 2 },
  { name: 'different names', text: 'using C = A;\nusing D = A;\n', want: 0 },
  { name: 'duplicate inside a block comment', text: 'using C = A;\n/*\nusing C = A;\n*/\n', want: 0 },
  { name: 'duplicate inside a line comment', text: 'using C = A;\n// using C = A;\n', want: 0 },
  { name: 'same name in different namespaces is legal', text: 'namespace a {\nusing C = X;\n}\nnamespace b {\nusing C = Y;\n}\n', want: 0 },
  { name: 'function-local alias after a namespace-scope one', text: 'using C = A;\nvoid f() {\nusing C = B;\n}\n', want: 0 },
  { name: 'duplicate after a scope closes', text: 'namespace a {\nint x;\n}\nusing C = A;\nusing C = A;\n', want: 1 },
];
{
  const wrong = ALIAS_CASES.filter((c) => duplicateAliases(c.text).length !== c.want);
  if (wrong.length) {
    console.error(`FAIL ${NAME}: the duplicate-alias scanner is wrong - ${JSON.stringify(wrong.map((c) => c.name))} did not report the expected ${JSON.stringify(wrong.map((c) => c.want))} duplicate(s). Alias parsing must ignore comments and must not confuse a nested scope with the namespace scope.`);
    process.exit(1);
  }
}

// batch293: a statement that starts at column 0 while it is inside a function
// body, a named namespace or a class body. The compiler accepts it, so nothing
// else notices, but it reads as if the line had left its block: editors fold
// the enclosing region differently, and a reviewer scanning the indentation
// sees a statement that appears to belong to the file scope. Measured: 92 such
// lines in 21 files (`settings.cpp` built five groups at column 0, `OnTick` and
// `DrainCommandResults` were 8 spaces short for their whole 162-line bodies,
// `dhcp.h` declared eight message-type constants at column 0 inside
// `namespace proto`).
//
// The rule needs the brace stack, because the SAME column-0 line is correct in
// one scope and wrong in another: test files put anonymous-namespace content at
// column 0 by convention, while named namespaces in `src/` indent their
// contents. Comments and string literals are stripped first so a `{` inside
// either cannot open a phantom scope.
const COL0_EXEMPT = /^(#|\}|\{|\)|;)/;
const COL0_EXEMPT_WORD = /^(public|private|protected)\s*:|^(case\b|default\s*:)/;

function stripCommentsAndStrings(text) {
  const out = text.split('');
  let i = 0;
  let state = 'code';
  let rawDelim = '';
  while (i < text.length) {
    const c = text[i];
    const n = text[i + 1];
    if (state === 'code') {
      if (c === '/' && n === '/') { state = 'line'; out[i] = ' '; out[i + 1] = ' '; i += 2; continue; }
      if (c === '/' && n === '*') { state = 'block'; out[i] = ' '; out[i + 1] = ' '; i += 2; continue; }
      if (c === '"') { state = 'str'; out[i] = ' '; i += 1; continue; }
      if (c === "'") { state = 'chr'; out[i] = ' '; i += 1; continue; }
      if (c === 'R' && n === '"') {
        const close = text.indexOf('(', i + 2);
        if (close > 0) {
          rawDelim = text.slice(i + 2, close);
          for (let k = i; k <= close; ++k) out[k] = ' ';
          i = close + 1;
          state = 'raw';
          continue;
        }
      }
      i += 1;
      continue;
    }
    if (state === 'line') {
      if (c === '\n') state = 'code';
      else out[i] = ' ';
      i += 1;
      continue;
    }
    if (state === 'block') {
      if (c === '*' && n === '/') { out[i] = ' '; out[i + 1] = ' '; i += 2; state = 'code'; continue; }
      if (c !== '\n') out[i] = ' ';
      i += 1;
      continue;
    }
    if (state === 'str' || state === 'chr') {
      if (c === '\\') { out[i] = ' '; if (text[i + 1] !== '\n') out[i + 1] = ' '; i += 2; continue; }
      if ((state === 'str' && c === '"') || (state === 'chr' && c === "'")) { out[i] = ' '; i += 1; state = 'code'; continue; }
      if (c !== '\n') out[i] = ' ';
      i += 1;
      continue;
    }
    if (state === 'raw') {
      if (c === ')' && text.slice(i + 1, i + 1 + rawDelim.length) === rawDelim && text[i + 1 + rawDelim.length] === '"') {
        const end = i + 1 + rawDelim.length;
        for (let k = i; k <= end; ++k) if (text[k] !== '\n') out[k] = ' ';
        i = end + 1;
        state = 'code';
        continue;
      }
      if (c !== '\n') out[i] = ' ';
      i += 1;
      continue;
    }
  }
  return out.join('');
}

function columnZeroIndent(text) {
  const code = stripCommentsAndStrings(text).split('\n');
  const rawLines = text.split(/\r?\n/);
  const stack = [];
  const bad = [];
  let head = '';
  let stmtIndent = 0;
  let stmtOpen = false;
  for (let li = 0; li < code.length; ++li) {
    const line = code[li];
    const raw = rawLines[li] || '';
    const trimmed = line.trim();
    const rawTrim = raw.trim();
    // batch298: a pure `//` comment at column 0 inside an indented scope is
    // the same defect as a statement there; the code pass below cannot see
    // it because stripCommentsAndStrings blanks the comment text.
    if (raw.length > 0 && !/^\s/.test(raw) && /^\/\//.test(raw)) {
      const inner = stack.length ? stack[stack.length - 1] : null;
      if (inner && inner.kind !== 'anon-namespace') {
        bad.push({ line: li + 1, text: rawTrim.slice(0, 100), want: inner.indent + 4 });
      }
    }
    if (trimmed) {
      const inner = stack.length ? stack[stack.length - 1] : null;
      const col0 = raw.length > 0 && !/^\s/.test(raw);
      if (col0 && inner && inner.kind !== 'anon-namespace' &&
          !COL0_EXEMPT.test(rawTrim) && !COL0_EXEMPT_WORD.test(rawTrim)) {
        bad.push({ line: li + 1, text: rawTrim.slice(0, 100), want: inner.indent + 4 });
      }
      if (!stmtOpen) { stmtIndent = (raw.match(/^ */) || [''])[0].length; stmtOpen = true; }
    }
    for (let ci = 0; ci < line.length; ++ci) {
      const c = line[ci];
      if (c === '{') {
        const h = head.trim();
        let kind = 'block';
        if (/(^|\s)namespace(\s+[A-Za-z_]\w*)?$/.test(h)) {
          kind = /namespace\s+[A-Za-z_]\w*$/.test(h) ? 'namespace' : 'anon-namespace';
        } else if (/(^|\s)(class|struct|union|enum)\b[^;]*$/.test(h)) {
          kind = 'class';
        } else if (/(^|\s)extern\s*$/.test(h)) {
          kind = 'extern';
        }
        stack.push({ kind, indent: stmtIndent });
        head = '';
        stmtOpen = false;
      } else if (c === '}') {
        stack.pop();
        head = '';
        stmtOpen = false;
      } else if (c === ';') {
        head = '';
        stmtOpen = false;
      } else {
        head += c;
      }
    }
    if (trimmed) head += ' ';
  }
  return bad;
}

// batch298: a comment block belongs to the code it annotates, so it must not
// be indented deeper than the code that follows it. Exempt: a block that ends
// a scope (the next line closes it), one that documents a preprocessor branch,
// a continuation of an aligned trailing comment, and a `///<` doc continuation.
// No compiler sees this defect; the comment simply stops lining up with its
// block and the reader has to re-derive the structure.
function commentIndentProblems(text) {
  const bad = [];
  const lines = text.split(/\r?\n/);
  const indentOf = (s) => (s.match(/^ */) || [''])[0].length;
  const isComment = (s) => /^\s*\/\//.test(s);
  const isBlank = (s) => s.trim() === '';
  for (let i = 0; i < lines.length; ++i) {
    if (!isComment(lines[i])) continue;
    if (i > 0 && isComment(lines[i - 1])) continue;   // report the block once
    let end = i;
    while (end + 1 < lines.length && isComment(lines[end + 1])) ++end;
    const head = lines[i].trim();
    if (head.startsWith('///<')) continue;   // trailing-doc continuation
    const ind = indentOf(lines[i]);
    let prev = i - 1;
    while (prev >= 0 && isBlank(lines[prev])) --prev;
    if (prev >= 0) {
      const slash = lines[prev].indexOf('//');
      if (slash >= 0 && lines[prev].slice(0, slash).trim() !== '' && slash === ind) {
        continue;   // aligned continuation of a trailing comment
      }
    }
    let next = end + 1;
    while (next < lines.length && (isBlank(lines[next]) || isComment(lines[next]))) ++next;
    if (next >= lines.length) continue;
    const nextTrim = lines[next].trim();
    if (nextTrim.startsWith('#')) continue;   // preprocessor at column 0
    if (/^[})\]]/.test(nextTrim)) continue;   // the block ends here
    if (COL0_EXEMPT_WORD.test(nextTrim)) continue;   // case/default/access
    if (ind > indentOf(lines[next])) {
      bad.push({ line: i + 1, text: head.slice(0, 100), want: indentOf(lines[next]) });
    }
  }
  return bad;
}

const COMMENT_CASES = [
  { name: 'comment at the code indent', text: 'void f() {\n    // note\n    int x = 0;\n}\n', want: 0 },
  { name: 'over-indented comment', text: 'void f() {\n        // note\n    int x = 0;\n}\n', want: 1 },
  { name: 'comment before a closing brace', text: 'void f() {\n    do_a();\n        // note\n}\n', want: 0 },
  { name: 'comment before a preprocessor line', text: 'void f() {\n    // note\n#include "x"\n}\n', want: 0 },
  { name: 'trailing-comment continuation', text: 'void f() {\n    int x = 0;  // note\n                // more\n    int y = 0;\n}\n', want: 0 },
  { name: 'trailing doc continuation', text: 'struct A {\n    int x;  ///< note\n            ///< more\n};\n', want: 0 },
  { name: 'comment before a case label', text: 'void f(int v) {\n    switch (v) {\n        case 1:\n            do_a();\n            // note\n        case 2:\n            break;\n    }\n}\n', want: 0 },
  { name: 'comment before a dedented statement', text: 'void f() {\n    do_a();\n        // note\n    do_b();\n}\n', want: 1 },
  { name: 'column-0 comment is not this rule', text: 'void f() {\n// note\n    int x = 0;\n}\n', want: 0 },
  { name: 'two over-indented blocks both counted', text: 'void f() {\n        // a\n    do_a();\n        // b\n    do_b();\n}\n', want: 2 },
];
{
  const wrong = COMMENT_CASES.filter((c) => commentIndentProblems(c.text).length !== c.want);
  if (wrong.length) {
    console.error(`FAIL ${NAME}: the comment-indent scanner is wrong - ${JSON.stringify(wrong.map((c) => c.name))} did not report the expected ${JSON.stringify(wrong.map((c) => c.want))} finding(s). A comment must not sit deeper than the code it annotates; a block end, a preprocessor branch, an aligned trailing comment and a \`///<\` continuation are exempt.`);
    process.exit(1);
  }
}

const COL0_CASES = [
  { name: 'top-level statement is fine', text: 'int x = 0;\n', want: 0 },
  { name: 'indented statement is fine', text: 'void f() {\n    int x = 0;\n}\n', want: 0 },
  { name: 'statement inside a function', text: 'void f() {\nint x = 0;\n}\n', want: 1 },
  { name: 'statement inside a nested block', text: 'void f() {\n    if (1) {\nint x = 0;\n    }\n}\n', want: 1 },
  { name: 'declaration inside a named namespace', text: 'namespace a {\nint x = 0;\n}\n', want: 1 },
  { name: 'anonymous namespace keeps column 0', text: 'namespace {\nvoid f() {\n}\n}\n', want: 0 },
  { name: 'class member at column 0', text: 'class A {\nint x = 0;\n};\n', want: 1 },
  { name: 'closing brace at column 0', text: 'void f() {\n    int x = 0;\n}\n', want: 0 },
  { name: 'preprocessor at column 0', text: 'void f() {\n#if X\n    int x = 0;\n#endif\n}\n', want: 0 },
  { name: 'access specifier at column 0', text: 'class A {\npublic:\n    int x = 0;\n};\n', want: 0 },
  { name: 'case label at column 0', text: 'void f(int v) {\n    switch (v) {\ncase 1:\n        break;\n    }\n}\n', want: 0 },
  { name: 'brace in a string opens no scope', text: 'void f() {\n    const char* s = "{";\n    int x = 0;\n}\n', want: 0 },
  { name: 'brace in a comment opens no scope', text: 'void f() {\n    // {\n    int x = 0;\n}\n', want: 0 },
  { name: 'brace in a raw string opens no scope', text: 'void f() {\n    const char* s = R"x({\n)x";\n    int x = 0;\n}\n', want: 0 },
  { name: 'column-0 comment inside a function', text: 'void f() {\n// note\n    int x = 0;\n}\n', want: 1 },
  { name: 'column-0 comment in an anonymous namespace', text: 'namespace {\n// note\nvoid f() {\n}\n}\n', want: 0 },
  { name: 'indented comment is fine', text: 'void f() {\n    // note\n    int x = 0;\n}\n', want: 0 },
  { name: 'column-0 comment at file scope', text: '// note\nint x = 0;\n', want: 0 },
];
{
  const wrong = COL0_CASES.filter((c) => columnZeroIndent(c.text).length !== c.want);
  if (wrong.length) {
    console.error(`FAIL ${NAME}: the column-0 scanner is wrong - ${JSON.stringify(wrong.map((c) => c.name))} did not report the expected ${JSON.stringify(wrong.map((c) => c.want))} finding(s). The rule must depend on the enclosing scope: anonymous-namespace content may sit at column 0, everything else must be indented.`);
    process.exit(1);
  }
}

// Drive the extractor with synthetic text: no directive, a duplicate, a
// duplicate inside a block comment, one after a block comment, one inside a
// line comment, one after a line comment on the same line, an indented
// directive, and a directive that is not at the start of the line. Each case
// pins one branch of the parser, so narrowing any of them turns the gate red
// on its own.
const DUP_CASES = [
  { name: 'no includes', text: '#pragma once\nint x;\n', want: 0 },
  { name: 'single include', text: '#include <a>\n#include "b"\n', want: 0 },
  { name: 'verbatim duplicate', text: '#include <a>\n#include <b>\n#include <a>\n', want: 1 },
  { name: 'six duplicates all counted', text: '#include <a>\n#include <b>\n#include <c>\n#include <d>\n#include <e>\n#include <f>\n#include <a>\n#include <b>\n#include <c>\n#include <d>\n#include <e>\n#include <f>\n', want: 6 },
  { name: 'duplicate in block comment', text: '#include <a>\n/*\n#include <a>\n*/\n', want: 0 },
  { name: 'duplicate in line comment', text: '#include <a>\n// #include <a>\n', want: 0 },
  { name: 'duplicate after a trailing line comment', text: '#include <a>  // <a> is needed\n#include <a>\n', want: 1 },
  { name: 'include inside a trailing comment is not a directive', text: '#include <a>  // never #include <b>\n#include <b>\n', want: 0 },
  { name: 'duplicate after block comment ends', text: '/* x */ #include <a>\n#include <a>\n', want: 1 },
  { name: 'indented directive is still a directive', text: '  #include <a>\n  #include <a>\n', want: 1 },
  { name: 'include not at line start is not a directive', text: 'int x; #include <a>\n#include <a>\n', want: 0 },
  { name: 'angle vs quote spelling', text: '#include <a>\n#include "a"\n', want: 0 },
];
{
  const wrong = DUP_CASES.filter((c) => duplicateIncludes(c.text).length !== c.want);
  if (wrong.length) {
    console.error(`FAIL ${NAME}: the duplicate-include scanner is wrong - ${JSON.stringify(wrong.map((c) => c.name))} did not report the expected ${JSON.stringify(wrong.map((c) => c.want))} duplicate(s). Directive parsing must ignore comments and keep <angle> and "quote" spellings distinct.`);
    process.exit(1);
  }
}

// batch294: trailing whitespace and a missing final newline. Neither changes
// behaviour, so no compiler or test can see them, but both corrupt the tools
// that read the tree: a trailing space makes `git diff` show a changed line
// after an editor strips it, a stray `\r` at EOF (measured: 18 files ended
// `\r\n\r`) makes the last line look modified to every text tool, and a file
// without a final newline concatenates with the next file when cat'd. The
// scanner reports the LINE so the fix is mechanical.
//
// batch308: the same 18 files also carried 1-6 BLANK lines at EOF. A file ends
// with exactly one newline; extra blank lines are pure noise and make every
// diff that touches the tail ambiguous, so they are reported too.
//
// A tab is refused for the same reason: this tree is space-indented, so a tab
// is either a paste from another project or an editor misconfiguration.
function whitespaceProblems(text) {
  const bad = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/[ \t]+$/.test(line)) bad.push({ line: i + 1, what: 'trailing whitespace' });
    if (/\t/.test(line.replace(/[ \t]+$/, ''))) bad.push({ line: i + 1, what: 'tab character' });
  }
  if (text.length > 0 && !text.endsWith('\n')) {
    bad.push({ line: lines.length, what: 'missing final newline' });
  }
  // batch308: exactly ONE final newline. A second (or sixth) blank line at
  // EOF is noise; 18 build-input files carried them.
  const tail = text.match(/(?:\r?\n)+$/);
  if (tail && (tail[0].match(/\n/g) || []).length > 1) {
    bad.push({ line: lines.length, what: 'trailing blank line(s) at EOF' });
  }
  if (/\r\r\n/.test(text)) {
    bad.push({ line: 0, what: 'doubled carriage return (\\r\\r\\n)' });
  }
  // batch313: one file, one line ending. A file that mixes CRLF and lone LF
  // renders inconsistently in every editor and makes "did this line change?"
  // depend on which tool wrote it (measured: 7 C/C++ files mixed both, one of
  // them 276 LF lines appended to a CRLF file). Count from the LF total so no
  // lookbehind is needed.
  const crlf = (text.match(/\r\n/g) || []).length;
  const loneLf = (text.match(/\n/g) || []).length - crlf;
  if (crlf > 0 && loneLf > 0) {
    bad.push({
      line: 0,
      what: `mixed line endings (${crlf} CRLF, ${loneLf} LF)`,
    });
  }
  return bad;
}

const WS_CASES = [
  { name: 'clean text', text: 'int x;\n', want: 0 },
  { name: 'trailing space', text: 'int x; \n', want: 1 },
  { name: 'trailing tab', text: 'int x;\t\n', want: 1 },
  { name: 'tab indentation', text: '\tint x;\n', want: 1 },
  { name: 'missing final newline', text: 'int x;', want: 1 },
  { name: 'CRLF is fine', text: 'int x;\r\nint y;\r\n', want: 0 },
  { name: 'doubled CR', text: 'int x;\r\r\n', want: 1 },
  { name: 'empty file', text: '', want: 0 },
  { name: 'space inside a string is not trailing', text: 'const char* s = "a ";\n', want: 0 },
  { name: 'trailing blank line', text: 'int x;\n\n', want: 1 },
  { name: 'CRLF trailing blank lines', text: 'int x;\r\n\r\n\r\n', want: 1 },
  { name: 'mixed CRLF and LF', text: 'int x;\r\nint y;\n', want: 1 },
  { name: 'LF only is fine', text: 'int x;\nint y;\n', want: 0 },
];
{
  const wrong = WS_CASES.filter((c) => whitespaceProblems(c.text).length !== c.want);
  if (wrong.length) {
    console.error(`FAIL ${NAME}: the whitespace scanner is wrong - ${JSON.stringify(wrong.map((c) => c.name))} did not report the expected ${JSON.stringify(wrong.map((c) => c.want))} finding(s). Trailing whitespace, tabs, a missing final newline, trailing blank lines at EOF, a doubled CR and mixed line endings must each be reported.`);
    process.exit(1);
  }
}

// batch317: a `<<` chain is ONE expression, so its continuation lines must
// line up. A line indented one space deeper reads as a different nesting level
// and makes the whole statement look mis-nested (measured: the /api/status
// body in web_api.cpp had an 18-line chain with two lines one space too deep).
// Runs shorter than two lines cannot be misaligned. The expected indent is the
// run's MODE, so one drifted line is reported and the rest are left alone.
function continuationIndentProblems(text) {
  const bad = [];
  const lines = text.split(/\r?\n/);
  const flush = (start, end) => {
    if (start < 0 || end - start < 2) return;
    const counts = new Map();
    for (let i = start; i < end; i++) {
      const m = /^(\s*)<</.exec(lines[i]);
      if (m) counts.set(m[1].length, (counts.get(m[1].length) || 0) + 1);
    }
    let want = -1;
    let best = -1;
    for (const [indent, n] of counts) {
      if (n > best) { best = n; want = indent; }
    }
    for (let i = start; i < end; i++) {
      const m = /^(\s*)<</.exec(lines[i]);
      if (m && m[1].length !== want) {
        bad.push({ line: i + 1, text: lines[i].trim(), want });
      }
    }
  };
  let start = -1;
  for (let i = 0; i < lines.length; i++) {
    if (/^(\s*)<</.test(lines[i])) {
      if (start < 0) start = i;
    } else {
      flush(start, i);
      start = -1;
    }
  }
  flush(start, lines.length);
  return bad;
}

const CONT_CASES = [
  { name: 'aligned chain', text: 'a << "x"\n  << "y"\n  << "z";\n', want: 0 },
  { name: 'one line drifted', text: 'a << "x"\n   << "y"\n  << "z";\n', want: 1 },
  { name: 'single continuation', text: 'a <<\n  "x";\n', want: 0 },
  { name: 'CRLF chain', text: 'a << "x"\r\n  << "y";\r\n', want: 0 },
  { name: 'comment splits the chain', text: 'a << "x"\n  << "y";\n// note\nb << "p"\n  << "q";\n', want: 0 },
  { name: 'both lines drifted', text: 'a << "x"\n   << "y"\n   << "z";\n', want: 0 },
];
{
  const wrong = CONT_CASES.filter((c) => continuationIndentProblems(c.text).length !== c.want);
  if (wrong.length) {
    console.error(`FAIL ${NAME}: the continuation scanner is wrong - ${JSON.stringify(wrong.map((c) => c.name))} did not report the expected ${JSON.stringify(wrong.map((c) => c.want))} finding(s). A '<<' chain is one expression; its continuation lines must share one indent.`);
    process.exit(1);
  }
}

// batch319: a brace that opens a MULTI-LINE body must be alone on its line.
// `if (x) {  // note` is fine (the text after the brace is a comment) and a
// one-line body `{ return false; }` is fine; a STATEMENT crammed between the
// brace and the newline (measured: router.cpp's Update signature carried
// `snapshot_ = std::move(snapshot);` on the signature line) is not - it hides
// the first statement of the body and makes the block look empty.
function crammedBraceProblems(text) {
  const bad = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = /\{\s+(\S.*)$/.exec(line);
    if (!m) continue;
    if (m[1].startsWith('//')) continue;              // trailing comment
    if (/^\\\s*$/.test(m[1])) continue;               // macro line continuation
    if (line.indexOf('}', m.index) !== -1) continue;  // body closes on this line
    const before = line.slice(0, m.index);
    if (!/\)\s*$/.test(before)) continue;            // not a body-opening brace
    bad.push({ line: i + 1, text: line.trim() });
  }
  return bad;
}

const CRAMMED_CASES = [
  { name: 'brace alone', text: 'void f() {\n    g();\n}\n', want: 0 },
  { name: 'crammed statement', text: 'void f() {    g();\n    h();\n}\n', want: 1 },
  { name: 'trailing comment', text: 'if (x) {  // note\n    g();\n}\n', want: 0 },
  { name: 'one-line body', text: 'bool f() { return true; }\n', want: 0 },
  { name: 'lambda one-liner', text: 'sort(v, [](int a, int b) { return a < b; });\n', want: 0 },
  { name: 'CRLF crammed', text: 'void f() {    g();\r\n}\r\n', want: 1 },
];
{
  const wrong = CRAMMED_CASES.filter((c) => crammedBraceProblems(c.text).length !== c.want);
  if (wrong.length) {
    console.error(`FAIL ${NAME}: the crammed-statement scanner is wrong - ${JSON.stringify(wrong.map((c) => c.name))} did not report the expected ${JSON.stringify(wrong.map((c) => c.want))} finding(s). A multi-line body's opening brace must be the last thing on its line.`);
    process.exit(1);
  }
}

const SOURCE_EXT = /\.(cpp|cc|cxx|h|hpp|hxx)$/i;

// batch230: the file-level scan is a pure function over (name, text) pairs so
// the self-check can drive the REAL scan path - not just the parser. Without
// this, narrowing the wiring (`for (const d of [])`) left every assertion
// green: the parser still worked, nothing fed it. `unreadable` is reported
// separately because a read failure must not look like "clean".
const TEXT_EXT = /\.(cpp|cc|cxx|h|hpp|hxx|js|mjs|css|html)$/i;

function scanSources(files) {
  const dups = [];
  const aliases = [];
  const col0 = [];
  const ci = [];
  const cont = [];
  const crammed = [];
  const ws = [];
  const unreadable = [];
  let sources = 0;
  for (const file of files) {
    if (TEXT_EXT.test(file.name) && typeof file.text === 'string') {
      for (const w of whitespaceProblems(file.text)) {
        ws.push({ path: file.path, line: w.line, what: w.what });
      }
    }
    if (!SOURCE_EXT.test(file.name)) continue;
    sources++;
    if (typeof file.text !== 'string') {
      unreadable.push(file.path);
      continue;
    }
    for (const d of duplicateIncludes(file.text)) {
      dups.push({
        path: file.path,
        header: d.header,
        first: d.first,
        again: d.again,
      });
    }
    for (const a of duplicateAliases(file.text)) {
      aliases.push({
        path: file.path,
        name: a.name,
        first: a.first,
        again: a.again,
      });
    }
    for (const c of columnZeroIndent(file.text)) {
      col0.push({
        path: file.path,
        line: c.line,
        text: c.text,
        want: c.want,
      });
    }
    for (const c of commentIndentProblems(file.text)) {
      ci.push({
        path: file.path,
        line: c.line,
        text: c.text,
        want: c.want,
      });
    }
    for (const c of continuationIndentProblems(file.text)) {
      cont.push({
        path: file.path,
        line: c.line,
        text: c.text,
        want: c.want,
      });
    }
    for (const c of crammedBraceProblems(file.text)) {
      crammed.push({
        path: file.path,
        line: c.line,
        text: c.text,
      });
    }
  }
  return { dups, aliases, col0, ci, cont, crammed, ws, unreadable, sources };
}

{
  // Drive the whole scan path, not just the parser: two bait files, one
  // duplicated and one not, plus a non-source file and an unreadable one.
  const out = scanSources([
    { name: 'a.cpp', path: 'a.cpp', text: '#include <vector>\n#include <vector>\n' },
    { name: 'b.h', path: 'b.h', text: '#include <string>\n' },
    { name: 'd.cpp', path: 'd.cpp', text: 'void f() {\nint x = 0;\n}\n' },
    { name: 'g.cpp', path: 'g.cpp', text: 'void g() {\n        // note\n    int x = 0;\n}\n' },
    { name: 'e.js', path: 'e.js', text: 'let x = 1; \n' },
    { name: 'm.cpp', path: 'm.cpp', text: 'int a;\r\nint b;\n' },
    { name: 'k.cpp', path: 'k.cpp', text: 'a << "x"\n   << "y"\n  << "z";\n' },
    { name: 'n.cpp', path: 'n.cpp', text: 'void f() {    g();\n    h();\n}\n' },
    { name: 'notes.md', path: 'notes.md', text: '#include <x>\n#include <x>\n' },
    { name: 'c.cpp', path: 'c.cpp', text: null },
  ]);
  const problems = [];
  if (out.dups.length !== 1) problems.push(`expected 1 duplicate from the bait, got ${out.dups.length}`);
  if (out.dups.length && out.dups[0].path !== 'a.cpp') problems.push(`the duplicate was attributed to ${JSON.stringify(out.dups[0].path)} instead of a.cpp`);
  if (out.sources !== 8) problems.push(`expected 8 C/C++ files (a.cpp, b.h, d.cpp, g.cpp, m.cpp, k.cpp, n.cpp, c.cpp), got ${out.sources} - the extension filter is wrong`);
  if (out.col0.length !== 1) problems.push(`expected 1 column-0 finding from the bait, got ${out.col0.length}`);
  if (out.col0.length && out.col0[0].path !== 'd.cpp') problems.push(`the column-0 finding was attributed to ${JSON.stringify(out.col0[0].path)} instead of d.cpp`);
  if (out.ci.length !== 1) problems.push(`expected 1 comment-indent finding from the bait, got ${out.ci.length}`);
  if (out.ci.length && out.ci[0].path !== 'g.cpp') problems.push(`the comment-indent finding was attributed to ${JSON.stringify(out.ci[0].path)} instead of g.cpp`);
  if (out.cont.length !== 1) problems.push(`expected 1 continuation-indent finding from the bait, got ${out.cont.length}`);
  if (out.cont.length && out.cont[0].path !== 'k.cpp') problems.push(`the continuation-indent finding was attributed to ${JSON.stringify(out.cont[0].path)} instead of k.cpp`);
  if (out.crammed.length !== 1) problems.push(`expected 1 crammed-statement finding from the bait, got ${out.crammed.length}`);
  if (out.crammed.length && out.crammed[0].path !== 'n.cpp') problems.push(`the crammed-statement finding was attributed to ${JSON.stringify(out.crammed[0].path)} instead of n.cpp`);
  if (out.ws.length !== 2) problems.push(`expected 2 whitespace findings (trailing space + mixed EOL), got ${out.ws.length}`);
  if (out.ws.length && out.ws[0].path !== 'e.js') problems.push(`the whitespace finding was attributed to ${JSON.stringify(out.ws[0].path)} instead of e.js`);
  if (out.ws.length > 1 && out.ws[1].path !== 'm.cpp') problems.push(`the mixed-EOL finding was attributed to ${JSON.stringify(out.ws[1].path)} instead of m.cpp`);
  if (out.unreadable.length !== 1) problems.push(`expected 1 unreadable entry, got ${out.unreadable.length}`);
  if (problems.length) {
    console.error(`FAIL ${NAME}: the include scan is not wired end to end - ${problems.join('; ')}. A parser that nothing feeds reports a clean tree for any input.`);
    process.exit(1);
  }
}

const sourceFiles = [];

const found = [];
let scannedFiles = 0;
let scannedDirs = 0;

function walk(dir, depth) {
  if (depth > 12) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  scannedDirs++;
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, depth + 1);
      continue;
    }
    scannedFiles++;
    const rel = relative(repo, full).replace(/\\/g, '/');
    if (LEFTOVER.test(entry.name)) {
      let bytes = 0;
      try { bytes = statSync(full).size; } catch { /* size is cosmetic */ }
      found.push({ path: rel, bytes });
    }
    if (SOURCE_EXT.test(entry.name)) {
      let text = null;
      try { text = readFileSync(full, 'utf8'); } catch { text = null; }
      sourceFiles.push({ name: entry.name, path: rel, text });
    }
  }
}

for (const rel of ROOTS) {
  const dir = join(repo, rel);
  if (existsSync(dir)) walk(dir, 0);
}
for (const rel of TOP_FILES) {
  const file = join(repo, rel);
  if (!existsSync(file)) continue;
  scannedFiles++;
  if (LEFTOVER.test(rel)) found.push({ path: rel, bytes: 0 });
}

// batch230: the DECISION is a pure function too. The self-check above drives
// the scanner, but a scanner whose result never reaches the verdict still
// reports a clean tree (measured: replacing `dups.push(...scanned.dups)` with
// `void scanned.dups` left the gate green while a bait file sat in the tree).
// Keeping "given these findings, what do we say" as data makes the whole chain
// testable without needing a dirty checkout on disk.
//
// Returns { code, lines } - code 0 means OK, 1 means FAIL.
function judgeScan({ dups, aliases = [], col0 = [], ci = [], cont = [], crammed = [], ws = [], found, scannedFiles, scannedSources, roots }) {
  if (scannedFiles === 0) {
    return {
      code: 1,
      lines: [`FAIL ${NAME}: scanned 0 files under ${roots.join(', ')} - the tree layout moved, this gate is no longer looking at the sources`],
    };
  }
  if (scannedSources === 0) {
    return {
      code: 1,
      lines: [`FAIL ${NAME}: the duplicate-include scan saw 0 C/C++ file(s) - SOURCE_EXT stopped matching, so "no duplicate includes" is meaningless`],
    };
  }
  if (found.length) {
    const lines = [`FAIL ${NAME}: ${found.length} editor/merge leftover(s) inside the build inputs:`];
    for (const f of found) {
      lines.push(`  - ${f.path} (${f.bytes} bytes) is not a build input; every text tool that reads this tree will now answer with stale code. Delete it.`);
    }
    return { code: 1, lines };
  }
  if (dups.length) {
    const lines = [`FAIL ${NAME}: ${dups.length} duplicate #include directive(s) inside the build inputs:`];
    for (const d of dups) {
      lines.push(`  - ${d.path}:${d.again} re-includes "${d.header}" (already included at line ${d.first}). The second directive adds nothing but preprocessor work; delete one.`);
    }
    return { code: 1, lines };
  }
  if (aliases.length) {
    const lines = [`FAIL ${NAME}: ${aliases.length} duplicate namespace alias definition(s) inside the build inputs:`];
    for (const a of aliases) {
      lines.push(`  - ${a.path}:${a.again} redefines "${a.name}" (already defined at line ${a.first}). A pasted block, not a deliberate shadow; two identical aliases at the same scope make the name look re-resolved. Delete one.`);
    }
    return { code: 1, lines };
  }
  if (col0.length) {
    const lines = [`FAIL ${NAME}: ${col0.length} statement(s) start at column 0 inside an indented scope:`];
    for (const c of col0) {
      lines.push(`  - ${c.path}:${c.line} "${c.text}" starts at column 0 but belongs ${c.want} space(s) in. The line reads as if it had left its block; indent it to match its scope.`);
    }
    return { code: 1, lines };
  }
  if (ci.length) {
    const lines = [`FAIL ${NAME}: ${ci.length} comment block(s) are indented deeper than the code they annotate:`];
    for (const c of ci) {
      lines.push(`  - ${c.path}:${c.line} "${c.text}" is deeper than the following code (${c.want} space(s)). A drifted comment no longer lines up with its block; indent it with the code.`);
    }
    return { code: 1, lines };
  }
  if (crammed.length) {
    const lines = [`FAIL ${NAME}: ${crammed.length} statement(s) are crammed onto a body-opening brace:`];
    for (const c of crammed) {
      lines.push(`  - ${c.path}:${c.line} "${c.text}" puts code after the '{' that opens a multi-line body. The first statement of the body must start on its own line.`);
    }
    return { code: 1, lines };
  }
  if (cont.length) {
    const lines = [`FAIL ${NAME}: ${cont.length} '<<' continuation line(s) are misaligned:`];
    for (const c of cont) {
      lines.push(`  - ${c.path}:${c.line} "${c.text}" sits at a different indent than the rest of its chain (${c.want} space(s)). A '<<' chain is one expression; a drifted line reads as a different nesting level. Align it.`);
    }
    return { code: 1, lines };
  }
  if (ws.length) {
    const lines = [`FAIL ${NAME}: ${ws.length} whitespace defect(s) inside the build inputs:`];
    for (const w of ws.slice(0, 50)) {
      lines.push(`  - ${w.path}:${w.line} ${w.what}. It changes no behaviour but corrupts every text tool that reads the tree; remove it.`);
    }
    if (ws.length > 50) lines.push(`  ... and ${ws.length - 50} more.`);
    return { code: 1, lines };
  }
  return { code: 0, lines: [`OK ${NAME} (${scannedFiles} file(s) in ${scannedDirs} dir(s) across ${roots.join(', ')}, no editor/merge leftovers, no duplicate includes, no duplicate aliases, no column-0 statements, no over-indented comments, no misaligned '<<' continuations, no crammed statements, no whitespace defects)`] };
}

{
  // Each verdict branch, driven with synthetic findings.
  const CASES = [
    { name: 'no sources scanned', args: { dups: [], found: [], scannedFiles: 10, scannedSources: 0 }, wantCode: 1, want: /saw 0 C\/C\+\+ file/ },
    { name: 'no files scanned', args: { dups: [], found: [], scannedFiles: 0, scannedSources: 10 }, wantCode: 1, want: /scanned 0 files/ },
    { name: 'a leftover', args: { dups: [], found: [{ path: 'x.bak', bytes: 1 }], scannedFiles: 10, scannedSources: 10 }, wantCode: 1, want: /editor\/merge leftover/ },
    { name: 'a duplicate', args: { dups: [{ path: 'a.cpp', header: '<v>', first: 1, again: 2 }], found: [], scannedFiles: 10, scannedSources: 10 }, wantCode: 1, want: /duplicate #include directive/ },
    { name: 'a duplicate alias', args: { dups: [], aliases: [{ path: 'b.cpp', name: 'Clock', first: 9, again: 27 }], found: [], scannedFiles: 10, scannedSources: 10 }, wantCode: 1, want: /duplicate namespace alias/ },
    { name: 'a column-0 statement', args: { dups: [], aliases: [], col0: [{ path: 'c.cpp', line: 4, text: 'int x = 0;', want: 8 }], found: [], scannedFiles: 10, scannedSources: 10 }, wantCode: 1, want: /column 0 inside an indented scope/ },
    { name: 'an over-indented comment', args: { dups: [], aliases: [], col0: [], ci: [{ path: 'g.cpp', line: 2, text: '// note', want: 4 }], ws: [], found: [], scannedFiles: 10, scannedSources: 10 }, wantCode: 1, want: /indented deeper than the code/ },
    { name: 'a misaligned continuation', args: { dups: [], aliases: [], col0: [], ci: [], cont: [{ path: 'k.cpp', line: 2, text: '<< "y"', want: 2 }], ws: [], found: [], scannedFiles: 10, scannedSources: 10 }, wantCode: 1, want: /continuation line\(s\) are misaligned/ },
    { name: 'a crammed statement', args: { dups: [], aliases: [], col0: [], ci: [], cont: [], crammed: [{ path: 'n.cpp', line: 1, text: 'void f() {    g();' }], ws: [], found: [], scannedFiles: 10, scannedSources: 10 }, wantCode: 1, want: /crammed onto a body-opening brace/ },
    { name: 'a whitespace defect', args: { dups: [], aliases: [], col0: [], ws: [{ path: 'e.cpp', line: 7, what: 'trailing whitespace' }], found: [], scannedFiles: 10, scannedSources: 10 }, wantCode: 1, want: /whitespace defect/ },
    { name: 'clean', args: { dups: [], aliases: [], col0: [], ci: [], ws: [], found: [], scannedFiles: 10, scannedSources: 10 }, wantCode: 0, want: /^OK / },
  ];
  const wrong = [];
  for (const c of CASES) {
    let got;
    try {
      got = judgeScan({ ...c.args, roots: ROOTS });
    } catch (e) {
      wrong.push(`${c.name} THREW (${e && e.message})`);
      continue;
    }
    if (!got || got.code !== c.wantCode) {
      wrong.push(`${c.name}: code ${got && got.code} instead of ${c.wantCode}`);
      continue;
    }
    const text = (got.lines || []).join('\n');
    if (!c.want.test(text)) wrong.push(`${c.name}: message ${JSON.stringify(text.slice(0, 80))} does not match ${c.want}`);
  }
  if (wrong.length) {
    console.error(`FAIL ${NAME}: the verdict is wrong - ${wrong.join('; ')}. Every finding kind must produce its own failure, and a clean tree must still pass.`);
    process.exit(1);
  }
}

// The whole pipeline as one function: leftovers + collected sources -> verdict.
// The main path calls it with the real tree; the self-check calls it with
// synthetic collections. That is what makes "the scan feeds the verdict"
// testable - driving the scanner and the verdict separately lets the wiring
// between them rot silently (measured: `dups.push(...scanned.dups)` and
// `judgeScan({dups, ...})` could each be neutered with every assertion green).
function analyse({ sourceFiles, found, scannedFiles, roots }) {
  const scanned = scanSources(sourceFiles);
  if (scanned.unreadable.length) {
    return {
      code: 1,
      lines: [`FAIL ${NAME}: could not read ${scanned.unreadable.length} source file(s) for the duplicate-include scan: ${scanned.unreadable.slice(0, 3).join(', ')}`],
    };
  }
  return judgeScan({
    dups: scanned.dups,
    aliases: scanned.aliases,
    col0: scanned.col0,
    ci: scanned.ci,
    cont: scanned.cont,
    crammed: scanned.crammed,
    ws: scanned.ws,
    found,
    scannedFiles,
    scannedSources: scanned.sources,
    roots,
  });
}

{
  // End to end over synthetic collections: a dirty tree, a clean tree, and an
  // unreadable source. Each case exercises leftovers+scan+verdict together.
  const WIRE_CASES = [
    {
      name: 'dirty tree reports the duplicate',
      input: {
        sourceFiles: [
          { name: 'a.cpp', path: 'a.cpp', text: '#include <vector>\n#include <vector>\n' },
          { name: 'b.cpp', path: 'b.cpp', text: '#include <string>\n' },
        ],
        found: [], scannedFiles: 2, roots: ROOTS,
      },
      wantCode: 1, want: /duplicate #include directive/,
    },
    {
      name: 'dirty tree reports the leftover',
      input: {
        sourceFiles: [{ name: 'a.cpp', path: 'a.cpp', text: '#include <vector>\n' }],
        found: [{ path: 'x.bak', bytes: 3 }], scannedFiles: 2, roots: ROOTS,
      },
      wantCode: 1, want: /editor\/merge leftover/,
    },
    {
      name: 'unreadable source fails',
      input: {
        sourceFiles: [{ name: 'a.cpp', path: 'a.cpp', text: null }],
        found: [], scannedFiles: 1, roots: ROOTS,
      },
      wantCode: 1, want: /could not read/,
    },
    {
      name: 'dirty tree reports the duplicate alias',
      input: {
        sourceFiles: [{ name: 'a.cpp', path: 'a.cpp', text: 'using C = A;\nusing C = A;\n' }],
        found: [], scannedFiles: 1, roots: ROOTS,
      },
      wantCode: 1, want: /duplicate namespace alias/,
    },
    {
      name: 'dirty tree reports the column-0 statement',
      input: {
        sourceFiles: [{ name: 'a.cpp', path: 'a.cpp', text: 'void f() {\nint x = 0;\n}\n' }],
        found: [], scannedFiles: 1, roots: ROOTS,
      },
      wantCode: 1, want: /column 0 inside an indented scope/,
    },
    {
      name: 'dirty tree reports the over-indented comment',
      input: {
        sourceFiles: [{ name: 'a.cpp', path: 'a.cpp', text: 'void f() {\n        // note\n    int x = 0;\n}\n' }],
        found: [], scannedFiles: 1, roots: ROOTS,
      },
      wantCode: 1, want: /indented deeper than the code/,
    },
    {
      name: 'dirty tree reports the crammed statement',
      input: {
        sourceFiles: [{ name: 'a.cpp', path: 'a.cpp', text: 'void f() {    g();\n    h();\n}\n' }],
        found: [], scannedFiles: 1, roots: ROOTS,
      },
      wantCode: 1, want: /crammed onto a body-opening brace/,
    },
    {
      name: 'dirty tree reports the misaligned continuation',
      input: {
        sourceFiles: [{ name: 'a.cpp', path: 'a.cpp', text: 'a << "x"\n   << "y"\n  << "z";\n' }],
        found: [], scannedFiles: 1, roots: ROOTS,
      },
      wantCode: 1, want: /continuation line\(s\) are misaligned/,
    },
    {
      name: 'dirty tree reports trailing whitespace',
      input: {
        sourceFiles: [{ name: 'a.cpp', path: 'a.cpp', text: 'int x; \n' }],
        found: [], scannedFiles: 1, roots: ROOTS,
      },
      wantCode: 1, want: /whitespace defect/,
    },
    {
      name: 'clean tree passes',
      input: {
        sourceFiles: [{ name: 'a.cpp', path: 'a.cpp', text: '#include <vector>\n' }],
        found: [], scannedFiles: 1, roots: ROOTS,
      },
      wantCode: 0, want: /^OK /,
    },
  ];
  const wrong = [];
  for (const c of WIRE_CASES) {
    let got;
    try {
      got = analyse(c.input);
    } catch (e) {
      wrong.push(`${c.name} THREW (${e && e.message})`);
      continue;
    }
    if (!got || got.code !== c.wantCode) {
      wrong.push(`${c.name}: code ${got && got.code} instead of ${c.wantCode}`);
      continue;
    }
    const text = (got.lines || []).join('\n');
    if (!c.want.test(text)) wrong.push(`${c.name}: message ${JSON.stringify(text.slice(0, 80))} does not match ${c.want}`);
  }
  if (wrong.length) {
    console.error(`FAIL ${NAME}: the scan is not wired to the verdict - ${wrong.join('; ')}. A scanner whose findings never reach the verdict reports a clean tree no matter what is in it.`);
    process.exit(1);
  }
}

{
  const verdict = analyse({ sourceFiles, found, scannedFiles, roots: ROOTS });
  for (const line of verdict.lines) {
    if (verdict.code === 0) console.log(line);
    else console.error(line);
  }
  process.exit(verdict.code);
}
