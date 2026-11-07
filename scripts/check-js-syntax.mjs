#!/usr/bin/env node
// Gate: web_js_syntax
// Extract every inline <script> block from www/index.html and syntax-check the
// concatenation with `node --check` (classic-script parse mode, matching the
// browser's non-module <script> semantics).
//
// Usage: node scripts/check-js-syntax.mjs <repo-root>
// Exit:  0 = OK, 1 = FAIL (missing arg / unreadable file / no inline script /
//        syntax error). Never silently skips.
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';

const NAME = 'js-syntax';
const JS_TYPES = new Set(['', 'text/javascript', 'application/javascript', 'module', 'text/ecmascript', 'application/ecmascript']);

function fail(detail) {
  console.error(`FAIL ${NAME}: ${detail}`);
  process.exit(1);
}

const root = process.argv[2];
if (!root) fail('missing <repo-root> argument (usage: node scripts/check-js-syntax.mjs <repo-root>)');

const htmlPath = join(resolve(root), 'www', 'index.html');
let html;
try {
  html = readFileSync(htmlPath, 'utf8');
} catch (e) {
  fail(`cannot read ${htmlPath}: ${e.message}`);
}

const blocks = [];
const re = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
let m;
while ((m = re.exec(html)) !== null) {
  const attrs = m[1] || '';
  if (/\bsrc\s*=/i.test(attrs)) continue; // external script: no inline code to check
  const tm = attrs.match(/\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
  if (tm) {
    const type = (tm[1] ?? tm[2] ?? tm[3] ?? '').trim().toLowerCase();
    if (!JS_TYPES.has(type)) continue; // e.g. application/json: not JavaScript
  }
  blocks.push(m[2]);
}
if (blocks.length === 0) fail(`no inline <script> block found in ${htmlPath}`);

const code = blocks.join('\n;\n');
const dir = mkdtempSync(join(tmpdir(), 'vgww-js-'));
const file = join(dir, 'app.js');
try {
  writeFileSync(file, code);
  try {
    execFileSync(process.execPath, ['--check', file], { stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    const stderr = String((e && e.stderr) || (e && e.message) || e).trim();
    fail(`node --check rejected the extracted script (${blocks.length} block(s), ${code.length} bytes):\n${stderr}`);
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}

console.log(`OK ${NAME} (${blocks.length} inline block(s), ${code.length} bytes checked)`);
