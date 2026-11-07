#!/usr/bin/env node
// t2-driver.mjs - batch19 R4-P1 T2 batch translation driver.
//
// Runs `opencode run` (non-interactive) over the residual native-private keys,
// one batch of languages per call, parses strict JSON, and merges the valid
// entries into scripts/native-i18n-t2/<code>.json (placeholder-safe). Fully
// resumable: complete languages are skipped. Progress is written to
// logs/b19-r4/t2-progress/driver.json (polled by the caller) and per-batch
// logs. No credentials are read or written.
//
// Usage: node scripts/t2-driver.mjs <repo-root> [batchSize] [maxBatches]
import { readFileSync, writeFileSync, existsSync, readdirSync, mkdirSync, appendFileSync, openSync, closeSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';

const repo = resolve(process.argv[2] || 'F:/vgww');
const BATCH = Number(process.argv[3] || 3);
const MAXB = Number(process.argv[4] || 0); // 0 = all remaining
const ONLY = process.argv[5] || '';        // optional single-language filter (backfill)
const OC = 'D:\\Program Files\\opencode\\opencode.exe';
const t2Dir = join(repo, 'scripts', 'native-i18n-t2');
const progDir = join(repo, 'logs', 'b19-r4', 't2-progress');
if (!existsSync(progDir)) mkdirSync(progDir, { recursive: true });
if (!existsSync(t2Dir)) mkdirSync(t2Dir, { recursive: true });
const statusPath = join(progDir, 'driver.json');
const logPath = join(progDir, 'driver.log');
const log = (m) => { const line = `${new Date().toISOString()} ${m}`; appendFileSync(logPath, line + '\n'); };
const writeStatus = (o) => writeFileSync(statusPath, JSON.stringify(o, null, 2));

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
const needT2 = names.map((n, i) => ({ n, en: en[i] })).filter(({ n }) => !(n in t1));
const braces = (s) => (s.match(/\{/g) || []).length;

const inc = readFileSync(join(repo, 'src', 'ui', 'i18n_languages.inc'), 'utf8');
const catalog = [...inc.matchAll(/\{"([^"]+)", "((?:[^"\\]|\\.)*)", (true|false)\}/g)]
  .map((m) => ({ code: m[1], name: m[2].replace(/\\(.)/g, '$1') }));
const rtlSet = new Set(readFileSync(join(repo, 'scripts', 'rtl-languages.txt'), 'utf8').split(/\r?\n/).map((l) => l.replace(/#.*$/, '').trim()).filter((l) => l !== ''));
const mainstream = ['zh-TW', 'ja', 'ko', 'es', 'fr', 'de', 'pt', 'ru', 'it', 'tr', 'vi', 'pl', 'nl', 'id', 'th', 'hi', 'uk', 'fa', 'ar', 'he', 'sv', 'da', 'fi', 'no', 'cs', 'el', 'hu', 'ro', 'sk', 'bg'];
const byCode = new Map(catalog.map((c) => [c.code, c]));
function order() {
  const out = [];
  const seen = new Set();
  const push = (code) => { if (code && code !== 'en' && code !== 'zh-CN' && byCode.has(code) && !seen.has(code)) { seen.add(code); out.push(byCode.get(code)); } };
  for (const c of catalog) if (rtlSet.has(c.code)) push(c.code);   // 17 RTL first (P2 prerequisite)
  for (const c of mainstream) push(c);
  for (const c of catalog) push(c.code);
  return out;
}
const langsOrdered = order();

const t2Of = (code) => (existsSync(join(t2Dir, `${code}.json`)) ? JSON.parse(readFileSync(join(t2Dir, `${code}.json`), 'utf8').replace(/^\uFEFF/, '')) : {});
const pendingKeys = (code) => { const d = t2Of(code); return needT2.filter(({ n }) => !(typeof d[n] === 'string' && d[n] !== '')); };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Async spawn, but with FILE-redirected stdio (the probe-proven shape: no pipe
// buffering / no stdin-EOF hang) and a synchronous tree kill on timeout.
function runOc(prompt, timeoutMs, tag = 'b') {
  return new Promise((resolve, reject) => {
    const outPath = join(progDir, `oc-${tag}.out`);
    const errPath = join(progDir, `oc-${tag}.err`);
    const ofd = openSync(outPath, 'w');
    const efd = openSync(errPath, 'w');
    const child = spawn(OC, ['run', prompt], {
      cwd: repo,
      windowsHide: true,
      stdio: ['ignore', ofd, efd],  // stdin = NUL; stdout/stderr -> files
    });
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      // Synchronous tree kill so the whole opencode subtree dies before the
      // driver moves on (a fire-and-forget spawn never completed on Windows).
      try { spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true }); } catch { /* ignore */ }
      try { child.kill('SIGKILL'); } catch { /* ignore */ }
      try { closeSync(ofd); } catch { /* ignore */ }
      try { closeSync(efd); } catch { /* ignore */ }
      reject(new Error(`timeout ${timeoutMs}ms`));
    }, timeoutMs);
    child.on('error', (e) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      try { closeSync(ofd); } catch { /* ignore */ }
      try { closeSync(efd); } catch { /* ignore */ }
      reject(e);
    });
    child.on('close', (code) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      try { closeSync(ofd); } catch { /* ignore */ }
      try { closeSync(efd); } catch { /* ignore */ }
      let out = '';
      try { out = readFileSync(outPath, 'utf8'); } catch { /* ignore */ }
      if (code === 0) resolve(out); else reject(new Error(`exit ${code}`));
    });
  });
}
function parseJson(text) {
  const a = text.indexOf('{'); const b = text.lastIndexOf('}');
  if (a < 0) throw new Error('no JSON object in output');
  const raw = text.slice(a, b > a ? b + 1 : text.length);
  // 1) direct, 2) trailing-comma fix, 3) balance missing closers.
  try { return JSON.parse(raw); } catch { /* repair */ }
  const deComma = raw.replace(/,\s*(?=[}\]])/g, '');
  try { return JSON.parse(deComma); } catch { /* balance */ }
  let depthObj = 0, depthArr = 0, inStr = false, esc = false;
  for (const ch of deComma) {
    if (inStr) { if (esc) esc = false; else if (ch === '\\') esc = true; else if (ch === '"') inStr = false; continue; }
    if (ch === '"') inStr = true;
    else if (ch === '{') depthObj++;
    else if (ch === '}') depthObj--;
    else if (ch === '[') depthArr++;
    else if (ch === ']') depthArr--;
  }
  let fixed = deComma;
  if (inStr) fixed += '"';
  fixed += ']'.repeat(Math.max(0, depthArr)) + '}'.repeat(Math.max(0, depthObj));
  return JSON.parse(fixed);
}
function buildPrompt(langs) {
  const keys = needT2.map(({ n, en: e }) => `${n}\t${e}`).join('\n');
  const targets = langs.map((l) => `${l.name} (${l.code})`).join(', ');
  return [
    'You are a professional software UI localizer. Translate the English UI strings below into EVERY target language.',
    'Output STRICT JSON only (no markdown, no prose, no comments).',
    'Keys must be returned verbatim: do NOT add, drop, rename, shorten, split or merge any key. Return EVERY key exactly as listed on the left of the tab. Preserve placeholders such as {0} exactly. Never translate these product/technical terms: VGWW, ndisrd, WinpkFilter, README, MAC, IP, VLAN, IPv6, DHCP, DHCPv6, DUID, ULA, RA, DNS, TCP, UDP, Windows, PPP PRIVATE NETWORK.',
    'Return exactly: {"<code>": {"<Key>": "<translation>", ...}, ...} covering EVERY key for EVERY listed language.',
    `Target languages: ${targets}`,
    'Keys (Key<TAB>English):',
    keys,
  ].join('\n');
}
function merge(code, incoming) {
  const cur = t2Of(code);
  let added = 0, rejected = 0;
  for (const { n, en: e } of needT2) {
    const v = incoming[n];
    if (typeof v !== 'string' || v === '') continue;
    if (braces(v) !== braces(e)) { rejected++; continue; }
    if (typeof cur[n] !== 'string' || cur[n] === '') { cur[n] = v; added++; }
  }
  // Single-pending disambiguation: some models rename/shorten the key
  // (observed: AboutOpenWeb -> AboutOpen), so the exact-name merge above can
  // never fill the last missing key and the language retries forever. When
  // exactly ONE needed key is still pending and the reply carries exactly ONE
  // entry that is not a known key, accept it for that key (the prompt carried
  // its English source; the brace check still guards placeholders).
  if (added === 0) {
    const pending = needT2.filter(({ n }) => !(typeof cur[n] === 'string' && cur[n] !== ''));
    if (pending.length === 1) {
      const known = new Set(needT2.map((x) => x.n));
      const extra = Object.keys(incoming).filter((k) => !known.has(k));
      if (extra.length === 1) {
        const v = incoming[extra[0]];
        if (typeof v === 'string' && v !== '' &&
            braces(v) === braces(pending[0].en)) {
          cur[pending[0].n] = v;
          added++;
        }
      }
    }
  }
  if (added > 0) writeFileSync(join(t2Dir, `${code}.json`), JSON.stringify(cur, null, 2));
  return { added, rejected };
}

const pendingLangs = langsOrdered.filter((l) => (!ONLY || l.code === ONLY) && pendingKeys(l.code).length > 0);
// Work queue of language groups; a failing multi-group splits into singletons.
let groups = [];
for (let i = 0; i < pendingLangs.length; i += BATCH) groups.push(pendingLangs.slice(i, i + BATCH));
const attempts = new Map();
const failedLangs = new Set();
const MAX_ATTEMPTS = 3;
let batchNo = 0, doneBatches = 0;
const startedAt = Date.now();
writeStatus({ state: 'running', startedAt: new Date().toISOString(), pendingLangs: pendingLangs.length, groups: groups.length, batchSize: BATCH, doneBatches: 0 });
log(`start pending languages=${pendingLangs.length} groups=${groups.length} batch=${BATCH}`);

(async () => {
while (groups.length > 0 && (MAXB === 0 || doneBatches < MAXB)) {
  const batch = groups.shift();
  batchNo++;
  let result = null, err = '';
  // Timeout gradient: a fresh multi-language group gets 15 min; an isolated
  // single-language retry gets 6 min (bad attempts recycle quickly).
  const timeoutMs = (batch.length === 1) ? 360000 : 900000;
  try {
    const out = await runOc(buildPrompt(batch), timeoutMs, `b${batchNo}`);
    result = parseJson(out);
  } catch (e) { err = String(e.message || e); await sleep(15000); }  // backoff before any retry
  let added = 0, rejected = 0;
  if (result) {
    for (const l of batch) {
      const sub = result[l.code];
      if (sub && typeof sub === 'object') { const r = merge(l.code, sub); added += r.added; rejected += r.rejected; }
    }
  }
  const unresolved = batch.filter((l) => pendingKeys(l.code).length > 0);
  let action = 'ok';
  if (unresolved.length > 0) {
    if (batch.length > 1) {
      // Isolate: after a group failure, retry each still-pending language
      // ALONE (batch=1) so one bad language cannot stall the whole group and
      // good languages land immediately.
      for (const l of unresolved) groups.push([l]);
      action = `isolate+${unresolved.length}`;
    } else {
      const code = batch[0].code;
      const a = (attempts.get(code) || 0) + 1;
      attempts.set(code, a);
      if (a < MAX_ATTEMPTS) {
        groups.push(batch);
        action = `retry${a}`;
      } else {
        failedLangs.add(code);
        writeFileSync(join(progDir, `failed-${code}.txt`), `lang=${code} err=${err}\n`);
        action = 'giveup';
      }
    }
  }
  doneBatches++;
  const elapsed = Math.round((Date.now() - startedAt) / 1000);
  writeFileSync(join(progDir, `batch-${String(batchNo).padStart(3, '0')}.txt`),
    `batch ${batchNo} langs=${batch.map((l) => l.code).join(',')}\nadded=${added} rejected=${rejected} action=${action} err=${err}\n`);
  writeStatus({ state: 'running', batch: batchNo, doneBatches, groupsLeft: groups.length, lastAdded: added, lastRejected: rejected, lastAction: action, lastError: err, elapsedSec: elapsed });
  log(`batch ${batchNo} langs=[${batch.map((l) => l.code).join(',')}] +${added} rej=${rejected} ${action} groupsLeft=${groups.length} err=${err}`);
}
const t2Files = existsSync(t2Dir) ? readdirSync(t2Dir).filter((f) => f.endsWith('.json')).length : 0;
const done = { state: 'done', doneAt: new Date().toISOString(), batches: batchNo, groupsLeft: groups.length, pendingLangs: groups.reduce((a, g) => a + g.length, 0), failedLangs: [...failedLangs], t2Files, elapsedSec: Math.round((Date.now() - startedAt) / 1000) };
writeStatus(done);
writeFileSync(join(progDir, 'DONE.json'), JSON.stringify(done, null, 2));
log(`done batches=${batchNo} groupsLeft=${groups.length} t2Files=${t2Files}`);
})();
