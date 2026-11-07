// VGWW web smoke test (S4.6-W7 asset, persisted under tools/smoke).
//
// What it does (no build, node >= 22 required for the global WebSocket):
//   1. writes a temporary config from config.example.json with web.port overridden
//   2. starts  build_s4/Release/vgww.exe --web-only --config <that config>
//   3. probes  GET /  (200 + SPA doctype), GET /api/status (200 + whole-body JSON),
//              a static path, and a raw-socket HEAD /  (headers may carry
//              Content-Length, the body must be 0 bytes - S4.6-W4 fix)
//   4. renders the page in Edge over the DevTools protocol and asserts the
//      dashboard text (Edge 153 has no working --dump-dom, see README)
//   5. kills the process and proves the port is released again
//
// Usage:
//   node tools/smoke/w7-smoke.mjs [--exe=<path>] [--config-template=<path>]
//        [--port=18080] [--log=<file>] [--edge-check=<file>]
//
// Defaults: exe   = <repo>/build_s4/Release/vgww.exe
//           template = <repo>/config.example.json
//           port  = 18080 (must be free; the script aborts otherwise)
//           log   = <os tmp>/vgww-smoke-<port>.log  (plus .exe-stdout.txt)
// Expected output: a PASS/FAIL line per check and a final
//   "RESULT: PASS - smoke green"  (exit 0)  or
//   "RESULT: FAIL - N check(s) failed" (exit 1).
// Reference runs: .superpowers/sdd/2026-09-21-s4-ui/logs/w7-smoke-final.20260923-154308.log
// (1 known FAIL before S4.6-W8) and logs/w8-smoke.20260923-155635.log (10/10 green).
import { spawn, execFileSync } from 'node:child_process';
import { writeFileSync, readFileSync, mkdirSync, openSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import net from 'node:net';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../..');
const arg = (name, dflt) => {
  const hit = process.argv.slice(2).find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : dflt;
};

const exe = arg('exe', resolve(repoRoot, 'build_s4/Release/vgww.exe'));
const template = arg('config-template', resolve(repoRoot, 'config.example.json'));
const PORT = Number(arg('port', '18080'));
const HOST = '127.0.0.1';
const BASE = `http://${HOST}:${PORT}`;
const cfg = arg('config', resolve(tmpdir(), `vgww-smoke-${PORT}.json`));
const logPath = arg('log', resolve(tmpdir(), `vgww-smoke-${PORT}.log`));
const edgeCheck = arg('edge-check', resolve(here, 'w7-edge-check.mjs'));

mkdirSync(dirname(cfg), { recursive: true });
mkdirSync(dirname(logPath), { recursive: true });
const lines = [];
const say = (s) => { lines.push(s); console.log(s); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
const check = (label, cond, detail) => {
  if (!cond) failures++;
  say(`${cond ? 'PASS' : 'FAIL'}  ${label}${detail ? '  [' + detail + ']' : ''}`);
};

function rawRequest(method, path) {
  return new Promise((resolve, reject) => {
    const s = net.connect(PORT, HOST);
    let data = Buffer.alloc(0);
    const timer = setTimeout(() => { s.destroy(); reject(new Error('raw request timeout')); }, 8000);
    s.on('connect', () => s.write(`${method} ${path} HTTP/1.1\r\nHost: ${HOST}:${PORT}\r\nConnection: close\r\n\r\n`));
    s.on('data', (d) => { data = Buffer.concat([data, d]); });
    s.on('end', () => { clearTimeout(timer); resolve(data); });
    s.on('error', (e) => { clearTimeout(timer); reject(e); });
  });
}
function splitRaw(buf) {
  const at = buf.indexOf('\r\n\r\n');
  if (at < 0) return { header: buf.toString('utf8'), body: Buffer.alloc(0) };
  return { header: buf.slice(0, at).toString('utf8'), body: buf.slice(at + 4) };
}
const statusOf = (header) => (header.match(/^HTTP\/1\.[01] (\d+)/) || [])[1];

async function portFree() {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once('error', () => resolve(false));
    srv.listen(PORT, HOST, () => srv.close(() => resolve(true)));
  });
}

// ---- temporary config: port + deterministic token ----
const cfgJson = JSON.parse(readFileSync(template, 'utf8'));
cfgJson.web = { port: PORT, token: 'w7-smoke-token' };
writeFileSync(cfg, JSON.stringify(cfgJson, null, 2));

say(`===== VGWW web smoke @ ${new Date().toISOString()} =====`);
say(`exe=${exe} config=${cfg} log=${logPath}`);

if (!(await portFree())) { say(`FAIL  port ${PORT} is already bound before start`); process.exit(1); }

const outFd = openSync(`${logPath}.exe-stdout.txt`, 'w');
const child = spawn(exe, ['--web-only', `--config=${cfg}`], { stdio: ['ignore', outFd, outFd] });
say(`started pid=${child.pid}`);

let up = false;
for (let i = 0; i < 60 && !up; i++) {
  await sleep(500);
  try {
    const r = await fetch(`${BASE}/api/status`);
    up = r.status === 200;
  } catch { /* retry */ }
}
check('server answers /api/status within 30s', up, `attempts=${up ? 'ok' : '60'}`);
if (!up) {
  try { child.kill(); } catch { /* already gone */ }
  say('RESULT: FAIL (server never came up)');
  writeFileSync(logPath, lines.join('\n') + '\n');
  process.exit(1);
}

// ---- GET / ----
{
  const buf = await rawRequest('GET', '/');
  const { header, body } = splitRaw(buf);
  const st = statusOf(header);
  check('GET / -> 200', st === '200', `status=${st} body=${body.length}B`);
  check('GET / body is the SPA', body.toString('utf8', 0, 200).includes('<!DOCTYPE html'), 'doctype');
  say(`      GET / headers: ${header.split('\r\n').slice(0, 6).join(' | ')}`);
}
// ---- GET /api/status: whole-body JSON (S4.6-W8 regression guard) ----
{
  const r = await fetch(`${BASE}/api/status`);
  const text = await r.text();
  let keys = null;
  try { keys = Object.keys(JSON.parse(text)).sort(); } catch { /* not json */ }
  check('GET /api/status -> 200 JSON', r.status === 200 && keys !== null, `status=${r.status} keys=${keys ? keys.join(',') : 'n/a'}`);
}
// ---- static asset probe ----
{
  const seen = [];
  for (const p of ['/index.html', '/favicon.ico']) {
    const buf = await rawRequest('GET', p);
    const { header, body } = splitRaw(buf);
    seen.push(`${p}=${statusOf(header)}/${body.length}B`);
  }
  check('a static asset answers 200', seen.some((s) => s.startsWith('/index.html=200')), seen.join(' '));
}
// ---- HEAD: headers allowed, body must be empty (S4.6-W4) ----
{
  const buf = await rawRequest('HEAD', '/');
  const { header, body } = splitRaw(buf);
  const st = statusOf(header);
  const cl = header.match(/content-length:\s*(\d+)/i);
  check('HEAD / -> 200', st === '200', `status=${st}`);
  check('HEAD / body is 0 bytes', body.length === 0, `body=${body.length}B content-length=${cl ? cl[1] : 'absent'}`);
  say(`      HEAD headers: ${header.split('\r\n').slice(0, 6).join(' | ')}`);
}
// ---- Edge render + text (CDP; Edge 153 has no working --dump-dom) ----
try {
  const out = execFileSync(process.execPath, [edgeCheck, `${BASE}/`, dirname(logPath), 'smoke'], { encoding: 'utf8' });
  out.trim().split('\n').forEach((l) => say('      ' + l));
  check('Edge renders the dashboard (text contains Dashboard)', /containsDashboardText=true/.test(out));
} catch (e) {
  const out = `${e.stdout || ''}${e.stderr || ''}`;
  out.trim().split('\n').forEach((l) => say('      ' + l));
  check('Edge renders the dashboard (text contains Dashboard)', false, 'edge check exit != 0');
}
// ---- stop + port release ----
try { execFileSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore' }); } catch { /* already gone */ }
await sleep(1500);
check('process stopped', child.exitCode !== null || child.killed, `exitCode=${child.exitCode}`);
check(`port ${PORT} released`, await portFree(), 'bind test');
say(`exe stdout: ${readFileSync(`${logPath}.exe-stdout.txt`, 'utf8').trim().split('\n').slice(0, 4).join(' | ')}`);
say(failures === 0 ? 'RESULT: PASS - smoke green' : `RESULT: FAIL - ${failures} check(s) failed`);
writeFileSync(logPath, lines.join('\n') + '\n');
process.exit(failures === 0 ? 0 : 1);
