// VGWW Edge render check (S4.6-W7 asset, persisted under tools/smoke).
// Companion of w7-smoke.mjs: opens a URL in headless Edge and extracts the
// rendered title, DOM facts and body text over the DevTools protocol.
//
// Why CDP instead of --dump-dom: the Edge build used for S4.6 (153.0.4234.48)
// returns 0 bytes for --dump-dom with every URL form (file://, http://, even a
// data: URL), in both headless modes, with and without --virtual-time-budget.
// The CDP route was verified to work and yields the same evidence.
//
// Usage:
//   node tools/smoke/w7-edge-check.mjs <url> <outDir> [label] [--serve]
//     --serve  also starts a static server on 127.0.0.1:18080 serving <repo>/www
//              (useful to check the SPA without vgww.exe)
// Output: <outDir>/w7-<label>-dom.txt with title/facts/innerText, plus a
//   "containsDashboardText=true|false" line; exit 0 when the dashboard text is
//   present. Requires node >= 22 (global WebSocket) and Edge at the path below.
import { createServer } from 'node:http';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../..');
const url = process.argv[2] || 'http://127.0.0.1:18080/';
const outDir = process.argv[3] || process.env.TEMP || '.';
const label = process.argv[4] || 'edge';
const edge = process.env.VGWW_EDGE || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';
const port = Number(process.env.VGWW_EDGE_CDP_PORT || 9223);
mkdirSync(outDir, { recursive: true });

function startStatic(dir, listenPort) {
  const srv = createServer((req, res) => {
    const path = req.url.split('?')[0];
    const file = path === '/' ? `${dir}/index.html` : `${dir}${path}`;
    try {
      const body = readFileSync(file);
      res.writeHead(200, { 'Content-Type': file.endsWith('.html') ? 'text/html; charset=utf-8' : 'application/octet-stream', 'Content-Length': body.length });
      res.end(req.method === 'HEAD' ? undefined : body);
    } catch {
      res.writeHead(404, { 'Content-Length': 0 });
      res.end();
    }
  });
  return new Promise((resolve) => srv.listen(listenPort, '127.0.0.1', () => resolve(srv)));
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function cdpText(targetUrl, outFile) {
  const profile = `${process.env.TEMP || '.'}/vgww-edge-${Date.now()}`;
  const child = spawn(edge, [
    '--headless=new', '--disable-gpu', '--no-first-run', '--disable-extensions',
    `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, '--lang=en-US',
    'about:blank',
  ], { stdio: 'ignore' });

  const deadline = Date.now() + 30000;
  let target = null;
  while (Date.now() < deadline) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      target = list.find((t) => t.type === 'page');
      if (target) break;
    } catch { /* not up yet */ }
    await sleep(400);
  }
  if (!target) throw new Error('CDP endpoint did not come up');

  const ws = new WebSocket(target.webSocketDebuggerUrl);
  const pending = new Map();
  let seq = 0;
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++seq;
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
  await new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve, { once: true });
    ws.addEventListener('error', reject, { once: true });
  });
  ws.addEventListener('message', (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
    }
  });

  await send('Page.enable');
  await send('Page.navigate', { url: targetUrl });
  await sleep(2500);
  const title = (await send('Runtime.evaluate', { expression: 'document.title', returnByValue: true })).result.value;
  const innerText = (await send('Runtime.evaluate', { expression: 'document.body.innerText', returnByValue: true })).result.value;
  const facts = (await send('Runtime.evaluate', {
    expression: `JSON.stringify({
      theme: document.documentElement.dataset.theme,
      lang: document.documentElement.lang,
      navLinks: document.querySelectorAll("#nav a").length,
      pages: document.querySelectorAll("main > section[id]").length,
      cards: document.querySelectorAll(".cards").length,
      favicon: !!document.querySelector('link[rel="icon"]'),
      inlineStyles: document.querySelectorAll("[style]").length,
      langOptions: document.querySelectorAll("#langsel option").length,
      themeSel: (document.getElementById("theme-sel")||{}).value || null,
      cardValues: [...document.querySelectorAll("#cards .card .v")].map(e => e.textContent.trim()).slice(0,4)
    })`,
    returnByValue: true,
  })).result.value;

  writeFileSync(outFile, `url: ${targetUrl}\ntitle: ${title}\nfacts: ${facts}\n\n--- innerText ---\n${innerText}\n`);
  ws.close();
  child.kill('SIGKILL');
  return { title, facts, text: innerText };
}

let srv = null;
if (process.argv.includes('--serve')) {
  srv = await startStatic(resolve(repoRoot, 'www'), 18080);
  console.log(`static server on http://127.0.0.1:18080/ (${resolve(repoRoot, 'www')})`);
}
const out = resolve(outDir, `w7-${label}-dom.txt`);
const r = await cdpText(url, out);
// ASCII-only assertion: the smoke runs without a stored language -> en.
const hasDashboard = /Dashboard/.test(r.text);
console.log(`title=${r.title}`);
console.log(`facts=${r.facts}`);
console.log(`innerText bytes=${r.text.length} containsDashboardText=${hasDashboard}`);
console.log(`dom evidence: ${out}`);
if (srv) srv.close();
process.exit(hasDashboard ? 0 : 1);
