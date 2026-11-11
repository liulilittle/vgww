#!/usr/bin/env node
// Gate: web_logic
//
// The other five web gates are STATIC: they parse the inline script and assert
// shapes (keys exist, interpolations are escaped, syntax parses). None of them
// can tell whether a UI flow actually behaves, so a state-machine bug - the
// kind that silently deletes a user's rule - sails through all of them.
//
// This gate runs the REAL inline script of www/index.html inside a minimal DOM
// stub and drives it through the rate-limit editor, which owns the only piece
// of cross-render mutable state in the console (`editingMac`). It asserts the
// observable contract - the JSON body the console POSTs - so a regression is a
// red test here rather than a user losing a rule in production.
//
// The stub is deliberately small: only the DOM surface the script touches at
// load time and in the rate-limit page. Anything the script does not exercise
// is not modelled (and must not be, or the gate would test the stub).
//
// Usage: node scripts/check-web-logic.mjs <repo-root>
// Exit:  0 = OK, 1 = FAIL (or unreadable input).
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import vm from 'node:vm';

const NAME = 'web_logic';

// Unhandled promise rejections are a real defect class here: the page is a pile
// of fire-and-forget async helpers, and a rejection nobody catches is invisible
// to the operator (no toast) while still showing up as an error in the console.
// Node turns any unhandled rejection into this event, including ones whose
// promise belongs to the vm context.
const rejections = [];
process.on('unhandledRejection', (r) => {
  rejections.push(String((r && r.message) || r));
});

const REL = 'www/index.html';
const root = process.argv[2];
if (!root) {
  console.error(`FAIL ${NAME}: missing <repo-root> argument (usage: node scripts/check-web-logic.mjs <repo-root>)`);
  process.exit(1);
}

let html;
try {
  html = readFileSync(join(resolve(root), REL), 'utf8');
} catch (e) {
  console.error(`FAIL ${NAME}: cannot read ${REL}: ${e.message}`);
  process.exit(1);
}

// ------------------------------------------------------------ script extraction
// Only inline scripts: an external src= would not be runnable here, and the
// page has none (it is a single-file distribution).
const scripts = [];
{
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const attrs = m[1] || '';
    if (/\bsrc\s*=/i.test(attrs)) continue;
    scripts.push(m[2]);
  }
}
if (scripts.length === 0) {
  console.error(`FAIL ${NAME}: no inline <script> block found in ${REL}`);
  process.exit(1);
}

// ------------------------------------------------------------------- DOM stub
function makeElement(tag) {
  const el = {
    tagName: String(tag || 'div').toUpperCase(),
    id: '',
    hidden: false,
    value: '',
    disabled: false,
    checked: false,
    placeholder: '',
    options: [],
    dataset: {},
    style: {},
    children: [],
    classList: null,
    attrs: {},
    setAttribute(name, value) { this.attrs[name] = String(value); },
    getAttribute(name) { return Object.prototype.hasOwnProperty.call(this.attrs, name) ? this.attrs[name] : null; },
    removeAttribute(name) { delete this.attrs[name]; },
    // Event wiring is part of the behaviour: a double-registered or duplicated
    // activation path is invisible unless the harness can dispatch. Listeners
    // are recorded so a case can call them the way the browser would.
    __on: {},
    addEventListener(type, fn) {
      (this.__on[type] || (this.__on[type] = [])).push(fn);
    },
    removeEventListener(type, fn) {
      const list = this.__on[type];
      if (!list) return;
      const i = list.indexOf(fn);
      if (i >= 0) list.splice(i, 1);
    },
    // Parent linkage is what makes `closest` and "which row owns this node"
    // answerable at all; without it a row's structure is invisible.
    get parentElement() { return this.__parent || null; },
    closest(sel) {
      const want = String(sel).replace(/^[.#]/, '').toUpperCase();
      let n = this;
      while (n) {
        if (String(n.tagName || '').toUpperCase() === want) return n;
        if (String(sel) === 'a' && String(n.tagName || '').toUpperCase() === 'A') return n;
        n = n.__parent || null;
      }
      return String(sel) === 'a' ? this : null;
    },
    appendChild(child) {
      this.children.push(child);
      child.__parent = this;
      return child;
    },
    removeChild(child) {
      const i = this.children.indexOf(child);
      if (i >= 0) this.children.splice(i, 1);
      child.__parent = null;
      dropFocusWithin(child);
      return child;
    },
    // batch216: the language filter now reconciles the <select> in place instead
    // of rebuilding it, so the page needs insertBefore. The stub must model the
    // real contract, including the "move an existing node" case (a node already
    // in this parent is removed from its old position first, not duplicated) and
    // `ref === null` meaning append.
    insertBefore(child, ref) {
      if (ref === undefined) throw new TypeError('insertBefore needs a reference node');
      const prev = this.children.indexOf(child);
      if (prev >= 0) this.children.splice(prev, 1);
      if (ref === null) {
        this.children.push(child);
      } else {
        const at = this.children.indexOf(ref);
        if (at < 0) throw new Error('insertBefore: reference node is not a child');
        this.children.splice(at, 0, child);
      }
      child.__parent = this;
      return child;
    },
    querySelector() { return makeElement(); },
    // Descendant lookup by tag name (all the product code needs: "the buttons
    // inside this row").
    querySelectorAll(sel) {
      const want = String(sel).replace(/^[.#]/, '').toUpperCase();
      const out = [];
      const walk = (n) => {
        for (const c of n.children) {
          if (String(c.tagName || '').toUpperCase() === want) out.push(c);
          walk(c);
        }
      };
      walk(this);
      return out;
    },
    __focused: false,
    focus() {
      this.__focused = true;
      this.__focusCount = (this.__focusCount || 0) + 1;
      if (typeof setActiveNode === 'function') setActiveNode(this);
    },
    blur() {
      this.__focused = false;
      if (typeof setActiveNode === 'function' && activeNode === this) setActiveNode(null);
    },
    click() {},
    getBoundingClientRect() { return { left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0 }; },
  };
  // textContent / innerHTML behave like the DOM, not like two independent
  // strings: assigning either one REPLACES the children, and reading
  // textContent includes the children's text. Without this, a loader that
  // writes rows with `textContent = ""` + appendChild() (fillRows) looks empty
  // to an innerHTML assertion no matter what it rendered - which would make an
  // ordering test pass even when the guard was removed (a fake test).
  let ownText = '';
  let ownHtml = '';
  // Stub-only observable: how many times the node was REPLACED. Assigning
  // textContent/innerHTML throws the children away - in a browser that also
  // collapses the operator's text selection - so a "did you repaint?" question
  // needs a counter, not a value comparison.
  el.__writes = 0;
  // classList and className are ONE thing in a browser: `classList.add("x")`
  // changes `className`, and assigning `className` resets the set. Keeping them
  // independent here made `classList.toggle("spd", ...)` invisible to any
  // assertion written against className - exactly the kind of stub unfaithfulness
  // that turns a real regression into a green test.
  const classSet = new Set();
  el.classList = {
    add(...names) { for (const n of names) classSet.add(String(n)); },
    remove(...names) { for (const n of names) classSet.delete(String(n)); },
    toggle(name, force) {
      const on = force === undefined ? !classSet.has(name) : !!force;
      if (on) classSet.add(name); else classSet.delete(name);
      return on;
    },
    contains(name) { return classSet.has(name); },
  };
  // batch187: count className writes the way __writes counts textContent
  // writes. A writer that strips a class and re-adds it on every repaint is
  // invisible to a "does the list contain spd" assertion - the end state
  // matches - so counting the writes is the only way to see the churn.
  el.__classWrites = 0;
  Object.defineProperty(el, 'className', {
    get() { return [...classSet].join(' '); },
    set(v) {
      el.__classWrites++;
      classSet.clear();
      for (const tok of String(v == null ? '' : v).split(/\s+/)) {
        if (tok) classSet.add(tok);
      }
    },
  });
  Object.defineProperty(el, 'textContent', {
    get() {
      let out = ownText;
      for (const c of el.children) out += c.textContent;
      return out;
    },
    set(v) {
      el.__writes++;
      // batch185: textContent is a DOMString. Assigning null/undefined does NOT
      // clear it - WebIDL converts to the strings "null"/"undefined", which is
      // exactly how a missing counter reaches the screen. Dropping them to ''
      // here made that class of defect invisible to every assertion in this file.
      ownText = String(v);
      ownHtml = '';
      for (const c of el.children) { c.__parent = null; dropFocusWithin(c); }
      el.children.length = 0;
    },
  });
  Object.defineProperty(el, 'innerHTML', {
    get() { return ownHtml; },
    set(v) {
      el.__writes++;
      ownHtml = v == null ? '' : String(v);
      ownText = '';
      for (const c of el.children) { c.__parent = null; dropFocusWithin(c); }
      el.children.length = 0;
      // A browser PARSES the markup into real elements. Leaving children empty
      // here would make every row invisible to the harness - which is exactly
      // how a page that destroys its rows on each repaint stayed untested.
      for (const child of parseHtml(ownHtml)) { el.children.push(child); child.__parent = el; }
    },
  });
  return el;
}

// Minimal tag parser for the row markup the console builds. It is deliberately
// small: text content plus nested elements, void tags, self-closing handled,
// and quoted attribute values. HTML entities are decoded the few ways the
// product writes them, because assertions read textContent.
const VOID_TAGS = new Set(['br', 'hr', 'img', 'input', 'meta', 'link']);
function decodeEntities(s) {
  return String(s)
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&');
}
function parseHtml(html) {
  const root = [];
  const stack = [{ children: root, tag: '' }];
  const re = /<!--[\s\S]*?-->|<\/([a-zA-Z][\w-]*)\s*>|<([a-zA-Z][\w-]*)((?:\s+[^\s=>/]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*(\/?)>|([^<]+)/g;
  let m;
  while ((m = re.exec(String(html))) !== null) {
    if (m[0].startsWith('<!--')) continue;
    const top = stack[stack.length - 1];
    if (m[1]) {
      // closing tag: pop to the matching element (tolerates stray closes)
      for (let i = stack.length - 1; i > 0; i--) {
        if (stack[i].tag === m[1].toLowerCase()) { stack.length = i; break; }
      }
      continue;
    }
    if (m[2]) {
      const tag = m[2].toLowerCase();
      const node = makeElement(tag);
      for (const a of m[3].matchAll(/([^\s=]+)(?:\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) {
        const name = a[1];
        const val = a[3] !== undefined ? a[3] : a[4] !== undefined ? a[4] : a[5] !== undefined ? a[5] : '';
        node.setAttribute(name, decodeEntities(val));
      }
      top.children.push(node);
      node.__parent = top.children === root ? null : null;
      if (!m[4] && !VOID_TAGS.has(tag)) stack.push({ children: node.children, tag, el: node });
      else node.__parent = null;
      continue;
    }
    if (m[5] !== undefined) {
      const text = decodeEntities(m[5]);
      if (text) {
        // A real browser has a TEXT NODE here, not a bare string. Keeping it a
        // node means "walk the children" and "reparent" behave uniformly.
        const textNode = makeElement('#text');
        textNode.textContent = text;
        top.children.push(textNode);
      }
    }
  }
  return root.filter((n) => typeof n !== 'string');
}

// Focus helpers. `setActiveNode` is what `focus()` calls; `dropFocusWithin` is
// what every "the children are gone" path calls. Together they reproduce the
// browser rule that matters here: a focused element removed from the document
// does not stay focused - focus falls back to <body>.
let activeNodeSetter = null;
function setActiveNode(node) {
  activeNodeSetter(node);
  if (node) node.__focused = true;
}
function dropFocusWithin(node) {
  if (!node) return;
  if (activeNode === node) { activeNodeSetter(null); node.__focused = false; return; }
  for (const c of node.children) dropFocusWithin(c);
}

// Every selector resolves to ONE stable element, so a test can set `#rl-mac`
// and the code under test reads the same object back.
//
// batch179: an element's TAG has to match the page, not default to <div>. The
// page distinguishes input from select in real code (`el.tagName === "SELECT"`
// decides who owns the Enter key), and a stub where everything is a div makes
// that distinction unobservable - a hijacked select looks identical to a text
// field. Read the tag for each id out of the markup once.
const TAG_BY_ID = new Map(
  [...html.matchAll(/<(input|select|textarea|button)\b([^>]*\bid="([\w-]+)")/gi)]
    .map((m) => [m[3], m[1].toLowerCase()]),
);
const nodes = new Map();
function nodeFor(selector) {
  if (!nodes.has(selector)) {
    const id = String(selector).replace(/^#/, '').replace(/\s.*$/, '');
    nodes.set(selector, makeElement(TAG_BY_ID.get(id) || 'div'));
  }
  return nodes.get(selector);
}

// Selector groups the script reads as a LIST (e.g. the settings form fields).
// Each element is created through nodeFor() so it is the same object the code
// later reaches by id - otherwise a value written through getElementById()
// would be invisible to readSettingsDirtyState().
const lists = new Map();
function registerList(selector, ids) {
  lists.set(selector, ids.map((id) => {
    const el = nodeFor(`#${id}`);
    el.id = id;
    return el;
  }));
}

// Listeners registered on the window/document, so a case can dispatch them in
// the order the browser would (click handler first, then the default action
// changes the hash, then hashchange fires).
const windowListeners = {};
function recordWindowListener(type, fn) {
  (windowListeners[type] || (windowListeners[type] = [])).push(fn);
}

// Focus is a DOCUMENT-level fact, not a per-node flag: in a browser the focused
// element becomes document.activeElement, and when that element is removed from
// the tree the browser moves focus to <body>. Without modelling both, a page
// that destroys the focused row on every repaint looks perfectly fine - the
// node keeps its stale __focused flag - while the keyboard operator is actually
// thrown back to the top of the document.
let activeNode = null;
activeNodeSetter = (node) => { activeNode = node; };
const document = {
  readyState: 'complete',
  title: '',
  documentElement: makeElement('html'),
  body: makeElement('body'),
  get activeElement() { return activeNode; },
  getElementById(id) { return nodeFor(`#${id}`); },
  querySelector(selector) { return nodeFor(selector); },
  querySelectorAll(selector) { return lists.get(selector) || []; },
  // batch206: the real createElement() throws InvalidCharacterError for a
  // name that is not a valid HTML tag (a caller that passes a DOM nodeName
  // such as "#text" was silently accepted here, so the browser crash this
  // gate exists to catch was never observed). Reject the same names the
  // platform does, so such a bug fails the suite instead of the page.
  createElement(tag) {
    const name = String(tag == null ? '' : tag);
    if (!/^[A-Za-z][A-Za-z0-9-]*$/.test(name)) {
      const err = new Error(
        "Failed to execute 'createElement': the tag name '" + name +
        "' is not a valid element name");
      err.name = 'InvalidCharacterError';
      throw err;
    }
    return makeElement(name);
  },
  addEventListener(type, fn) { recordWindowListener(type, fn); },
};

const store = new Map();
const localStorage = {
  getItem(k) { return store.has(k) ? store.get(k) : null; },
  setItem(k, v) { store.set(k, String(v)); },
  removeItem(k) { store.delete(k); },
};

// ------------------------------------------------------------- fetch recording
// `requests` is the observable the assertions read: the JSON body the console
// actually posts. `failNext` makes exactly the next POST reject, which is how
// the "a failed save must not lose the edit context" case is driven.
const requests = [];
let ratelimitRules = [];
let portmapRules = [];
let bansList = [];
let clientList = [];
let leaseList = [];
let bind4List = [];
let bind6List = [];
let lease6List = [];
// The console ring snapshot the /api/console stub serves.
let consoleText = '';
let statusPayload = {
  gateway: { ip: '192.168.0.1', ipv6: '' },
  stats: { rx_frames: 0, tx_frames: 0, tcp_accepted: 0 },
  bridge: {},
};
// /api/system feeds the host tiles (CPU / memory / live throughput). Kept
// separate so a test can make two overlapping refreshes disagree on the value.
let systemPayload = {
  proc: { cpu_percent: 0, ws_bytes: 0, virt_bytes: 0, cores: 4 },
  throughput: { up_bps: 0, down_bps: 0 },
  uptime_s: 1,
  version: 'test',
};
let failNextPost = false;
// The server-side config the settings page reads. Mutated by the save cases.
let configPayload = null;
// Paths whose GET response is held back so a test can control the ORDER in
// which two overlapping requests come back (the out-of-order render case).
// batch181: config POST / apply-status replies, so the apply-outcome path is
// reachable from a case.
let configPostReply = { ok: true };
let applyStatusReply = { attempt_id: 0, completed_id: 0, ok: true, error: '' };
let applyStatusPolls = 0;
const deferredPaths = new Set();
const deferredResponses = new Map(); // path -> [release]

function jsonResponse(payload, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() { return payload; },
    async text() { return JSON.stringify(payload); },
  };
}

function payloadFor(path) {
  if (path === '/api/ratelimit') return JSON.parse(JSON.stringify(ratelimitRules));
  if (path === '/api/portmap') return JSON.parse(JSON.stringify(portmapRules));
  if (path === '/api/bans') return JSON.parse(JSON.stringify(bansList));
  if (path === '/api/clients') return { clients: JSON.parse(JSON.stringify(clientList)) };
  if (path === '/api/status') return JSON.parse(JSON.stringify(statusPayload));
  if (path === '/api/system') return JSON.parse(JSON.stringify(systemPayload));
  if (path === '/api/console') return { text: consoleText };
  if (path === '/api/dhcp/leases') return JSON.parse(JSON.stringify(leaseList));
  if (path === '/api/dhcp/bindings') return JSON.parse(JSON.stringify(bind4List));
  if (path === '/api/dhcp6/bindings') return JSON.parse(JSON.stringify(bind6List));
  if (path === '/api/dhcp6/leases') return JSON.parse(JSON.stringify(lease6List));
  if (path === '/api/config') return JSON.parse(JSON.stringify(configPayload || {}));
  return {};
}

async function fetchStub(path, opts) {
  const method = (opts && opts.method) || 'GET';
  const body = opts && opts.body ? String(opts.body) : '';
  requests.push({ path: String(path), method, body });
  if (method === 'POST' && path === '/api/config') {
    // batch181: the real endpoint answers {"ok":true,"note":"applied",
    // "apply_id":N} and the page then polls /api/config/apply-status until
    // completed_id catches up. The stub used to answer {} for every config
    // POST, so `saved.note` was never 'applied', the poll never ran, and the
    // "apply failed / apply timed out" branches were dead code under test.
    return jsonResponse(configPostReply);
  }
  if (method === 'GET' && path === '/api/config/apply-status') {
    applyStatusPolls++;
    return jsonResponse(applyStatusReply);
  }
  if (method === 'POST' && path === '/api/ratelimit') {
    if (failNextPost) {
      failNextPost = false;
      return jsonResponse({ error: 'too many ratelimits' }, 400);
    }
    return jsonResponse({ ok: true });
  }
  if (method === 'GET' && deferredPaths.has(path)) {
    // Snapshot now, deliver later: that is exactly what a slow response is.
    const payload = payloadFor(path);
    return new Promise((resolve) => {
      if (!deferredResponses.has(path)) deferredResponses.set(path, []);
      deferredResponses.get(path).push({
        resolveOk: () => resolve(jsonResponse(payload)),
        resolveError: () => resolve(jsonResponse({ error: 'read failed' }, 500)),
      });
    });
  }
  return jsonResponse(payloadFor(path));
}

// ------------------------------------------------------------------ sandbox
// Repeating work is driven by timers, so the harness records them the way it
// records listeners: a case can fire the 2 s poll (or the 3 s live-page poll)
// on demand instead of waiting in real time.
const intervals = [];
// batch181: see the setTimeout note in the sandbox below.
const timers = [];
let timerSeq = 0;
function recordTimer(fn, ms) {
  const delay = Number(ms) || 0;
  // A short delay is a poll interval: the code under test is WAITING on it to
  // make progress (pollApplyStatus sleeps 250 ms between requests), and holding
  // it back would deadlock the case. A long delay is an expiry (a toast lives
  // 2600 ms): running that inline would delete the message before the case can
  // assert on it, so it is queued for drainTimers().
  if (delay <= 300) { if (typeof fn === "function") fn(); return ++timerSeq; }
  timers.push({ id: ++timerSeq, fn, ms: delay });
  return timerSeq;
}
/// Run every queued timer callback once, earliest delay first. A callback that
/// queues another timer is NOT run in the same drain (that would loop forever on
/// a self-rescheduling poll); call drainTimers() again to run the next round.
function drainTimers() {
  const batch = timers.splice(0, timers.length).sort((a, b) => a.ms - b.ms);
  let ran = 0;
  for (const t of batch) { if (typeof t.fn === "function") { t.fn(); ran++; } }
  return ran;
}
function recordInterval(fn, ms) {
  intervals.push({ fn, ms: Number(ms) || 0 });
  return intervals.length;
}

const sandbox = {
  console,
  document,
  localStorage,
  navigator: { language: 'en' },
  // A real Location always has string `port` ('' for the default port) and
  // string `hostname`. Leaving them undefined made "is the port about to
  // change?" (String(cfg.web.port) !== String(location.port)) ALWAYS true, so
  // every save took the "the server moved" early return and the post-save
  // reload path was never executed by any test.
  location: { hash: '', href: 'http://127.0.0.1/', protocol: 'http:', host: '127.0.0.1', hostname: '127.0.0.1', port: '8080' },
  fetch: fetchStub,
  confirm: () => true,
  alert: () => {},
  // batch181: setTimeout used to be a no-op that never called back, so any code
  // awaiting a timer (pollApplyStatus waits 250 ms between apply-status polls)
  // hung forever and the apply-outcome path was untestable. It cannot just fire
  // synchronously either: toast() uses a 2600 ms timer to expire an entry, and
  // running it inline removes every toast before the caller can look at it.
  // Queue the callback with its delay instead, and let a test drain the queue
  // (drainTimers) or advance a chosen amount of virtual time (advanceTimers).
  setTimeout: (fn, ms) => recordTimer(fn, ms),
  clearTimeout: (id) => { const i = timers.findIndex((t) => t.id === id); if (i >= 0) timers.splice(i, 1); },
  setInterval: (fn, ms) => recordInterval(fn, ms),
  clearInterval: () => {},
  requestAnimationFrame: (fn) => { if (typeof fn === 'function') fn(); return 0; },
  encodeURIComponent,
  decodeURIComponent,
  isFinite,
  Math,
  Date,
  JSON,
  String,
  Number,
  Object,
  Array,
  Promise,
  Error,
  Map,
  Set,
};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
sandbox.window.addEventListener = (type, fn) => recordWindowListener(type, fn);
sandbox.window.matchMedia = undefined;

// The language picker's list is markup, and the script snapshots it at load:
// `const langOptions = Array.from(langsel.options).map(...)`. A stub whose
// #langsel has no children makes that snapshot empty, so filterLangs() always
// rebuilds zero entries - the filter, its "current language is pinned" rule and
// its reset-on-choice behaviour all become untestable. Seed the real options
// from the page itself (never from a literal list here: that would let the
// test and the page drift apart).
(function seedLanguageOptions() {
  const bodyMatch = html.match(/<body\b[^>]*>([\s\S]*)<\/body\s*>/i);
  const markup = bodyMatch ? bodyMatch[1].slice(0, bodyMatch[1].search(/<script\b/i)) : '';
  const sel = markup.match(/<select id="langsel"[\s\S]*?<\/select\s*>/i);
  if (!sel) return;
  const host = nodeFor('#langsel');
  for (const m of sel[0].matchAll(/<option\b[^>]*\bvalue="([^"]+)"[^>]*>([^<]*)<\/option>/g)) {
    const opt = makeElement('option');
    opt.value = m[1];
    opt.textContent = m[2];
    host.appendChild(opt);
  }
  host.options = host.children.slice();
})();

const context = vm.createContext(sandbox);
try {
  vm.runInContext(scripts.join('\n;\n'), context, { filename: REL });
} catch (e) {
  console.error(`FAIL ${NAME}: the inline script threw at load time: ${e && e.message ? e.message : e}`);
  process.exit(1);
}

// The functions the gate drives. A missing one means the page was restructured
// and this gate must be updated rather than silently passing.
// batch168: this list used to be written by hand and had drifted - it named
// three functions no case ever calls and missed eight that cases DO call. A
// hand-maintained list cannot stay correct, and its failure mode is the wrong
// one: it reports "the page was restructured" only for names someone remembered
// to add. It is derived instead: every sandbox function a case actually calls
// must exist, plus the two entry points a case reaches indirectly (api() is the
// transport every loader goes through, readSettingsDirtyState() is the draft
// state the snapshot cases compare against).
// Read the source, drop comment lines (the only place a bare `sandbox.name(`
// appears outside a real call is in prose) and drop this very statement so the
// extractor cannot match its own pattern text.
const SELF_SOURCE = readFileSync(new URL(import.meta.url), 'utf8')
  .split('\n')
  .filter((l) => !/^\s*\/\//.test(l) && !/SELF_SOURCE|const required/.test(l) && !/matchAll\(\/sandbox/.test(l))
  .join('\n');
const required = ['api', 'readSettingsDirtyState'].concat(
  [...new Set([...SELF_SOURCE.matchAll(/sandbox\.([A-Za-z_$][\w$]*)\s*\(/g)].map((m) => m[1]))]);
const missing = required.filter((n) => typeof sandbox[n] !== 'function');
if (missing.length) {
  console.error(`FAIL ${NAME}: inline script no longer defines: ${missing.join(', ')}`);
  process.exit(1);
}

// --------------------------------------------------------------------- cases
const failures = [];
function check(name, fn) {
  try {
    fn();
  } catch (e) {
    failures.push(`${name}: ${e && e.message ? e.message : e}`);
  }
}
function eq(actual, expected, what) {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);
  if (a !== b) throw new Error(`${what}: expected ${b}, got ${a}`);
}
function ok(cond, what) {
  if (!cond) throw new Error(what);
}
// Tables are painted with elements now (not markup strings), so assertions read
// structure: the body's text for content, and the cell attributes for spans.
function tableText(tbody) {
  let out = '';
  for (const tr of tbody.children) out += tr.textContent;
  return out;
}
function firstCell(tbody) {
  return tbody.children.length ? tbody.children[0].children[0] : null;
}

const RULE_A = { mac: 'AA:BB:CC:DD:EE:01', uplink_kbps: 100, downlink_kbps: 200 };

function setForm(mac, up, down) {
  nodeFor('#rl-mac').value = mac;
  nodeFor('#rl-up').value = String(up);
  nodeFor('#rl-down').value = String(down);
}
function lastPost() {
  for (let i = requests.length - 1; i >= 0; i--) {
    const r = requests[i];
    if (r.method === 'POST' && r.path === '/api/ratelimit') return r;
  }
  return null;
}
function postCount() {
  return requests.filter((r) => r.method === 'POST' && r.path === '/api/ratelimit').length;
}
function bodyOf(request) {
  ok(request !== null, 'no POST /api/ratelimit was issued');
  return JSON.parse(request.body);
}
// Drain every pending microtask so a chain of awaits (api() -> json()) that is
// still unwinding can issue its next request before the test looks.
function flush() {
  return new Promise((resolve) => setImmediate(resolve));
}

const cases = [];
async function run(name, fn) {
  try {
    await fn();
  } catch (e) {
    failures.push(`${name}: ${e && e.message ? e.message : e}`);
  } finally {
    // batch169: the page's render tickets are a monotonic counter shared by every
    // case. Once one case triggers a load (a language switch does), the counter
    // moves on and any later direct `renderX()` call becomes a silent no-op:
    // the loader takes a ticket, sees a newer one exists and returns before
    // painting. A case that then asserts "the error row was painted" fails for a
    // reason that has nothing to do with the code under test - and, worse, a
    // case that asserts nothing fails silently. Reset the counter between cases
    // so each one starts from a known ticket state. The row-reconcile cache is
    // keyed by tbody ELEMENT identity, so a placeholder text cached by an earlier
    // case would make paintTable() decide "already showing that" and skip the
    // repaint - clear it for the same reason.
    try {
      vm.runInContext("renderTicket.clear();", context);
      vm.runInContext("paintedRows.clear();", context);
    }
    catch (e) { failures.push("[harness] renderTicket reset failed: " + (e && e.message)); }
  }
}

// Case 1 (batch147, bug a): the edit context must die with the render it came
// from. Clicking [edit] on rule A, navigating away and back, then saving a NEW
// MAC must be a plain add - not "replace A", which would delete a rule the
// operator never touched.
cases.push(['edit context does not survive a re-render', async () => {
  ratelimitRules = [RULE_A];
  await sandbox.loadRateLimits();
  sandbox.editRateLimit(RULE_A.mac);
  // Navigation away and back re-renders the table.
  await sandbox.loadRateLimits();
  setForm('AA:BB:CC:DD:EE:02', 500, 500);
  const before = postCount();
  await sandbox.addRateLimit();
  ok(postCount() === before + 1, 'a save must issue exactly one POST');
  const body = bodyOf(lastPost());
  eq(body.replace_mac, undefined, 'replace_mac after a re-render');
  eq(body.mac, 'AA:BB:CC:DD:EE:02', 'mac');
  eq(body.uplink_kbps, 500, 'uplink_kbps');
  eq(body.downlink_kbps, 500, 'downlink_kbps');
}]);

// Case 2 (batch147, bug b): a FAILED save must keep the edit context so a retry
// still replaces the old rule. Clearing it before the request turns the retry
// into a plain add: two rules for one client, and the token bucket honours the
// FIRST match, so the stale cap stays in force.
cases.push(['a failed save keeps the edit context for the retry', async () => {
  ratelimitRules = [RULE_A];
  await sandbox.loadRateLimits();
  sandbox.editRateLimit(RULE_A.mac);
  setForm('AA:BB:CC:DD:EE:03', 700, 700);
  failNextPost = true;
  const before = postCount();
  await sandbox.addRateLimit();
  ok(postCount() === before + 1, 'the failing save must still POST once');
  eq(bodyOf(lastPost()).replace_mac, RULE_A.mac, 'first (failing) attempt');
  // Retry, same form, backend healthy now.
  await sandbox.addRateLimit();
  ok(postCount() === before + 2, 'the retry must POST again');
  eq(bodyOf(lastPost()).replace_mac, RULE_A.mac, 'retry replace_mac');
  eq(bodyOf(lastPost()).mac, 'AA:BB:CC:DD:EE:03', 'retry mac');
}]);

// Case 3 (regression guard): a successful edit of the SAME mac is an upsert,
// not a re-key, and the context must be dropped afterwards so the next plain
// add does not carry a stale replace_mac.
cases.push(['a successful edit clears the context', async () => {
  ratelimitRules = [RULE_A];
  await sandbox.loadRateLimits();
  sandbox.editRateLimit(RULE_A.mac);
  setForm(RULE_A.mac, 900, 900);
  const before = postCount();
  await sandbox.addRateLimit();
  eq(bodyOf(lastPost()).replace_mac, undefined, 'same-mac edit must not re-key');
  setForm('AA:BB:CC:DD:EE:04', 400, 400);
  await sandbox.addRateLimit();
  ok(postCount() === before + 2, 'the follow-up add must POST');
  eq(bodyOf(lastPost()).replace_mac, undefined, 'context cleared after success');
}]);

// Case 4: the delete path still targets the MAC it was given (a plain guard
// against the row_id/encodeURIComponent pair drifting apart).
cases.push(['delete targets the given MAC', async () => {
  ratelimitRules = [RULE_A];
  await sandbox.loadRateLimits();
  const before = requests.length;
  await sandbox.delRateLimit(RULE_A.mac);
  const del = requests.slice(before).find((r) => r.method === 'DELETE');
  ok(del !== undefined, 'delete must issue a DELETE');
  eq(del.path, `/api/ratelimit?mac=${encodeURIComponent(RULE_A.mac)}`, 'delete path');
}]);

// The rendered text of a tbody: what the operator actually sees. The action
// tables are built as elements (batch165), so their body has no innerHTML
// string to search - reading textContent is the faithful question either way.
const tableTextOf = (tbody) => tbody.textContent;
const labelsIn = (tbody) => {
  const out = [];
  const walk = (n) => {
    for (const c of n.children) {
      const l = c.getAttribute && c.getAttribute('aria-label');
      if (l) out.push(l);
      walk(c);
    }
  };
  walk(tbody);
  return out;
};

// ---------------------------------------------------------------- settings
// batch148: the settings form is the operator's DRAFT as soon as they type.
// Every unasked-for reload refilled the fields from the server and then reset
// the dirty snapshot to match, so the edits vanished AND the badge claimed
// "clean". A language switch does exactly that (applyI18n -> load(page)).
// Derive the settings controls from the page markup instead of listing three of
// them by hand: a hand-written subset silently made two thirds of the form
// invisible to every case that reads or writes a setting (the dirty badge, the
// numeric checks, the save path). set-dirty is a badge and set-save a button,
// so only the real inputs/selects are registered.
const SETTINGS_CONTROL_IDS = [...new Set(
  [...html.matchAll(/<(?:input|select)\b[^>]*\bid="(set-[a-z0-9-]+)"/g)].map((m) => m[1]),
)].filter((id) => id !== 'set-dirty' && id !== 'set-save');
registerList('#page-settings input, #page-settings select', SETTINGS_CONTROL_IDS);

// batch163: this fixture must mirror what GET /api/config ACTUALLY emits - every
// numeric setting it omits would load into its input as "" and then trip the new
// range check. src/web/web_api.cpp emits all of these unconditionally (bridge.
// mac_table_size, ipv6.prefix_len / ra_lifetime_s, ipv6.dhcpv6.lease_seconds),
// so a fixture without them is not a smaller server, it is a DIFFERENT one.
// batch222: ipv6.enabled and ipv6.ula_prefix belong here for the same reason -
// web_api.cpp:1859-1869 always emits them, and an all-zero prefix comes back as
// the compressed "::" (asio::ip::make_address_v6), never as "".
const SERVER_CONFIG = {
  adapter: 'eth0',
  gateway: { ipv4: '192.168.0.1', mask: '255.255.255.0', mac: '02:00:00:00:00:01' },
  perf: { workers: 8, max_conns: 4096 },
  vlan: { id: 0 },
  mode: 'main',
  web: { port: 8080 },
  bridge: { mac_table_size: 4096 },
  dhcp: { enabled: true, pool: ['192.168.0.100', '192.168.0.200'], lease_hours: 24, dns: [] },
  ipv6: {
    enabled: false,
    ula_prefix: '::',
    prefix_len: 64,
    ra_lifetime_s: 1800,
    dhcpv6: { lease_seconds: 3600 },
  },
};

function resetSettingsForm() {
  nodeFor('#set-dirty').hidden = true;
  nodeFor('#set-adapter').value = '';
  nodeFor('#set-workers').value = '';
  nodeFor('#set-dhcp-poolstart').value = '';
}

// Case 5: an unsaved edit survives an unasked-for reload.
cases.push(['an unsaved settings draft survives a reload', async () => {
  configPayload = SERVER_CONFIG;
  resetSettingsForm();
  await sandbox.loadSettings();
  eq(nodeFor('#set-workers').value, '8', 'initial fill from the server');
  eq(nodeFor('#set-adapter').value, 'eth0', 'initial adapter');

  // The operator types a new worker count.
  nodeFor('#set-workers').value = '16';
  eq(sandbox.syncDirty(), true, 'typing must mark the form dirty');

  // An unasked-for reload (language switch re-renders the current page).
  await sandbox.loadSettings();
  eq(nodeFor('#set-workers').value, '16', 'draft after a reload');
  eq(sandbox.syncDirty(), true, 'the draft must still be reported dirty');
  ok(nodeFor('#set-dirty').hidden === false, 'the dirty badge must stay visible');
}]);

// Case 6 (the escape hatch): an EXPLICIT reload - the one a successful save
// performs - must adopt the server's values, so server-side normalisation is
// never hidden behind a stale draft.
cases.push(['an explicit reload adopts the server values', async () => {
  configPayload = SERVER_CONFIG;
  resetSettingsForm();
  await sandbox.loadSettings();
  nodeFor('#set-workers').value = '99999';
  eq(sandbox.syncDirty(), true, 'dirty before the explicit reload');
  await sandbox.loadSettings(true);
  eq(nodeFor('#set-workers').value, '8', 'explicit reload adopts the server value');
  eq(sandbox.syncDirty(), false, 'explicit reload clears the dirty state');
}]);

// ------------------------------------------------- out-of-order responses
// batch150: a page's data is requested more than once in quick succession - the
// router loads it on navigation and every CRUD action reloads after it lands.
// The two responses ride separate connections, so the OLDER one can arrive
// LAST. Nothing stopped it from repainting: a rule the operator just deleted
// reappeared, and a stale FAILURE painted "network error" over good rows.
// These cases pin "only the newest request for a table may render".
function releaseDeferred(path) {
  const q = deferredResponses.get(path);
  ok(q && q.length > 0, `expected a held-back ${path} response`);
  q.shift().resolveOk();
}
function releaseDeferredError(path) {
  const q = deferredResponses.get(path);
  ok(q && q.length > 0, `expected a held-back ${path} response`);
  q.shift().resolveError();
}

cases.push(['a late, older response cannot repaint the rate-limit table', async () => {
  ratelimitRules = [RULE_A];
  deferredPaths.add('/api/ratelimit');
  const stale = sandbox.loadRateLimits();   // request #1: held back
  deferredPaths.delete('/api/ratelimit');

  ratelimitRules = [];                      // the rule was deleted meanwhile
  await sandbox.loadRateLimits();           // request #2: renders "empty"
  const tbody = nodeFor('#rl-table tbody');
  ok(!tableTextOf(tbody).includes(RULE_A.mac), 'the fresh render must show no rule');

  releaseDeferred('/api/ratelimit');        // now the OLD answer arrives
  await stale;
  ok(!tableTextOf(tbody).includes(RULE_A.mac),
     `a deleted rule must not reappear, got: ${tableTextOf(tbody)}`);
}]);

cases.push(['a late failure cannot replace good rows with "network error"', async () => {
  ratelimitRules = [RULE_A];
  deferredPaths.add('/api/ratelimit');
  const stale = sandbox.loadRateLimits();   // request #1: held back
  deferredPaths.delete('/api/ratelimit');
  await sandbox.loadRateLimits();           // request #2: renders the rule
  const tbody = nodeFor('#rl-table tbody');
  ok(tableTextOf(tbody).includes(RULE_A.mac), 'the fresh render must show the rule');

  // The held-back request now fails (its connection died).
  releaseDeferredError('/api/ratelimit');
  await stale;
  ok(tableTextOf(tbody).includes(RULE_A.mac),
     `a stale FAILURE must not wipe good rows, got: ${tableTextOf(tbody)}`);
}]);

cases.push(['the port-map table obeys the same ordering rule', async () => {
  portmapRules = [{ id: 7, proto: 'tcp', wan_port: 8080, lan_ip: '192.168.1.10', lan_port: 80 }];
  deferredPaths.add('/api/portmap');
  const stale = sandbox.loadPortMap();      // request #1: held back
  deferredPaths.delete('/api/portmap');

  portmapRules = [];                        // deleted meanwhile
  await sandbox.loadPortMap();              // request #2
  const tbody = nodeFor('#pm-table tbody');
  ok(!tableTextOf(tbody).includes('192.168.1.10'), 'the fresh render must show no rule');

  releaseDeferred('/api/portmap');
  await stale;
  ok(!tableTextOf(tbody).includes('192.168.1.10'),
     `a deleted port-map rule must not reappear, got: ${tableTextOf(tbody)}`);
}]);

// The device table caches a count for the "clients" tile, so a stale answer
// would also corrupt that tile's next read - the guard has to cover the cache,
// not just the DOM.
cases.push(['a stale device list cannot repaint the table or its cached count', async () => {
  // The scope filter defaults to "WAN only", which would hide a lan:true client
  // and make the table assertion vacuous - select "all" so the row really renders.
  nodeFor('#dev-scope').value = 'all';
  nodeFor('#dev-sort').value = 'rate';
  nodeFor('#dev-dir').value = 'desc';
  clientList = [{ ip: '192.168.1.77', mac: 'AA:BB:CC:00:11:22', up_bps: 1, down_bps: 1, last_seen_s: 1, lan: true }];
  deferredPaths.add('/api/clients');
  const stale = sandbox.renderDevices();    // request #1: held back
  deferredPaths.delete('/api/clients');

  clientList = [];
  await sandbox.renderDevices();            // request #2
  const tbody = nodeFor('#dev-table tbody');
  ok(!tableText(tbody).includes('192.168.1.77'), 'the fresh render must show no device');

  releaseDeferred('/api/clients');
  await stale;
  ok(!tableText(tbody).includes('192.168.1.77'),
     `a vanished device must not reappear, got: ${tableText(tbody)}`);
  eq(sandbox.window.__clientCount, 0, 'cached client count');
}]);

// Three sequential awaits: the guard must sit before the WRITES, not after the
// first await - otherwise a newer load that finishes in between is clobbered by
// the tail of the older one.
cases.push(['the lease tables guard after all four reads', async () => {
  leaseList = [{ mac: 'AA:BB:CC:DD:EE:99', ip: '192.168.1.99', expires_in_s: 60, is_static: false, hostname: 'gone' }];
  lease6List = [{ duid: '00:03:00:01:aa:bb', iaid: 7, ip: 'fd00::99', expires_in_s: 60, is_static: false, hostname: 'gone6' }];
  bind4List = [{ mac: 'AA:BB:CC:DD:EE:98', ip: '192.168.1.98', hostname: 'gone4b' }];
  bind6List = [{ duid: '00:03:00:01:aa:cc', ip: 'fd00::98', hostname: 'gone6b' }];

  // Determinism: a plain load must really render all FOUR tables, otherwise
  // the "must not reappear" assertions below would pass on an empty table.
  // fillRows() writes rows with textContent + appendChild, so these assertions
  // read textContent (the stub composes it from the children).
  const tbody = nodeFor('#le-table tbody');
  const tbodyV6 = nodeFor('#le-v6 tbody');
  const tbodyB4 = nodeFor('#le-bind tbody');
  const tbodyB6 = nodeFor('#le-bind6 tbody');
  await sandbox.loadLeases();
  ok(tbody.textContent.includes('192.168.1.99'), 'a plain load renders v4 leases');
  ok(tbodyV6.textContent.includes('fd00::99'), 'a plain load renders v6 leases');
  ok(tbodyB4.textContent.includes('192.168.1.98'), 'a plain load renders v4 bindings');
  ok(tbodyB6.textContent.includes('fd00::98'), 'a plain load renders v6 bindings');

  // Hold the LAST read: by then #1 has snapshotted all four responses, so
  // releasing it after #2 has painted must not bring ANY of them back. This is
  // what pins the guard to "immediately before the writes" - a guard placed
  // after any earlier await lets that await's data win instead.
  deferredPaths.add('/api/dhcp6/bindings');
  const stale = sandbox.loadLeases();       // request #1
  await flush();
  ok(deferredResponses.has('/api/dhcp6/bindings'),
     'the older load never reached the last read');
  deferredPaths.delete('/api/dhcp6/bindings');

  leaseList = [];
  lease6List = [];
  bind4List = [];
  bind6List = [];
  await sandbox.loadLeases();               // request #2: renders empty
  ok(!tbody.textContent.includes('192.168.1.99'), 'the fresh render must show no lease');
  ok(!tbodyV6.textContent.includes('fd00::99'), 'the fresh render must show no v6 lease');
  ok(!tbodyB4.textContent.includes('192.168.1.98'), 'the fresh render must show no v4 binding');
  ok(!tbodyB6.textContent.includes('fd00::98'), 'the fresh render must show no v6 binding');

  releaseDeferred('/api/dhcp6/bindings');
  await stale;
  ok(!tbody.textContent.includes('192.168.1.99'),
     `an expired lease must not reappear, got: ${tbody.textContent}`);
  ok(!tbodyV6.textContent.includes('fd00::99'),
     `an expired v6 lease must not reappear, got: ${tbodyV6.textContent}`);
  ok(!tbodyB4.textContent.includes('192.168.1.98'),
     `an expired binding must not reappear, got: ${tbodyB4.textContent}`);
  ok(!tbodyB6.textContent.includes('fd00::98'),
     `an expired v6 binding must not reappear, got: ${tbodyB6.textContent}`);
}]);
// The dashboard has its own 2 s refresh, so it needs the same guard - and it is
// also the one path with no other coverage: an undefined identifier in its
// error branch only shows up when /api/status actually fails, which is exactly
// when the operator is already having a bad day.
// batch200: /api/dhcp/leases, /api/dhcp6/leases, /api/dhcp/bindings and
// /api/dhcp6/bindings are four INDEPENDENT read-only snapshots, and the page
// fetched them one after another - four round-trips of wall clock for one
// repaint, repeated every 3 s while the page is open, against a server that
// serves connections from only two workers (http_server.cpp:215). Nothing in
// the four reads depends on anything in the other three.
cases.push(['the four lease reads are issued together, not one after another', async () => {
  leaseList = [];
  lease6List = [];
  bind4List = [];
  bind6List = [];
  requests.length = 0;

  // Hold the FIRST of the four. Under a serial fetch the remaining three
  // cannot even be issued until this one answers, so the count stays at 1.
  // Under a concurrent fetch all four are in flight immediately.
  deferredPaths.add('/api/dhcp/leases');
  let done;
  try {
    const load = sandbox.loadLeases();
    await flush();
    const issued = requests.filter((r) => r.method === 'GET').map((r) => r.path);
    const leaseReads = issued.filter((x) => /^\/api\/dhcp6?\/leases$/.test(x));
    const bindReads = issued.filter((x) => /^\/api\/dhcp6?\/bindings$/.test(x));
    eq(leaseReads.length, 2, 'both lease lists must be requested, got: ' + JSON.stringify(issued));
    eq(bindReads.length, 2, 'both binding lists must be requested, got: ' + JSON.stringify(issued));
    eq(issued.length, 4, 'all four reads must ride at once, got: ' + JSON.stringify(issued));
    done = load;
  } finally {
    deferredPaths.delete('/api/dhcp/leases');
    releaseDeferred('/api/dhcp/leases');
  }
  await done;

  // The whole point is that the LAST of the four no longer gates the row
  // count: one failing read must not leave the other three unpainted. Each
  // table is filled independently, so a single 500 still fills three.
  requests.length = 0;
  leaseList = [{ mac: 'AA:BB:CC:DD:EE:01', ip: '192.168.1.10', expires_in_s: 60, is_static: false, hostname: 'kept4' }];
  lease6List = [{ duid: '00:03:00:01:aa:0a', iaid: 1, ip: 'fd00::0a', expires_in_s: 60, is_static: false, hostname: 'kept6' }];
  bind4List = [{ mac: 'AA:BB:CC:DD:EE:0b', ip: '192.168.1.11', hostname: 'bound4' }];
  bind6List = [{ duid: '00:03:00:01:aa:0b', ip: 'fd00::0b', hostname: 'bound6' }];
  await sandbox.loadLeases();
  const t4 = nodeFor('#le-table tbody');
  const t6 = nodeFor('#le-v6 tbody');
  const b4 = nodeFor('#le-bind tbody');
  const b6 = nodeFor('#le-bind6 tbody');
  ok(t4.textContent.includes('192.168.1.10'), 'the v4 lease table is filled');
  ok(t6.textContent.includes('fd00::0a'), 'the v6 lease table is filled');
  ok(b4.textContent.includes('192.168.1.11'), 'the v4 binding table is filled');
  ok(b6.textContent.includes('fd00::0b'), 'the v6 binding table is filled');

  // A well-formed but non-list answer must render as an EMPTY table, not as
  // garbage. The old code guarded each payload with Array.isArray at the call
  // site; folding the four reads into one Promise.allSettled hands the raw
  // value to fillRows, so that guard now lives in value() - and without it
  // rows.map would throw and the four tables would keep whatever they showed
  // before. One endpoint changing shape must not freeze the page.
  leaseList = { not: 'a list' };
  lease6List = 'nope';
  bind4List = { length: 3 };
  bind6List = 42;
  await sandbox.loadLeases();
  ok(!nodeFor('#le-table tbody').textContent.includes('192.168.1.10'),
     'a non-list v4 lease answer must leave the table empty');
  ok(!nodeFor('#le-v6 tbody').textContent.includes('fd00::0a'),
     'a non-list v6 lease answer must leave the table empty');
  ok(!nodeFor('#le-bind tbody').textContent.includes('192.168.1.11'),
     'a non-list v4 binding answer must leave the table empty');
  ok(!nodeFor('#le-bind6 tbody').textContent.includes('fd00::0b'),
     'a non-list v6 binding answer must leave the table empty');
}]);

cases.push(['the dashboard cards obey the ordering rule and its error branch runs', async () => {
  statusPayload.stats.rx_frames = 111;
  deferredPaths.add('/api/status');
  const stale = sandbox.refreshStatus();     // request #1: held back
  deferredPaths.delete('/api/status');

  statusPayload.stats.rx_frames = 222;
  await sandbox.refreshStatus();             // request #2
  const cards = nodeFor('#cards');
  ok(tableText(cards).includes('222'), 'the fresh render must show the new count');

  releaseDeferred('/api/status');
  await stale;
  ok(!tableText(cards).includes('111'),
     `a stale status must not repaint the cards, got: ${tableText(cards)}`);

  // Error branch: it must run without throwing (no undefined identifiers) and
  // must not leave the table claiming old data.
  const tbody = nodeFor('#dev-table tbody');
  const realFetch = sandbox.fetch;
  sandbox.fetch = async (p, o) => {
    if (String(p) === '/api/status') {
      return { ok: false, status: 500, async json() { return {}; }, async text() { return 'boom'; } };
    }
    return realFetch(p, o);
  };
  try {
    await sandbox.refreshStatus();
  } finally {
    sandbox.fetch = realFetch;
  }
  const cell = firstCell(tbody);
  ok(cell && cell.getAttribute('colspan') === '6',
     `the dashboard error branch must mark the table, got: ${tableText(tbody)}`);
}]);

// batch151: refreshStatus checked its ticket right after /api/status and then
// went on to await renderDevices + renderSystem. Two consequences, both real:
// a superseded refresh still issued a /api/system request, and renderSystem
// itself painted with no ticket at all - so two overlapping host-tile refreshes
// could land out of order and leave the OLD cpu/throughput on screen. The
// dashboard is the only page that repaints on a timer, so this repeats forever
// while the operator watches it.
cases.push(['the host tiles obey the ordering rule too', async () => {
  const hc = nodeFor('#host-cards');
  systemPayload.proc = { cpu_percent: 11, ws_bytes: 1048576, virt_bytes: 1048576, cores: 4 };
  deferredPaths.add('/api/system');
  const older = sandbox.renderSystem();       // request #1: held back
  deferredPaths.delete('/api/system');

  systemPayload.proc = { cpu_percent: 22, ws_bytes: 1048576, virt_bytes: 1048576, cores: 4 };
  await sandbox.renderSystem();               // request #2
  ok(tableText(hc).includes('22.0%'), 'the fresh render must show the new cpu');

  releaseDeferred('/api/system');             // request #1 arrives last
  await older;
  ok(!tableText(hc).includes('11.0%'),
     `a stale /api/system must not repaint the host tiles, got: ${tableText(hc)}`);
}]);

cases.push(['a superseded dashboard refresh stops before the host tiles', async () => {
  // #1 passes its own /api/status gate, then stalls inside renderDevices.
  // refreshStatus awaits /api/status first, so the held /api/clients request is
  // only issued a few microtasks later - flush them before releasing.
  statusPayload.stats.rx_frames = 501;
  deferredPaths.add('/api/clients');
  const stale = sandbox.refreshStatus();
  await flush();
  ok(deferredResponses.has('/api/clients'),
     'the superseded refresh never asked for the client list');
  deferredPaths.delete('/api/clients');

  // #2 runs to completion while #1 is still waiting for /api/clients.
  statusPayload.stats.rx_frames = 502;
  await sandbox.refreshStatus();

  const before = requests.filter((r) => r.path === '/api/system').length;
  releaseDeferred('/api/clients');
  await stale;
  const after = requests.filter((r) => r.path === '/api/system').length;
  ok(after === before,
     `a superseded refresh must not fetch /api/system (before=${before}, after=${after})`);
}]);

// batch152: /api/status used to nest "bridge" inside "dhcp6", so st.bridge came
// back undefined and the Bridge page rendered five blank rows. The fix is on
// the server (the object is top level again); this case pins the CONSUMER half
// so a future frontend edit cannot quietly start reading the nested shape.
cases.push(['the bridge page reads a top-level bridge object', async () => {
  statusPayload.bridge = { enabled: true, upstream: 'eth0', downstream: 'eth1',
                           mac_count: 3, state: 'running' };
  await sandbox.loadBridge();
  eq(nodeFor('#br-state').textContent, 'running', 'bridge state row');
  ok(nodeFor('#br-enabled').textContent.length > 0, 'the enabled row must be filled');
  eq(nodeFor('#br-up').textContent, 'eth0', 'upstream row');
  eq(nodeFor('#br-down').textContent, 'eth1', 'downstream row');
  eq(nodeFor('#br-maccount').textContent, '3', 'mac count row');

  delete statusPayload.bridge;
  statusPayload.dhcp6 = { bridge: { enabled: true, upstream: 'n0',
                                    downstream: 'n1', mac_count: 9,
                                    state: 'listening' } };
  await sandbox.loadBridge();
  eq(nodeFor('#br-state').textContent, '', 'a nested bridge must not feed the page');
  eq(nodeFor('#br-up').textContent, '', 'nested upstream must not be shown');
}]);

// batch153: the console page is the one page that repaints every 3 s WHILE the
// operator is looking at it. Assigning textContent replaces the text node, and
// a replaced node takes the operator's selection with it - so selecting a log
// line to copy was impossible: the next poll wiped it. The snapshot is also up
// to 2000 lines, and re-running layout for unchanged text is pure waste.
cases.push(['the console is not repainted when the snapshot did not change', async () => {
  consoleText = 'line one\nline two';
  const out = nodeFor('#cl-out');
  await sandbox.loadConsole();
  eq(out.textContent, 'line one\nline two', 'the first load paints the log');
  const afterFirst = out.__writes;
  ok(afterFirst > 0, 'the first load must write the snapshot');

  // The 3 s poll: the ring did not grow, so the visible text is identical.
  await sandbox.loadConsole();
  eq(out.__writes, afterFirst,
     'an identical snapshot must not be rewritten (that would destroy the selection)');

  // A new line really must appear, so the guard cannot be "never repaint".
  consoleText = 'line one\nline two\nline three';
  await sandbox.loadConsole();
  ok(out.__writes > afterFirst, 'a changed snapshot must be repainted');
  ok(out.textContent.includes('line three'), `the new line must appear, got: ${out.textContent}`);

  // An empty ring still has to show the placeholder - and must update when the
  // ring goes from empty to non-empty and back.
  consoleText = '';
  await sandbox.loadConsole();
  eq(out.textContent, sandbox.t('cl.empty'), 'an empty ring shows the placeholder');
  const afterEmpty = out.__writes;
  await sandbox.loadConsole();
  eq(out.__writes, afterEmpty, 'the placeholder is not rewritten either');
}]);
// batch154: the "Devices" table is the one place the Web UI and the native UI
// show the same data with the same three controls, and the labels promise the
// same meaning ("all/lan/wan, rate/up/down/activity, asc/desc"). The activity
// key is `last_seen_s`, which the API defines as SECONDS SINCE the last packet
// - an AGE. The native page maps it to (0xFFFFFFFF - age) so that "larger" is
// "more recent" and the default Descending list leads with the busiest client.
// The Web page sorted by the raw age, so Descending led with the client that
// had been silent the longest: the same three controls produced the opposite
// list, and the operator's "who is active right now" question got the wrong
// answer first.
cases.push(['device sorting means the same thing as the native page', async () => {
  const tbody = nodeFor('#dev-table tbody');
  nodeFor('#dev-scope').value = 'all';
  const mk = (n, seen, up, down) => ({
    ip: `10.0.0.${n}`, mac: `AA:AA:AA:AA:AA:0${n}`,
    up_bps: up, down_bps: down, last_seen_s: seen, lan: true,
  });
  // seen: 1 = active a second ago, 300 = silent for five minutes.
  clientList = [mk(1, 300, 0, 0), mk(2, 1, 0, 0), mk(3, 60, 0, 0)];

  const order = async (sort, dir) => {
    nodeFor('#dev-sort').value = sort;
    nodeFor('#dev-dir').value = dir;
    await sandbox.renderDevices();
    const text = tableText(tbody);
    return [1, 2, 3]
      .map((n) => ({ n, at: text.indexOf(`10.0.0.${n}`) }))
      .sort((a, b) => a.at - b.at)
      .map((x) => x.n);
  };

  // Descending activity = most recently active first (matches the native page).
  eq(await order('seen', 'desc'), [2, 3, 1], 'desc = most recently active first');
  // Ascending = the quietest last-seen first.
  eq(await order('seen', 'asc'), [1, 3, 2], 'asc = least recently active first');

  // The other keys are "bigger value = busier", so desc must lead with the
  // largest. This pins the fix to the ONE inverted key instead of flipping
  // the whole comparator.
  clientList = [mk(1, 5, 100, 0), mk(2, 5, 900, 0), mk(3, 5, 400, 0)];
  eq(await order('up', 'desc'), [2, 3, 1], 'desc = most upload first');
  eq(await order('up', 'asc'), [1, 3, 2], 'asc = least upload first');
}]);
// batch154: clicking a nav link runs the loader TWICE. The click handler
// activates the page immediately, and then the browser's default action
// changes location.hash, which fires hashchange, which activates the SAME page
// again - so every navigation issued its request burst twice (for the
// dashboard: two /api/status + two /api/clients + two /api/system, one of the
// pairs always thrown away as stale by the render tickets). The harness records
// listeners now, so this is a red/green case instead of a browser-only hunch.
cases.push(['one nav click activates a page exactly once', async () => {
  const navEl = nodeFor('#nav');
  ok(Array.isArray(navEl.__on.click) && navEl.__on.click.length > 0,
     'the nav click handler must be registered');
  ok(Array.isArray(windowListeners.hashchange) && windowListeners.hashchange.length > 0,
     'the hashchange handler must be registered');

  const click = (hash) => {
    const anchor = { hash, closest: () => anchor };
    for (const fn of navEl.__on.click) fn({ target: anchor });
  };
  const hashchange = () => { for (const fn of windowListeners.hashchange) fn(); };
  const count = (path) => requests.filter((r) => r.path === path).length;

  // (1) Navigate to a page we are NOT on: the click handler runs while
  // location.hash is still the old value, then the default action moves it and
  // hashchange fires. The loader must run once in total.
  sandbox.location.hash = '#dashboard';
  const before = count('/api/portmap');
  click('#portmap');
  sandbox.location.hash = '#portmap';   // the default action
  hashchange();
  eq(count('/api/portmap') - before, 1, 'a navigation must load the page once, not twice');

  // (2) Clicking the page we are ALREADY on produces no hashchange at all, so
  // the click handler is the only thing that can serve it - exactly once.
  const beforeSame = count('/api/portmap');
  click('#portmap');
  eq(count('/api/portmap') - beforeSame, 1, 're-clicking the active page refreshes it once');
}]);
// batch154 (same class as the nav click): a language switch re-rendered the
// dashboard TWICE - `applyI18n` special-cased the dashboard with refreshStatus()
// and then called load(), which for the dashboard IS refreshStatus. Startup was
// worse: applyI18n did both of those and then activate() loaded the dashboard a
// third time. Three identical bursts on boot, two on every language switch.
cases.push(['a page is loaded once per activation, not once per code path', async () => {
  const count = (path) => requests.filter((r) => r.path === path).length;

  // Boot: exactly one dashboard burst.
  eq(startupRequests.filter((r) => r.path === '/api/status').length, 1, 'boot loads /api/status once');
  eq(startupRequests.filter((r) => r.path === '/api/clients').length, 1, 'boot loads /api/clients once');
  eq(startupRequests.filter((r) => r.path === '/api/system').length, 1, 'boot loads /api/system once');

  // Language switch while the dashboard is showing.
  sandbox.location.hash = '#dashboard';
  const before = count('/api/status');
  sandbox.applyI18n();
  await flush();
  await flush();
  eq(count('/api/status') - before, 1, 'a language switch reloads the page once');
}]);
// batch155: the dashboard poll had no in-flight guard, while the 3 s live-page
// poll did. That asymmetry is backwards: the dashboard is the HEAVIER loader
// (three sequential requests: /api/status -> /api/clients -> /api/system), and
// each request may burn the server's full 5 s IO budget. Against a slow or
// wedged listener one refresh can therefore take 15 s, during which the 2 s
// timer fires seven more times - eight overlapping chains, up to 24 requests
// queued behind a server that has TWO connection workers. The page slows the
// very server it is polling. A tick that lands while the previous refresh is
// still running must be skipped, and the poll must resume on the next tick.
cases.push(['the dashboard poll does not stack up when a refresh is slow', async () => {
  const poll = intervals.filter((x) => x.ms === 2000);
  eq(poll.length, 1, 'exactly one 2 s dashboard poll must be registered');
  const tick = poll[0].fn;
  const statusCount = () => requests.filter((r) => r.path === '/api/status').length;

  // The listener is slow: /api/status stays unanswered across several ticks.
  nodeFor('#page-dashboard').hidden = false;
  deferredPaths.add('/api/status');
  const before = statusCount();
  tick();
  await flush();
  eq(statusCount() - before, 1, 'the first tick must issue one request');
  tick();
  tick();
  tick();
  await flush();
  eq(statusCount() - before, 1,
     'ticks that land while a refresh is in flight must be dropped, not queued');

  // Let it finish. The guard must clear, or the dashboard would freeze forever.
  releaseDeferred('/api/status');
  await flush();
  await flush();
  deferredPaths.delete('/api/status');
  const afterFinish = statusCount();
  tick();
  await flush();
  ok(statusCount() > afterFinish,
     `the poll must resume after the slow refresh completes (before=${afterFinish}, after=${statusCount()})`);
}]);
// batch155: "Sort by" and the LAN/All filter are pure client-side operations on
// data the page already holds - yet each change re-fetched /api/clients. The
// table therefore waited for a round-trip before it re-ordered, and when the
// link failed the dropdown REPLACED the visible table with "network error",
// throwing away rows the page had in memory. Two assertions: a local repaint
// works with no network at all, and a real load still reports its failure.
cases.push(['filter and sort repaint from memory, without the network', async () => {
  const tbody = nodeFor('#dev-table tbody');
  nodeFor('#dev-scope').value = 'all';
  nodeFor('#dev-sort').value = 'rate';
  nodeFor('#dev-dir').value = 'desc';
  clientList = [
    { ip: '10.0.0.1', mac: 'AA:AA:AA:AA:AA:01', up_bps: 10, down_bps: 0, last_seen_s: 5, lan: true },
    { ip: '10.0.0.2', mac: 'AA:AA:AA:AA:AA:02', up_bps: 900, down_bps: 0, last_seen_s: 5, lan: true },
  ];
  await sandbox.renderDevices();
  ok(tableText(tbody).includes('10.0.0.1'), 'the initial load must paint both rows');

  // The link is down from here on.
  const realFetch = sandbox.fetch;
  sandbox.fetch = async () => { throw new Error('offline'); };
  try {
    nodeFor('#dev-sort').value = 'up';
    nodeFor('#dev-dir').value = 'desc';
    sandbox.resortDevices();
    // The repaint must be SYNCHRONOUS. Flush first, so an implementation that
    // quietly re-fetched in the background would have landed its answer (or its
    // error row) before the assertions look - otherwise "it still shows rows"
    // is true only because the request has not resolved yet (a fake test).
    await flush();
    await flush();

    const shown = tableText(tbody);
    ok(shown.includes('10.0.0.1') && shown.includes('10.0.0.2'),
       `a sort change must keep the rows already on screen, got: ${shown}`);
    ok(shown.indexOf('10.0.0.2') < shown.indexOf('10.0.0.1'),
       `the new order must be applied locally (most upload first), got: ${shown}`);

    // Negative control: a real load still surfaces the failure, so the cache
    // cannot be silently papering over a dead link.
    await sandbox.renderDevices();
    const errCell = firstCell(tbody);

    ok(errCell && errCell.getAttribute('colspan') === '6',
       `a real load must still report the failure, got: ${tableText(tbody)}`);
  } finally {
    sandbox.fetch = realFetch;
  }
}]);
// batch156: the devices table is rebuilt from scratch on EVERY 2 s poll, and
// the neighbour table it mirrors holds up to 4096 entries - so each tick threw
// away and recreated up to 4096 <tr> elements (six cells each). Worse than the
// cost: replacing the rows also throws away the operator's text selection, so
// an IP or MAC in that table could never be selected long enough to copy. The
// table must be reconciled instead: same row identity in the same order means
// only the cells whose text actually changed get rewritten.
cases.push(['a poll repaint only rewrites the cells that changed', async () => {
  const tbody = nodeFor('#dev-table tbody');
  nodeFor('#dev-scope').value = 'all';
  nodeFor('#dev-sort').value = 'rate';
  nodeFor('#dev-dir').value = 'desc';
  clientList = [
    { ip: '10.1.0.1', mac: 'BB:BB:BB:BB:BB:01', up_bps: 900, down_bps: 0, last_seen_s: 5, lan: true },
    { ip: '10.1.0.2', mac: 'BB:BB:BB:BB:BB:02', up_bps: 100, down_bps: 0, last_seen_s: 9, lan: true },
  ];
  await sandbox.renderDevices();
  eq(tbody.children.length, 2, 'two device rows');
  const row0 = tbody.children[0];
  const ipCell = row0.children[0];
  const seenCell = row0.children[4];
  ok(ipCell.textContent === '10.1.0.1', `first row must be the busier client, got ${ipCell.textContent}`);
  const ipWrites = ipCell.__writes;
  const seenWrites = seenCell.__writes;

  // Next tick: only the "seen" age advanced; nothing else in the table changed.
  clientList[0].last_seen_s = 6;
  await sandbox.renderDevices();
  ok(tbody.children[0] === row0, 'the row element must be REUSED, not recreated');
  eq(tbody.children[0].children[0].__writes, ipWrites,
     'an unchanged cell must not be rewritten (that is what kills the selection)');
  ok(tbody.children[0].children[4].__writes > seenWrites,
     'the cell that changed must be rewritten');
  eq(tbody.children[0].children[4].textContent, sandbox.fmtFixedTime(6), 'the new age is painted');

  // A device leaves: the row set changed, so the body must be rebuilt and the
  // remaining row must be correct (not "patched" into the old shape).
  clientList = [clientList[1]];
  await sandbox.renderDevices();
  eq(tbody.children.length, 1, 'one device row after the removal');
  eq(tbody.children[0].children[1].textContent, 'BB:BB:BB:BB:BB:02', 'the surviving device is shown');

  // Empty list: the placeholder must span the table and carry the empty text.
  clientList = [];
  await sandbox.renderDevices();
  eq(tbody.children.length, 1, 'an empty list still renders one placeholder row');
  eq(tbody.children[0].children[0].getAttribute('colspan'), '6', 'the placeholder spans every column');
  eq(tbody.children[0].children[0].textContent, sandbox.t('dev.empty'), 'the placeholder text');
}]);
// The lease page repaints every 3 s while it is visible, and the cell that
// usually changes is "expires". It uses the same reconciler, but with no
// placeholder text: an empty lease list must leave the body EMPTY, not gain a
// one-cell row that would render as a stray bordered line.
cases.push(['lease tables reconcile and an empty list leaves no stray row', async () => {
  leaseList = [{ mac: 'AA:BB:CC:DD:EE:99', ip: '192.168.1.99', expires_in_s: 60,
                 is_static: false, hostname: 'h' }];
  lease6List = [];
  bind4List = [];
  bind6List = [];
  await sandbox.loadLeases();
  const tbody = nodeFor('#le-table tbody');
  eq(tbody.children.length, 1, 'one lease row');
  const row = tbody.children[0];
  const macWrites = row.children[0].__writes;
  const expWrites = row.children[2].__writes;

  leaseList[0].expires_in_s = 50;   // only the expiry cell changes
  await sandbox.loadLeases();
  ok(tbody.children[0] === row, 'the lease row element must be reused');
  eq(tbody.children[0].children[0].__writes, macWrites, 'the unchanged MAC cell must not be rewritten');
  ok(tbody.children[0].children[2].__writes > expWrites, 'the expiry cell must be rewritten');

  leaseList = [];
  await sandbox.loadLeases();
  eq(tbody.children.length, 0, 'an empty lease list must leave no row at all');
}]);
// batch157: both dashboard tile rows were rebuilt wholesale on every 2 s poll
// (`innerHTML = ...`), 9 tiles plus 7 host tiles. Same two costs as the tables:
// every element recreated each tick, and the operator's selection destroyed -
// on the dashboard the gateway IP is the one value people actually copy.
cases.push(['the dashboard tiles are patched, not rebuilt', async () => {
  statusPayload.gateway = { ip: '192.168.50.1', ipv6: false };
  statusPayload.stats = { rx_frames: 1, tx_frames: 2, tcp_accepted: 3 };
  systemPayload.proc = { cpu_percent: 5, ws_bytes: 2097152, virt_bytes: 3145728, cores: 4 };
  systemPayload.throughput = { up_bps: 0, down_bps: 0 };
  systemPayload.uptime_s = 30;

  const statusCards = nodeFor('#cards');
  const hostCards = nodeFor('#host-cards');
  await sandbox.refreshStatus();
  eq(statusCards.children.length, 9, 'nine status tiles');
  eq(hostCards.children.length, 7, 'seven host tiles');

  const gwCard = statusCards.children[0];
  const gwKey = gwCard.children[0];
  const gwVal = gwCard.children[1];
  const gwValSpan = gwVal.children[0];
  eq(gwValSpan.textContent.trim(), '192.168.50.1', 'the gateway tile shows the address');
  const gwWrites = gwValSpan.__writes;

  // Next tick: a counter moved, nothing else.
  statusPayload.stats.rx_frames = 42;
  systemPayload.proc.cpu_percent = 6;
  await sandbox.refreshStatus();
  ok(statusCards.children[0] === gwCard, 'the tile element must be REUSED');
  eq(statusCards.children[0].children[1].children[0].__writes, gwWrites,
     'an unchanged tile value must not be rewritten (that is what kills the selection)');
  eq(statusCards.children[0].children[1].children[0].textContent.trim(), '192.168.50.1',
     'the address is still correct after the patch');
  // The counters that DID change are updated.
  ok(statusCards.children[2].children[1].children[0].textContent.includes('42'),
     `the RX tile must show the new count, got: ${statusCards.children[2].children[1].children[0].textContent}`);
  ok(hostCards.children[4].children[1].children[0].textContent.includes('6.0%'),
     `the CPU tile must show the new value, got: ${hostCards.children[4].children[1].children[0].textContent}`);

  // A tile that gains/loses the live-traffic cue keeps its element but changes
  // class; when traffic starts, the cue must actually appear.
  systemPayload.throughput = { up_bps: 2048, down_bps: 0 };
  await sandbox.refreshStatus();
  ok(hostCards.children[2].className.includes('spd'), 'the up tile must gain the live cue');
  ok(!hostCards.children[3].className.includes('spd'), 'the idle down tile must not have it');

  // The error branch still replaces the host tiles with a single message.
  const realFetch = sandbox.fetch;
  sandbox.fetch = async (p, o) => {
    if (String(p) === '/api/system') {
      return { ok: false, status: 500, async json() { return {}; }, async text() { return 'x'; } };
    }
    return realFetch(p, o);
  };
  try {
    await sandbox.renderSystem();
  } finally {
    sandbox.fetch = realFetch;
  }
  eq(hostCards.children.length, 1, 'the error state collapses the host tiles to one message');
  eq(hostCards.children[0].children[1].children[0].textContent, sandbox.t('err.network'),
     'the error message is shown');
}]);
// batch158: the settings form has NO client-side validation. A numeric field is
// read with Number(raw), so a typo ("8o" for "80") becomes NaN; JSON.stringify
// turns NaN into null and the WHOLE config is rejected by the server with the
// generic "invalid configuration rejected" - which names no field, so the
// operator has to guess among twenty inputs. Worse, the save looked like it was
// attempted: a request went out and nothing on the form pointed at the culprit.
cases.push(['a non-numeric setting is refused before it is sent', async () => {
  configPayload = SERVER_CONFIG;
  resetSettingsForm();
  await sandbox.loadSettings();
  const postCount = () => requests.filter(
    (r) => r.method === 'POST' && r.path === '/api/config').length;

  nodeFor('#set-workers').__focused = false;
  const before = postCount();
  nodeFor('#set-workers').value = '8o';        // a typo, not a number
  await sandbox.saveSettings();
  eq(postCount(), before,
     'an unparseable number must not be posted (NaN would serialise as null)');
  // The exact English sentence, deliberately NOT built from t(): if the key is
  // missing, t() returns the key itself and a self-referential assertion would
  // stay green while the operator reads "set.badnumWorkers". Read the LAST
  // toast (earlier cases leave their own messages in the queue).
  const box = nodeFor('#toast');
  const lastToast = box.children.length
    ? box.children[box.children.length - 1].textContent : '';
  eq(lastToast, 'not a number: Workers',
     'the message must be translated AND name the offending field');
  ok(nodeFor('#set-workers').__focused === true,
     'the offending field must take focus so the operator sees where to fix it');

  // Overflow is the same corruption with a different spelling: "1e999" parses
  // to Infinity, and JSON.stringify(Infinity) is ALSO null. A check that only
  // rejects NaN would let this one through.
  const beforeOverflow = postCount();
  nodeFor('#set-workers').value = '1e999';
  await sandbox.saveSettings();
  eq(postCount(), beforeOverflow, 'an overflow must not be posted either');

  // The form must stay usable: a valid value saves, and it is posted as a
  // NUMBER (the backend loader is strictly typed).
  nodeFor('#set-workers').value = '8';
  await sandbox.saveSettings();
  eq(postCount(), before + 1, 'a valid draft must still post');
  const posted = requests.filter(
    (r) => r.method === 'POST' && r.path === '/api/config').pop();
  eq(JSON.parse(posted.body).perf.workers, 8, 'the valid value is posted as a number');

  // batch163: clearing a field whose floor is above zero is NOT "unset" - the
  // 0 it would post is rejected by the loader (perf.workers must be in [1, 8]),
  // so it is refused locally like any other bad value. vlan.id is the one field
  // where 0 is a real value (untagged), and it must still save empty.
  nodeFor('#set-workers').value = '';
  await sandbox.saveSettings();
  eq(postCount(), before + 1, 'an empty field with a floor above zero must not post');
  nodeFor('#set-workers').value = '8';   // restore, so only vlan is under test
  nodeFor('#set-vlan').value = '';
  await sandbox.saveSettings();
  eq(postCount(), before + 2, 'vlan.id may be cleared (0 = untagged)');
}]);
// batch163: batch158 refused a field whose text is not a number, but checked
// only FINITENESS - never the RANGE the backend enforces. `workers = 99` is a
// perfectly finite number, so it was posted, the loader rejected the whole
// config, and the operator got the generic "invalid configuration rejected"
// naming none of the twenty inputs. The same held for a web port of 80 (below
// the documented 1024 floor), a VLAN id of 9999, a lease of 99999 hours, a
// prefix length of 128 - all silently turned into "the server refused
// everything", with the caret left nowhere.
//
// Bounds below are the ones src/core/config.cpp actually enforces, so the check
// cannot drift into refusing values the backend accepts.
cases.push(['an out-of-range setting is refused locally and names the field', async () => {
  configPayload = SERVER_CONFIG;
  resetSettingsForm();
  await sandbox.loadSettings();
  const postCount = () => requests.filter(
    (r) => r.method === 'POST' && r.path === '/api/config').length;
  // The toast queue merges an identical consecutive message into "<text> xN"
  // (a real feature: two identical errors must not stack). Strip that counter so
  // the assertion reads the MESSAGE, which is what this case is about.
  const lastToast = () => {
    const box = nodeFor('#toast');
    const raw = box.children.length ? box.children[box.children.length - 1].textContent : '';
    return raw.replace(/ x\d+$/, '');
  };

  // (field id, bad value, expected toast) - each is out of range but finite.
  const cases = [
    ['#set-workers', '99', 'out of range: Workers'],
    ['#set-workers', '0', 'out of range: Workers'],
    ['#set-webport', '80', 'out of range: Web port'],
    ['#set-vlan', '9999', 'out of range: VLAN id'],
    ['#set-dhcp-lease', '99999', 'out of range: Lease (hours)'],
    ['#set-ipv6-prefix', '128', 'out of range: Prefix length'],
    ['#set-ipv6-ra', '0', 'out of range: RA lifetime (s)'],
    ['#set-bridge-macs', '0', 'out of range: MAC table size'],
    ['#set-maxconns', '0', 'out of range: Max connections'],
  ];
  for (const [id, value, expected] of cases) {
    resetSettingsForm();
    // force=true: a plain reload preserves a dirty draft, so the previous
    // iteration's bad value would survive into this one.
    await sandbox.loadSettings(true);
    nodeFor(id).__focused = false;
    const before = postCount();
    nodeFor(id).value = value;
    await sandbox.saveSettings();
    eq(postCount(), before, `${id}="${value}" must not be posted - the loader would reject the whole config`);
    eq(lastToast(), expected, `the message must name ${id} and say it is out of range`);
    ok(nodeFor(id).__focused === true, `${id} must take focus`);
  }

  // The boundary values the backend DOES accept must still save - otherwise the
  // local check is stricter than the server and blocks legal configurations.
  const boundaries = [
    ['#set-workers', '8'], ['#set-webport', '1024'], ['#set-vlan', '4094'],
    ['#set-dhcp-lease', '8760'], ['#set-ipv6-prefix', '64'],
    ['#set-ipv6-ra', '65535'], ['#set-bridge-macs', '65536'],
    ['#set-maxconns', '1048576'],
  ];
  for (const [id, value] of boundaries) {
    resetSettingsForm();
    await sandbox.loadSettings(true);
    const before = postCount();
    nodeFor(id).value = value;
    await sandbox.saveSettings();
    eq(postCount(), before + 1, `${id}="${value}" is legal and must still be posted`);
  }

  // A FRACTION is refused as "not a number": ReadInteger rejects 64.9
  // ("must be a whole number"), so posting it would fail the whole config.
  // Without this case the integer guard could be deleted and every other
  // assertion would still pass.
  resetSettingsForm();
  await sandbox.loadSettings(true);
  const beforeFrac = postCount();
  nodeFor('#set-ipv6-prefix').value = '64.9';
  await sandbox.saveSettings();
  eq(postCount(), beforeFrac, 'a fractional value must not be posted');
  eq(lastToast(), 'not a number: Prefix length',
     'a fraction is refused as "not a number" and names the field');

  // vlan.id = 0 is the documented "untagged" case, not an out-of-range value.
  resetSettingsForm();
  await sandbox.loadSettings(true);
  const beforeZero = postCount();
  nodeFor('#set-vlan').value = '0';
  await sandbox.saveSettings();
  eq(postCount(), beforeZero + 1, 'vlan id 0 means "off" and must remain saveable');
  // "Saveable" has to mean the request the server ACCEPTS, not merely that a
  // request left the page. src/core/config.cpp:800 pins vlan.id to [1, 4094]
  // with kMinVlanId = 1, so an explicit 0 is rejected while an ABSENT id means
  // "VLAN off". The save path deletes it for exactly that reason; if it ever
  // sends the 0 through, the whole configuration is refused and the operator
  // sees a generic failure.
  const zeroBody = JSON.parse(requests.filter(
    (r) => r.method === 'POST' && r.path === '/api/config').pop().body);
  eq(zeroBody.vlan === undefined || zeroBody.vlan.id === undefined, true,
     'vlan id 0 must be sent as an ABSENT id (0 fails kMinVlanId = 1)');
}]);
// batch159: the two CRUD forms had the same unguarded numeric coercion the
// settings form had (batch158), but here it was worse than a bad error message.
//   * rate limit: `+value || 0` turns NaN into 0, and 0 means UNLIMITED. So a
//     typo in "Kbps up" posted a rule whose uplink cap is off, the server
//     accepted it (0 is a legal number), and the console reported success - the
//     cap the operator believes is in force silently is not.
//   * port mapping: NaN serialises to null, the server reads that as "field
//     absent", and answers "ports must be non-zero" - which sends the operator
//     looking for a zero instead of at the field they mistyped.
cases.push(['the CRUD forms refuse an unparseable port or Kbps value', async () => {
  const posts = (path) => requests.filter(
    (r) => r.method === 'POST' && r.path === path).length;

  // --- rate limit: a bad uplink must not become "unlimited" ---
  nodeFor('#page-ratelimit').hidden = false;
  nodeFor('#rl-mac').value = 'AA:BB:CC:DD:EE:77';
  nodeFor('#rl-up').value = '8o';        // typo for 80
  nodeFor('#rl-down').value = '100';
  const rlBefore = posts('/api/ratelimit');
  await sandbox.addRateLimit();
  eq(posts('/api/ratelimit'), rlBefore,
     'a non-numeric Kbps must not be posted (it would become 0 = unlimited)');
  const box = nodeFor('#toast');
  const rlToast = box.children.length ? box.children[box.children.length - 1].textContent : '';
  eq(rlToast, 'not a number: Uplink Kbps',
     'the message must be translated AND name the offending field');

  // A fractional value is not a valid integer either, and must be refused
  // rather than truncated by the server into "field absent".
  nodeFor('#rl-up').value = '80.5';
  await sandbox.addRateLimit();
  eq(posts('/api/ratelimit'), rlBefore, 'a fractional Kbps must not be posted');

  // A legal value still goes through, as an integer.
  nodeFor('#rl-up').value = '80';
  await sandbox.addRateLimit();
  eq(posts('/api/ratelimit'), rlBefore + 1, 'a valid rate limit must still post');
  const rlBody = JSON.parse(requests.filter(
    (r) => r.method === 'POST' && r.path === '/api/ratelimit').pop().body);
  eq(rlBody.uplink_kbps, 80, 'the uplink is posted as a number');

  // --- port mapping: a bad port must be rejected locally ---
  nodeFor('#page-portmap').hidden = false;
  nodeFor('#pm-proto').value = 'tcp';
  nodeFor('#pm-wan').value = '8080';
  nodeFor('#pm-lanip').value = '192.168.0.50';
  nodeFor('#pm-lanport').value = '9o';   // typo for 90
  const pmBefore = posts('/api/portmap');
  await sandbox.addMapping();
  eq(posts('/api/portmap'), pmBefore,
     'a non-numeric port must not be posted');
  const pmToast = box.children.length ? box.children[box.children.length - 1].textContent : '';
  eq(pmToast, 'not a number: LAN port',
     'the message must be translated AND name the offending field');

  // Out of range is still refused, with the range stated.
  nodeFor('#pm-lanport').value = '70000';
  await sandbox.addMapping();
  eq(posts('/api/portmap'), pmBefore, 'an out-of-range port must not be posted');
  const rangeToast = box.children.length ? box.children[box.children.length - 1].textContent : '';
  eq(rangeToast, 'out of range: LAN port',
     'the range message must name the field and the problem');

  // A legal mapping still posts, and the ports are numbers.
  nodeFor('#pm-lanport').value = '90';
  await sandbox.addMapping();
  eq(posts('/api/portmap'), pmBefore + 1, 'a valid mapping must still post');
  const pmBody = JSON.parse(requests.filter(
    (r) => r.method === 'POST' && r.path === '/api/portmap').pop().body);
  eq(pmBody.wan_port, 8080, 'the WAN port is posted as a number');
  eq(pmBody.lan_port, 90, 'the LAN port is posted as a number');
}]);

// batch212: readUintField() maps an EMPTY box to {ok:true, value:0} whenever
// min<=0, and both rate-limit fields pass min=0. Zero is a legal cap in this
// backend but it means UNLIMITED in that direction (batch159's own comment on
// addRateLimit: "0 means UNLIMITED in that direction"). The console then
// reports "Limit applied" while the direction the operator left blank is
// throttled by nothing. Note the two failure shapes differ, so both are driven:
//   * BOTH boxes blank -> the page posts {0,0} -> the server answers 400
//     (web_api.cpp:2284 "at least one direction > 0") -> a baffling error.
//   * ONE box blank    -> the page posts e.g. {100,0} -> the server ACCEPTS it,
//     and that direction silently becomes unlimited.
// The existing case only covered a TYPO, which batch159 fixed. A blank field is
// the same silent zero with a different spelling and was never exercised.
cases.push(['a blank rate-limit Kbps is refused, not silently sent as 0', async () => {
  const rlPosts = () => requests.filter(
    (r) => r.method === 'POST' && r.path === '/api/ratelimit');
  nodeFor('#page-ratelimit').hidden = false;
  nodeFor('#rl-mac').value = 'AA:BB:CC:DD:EE:88';

  // --- ONE box blank: the shape the server would accept ---
  nodeFor('#rl-up').value = '';
  nodeFor('#rl-down').value = '100';
  const before = rlPosts().length;
  await sandbox.addRateLimit();
  eq(rlPosts().length, before,
     'a blank uplink must not be posted as 0 - 0 means UNLIMITED in that direction');
  const box = nodeFor('#toast');
  const lastToast = box.children.length
    ? box.children[box.children.length - 1].textContent : '';
  eq(lastToast, 'not a number: Uplink Kbps',
     'the message must be translated AND name the blank field');

  // The downlink is a separate readUintField call on the same blank branch.
  nodeFor('#rl-up').value = '100';
  nodeFor('#rl-down').value = '';
  await sandbox.addRateLimit();
  eq(rlPosts().length, before, 'a blank downlink must not be posted either');
  const downToast = box.children.length
    ? box.children[box.children.length - 1].textContent : '';
  eq(downToast, 'not a number: Downlink Kbps',
     'the downlink must be named, not the uplink');

  // --- BOTH blank: the shape the server rejects with a message that names
  // neither field, so it must be caught here too (the first read refuses).
  nodeFor('#rl-up').value = '';
  nodeFor('#rl-down').value = '';
  await sandbox.addRateLimit();
  eq(rlPosts().length, before, 'two blank boxes must not reach the server at all');

  // --- An explicit 0 IS how one says "no limit" for a direction, and it must
  // keep working: this is the behaviour the blank branch was written to allow,
  // the mistake was conflating "not filled in" with "deliberately zero".
  nodeFor('#rl-up').value = '0';
  nodeFor('#rl-down').value = '100';
  await sandbox.addRateLimit();
  eq(rlPosts().length, before + 1, 'an explicit 0 must still post');
  const posted = JSON.parse(rlPosts().pop().body);
  eq(posted.uplink_kbps, 0, 'an explicit 0 is posted as the number 0');
  eq(posted.downlink_kbps, 100, 'the filled direction is posted as a number');
}]);

// batch213: the four lease reads use Promise.allSettled so one failing endpoint
// cannot discard the other three answers (batch200). The GOOD half of that is
// covered. The FAILING half was not: value() returns [] for a rejected read,
// and fillRows passes [] straight to paintTable - so a single transient 500
// ERASES that one table's rows while the page keeps polling every 3 s. Before
// batch200 a throw skipped every remaining table, which is what the comment
// describes; the modern failure mode is different and nobody looked at it.
cases.push(['a failed lease read keeps its rows instead of blanking the table', async () => {
  leaseList = [{ mac: 'AA:BB:CC:DD:EE:21', ip: '192.168.9.21', expires_in_s: 60, is_static: false, hostname: 'keepv4' }];
  lease6List = [{ duid: '00:03:00:01:aa:09', iaid: 1, ip: 'fd00::21', expires_in_s: 60, is_static: false, hostname: 'keepv6' }];
  bind4List = [{ mac: 'AA:BB:CC:DD:EE:22', ip: '192.168.9.22', hostname: 'keepb4' }];
  bind6List = [{ duid: '00:03:00:01:aa:0b', iaid: 1, ip: 'fd00::22', hostname: 'keepb6' }];
  await sandbox.loadLeases();
  const t4 = nodeFor('#le-table tbody');
  const t6 = nodeFor('#le-v6 tbody');
  const b4 = nodeFor('#le-bind tbody');
  const b6 = nodeFor('#le-bind6 tbody');
  ok(t4.textContent.includes('192.168.9.21'), 'setup: v4 lease row is painted');
  ok(t6.textContent.includes('fd00::21'), 'setup: v6 lease row is painted');

  // Only the v4 lease endpoint fails. The other three still answer.
  deferredPaths.add('/api/dhcp/leases');
  let done;
  try {
    done = sandbox.loadLeases();
    await flush();
  } finally {
    deferredPaths.delete('/api/dhcp/leases');
    releaseDeferredError('/api/dhcp/leases');
  }
  await done;
  // A transient failure is not evidence that the lease table is empty. Wiping
  // it tells the operator every lease vanished, and the 3 s poll will not put
  // them back until the endpoint recovers - long enough to act on bad data.
  ok(t4.textContent.includes('192.168.9.21'),
     'a failed v4 lease read must keep the last known rows, got: ' + t4.textContent);
  // The three reads that DID answer must still repaint normally - the point of
  // allSettled is that one failure does not block the others.
  ok(t6.textContent.includes('fd00::21'), 'the healthy v6 table keeps rendering');
  ok(b4.textContent.includes('192.168.9.22'), 'the healthy v4 binding table keeps rendering');
  ok(b6.textContent.includes('fd00::22'), 'the healthy v6 binding table keeps rendering');

  // Each of the four tables is its own fillRowsIfKnown call, so each needs its
  // own failure probe: wiring only one of them leaves the other three blanking
  // on a transient error while this case would stay green.
  const failOne = async (path) => {
    deferredPaths.add(path);
    let d;
    try {
      d = sandbox.loadLeases();
      await flush();
    } finally {
      deferredPaths.delete(path);
      releaseDeferredError(path);
    }
    await d;
  };
  await failOne('/api/dhcp6/leases');
  ok(t6.textContent.includes('fd00::21'),
     'a failed v6 lease read must keep the last known rows, got: ' + t6.textContent);
  await failOne('/api/dhcp/bindings');
  ok(b4.textContent.includes('192.168.9.22'),
     'a failed v4 binding read must keep the last known rows, got: ' + b4.textContent);
  await failOne('/api/dhcp6/bindings');
  ok(b6.textContent.includes('fd00::22'),
     'a failed v6 binding read must keep the last known rows, got: ' + b6.textContent);
  // ...and the healthy three must still be repainted by those same loads.
  ok(t4.textContent.includes('192.168.9.21'), 'the healthy v4 lease table still renders');
}]);

// batch214: the dashboard's "Clients" tile reads window.__clientCount, and when
// that cache is empty it fetches /api/clients itself. The catch turned ANY
// failure into clientCount = 0, so the tile confidently reported "0 clients" -
// a server that is restarting, an auth hiccup, a dropped connection - while the
// dashboard re-polls every 2 s. That is the same class as batch213: a failure
// rendered as a concrete value. "I do not know" must not look like "zero".
//
// The distinction that must survive: a well-formed answer that is NOT a list
// really does mean the count is unusable, and batch189 deliberately renders 0
// for it (the server answered; its answer is garbage). Only the rejected call
// is unknown.
cases.push(['a failed client count reads as unknown, not as zero clients', async () => {
  // Make the dashboard ask: no device render has populated the cache.
  vm.runInContext('window.__clientCount = null;', context);
  deferredPaths.add('/api/clients');
  let done;
  try {
    done = sandbox.renderSystem();
    await flush();
  } finally {
    deferredPaths.delete('/api/clients');
    releaseDeferredError('/api/clients');
  }
  await done;
  const cards = nodeFor('#host-cards');
  const text = cards.textContent;
  const clientsLabel = vm.runInContext('t("dash.clients")', context);
  // The tile must still exist (the other six readings are fine), but it must
  // not claim a count it never obtained.
  ok(text.includes(clientsLabel), 'the clients tile is still rendered, got: ' + text);
  ok(!new RegExp(clientsLabel + '\\s*0(?!\\d)').test(text),
     'a failed client read must not be painted as 0 clients, got: ' + text);
  // The unknown marker must be the translated one, not a bare dash or blank.
  ok(text.includes(vm.runInContext('t("dash.unknown")', context)),
     'the tile must say the count is unknown, got: ' + text);

  // Control: a NON-LIST answer is a real answer, and batch189 renders 0 for it.
  // If the fix above accidentally treats that as unknown too, this breaks.
  clientList = { not: 'a list' };
  vm.runInContext('window.__clientCount = null;', context);
  await sandbox.renderSystem();
  const text2 = nodeFor('#host-cards').textContent;
  ok(new RegExp(clientsLabel + '\\s*0(?!\\d)').test(text2),
     'a non-list clients payload is still a real answer and reads as 0, got: ' + text2);
}]);

// batch215: paintTable() decides whether to rebuild by comparing row KEYS and
// the row count - not the cell count. The patch path assumes the existing <tr>
// already has a <td> for every cell and silently skips when it does not
// (`if (td && ...)`). So if one payload for the same key carries fewer or more
// columns than the last, the table keeps the old cell layout and the extra
// values are dropped without a word. A server that gained or lost a column
// (or a list whose rows are ragged) renders a table that does not match its
// data, and every later poll keeps it that way because the keys still match.
cases.push(['a row that changes its cell count is rebuilt, not silently truncated', async () => {
  const tbody = nodeFor('#le-table tbody');
  // First paint: two cells under the key.
  sandbox.fillRows('le-table', [{ mac: 'AA:BB:CC:DD:EE:31', ip: '192.168.7.31' }],
                   (r) => [r.mac, r.ip]);
  eq(tbody.children.length, 1, 'setup: one row is painted');
  eq(tbody.children[0].children.length, 2, 'setup: the row has two cells');
  // Same key, but now three cells. A key-only comparison says "nothing to do",
  // the patch path finds no third <td>, and the third value vanishes.
  sandbox.fillRows('le-table', [{ mac: 'AA:BB:CC:DD:EE:31', ip: '192.168.7.31', hostname: 'grew' }],
                   (r) => [r.mac, r.ip, r.hostname]);
  eq(tbody.children[0].children.length, 3,
     'a row that gained a cell must render it, got cells: ' + tbody.children[0].children.length);
  ok(tbody.children[0].textContent.includes('grew'),
     'the new value must be visible, got: ' + tbody.children[0].textContent);
  // And the other direction: a row that shrinks must not keep a stale cell.
  sandbox.fillRows('le-table', [{ mac: 'AA:BB:CC:DD:EE:31', ip: '192.168.7.31' }],
                   (r) => [r.mac, r.ip]);
  eq(tbody.children[0].children.length, 2,
     'a row that lost a cell must drop it, got cells: ' + tbody.children[0].children.length);
  ok(!tbody.children[0].textContent.includes('grew'),
     'the dropped value must disappear, got: ' + tbody.children[0].textContent);

  // batch215: the column count is remembered between repaints, so a shape
  // change must still be noticed AFTER a normal patch has run. Without this,
  // recording the wrong width once would make every later change invisible.
  sandbox.fillRows('le-table', [{ mac: 'AA:BB:CC:DD:EE:41', ip: '10.0.0.41' }],
                   (r) => [r.mac, r.ip]);
  eq(tbody.children[0].children.length, 2, 'setup: two cells again');
  // A pure content patch: same key, same width, different text.
  sandbox.fillRows('le-table', [{ mac: 'AA:BB:CC:DD:EE:41', ip: '10.0.0.99' }],
                   (r) => [r.mac, r.ip]);
  ok(tbody.children[0].textContent.includes('10.0.0.99'), 'setup: the patch path ran');
  eq(tbody.children[0].children.length, 2, 'setup: still two cells');
  // NOW change the width - the remembered count came from the patch path.
  sandbox.fillRows('le-table', [{ mac: 'AA:BB:CC:DD:EE:41', ip: '10.0.0.99', hostname: 'afterpatch' }],
                   (r) => [r.mac, r.ip, r.hostname]);
  eq(tbody.children[0].children.length, 3,
     'a width change AFTER a patch must still rebuild, got cells: ' + tbody.children[0].children.length);
  ok(tbody.children[0].textContent.includes('afterpatch'),
     'the new value must be visible after a patch, got: ' + tbody.children[0].textContent);

  // A ragged list (rows with different widths) must not be patched into the
  // first row's shape: the extra cells would silently vanish.
  sandbox.fillRows('le-table',
                   [{ mac: 'AA:BB:CC:DD:EE:51', ip: '10.0.0.51' }],
                   (r) => [r.mac, r.ip]);
  sandbox.fillRows('le-table',
                   [{ mac: 'AA:BB:CC:DD:EE:51', ip: '10.0.0.51', hostname: 'wide' },
                    { mac: 'AA:BB:CC:DD:EE:52', ip: '10.0.0.52' }],
                   (r) => (r.hostname ? [r.mac, r.ip, r.hostname] : [r.mac, r.ip]));
  eq(tbody.children.length, 2, 'setup: two rows');
  eq(tbody.children[0].children.length, 3,
     'a ragged first row must keep its three cells, got: ' + tbody.children[0].children.length);
  eq(tbody.children[1].children.length, 2,
     'a ragged second row must keep its two cells, got: ' + tbody.children[1].children.length);

  // The ragged case above is painted onto a DIFFERENT key set, so it rebuilds
  // for that reason alone and never reaches the width comparison. Re-paint the
  // SAME ragged list: the keys match and the first row's width is unchanged,
  // so only the per-row width check can keep the patch path from writing two
  // cells into the three-cell second row and leaving a stale third <td>.
  sandbox.fillRows('le-table',
                   [{ mac: 'AA:BB:CC:DD:EE:51', ip: '10.0.0.51', hostname: 'wide' },
                    { mac: 'AA:BB:CC:DD:EE:52', ip: '10.0.0.52' }],
                   (r) => (r.hostname ? [r.mac, r.ip, r.hostname] : [r.mac, r.ip]));
  eq(tbody.children.length, 2, 'setup: same two rows');
  // Second paint of the SAME ragged list: now the keys and the first row's
  // width both match, so only the per-row width check keeps the patch path
  // from writing two cells into the three-cell row and leaving a stale <td>.
  sandbox.fillRows('le-table',
                   [{ mac: 'AA:BB:CC:DD:EE:51', ip: '10.0.0.51', hostname: 'wide' },
                    { mac: 'AA:BB:CC:DD:EE:52', ip: '10.0.0.52' }],
                   (r) => (r.hostname ? [r.mac, r.ip, r.hostname] : [r.mac, r.ip]));
  eq(tbody.children.length, 2, 'still two rows after the repeat');
  eq(tbody.children[1].children.length, 2,
     'a re-painted ragged second row must not keep a stale cell, got: ' + tbody.children[1].children.length);
  ok(!tbody.children[1].textContent.includes('wide'),
     'the narrow row must not inherit the wide row value, got: ' + tbody.children[1].textContent);

  // The decisive ragged case: the SECOND row gains a cell while the FIRST row
  // keeps its width, so `cols` and every key are unchanged. Only the per-row
  // width check can stop the patch path: without it the new third cell of row 2
  // finds no <td> to write and is dropped, and the table silently shows one
  // column fewer than the data.
  sandbox.fillRows('le-table',
                   [{ mac: 'AA:BB:CC:DD:EE:61', ip: '10.0.1.61', hostname: 'r1' },
                    { mac: 'AA:BB:CC:DD:EE:62', ip: '10.0.1.62' }],
                   (r) => (r.hostname ? [r.mac, r.ip, r.hostname] : [r.mac, r.ip]));
  eq(tbody.children.length, 2, 'setup: two rows, widths 3 and 2');
  eq(tbody.children[1].children.length, 2, 'setup: row 2 has two cells');
  sandbox.fillRows('le-table',
                   [{ mac: 'AA:BB:CC:DD:EE:61', ip: '10.0.1.61', hostname: 'r1' },
                    { mac: 'AA:BB:CC:DD:EE:62', ip: '10.0.1.62', hostname: 'grew2' }],
                   (r) => (r.hostname ? [r.mac, r.ip, r.hostname] : [r.mac, r.ip]));
  eq(tbody.children[1].children.length, 3,
     'a second row that gained a cell must render it, got: ' + tbody.children[1].children.length);
  ok(tbody.children[1].textContent.includes('grew2'),
     'the new second-row value must be visible, got: ' + tbody.children[1].textContent);
}]);

// batch216: filterLangs() emptied #langsel and recreated every <option> on each
// input event - typing "japan" built the list five times, about 2300 elements
// created and thrown away. batch164 already established the rule for the toast
// queue: rebuild only what changed, keep the nodes that stay. The cost here is
// not just CPU: the dropdown's open state, its scroll offset and any keyboard
// focus inside it belong to those nodes, so they are thrown away too.
//
// The check is element IDENTITY: filter twice from a full list narrowing one
// character at a time, and an <option> that survives both filters must be the
// SAME node (its textContent write counter only grows). A rebuild makes a new
// node whose counter restarts at 1.
cases.push(['the language filter reuses the options it keeps', async () => {
  const sel = nodeFor('#langsel');
  const filter = nodeFor('#lang-filter');
  filter.value = '';
  sandbox.filterLangs();
  const full = sel.children.length;
  ok(full > 100, 'setup: the full list is populated, got ' + full);
  // Filter by LANGUAGE CODE. The option labels are endonyms ("日本語"), so an
  // English word like "japan" matches nothing but the pinned current language;
  // the value is what the filter also matches on (index.html filterLangs).
  const target = sel.children.find((o) => o.value === 'ja');
  ok(!!target, 'setup: the Japanese option exists by code');
  const targetText = target.textContent;
  const beforeWrites = target.__writes;
  filter.value = 'j';
  sandbox.filterLangs();
  const kept = sel.children.filter((o) => o.value === 'ja');
  eq(kept.length, 1, 'the pinned/filtered list still holds exactly one Japanese option');
  ok(kept[0] === target,
     'an option that survives the filter must be the SAME element, not a rebuilt one');
  // Reconcile must leave an unchanged label alone: the element survived AND its
  // text was not rewritten (a rebuild would have made a node with __writes = 1).
  eq(kept[0].__writes, beforeWrites,
     'an unchanged label must not be rewritten, got writes: ' + kept[0].__writes);
  eq(kept[0].textContent, targetText, 'the surviving option keeps its label');
  filter.value = '';
  sandbox.filterLangs();
  eq(sel.children.length, full, 'clearing the filter restores the whole list');
  // The options that were REMOVED by the filter are re-created when the filter
  // clears, and each must come back with its own label - a reconcile that only
  // restores the value leaves 460 blank rows in the picker.
  const back = sel.children.filter((o) => o.value === 'ja');
  eq(back.length, 1, 'the Japanese option is back exactly once');
  ok(back[0].textContent.length > 0,
     'a re-created option must carry its label, got: ' + JSON.stringify(back[0].textContent));
  eq(back[0].textContent, targetText, 'the re-created option has the same label as before');
  // Every option must have a non-empty label, not just the one we tracked.
  const blank = Array.from(sel.children).filter((o) => !o.textContent);
  eq(blank.length, 0, 'no option may come back unlabelled, got ' + blank.length);
}]);

// batch217: paintTable() keeps a record of what it last painted, keyed by the
// tbody element. That record can outlive the DOM it describes: the page is a
// single document, but the body can be replaced under the painter (an error
// paint, a language switch that rebuilds, or any other writer). If the record
// were trusted blindly the patcher would write into rows that no longer exist
// and the table would stay half-empty. The comparison must therefore consult
// the DOM's current CHILD COUNT as well as the remembered keys - a stale
// record with a matching key list must still rebuild when the body is empty.
cases.push(['paintTable rebuilds when the remembered record outlives its DOM', async () => {
  const tbody = nodeFor('#le-table tbody');
  sandbox.fillRows('le-table', [{ mac: 'AA:BB:CC:DD:EE:71', ip: '10.9.0.71' }],
                   (r) => [r.mac, r.ip]);
  eq(tbody.children.length, 1, 'setup: one row');
  // Wipe the body WITHOUT telling the painter. This is what an external writer
  // or a replaced element looks like to paintTable.
  tbody.textContent = '';
  eq(tbody.children.length, 0, 'setup: the body is now empty');
  // Same keys as the remembered record. The patch path would index into
  // tbody.children[0] and throw (or, worse, write nothing).
  sandbox.fillRows('le-table', [{ mac: 'AA:BB:CC:DD:EE:71', ip: '10.9.0.71' }],
                   (r) => [r.mac, r.ip]);
  eq(tbody.children.length, 1, 'the row must come back, got ' + tbody.children.length);
  ok(tbody.children[0] && tbody.children[0].textContent.includes('10.9.0.71'),
     'the rebuilt row must carry the data, got: ' + (tbody.children[0] && tbody.children[0].textContent));
  // And the reverse order: a record that says "empty" while the DOM holds rows
  // (another writer added something) must not be treated as nothing to do.
  sandbox.fillRows('le-table', [], (r) => [r.mac]);
  eq(tbody.children.length, 0, 'setup: emptied through the painter');
  const stray = document.createElement('tr');
  stray.appendChild(document.createElement('td'));
  tbody.appendChild(stray);
  sandbox.fillRows('le-table', [], (r) => [r.mac]);
  eq(tbody.children.length, 0, 'a stray row must be cleared by the next paint, got ' + tbody.children.length);
}]);

// batch219: the port-mapping form validates the two PORTS strictly (a typo, a
// fraction and an out-of-range value are all refused locally and named), but
// the LAN address beside them is sent exactly as typed. The backend rejects a
// non-dotted-quad with 400 "invalid ip address" (web_api.cpp:2021-2026), so the
// operator's typo comes back as a generic failure with an English server string
// and no field name - the same class batch159 fixed for the ports, left
// unfinished for the address in the middle of the same form.
cases.push(['an unparseable LAN address is refused and named, like the ports', async () => {
  const posts = () => requests.filter(
    (r) => r.method === 'POST' && r.path === '/api/portmap').length;
  nodeFor('#page-portmap').hidden = false;
  nodeFor('#pm-proto').value = 'tcp';
  nodeFor('#pm-wan').value = '8080';
  nodeFor('#pm-lanport').value = '90';
  const box = nodeFor('#toast');
  const last = () => (box.children.length ? box.children[box.children.length - 1].textContent : '');

  // The stubbed server accepts everything (see the CRUD case), so "was it
  // posted" is the only observation that can distinguish a local refusal from
  // the generic server error.
  const bad = ['', 'not-an-ip', '192.168.0', '192.168.0.999', '192.168.0.1.5', '192.168.0.1a', '-1.2.3.4', '1.2.3.4.5.6'];
  for (const value of bad) {
    const before = posts();
    nodeFor('#pm-lanip').value = value;
    await sandbox.addMapping();
    eq(posts(), before,
       'an unusable LAN address must be refused before the wire, got ' + JSON.stringify(value));
    // A refusal must NAME the field: "add failed" leaves the operator hunting
    // through four inputs.
    const want = vm.runInContext('t("set.badnum") + t("pm.lanip")', context);
    // The toast queue collapses identical messages into one entry whose text
    // gains a " xN" repeat counter, so strip that suffix before comparing:
    // what matters is that the refusal NAMES the field, not how many times the
    // same sentence has been raised.
    const got = last().replace(/ x[0-9]+$/, '');
    eq(got, want,
       'the message must name the LAN address field, got: ' + JSON.stringify(last()) + ' for ' + JSON.stringify(value));
  }

  // Leading zeros are LEGAL to the backend (ParseIpv4, config.cpp:2219-2249;
  // batch140 relies on it), so the front-end must not refuse them - it is a
  // guard, not a second, stricter contract.
  const zeroBefore = posts();
  nodeFor('#pm-lanip').value = '192.168.001.050';
  await sandbox.addMapping();
  eq(posts(), zeroBefore + 1, 'a leading-zero octet is legal and must post');
  const zeroSent = JSON.parse(requests.filter(
    (r) => r.method === 'POST' && r.path === '/api/portmap').pop().body);
  eq(zeroSent.lan_ip, '192.168.001.050', 'the legal spelling is posted as typed (the server canonicalises)');
  // Surrounding whitespace is not part of an address: the box trims it (every
  // other field in this file is read with .trim()), and the trimmed value is
  // what must be posted - an untrimmed one would be refused by the server for
  // a reason the operator cannot see.
  nodeFor('#pm-wan').value = '8080';
  nodeFor('#pm-lanport').value = '90';
  const trimBefore = posts();
  nodeFor('#pm-lanip').value = '  192.168.0.60  ';
  await sandbox.addMapping();
  eq(posts(), trimBefore + 1, 'an address with surrounding spaces must still post');
  const trimSent = JSON.parse(requests.filter(
    (r) => r.method === 'POST' && r.path === '/api/portmap').pop().body);
  eq(trimSent.lan_ip, '192.168.0.60', 'the trimmed address is what goes on the wire, got: ' + trimSent.lan_ip);

  // A successful add CLEARS the form (batch174), so the fields must be filled
  // again before the next attempt - otherwise this control would be refusing
  // an empty WAN port and would prove nothing about the address.
  nodeFor('#pm-wan').value = '8080';
  nodeFor('#pm-lanport').value = '90';

  // A legal address still posts, and it goes out unchanged.
  const okBefore = posts();
  nodeFor('#pm-lanip').value = '192.168.0.50';
  await sandbox.addMapping();
  eq(posts(), okBefore + 1, 'a valid address must still post');
  const sent = requests.filter(
    (r) => r.method === 'POST' && r.path === '/api/portmap').pop();
  eq(JSON.parse(sent.body).lan_ip, '192.168.0.50', 'the address is posted as typed');
}]);

// batch220: the settings form validates every NUMERIC field before sending
// (batch158/163: refuse locally, name the field, put the caret in it), but the
// ADDRESS fields go out exactly as typed. The loader rejects any of them with
// 400 "invalid configuration rejected" (config.cpp:152-155 for
// gateway.ipv4/mask, :261-273 for the dhcp pool) - one generic sentence for a
// form with twenty inputs and no indication which one is wrong. This is the
// same unfinished work batch219 fixed for the port-mapping form; here it costs
// more, because the WHOLE configuration is refused, not one rule.
cases.push(['an unparseable address in the settings form is refused and named', async () => {
  const posts = () => requests.filter(
    (r) => r.method === 'POST' && r.path === '/api/config').length;
  const box = nodeFor('#toast');
  const last = () => (box.children.length
    ? box.children[box.children.length - 1].textContent : '').replace(/ x[0-9]+$/, '');

  const cases = [
    ['set-gw', 'set.gw', ['', 'nope', '192.168.0', '192.168.0.999', '300.1.1.1']],
    ['set-mask', 'set.mask', ['nope', '255.255.255', '255.255.255.256']],
    ['set-dhcp-poolstart', 'set.dhcp.poolstart', ['nope', '192.168.0']],
    ['set-dhcp-poolend', 'set.dhcp.poolend', ['nope', '1.2.3.4.5']],
  ];
  for (const [id, labelKey, bad] of cases) {
    for (const value of bad) {
      resetSettingsForm();
      configPayload = SERVER_CONFIG;
      await sandbox.loadSettings(true);
      const before = posts();
      nodeFor('#' + id).value = value;
      await sandbox.saveSettings();
      eq(posts(), before,
         id + ' = ' + JSON.stringify(value) + ' must be refused before the wire');
      eq(last(), vm.runInContext('t("set.badnum") + t("' + labelKey + '")', context),
         id + ' refusal must name the field, got: ' + JSON.stringify(last()));
    }
  }

  // Control: legal values still save, and each goes out as typed.
  resetSettingsForm();
  configPayload = SERVER_CONFIG;
  await sandbox.loadSettings(true);
  const okBefore = posts();
  nodeFor('#set-gw').value = '192.168.5.1';
  nodeFor('#set-mask').value = '255.255.255.0';
  await sandbox.saveSettings();
  eq(posts(), okBefore + 1, 'legal addresses must still save');
  const sent = JSON.parse(requests.filter(
    (r) => r.method === 'POST' && r.path === '/api/config').pop().body);
  eq(sent.gateway.ipv4, '192.168.5.1', 'the gateway address is posted');
  eq(sent.gateway.mask, '255.255.255.0', 'the netmask is posted');

  // A LEADING-ZERO octet is legal to the loader (ParseIpv4, config.cpp:2219-
  // 2249; batch140 relies on it), so the guard must not be stricter than the
  // contract it defends - the same control batch219 needed.
  resetSettingsForm();
  configPayload = SERVER_CONFIG;
  await sandbox.loadSettings(true);
  const zeroBefore = posts();
  nodeFor('#set-gw').value = '192.168.005.001';
  await sandbox.saveSettings();
  eq(posts(), zeroBefore + 1, 'a leading-zero octet is legal and must save');
}]);

// batch221: batch220 taught the settings form to refuse an address that is not
// a dotted quad, but two rules from the same validator are still unguarded:
//   * gateway.mask must be a CONTIGUOUS run of 1 bits (config.cpp:1099-1112:
//     "(~h & (~h + 1)) is zero exactly when h's leading 1-run has no gap").
//     255.0.255.0 parses as a dotted quad and is still refused by the loader,
//     so a per-octet range check is not enough - the whole configuration is
//     rejected with no field named.
//   * gateway.mac must parse as a MAC (config.cpp:154-155 via JsonToMac ->
//     ParseMac) and must be neither all-zero (:1089-1092) nor multicast
//     (:1093-1097). It is a plain text field today, sent exactly as typed.
cases.push(['the netmask must be a contiguous prefix and the MAC must parse', async () => {
  const posts = () => requests.filter(
    (r) => r.method === 'POST' && r.path === '/api/config').length;
  const box = nodeFor('#toast');
  const last = () => (box.children.length
    ? box.children[box.children.length - 1].textContent : '').replace(/ x[0-9]+$/, '');
  const setup = async () => {
    resetSettingsForm();
    configPayload = SERVER_CONFIG;
    await sandbox.loadSettings(true);
  };

  // --- netmask: legal dotted quads that are NOT a prefix ---
  for (const value of ['255.0.255.0', '255.255.0.255', '0.255.255.255']) {
    await setup();
    const before = posts();
    nodeFor('#set-mask').value = value;
    await sandbox.saveSettings();
    eq(posts(), before, 'netmask ' + JSON.stringify(value) + ' must be refused before the wire');
    eq(last(), vm.runInContext('t("set.badnum") + t("set.mask")', context),
       'the refusal must name the netmask, got: ' + JSON.stringify(last()));
  }

  // --- MAC: unparseable, all-zero, and multicast ---
  const badMacs = ['', 'nope', '02:00:00:00:00', '02:00:00:00:00:01:02',
                   '00:00:00:00:00:00', '01:00:00:00:00:01'];
  for (const value of badMacs) {
    await setup();
    const before = posts();
    nodeFor('#set-mac').value = value;
    await sandbox.saveSettings();
    eq(posts(), before, 'MAC ' + JSON.stringify(value) + ' must be refused before the wire');
    eq(last(), vm.runInContext('t("set.badnum") + t("set.mac")', context),
       'the refusal must name the MAC, got: ' + JSON.stringify(last()));
  }

  // --- controls: legal values must still save ---
  await setup();
  const okBefore = posts();
  nodeFor('#set-mask').value = '255.255.255.0';   // /24
  nodeFor('#set-mac').value = '02:00:00:00:00:01';
  await sandbox.saveSettings();
  eq(posts(), okBefore + 1, 'a /24 mask and a unicast MAC must save');

  // A non-byte-aligned prefix is legal (config.cpp:1104-1106 says /25-/31 pass).
  await setup();
  const slashBefore = posts();
  nodeFor('#set-mask').value = '255.255.255.128';   // /25
  nodeFor('#set-mac').value = '02:00:00:00:00:01';
  await sandbox.saveSettings();
  eq(posts(), slashBefore + 1, 'a /25 mask is a contiguous prefix and must save');

  // MAC spelling: the loader's ParseMac accepts other separators - the guard
  // must mirror it rather than insist on the colon form the UI happens to use.
  await setup();
  const dashBefore = posts();
  nodeFor('#set-mask').value = '255.255.255.0';
  nodeFor('#set-mac').value = '02-00-00-00-00-01';
  await sandbox.saveSettings();
  eq(posts(), dashBefore + 1, 'a dash-separated MAC is legal to ParseMac and must save');
}]);

// batch222: two more text fields the loader refuses outright were still sent
// exactly as typed, so one bad value killed the WHOLE save with no field named:
//   * bridge.upstream / bridge.downstream are capped at limits::kMaxAdapterBytes
//     (256; config.cpp:851-855 / :862-866) and, while bridge.enabled is true,
//     must both be non-empty and must differ (config.cpp:1316-1328).
//   * ipv6.ula_prefix must parse as an IPv6 address, optionally with a "/len"
//     suffix that matches ipv6.prefix_len (config.cpp:496-522), and when
//     ipv6.enabled is true it must additionally be a ULA (fc00::/7) whose host
//     bits past prefix_len are clear (config.cpp:1174-1202).
// The guard must never be STRICTER than the loader: an empty ULA box is legal
// (the key is simply not sent), and a blank bridge name is legal while the
// bridge is off.
cases.push(['bridge ports and the ULA prefix are checked against the loader', async () => {
  const posts = () => requests.filter(
    (r) => r.method === 'POST' && r.path === '/api/config').length;
  const box = nodeFor('#toast');
  const last = () => (box.children.length
    ? box.children[box.children.length - 1].textContent : '').replace(/ x[0-9]+$/, '');
  const setup = async () => {
    resetSettingsForm();
    configPayload = SERVER_CONFIG;
    await sandbox.loadSettings(true);
  };
  const refused = async (mutate, why) => {
    await setup();
    mutate();
    const before = posts();
    await sandbox.saveSettings();
    eq(posts(), before, why + ' must be refused before the wire');
    return last();
  };

  // --- bridge: a blank name while the bridge is ON is refused by the loader ---
  let msg = await refused(() => {
    nodeFor('#set-bridge-enabled').checked = true;
    nodeFor('#set-bridge-up').value = '';
    nodeFor('#set-bridge-down').value = 'Ethernet 2';
  }, 'a blank upstream while the bridge is enabled');
  eq(msg, vm.runInContext('t("set.badnum") + t("set.bridge.up")', context),
     'the refusal must name upstream, got: ' + JSON.stringify(msg));

  msg = await refused(() => {
    nodeFor('#set-bridge-enabled').checked = true;
    nodeFor('#set-bridge-up').value = 'Ethernet 1';
    nodeFor('#set-bridge-down').value = '';
  }, 'a blank downstream while the bridge is enabled');
  eq(msg, vm.runInContext('t("set.badnum") + t("set.bridge.down")', context),
     'the refusal must name downstream, got: ' + JSON.stringify(msg));

  // Same name on both sides: config.cpp:1323-1327 refuses it.
  msg = await refused(() => {
    nodeFor('#set-bridge-enabled').checked = true;
    nodeFor('#set-bridge-up').value = 'Ethernet 1';
    nodeFor('#set-bridge-down').value = 'Ethernet 1';
  }, 'the same adapter on both bridge sides');
  // The two names being equal makes BOTH fields wrong; SET_FIELDS lists
  // upstream first, so that is the one named - the operator still sees a field,
  // and fixing it fixes the pair.
  eq(msg, vm.runInContext('t("set.badnum") + t("set.bridge.up")', context),
     'a shared bridge port must name a bridge field, got: ' + JSON.stringify(msg));

  // Over-long names are refused regardless of the enable flag (parse-time).
  const tooLong = 'X'.repeat(257);
  msg = await refused(() => {
    nodeFor('#set-bridge-enabled').checked = false;
    nodeFor('#set-bridge-up').value = tooLong;
  }, 'a 257-byte upstream with the bridge off');
  eq(msg, vm.runInContext('t("set.badnum") + t("set.bridge.up")', context),
     'an over-long upstream must be named even while the bridge is off, got: ' + JSON.stringify(msg));

  // 256 bytes is exactly the cap and is legal.
  await setup();
  const exactBefore = posts();
  nodeFor('#set-bridge-enabled').checked = false;
  nodeFor('#set-bridge-up').value = 'X'.repeat(256);
  await sandbox.saveSettings();
  eq(posts(), exactBefore + 1, 'a 256-byte upstream is at the cap and must save');

  // The adapter name carries the same parse-time cap (config.cpp:1743-1746), and
  // it is the same field kind as the bridge ports - so it gets the same guard.
  msg = await refused(() => {
    nodeFor('#set-adapter').value = 'X'.repeat(257);
  }, 'a 257-byte adapter name');
  eq(msg, vm.runInContext('t("set.badnum") + t("set.adapter")', context),
     'an over-long adapter must be named, got: ' + JSON.stringify(msg));

  // --- ULA prefix ---
  for (const value of ['not-an-ipv6', 'fdaa:0:0', 'fdaa:0:0::/x', 'fdaa:0:0::/',
                       '1:2:3:4:5:6:7:8::', 'fdaa:0:0:00000::', '1:2:3:4:5:6:7',
                       'fdaa::1::2']) {
    msg = await refused(() => {
      nodeFor('#set-ipv6-enabled').checked = false;
      nodeFor('#set-ipv6-ula').value = value;
    }, 'ULA ' + JSON.stringify(value));
    eq(msg, vm.runInContext('t("set.badnum") + t("set.ipv6.ula")', context),
       'the refusal must name the ULA prefix, got: ' + JSON.stringify(msg));
  }

  // The "/len" suffix must agree with the prefix-length field (config.cpp:515-520).
  msg = await refused(() => {
    nodeFor('#set-ipv6-enabled').checked = false;
    nodeFor('#set-ipv6-ula').value = 'fdaa:0:0::/48';
    nodeFor('#set-ipv6-prefix').value = '64';
  }, 'a /48 ULA suffix against prefix_len 64');
  eq(msg, vm.runInContext('t("set.badnum") + t("set.ipv6.ula")', context),
     'the mismatch must name the ULA prefix, got: ' + JSON.stringify(msg));

  // Enabled + zero prefix: config.cpp:1179-1182 refuses it outright.
  msg = await refused(() => {
    nodeFor('#set-ipv6-enabled').checked = true;
    nodeFor('#set-ipv6-ula').value = '::';
  }, 'an all-zero ULA while ipv6 is enabled');
  eq(msg, vm.runInContext('t("set.badnum") + t("set.ipv6.ula")', context),
     'a missing ULA must be named, got: ' + JSON.stringify(msg));

  // Enabled + a global (non-fc00::/7) address: config.cpp:1184-1188.
  msg = await refused(() => {
    nodeFor('#set-ipv6-enabled').checked = true;
    nodeFor('#set-ipv6-ula').value = '2001:db8::';
    nodeFor('#set-ipv6-prefix').value = '64';
  }, 'a non-ULA prefix while ipv6 is enabled');
  eq(msg, vm.runInContext('t("set.badnum") + t("set.ipv6.ula")', context),
     'a non-ULA prefix must be named, got: ' + JSON.stringify(msg));

  // Enabled + host bits past prefix_len: config.cpp:1192-1202. The fourth group
  // (bits 48-63) is still inside a /64, so the offending bit must sit PAST it.
  msg = await refused(() => {
    nodeFor('#set-ipv6-enabled').checked = true;
    nodeFor('#set-ipv6-ula').value = 'fdaa:0:0:0:1::';
    nodeFor('#set-ipv6-prefix').value = '64';
  }, 'a /64 ULA with host bits set');
  eq(msg, vm.runInContext('t("set.badnum") + t("set.ipv6.ula")', context),
     'host bits past the prefix length must be named, got: ' + JSON.stringify(msg));

  // The same rule with the offending bit on the RIGHT of "::". This is the shape
  // that catches a "::" that is not expanded to the full eight groups: the byte
  // array falls short, the host-bit loop reads past its end and every undefined
  // byte compares as zero, so the address would slip through.
  msg = await refused(() => {
    nodeFor('#set-ipv6-enabled').checked = true;
    nodeFor('#set-ipv6-ula').value = 'fdaa::1';
    nodeFor('#set-ipv6-prefix').value = '64';
  }, 'a /64 ULA whose "::" hides host bits on the right');
  eq(msg, vm.runInContext('t("set.badnum") + t("set.ipv6.ula")', context),
     'host bits past the prefix length must be named, got: ' + JSON.stringify(msg));

  // --- controls that must still save ---
  await setup();
  let before = posts();
  nodeFor('#set-ipv6-enabled').checked = true;
  nodeFor('#set-ipv6-ula').value = 'fdaa:0:0::';
  nodeFor('#set-ipv6-prefix').value = '64';
  nodeFor('#set-bridge-enabled').checked = true;
  nodeFor('#set-bridge-up').value = 'Ethernet 1';
  nodeFor('#set-bridge-down').value = 'Ethernet 2';
  await sandbox.saveSettings();
  eq(posts(), before + 1, 'a legal ULA plus two distinct bridge ports must save');

  // A ULA suffix whose length MATCHES prefix_len is legal (config.cpp:515-521).
  await setup();
  before = posts();
  nodeFor('#set-ipv6-enabled').checked = true;
  nodeFor('#set-ipv6-ula').value = 'fdaa:0:0::/48';
  nodeFor('#set-ipv6-prefix').value = '48';
  await sandbox.saveSettings();
  eq(posts(), before + 1, 'a /48 suffix agreeing with prefix_len 48 must save');

  // /7 is the widest ULA prefix and must pass (the /len bound is [1,64]).
  await setup();
  before = posts();
  nodeFor('#set-ipv6-enabled').checked = true;
  nodeFor('#set-ipv6-ula').value = 'fc00::';
  nodeFor('#set-ipv6-prefix').value = '7';
  await sandbox.saveSettings();
  eq(posts(), before + 1, 'fc00::/7 is the widest ULA and must save');

  // A blank ULA is NOT legal, whatever the enable flag says: setByPath writes
  // the empty string as ipv6.ula_prefix, and the loader runs ParseIpv6Address on
  // any present key - which rejects "" at config.cpp:971-973 ("addr.empty()").
  // The GET never produces a blank (an all-zero prefix formats as
  // 0000:0000:...:0000, config.cpp:2004), so a blank only appears after the
  // operator clears the box, and then the whole save would 400 without naming it.
  msg = await refused(() => {
    nodeFor('#set-ipv6-enabled').checked = false;
    nodeFor('#set-ipv6-ula').value = '';
  }, 'a blank ULA with ipv6 off');
  eq(msg, vm.runInContext('t("set.badnum") + t("set.ipv6.ula")', context),
     'a blank ULA must be named, got: ' + JSON.stringify(msg));

  // Blank bridge names with the bridge OFF are legal too.
  await setup();
  before = posts();
  nodeFor('#set-bridge-enabled').checked = false;
  nodeFor('#set-bridge-up').value = '';
  nodeFor('#set-bridge-down').value = '';
  await sandbox.saveSettings();
  eq(posts(), before + 1, 'blank bridge names with the bridge off must save');
}]);

// batch223: two free-text fields that the loader refuses outright were still
// sent exactly as typed, and a refusal there kills the WHOLE save with no field
// named:
//   * dhcp.dns is a comma-separated list of IPv4 resolvers. Every entry must
//     parse (config.cpp:326-335) and be neither unspecified (0.0.0.0, :336-338),
//     loopback 127/8 (:350-353), multicast/broadcast >=224 (:354-358), the
//     gateway itself (:359-363), nor the LAN's network/broadcast address
//     (:364-378). At most kMaxDhcpDns = 4 entries (limits.h:25, :322-325).
//   * ipv6.dhcpv6.pool_start / pool_end are FULL IPv6 addresses with no "/len"
//     suffix (config.cpp:596-616). While DHCPv6 runs they must be both set or
//     both zero (:1219-1225), ordered (:1241-1245) and inside the ULA prefix
//     (:1246-1250).
// The guard must never be STRICTER than the loader: a blank DNS list is legal
// (the key is simply written as []), and blank pool bounds are the documented
// "derive the default range" spelling.
cases.push(['DHCP DNS entries and DHCPv6 pool bounds are checked against the loader', async () => {
  const posts = () => requests.filter(
    (r) => r.method === 'POST' && r.path === '/api/config').length;
  const box = nodeFor('#toast');
  const last = () => (box.children.length
    ? box.children[box.children.length - 1].textContent : '').replace(/ x[0-9]+$/, '');
  const setup = async () => {
    resetSettingsForm();
    configPayload = SERVER_CONFIG;
    await sandbox.loadSettings(true);
  };
  const refused = async (mutate, why) => {
    await setup();
    mutate();
    const before = posts();
    await sandbox.saveSettings();
    eq(posts(), before, why + ' must be refused before the wire');
    return last();
  };

  // --- dhcp.dns ---
  const dnsBlame = vm.runInContext('t("set.badnum") + t("set.dhcp.dns")', context);
  let msg = await refused(() => {
    nodeFor('#set-dhcp-dns').value = 'not-an-ip,1.1.1.1';
  }, 'a DNS list with an unparseable entry');
  eq(msg, dnsBlame, 'the refusal must name the DNS list, got: ' + JSON.stringify(msg));

  for (const bad of ['0.0.0.0', '127.0.0.1', '224.0.0.1', '255.255.255.255',
                     '192.168.0.1', '192.168.0.255', '192.168.0.0']) {
    msg = await refused(() => {
      nodeFor('#set-dhcp-dns').value = bad;
    }, 'DNS ' + JSON.stringify(bad));
    eq(msg, dnsBlame, 'DNS ' + JSON.stringify(bad) + ' must be refused and named, got: ' + JSON.stringify(msg));
  }

  // At most four resolvers (limits.h:25).
  msg = await refused(() => {
    nodeFor('#set-dhcp-dns').value = '1.1.1.1,8.8.8.8,9.9.9.9,1.0.0.1,8.8.4.4';
  }, 'five DNS entries');
  eq(msg, dnsBlame, 'too many resolvers must be refused and named, got: ' + JSON.stringify(msg));

  // The unspecified address is refused on its own (config.cpp:336-338), NOT via
  // the subnet-edge test - and on a /31 or /32 that test is deliberately exempt
  // (host_bits <= 1), so this is the only rule standing between 0.0.0.0 and the
  // wire. Without a narrow mask here the two rules are indistinguishable.
  msg = await refused(() => {
    nodeFor('#set-mask').value = '255.255.255.254';   // /31
    nodeFor('#set-dhcp-dns').value = '0.0.0.0';
  }, '0.0.0.0 as a resolver on a /31');
  eq(msg, dnsBlame, '0.0.0.0 must be refused and named, got: ' + JSON.stringify(msg));

  // Exactly four is the cap and is legal; a subnet host is fine.
  await setup();
  let before = posts();
  nodeFor('#set-dhcp-dns').value = '1.1.1.1, 8.8.8.8, 9.9.9.9, 1.0.0.1';
  await sandbox.saveSettings();
  eq(posts(), before + 1, 'four distinct public resolvers must save');

  // A blank list is legal (an empty array is the server's "use the host's").
  await setup();
  before = posts();
  nodeFor('#set-dhcp-dns').value = '';
  await sandbox.saveSettings();
  eq(posts(), before + 1, 'a blank DNS list must save');

  // --- ipv6.dhcpv6 pool bounds ---
  const poolBlame = vm.runInContext('t("set.badnum") + t("set.dhcpv6.poolstart")', context);
  for (const bad of ['not-an-ipv6', 'fdaa::/64', 'fdaa:0:0:::1', '1:2:3:4:5:6:7']) {
    msg = await refused(() => {
      nodeFor('#set-ipv6-enabled').checked = true;
      nodeFor('#set-ipv6-ula').value = 'fdaa:0:0::';
      nodeFor('#set-ipv6-prefix').value = '64';
      nodeFor('#set-dhcp6-enabled').checked = true;
      nodeFor('#set-dhcp6-poolstart').value = bad;
      nodeFor('#set-dhcp6-poolend').value = 'fdaa:0:0::1fff';
    }, 'DHCPv6 pool start ' + JSON.stringify(bad));
    eq(msg, poolBlame, 'pool start ' + JSON.stringify(bad) + ' must be refused and named, got: ' + JSON.stringify(msg));
  }

  // A "/len" suffix is explicitly refused (config.cpp:606-613).
  msg = await refused(() => {
    nodeFor('#set-ipv6-enabled').checked = true;
    nodeFor('#set-ipv6-ula').value = 'fdaa:0:0::';
    nodeFor('#set-ipv6-prefix').value = '64';
    nodeFor('#set-dhcp6-enabled').checked = true;
    nodeFor('#set-dhcp6-poolstart').value = 'fdaa:0:0::1000/64';
    nodeFor('#set-dhcp6-poolend').value = 'fdaa:0:0::1fff';
  }, 'a pool bound with a prefix suffix');
  eq(msg, poolBlame, 'a pool bound with "/len" must be named, got: ' + JSON.stringify(msg));

  // Only one bound set is refused (config.cpp:1219-1225).
  msg = await refused(() => {
    nodeFor('#set-ipv6-enabled').checked = true;
    nodeFor('#set-ipv6-ula').value = 'fdaa:0:0::';
    nodeFor('#set-ipv6-prefix').value = '64';
    nodeFor('#set-dhcp6-enabled').checked = true;
    nodeFor('#set-dhcp6-poolstart').value = 'fdaa:0:0::1000';
    nodeFor('#set-dhcp6-poolend').value = '';
  }, 'a pool with only one bound set');
  eq(msg, vm.runInContext('t("set.badnum") + t("set.dhcpv6.poolend")', context),
     'the half-set pool must name the missing bound, got: ' + JSON.stringify(msg));

  // The mirror image: an empty START with a set END must blame the start box.
  // Without this direction a "start-missing" that wrongly points at pool_end
  // looks identical, because that is the answer this direction already gives.
  msg = await refused(() => {
    nodeFor('#set-ipv6-enabled').checked = true;
    nodeFor('#set-ipv6-ula').value = 'fdaa:0:0::';
    nodeFor('#set-ipv6-prefix').value = '64';
    nodeFor('#set-dhcp6-enabled').checked = true;
    nodeFor('#set-dhcp6-poolstart').value = '';
    nodeFor('#set-dhcp6-poolend').value = 'fdaa:0:0::1fff';
  }, 'a pool whose start bound is the empty half');
  eq(msg, vm.runInContext('t("set.badnum") + t("set.dhcpv6.poolstart")', context),
     'an empty pool start must name the start box, got: ' + JSON.stringify(msg));

  // Out of order (config.cpp:1241-1245).
  msg = await refused(() => {
    nodeFor('#set-ipv6-enabled').checked = true;
    nodeFor('#set-ipv6-ula').value = 'fdaa:0:0::';
    nodeFor('#set-ipv6-prefix').value = '64';
    nodeFor('#set-dhcp6-enabled').checked = true;
    nodeFor('#set-dhcp6-poolstart').value = 'fdaa:0:0::1fff';
    nodeFor('#set-dhcp6-poolend').value = 'fdaa:0:0::1000';
  }, 'a reversed DHCPv6 pool');
  eq(msg, vm.runInContext('t("set.badnum") + t("set.dhcpv6.poolend")', context),
     'a reversed pool must name the end bound, got: ' + JSON.stringify(msg));

  // Outside the advertised ULA prefix (config.cpp:1246-1250).
  msg = await refused(() => {
    nodeFor('#set-ipv6-enabled').checked = true;
    nodeFor('#set-ipv6-ula').value = 'fdaa:0:0::';
    nodeFor('#set-ipv6-prefix').value = '64';
    nodeFor('#set-dhcp6-enabled').checked = true;
    nodeFor('#set-dhcp6-poolstart').value = 'fdaa:0:1::1000';
    nodeFor('#set-dhcp6-poolend').value = 'fdaa:0:1::1fff';
  }, 'a pool outside the ULA prefix');
  eq(msg, poolBlame, 'a pool outside the prefix must be named, got: ' + JSON.stringify(msg));

  // Only the END outside the prefix: the start box is correct, so blaming it
  // would send the operator to the wrong control. A single "outside" verdict
  // cannot tell these apart, which is exactly why this direction exists.
  msg = await refused(() => {
    nodeFor('#set-ipv6-enabled').checked = true;
    nodeFor('#set-ipv6-ula').value = 'fdaa:0:0::';
    nodeFor('#set-ipv6-prefix').value = '64';
    nodeFor('#set-dhcp6-enabled').checked = true;
    nodeFor('#set-dhcp6-poolstart').value = 'fdaa:0:0::1000';
    nodeFor('#set-dhcp6-poolend').value = 'fdaa:0:1::1fff';
  }, 'a pool whose END alone is outside the ULA prefix');
  eq(msg, vm.runInContext('t("set.badnum") + t("set.dhcpv6.poolend")', context),
     'an out-of-prefix end bound must name the end box, got: ' + JSON.stringify(msg));

  // --- controls that must still save ---
  await setup();
  before = posts();
  nodeFor('#set-ipv6-enabled').checked = true;
  nodeFor('#set-ipv6-ula').value = 'fdaa:0:0::';
  nodeFor('#set-ipv6-prefix').value = '64';
  nodeFor('#set-dhcp6-enabled').checked = true;
  nodeFor('#set-dhcp6-poolstart').value = 'fdaa:0:0::1000';
  nodeFor('#set-dhcp6-poolend').value = 'fdaa:0:0::1fff';
  await sandbox.saveSettings();
  eq(posts(), before + 1, 'a pool inside the ULA prefix must save');

  // Both bounds blank is the documented default range (config.cpp:1207-1208).
  await setup();
  before = posts();
  nodeFor('#set-ipv6-enabled').checked = true;
  nodeFor('#set-ipv6-ula').value = 'fdaa:0:0::';
  nodeFor('#set-ipv6-prefix').value = '64';
  nodeFor('#set-dhcp6-enabled').checked = true;
  nodeFor('#set-dhcp6-poolstart').value = '';
  nodeFor('#set-dhcp6-poolend').value = '';
  await sandbox.saveSettings();
  eq(posts(), before + 1, 'both pool bounds blank is the default range and must save');

  // DHCPv6 off: bounds are parsed but the ordering/prefix rules do not run
  // (config.cpp:1209 gates them on the service actually running). A reversed
  // pool that the loader would accept must NOT be refused here - the guard may
  // never be stricter than the contract it is guarding.
  await setup();
  before = posts();
  nodeFor('#set-dhcp6-enabled').checked = false;
  nodeFor('#set-dhcp6-poolstart').value = 'fdaa:0:0::1fff';
  nodeFor('#set-dhcp6-poolend').value = 'fdaa:0:0::1000';
  await sandbox.saveSettings();
  eq(posts(), before + 1,
     'a reversed pool with DHCPv6 off is accepted by the loader and must save');
}]);

// `currentLang` is a top-level `let` inside the script, so it lives in the
// vm's lexical scope and is NOT a property of the sandbox object: assigning
// sandbox.currentLang silently does nothing (which would make every
// translation assertion below a no-op that always passes). Change it from
// inside the context instead.
function setScriptLang(lang) {
  vm.runInContext(`currentLang = ${JSON.stringify(lang)};`, context);
}

// batch211: detectLang() decides which language the operator wakes up to, and
// its steps are order-sensitive - the page's own comments spell out the exact
// obligations ("zh-tw must land on zh-TW, never on the zh-CN prefix
// fallback", "Traditional-script variants (hk/mo/hant) must land on zh-TW").
// None of that was executed before: every other case SETS the language rather
// than detecting it, so reordering the steps left the whole suite green.
cases.push(['detectLang honours every documented fallback in order', async () => {
  // Drive it directly with a stubbed navigator and storage.
  const detectCases = [
    // [navigator.language, saved language, expected, why]
    ['en-US', null, 'en', 'an English locale stays English'],
    ['zh-TW', null, 'zh-TW', 'an exact match wins over every prefix rule'],
    ['zh-HK', null, 'zh-TW', 'Hong Kong is Traditional script - never zh-CN'],
    ['zh-MO', null, 'zh-TW', 'Macau is Traditional script - never zh-CN'],
    ['zh-Hant', null, 'zh-TW', 'an explicit Traditional tag is never zh-CN'],
    ['zh-CN', null, 'zh-CN', 'Simplified stays Simplified'],
    ['pt-BR', null, 'pt', 'a regional variant falls back to its base language'],
    ['ja-JP', null, 'ja', 'a base match wins over the prefix sweep'],
  ['xx-YY', null, 'en', 'an unknown locale falls back to en'],
  // batch211: a browser that reports NO language is not an unknown language -
  // it must still default to en, not to whatever the last fallback happens to be.
  [undefined, null, 'en', 'a missing navigator.language defaults to en'],
  ['', null, 'en', 'an empty navigator.language defaults to en'],
    ['ja-JP', 'de', 'de', 'a SAVED choice overrides the browser locale'],
    ['ja-JP', 'not-a-language', 'ja', 'a saved value that is not a language is ignored'],
  ];
  const realNav211 = sandbox.navigator;
  try {
    for (const [nav, saved, want, why] of detectCases) {
      sandbox.navigator = { language: nav };
      if (saved === null) localStorage.removeItem('vgww_lang');
      else localStorage.setItem('vgww_lang', saved);
      const got = sandbox.detectLang();
      eq(got, want, `detectLang(${nav}, saved=${JSON.stringify(saved)}) must be ${want} - ${why}, got ${got}`);
      // The answer must be a REAL language block, not a prefix that happens to
      // look right: t() would fall back to en for an unknown code.
      const known = vm.runInContext(`Object.prototype.hasOwnProperty.call(I18N, ${JSON.stringify(got)})`, context);
      eq(known, true, `detectLang returned ${got}, which is not a language block in I18N`);
    }
  } finally {
    sandbox.navigator = realNav211;
    localStorage.removeItem('vgww_lang');
  }
}]);

// batch160: the accessible name of every control is now translated at runtime
// (`data-i18n-aria` -> aria-label). That path is only real if applyI18n sets
// it, and it must be re-applied when the language changes - a name left in the
// previous language is worse than no name for someone using a screen reader in
// their own language. The markup side (every control HAS such an attribute) is
// covered by the web_a11y gate; this case covers the runtime half on a
// representative subset.
const ariaNamed = {
  '#dev-scope': 'a11y.devscope',
  '#dev-sort': 'a11y.devsort',
  '#dev-dir': 'a11y.devdir',
  '#tk': 'a11y.token',
  '#pm-lanph': 'pm.lanph',
};
registerList('[data-i18n-aria]', Object.keys(ariaNamed).map((s) => s.slice(1)));
for (const [sel, key] of Object.entries(ariaNamed)) {
  nodeFor(sel).setAttribute('data-i18n-aria', key);
}

cases.push(['control names follow the language switch', async () => {
  try {
    setScriptLang('en');
    sandbox.applyI18n(false);
    eq(nodeFor('#dev-scope').getAttribute('aria-label'), 'Filter devices by side',
       'the device filter is named in English');
    eq(nodeFor('#tk').getAttribute('aria-label'), 'Auth token field',
       'the token field is named in English');
    // The three device controls must NOT share a name - that was the bug this
    // whole batch exists for.
    const names = ['#dev-scope', '#dev-sort', '#dev-dir']
      .map((s) => nodeFor(s).getAttribute('aria-label'));
    ok(new Set(names).size === 3,
       `the three device controls need three different names, got: ${names.join(' | ')}`);

    setScriptLang('zh-CN');
    sandbox.applyI18n(false);
    eq(nodeFor('#dev-scope').getAttribute('aria-label'), '按侧筛选设备',
       'the name is translated, not left in the previous language');
    eq(nodeFor('#pm-lanph').getAttribute('aria-label'), 'LAN 端口',
       'a name that reuses an existing label key still resolves');
  } finally {
    setScriptLang('en');
    sandbox.applyI18n(false);
  }
}]);
// batch161: every row's action button used to have the SAME name ("Delete",
// "Edit", "Unblock" x N). A screen reader then lists N identical buttons and
// the operator cannot tell which entry will be removed. The name must carry the
// row's own data, and it must be rebuilt (not cached) when the language changes
// or the data changes.
cases.push(['row action buttons name the row they act on', async () => {
  try {
    setScriptLang('en');
    sandbox.applyI18n(false);
    ratelimitRules = [
      { mac: 'AA:BB:CC:DD:EE:11', uplink_kbps: 100, downlink_kbps: 200 },
      { mac: 'AA:BB:CC:DD:EE:22', uplink_kbps: 300, downlink_kbps: 400 },
    ];
    await sandbox.loadRateLimits();
    const labels = labelsIn(nodeFor('#rl-table tbody'));
    eq(labels.length, 4, 'two rules x (edit + remove) must each carry a name');
    ok(labels.includes('Edit AA:BB:CC:DD:EE:11'),
       `the edit button must name its MAC, got: ${labels.join(' | ')}`);
    ok(labels.includes('Remove AA:BB:CC:DD:EE:22'),
       `the remove button must name its MAC, got: ${labels.join(' | ')}`);
    ok(!labels.includes('Edit') && !labels.includes('Remove'),
       `no button may fall back to the bare verb, got: ${labels.join(' | ')}`);

    // Language switch: the same rows, re-rendered, must speak Chinese.
    setScriptLang('zh-CN');
    await sandbox.loadRateLimits();
    const zh = labelsIn(nodeFor('#rl-table tbody'));
    ok(zh.some((s) => s.includes('AA:BB:CC:DD:EE:11')),
       `the Chinese name must still identify the row, got: ${zh.join(' | ')}`);
    ok(!zh.some((s) => s.startsWith('Edit') || s.startsWith('Remove')),
       `the verb must be translated too, got: ${zh.join(' | ')}`);
  } finally {
    setScriptLang('en');
    sandbox.applyI18n(false);
  }
}]);
// batch162: a table's <caption> is its accessible name, and it is translated
// through the ordinary data-i18n path like any other visible string. The four
// lease tables sit on ONE page - if their names did not differ, a screen reader
// would announce four identical names and the operator could never tell the v4
// leases from the static IPv6 bindings.
//
// The keys are read FROM THE MARKUP, not listed here: an earlier version of
// this case hard-coded four distinct keys and then asserted they were distinct,
// which is a tautology - mutating the page so that two tables shared one key
// still passed. Whatever the page declares is what must come out translated and
// pairwise different.
cases.push(['table captions are translated and pairwise distinct', async () => {
  const capKeys = [];
  for (const m of html.matchAll(/<caption\b([^>]*)>/gi)) {
    const key = (m[1].match(/\bdata-i18n\s*=\s*"([^"]+)"/i) || [])[1];
    if (key) capKeys.push(key);
  }
  ok(capKeys.length >= 4,
     `expected at least the four lease-table captions in the markup, found ${capKeys.length}`);
  ok(new Set(capKeys).size === capKeys.length,
     `the markup gives two tables the same caption key: ${capKeys.join(', ')}`);

  // Drive the real translate path over one element per key.
  const ids = capKeys.map((_, i) => `cap-test-${i}`);
  registerList('[data-i18n]', ids);
  ids.forEach((id, i) => nodeFor(`#${id}`).setAttribute('data-i18n', capKeys[i]));
  const read = () => ids.map((id) => nodeFor(`#${id}`).textContent);
  try {
    setScriptLang('en');
    sandbox.applyI18n(false);
    const en = read();
    ok(en.every((s) => s && s !== capKeys[ids.indexOf(s)]),
       `every caption must resolve to text, got: ${en.join(' | ')}`);
    ok(new Set(en).size === en.length,
       `the rendered captions must all differ, got: ${en.join(' | ')}`);

    setScriptLang('zh-CN');
    sandbox.applyI18n(false);
    const zh = read();
    ok(zh.every((s, i) => s !== en[i]),
       `the captions must be translated, got: ${zh.join(' | ')}`);
    ok(new Set(zh).size === zh.length,
       `the translated captions must still all differ, got: ${zh.join(' | ')}`);
  } finally {
    setScriptLang('en');
    sandbox.applyI18n(false);
  }
}]);
// ------------------------------------------------------------- table spans
// batch149: an "empty" / "error" row has to span the whole table. The devices
// error row used to hardcode 5 while the table has 6 columns, so it stopped
// short of the right edge - a small but visible glitch that no static gate
// could see. The span is now derived from the table's own <thead>, which is
// also the only way this can stay correct when a column is added.
registerList('#dev-table thead th', ['ip', 'mac', 'up', 'down', 'seen', 'lan']);
registerList('#pm-table thead th', ['proto', 'wan', 'lan', 'del']);
registerList('#ban-table thead th', ['kind', 'value', 'unblock']);
registerList('#rl-table thead th', ['mac', 'up', 'down', 'remove']);
registerList('#le-v6 thead th', ['duid', 'ip6', 'expires', 'host']);

// batch165: focus must survive the repaint that follows a delete.
// The three mutable tables are repainted after every CRUD action. The focused
// control lives INSIDE a row, so a repaint that recreates the rows destroys it
// and the browser drops focus to <body> - a keyboard user is thrown back to the
// top of the document after each delete and has to tab in again from scratch.
// Deleting is the worst case: the row holding the focus disappears, so the
// caret must be placed somewhere deliberate (the next row's button, or the
// table's add button when the list empties).
cases.push(['deleting a row keeps the keyboard focus in the table', async () => {
  const rowCount = () => nodeFor('#rl-table tbody').children.length;
  // Buttons live in the row's last cell; between them the renderer inserts a
  // text node (the visual separator, as the old markup had). Read by tag, not
  // by child index - the index would land on the separator.
  const buttonIn = (row, idx) => row.querySelectorAll('button')[idx];

  ratelimitRules = [
    { mac: 'AA:BB:CC:DD:EE:11', uplink_kbps: 100, downlink_kbps: 200 },
    { mac: 'AA:BB:CC:DD:EE:22', uplink_kbps: 300, downlink_kbps: 400 },
    { mac: 'AA:BB:CC:DD:EE:33', uplink_kbps: 500, downlink_kbps: 600 },
  ];
  await sandbox.loadRateLimits();
  eq(rowCount(), 3, 'three rows are painted');

  // The operator tabs to the [remove] button of the SECOND row and activates it.
  const secondRow = nodeFor('#rl-table tbody').children[1];
  const removeBtn = buttonIn(secondRow, 1);
  removeBtn.focus();
  ok(sandbox.document.activeElement === removeBtn,
     'the harness must model document.activeElement (focus has to be observable)');

  ratelimitRules.splice(1, 1);   // the server drops it
  await sandbox.delRateLimit('AA:BB:CC:DD:EE:22');
  await flush();                 // the loader repaints asynchronously
  eq(rowCount(), 2, 'the row is gone');

  const active = sandbox.document.activeElement;
  ok(active !== sandbox.document.body,
     'focus must not fall back to <body> when the focused row is deleted');
  ok(active && active !== removeBtn,
     'the destroyed button cannot stay focused - focus has to move to a live control');
  const remaining = nodeFor('#rl-table tbody').children;
  const ownsActive = (row) => {
    let found = false;
    const walk = (n) => { if (n === active) found = true; for (const c of n.children) walk(c); };
    walk(row);
    return found;
  };
  ok(remaining.some(ownsActive),
     'focus must land on a control of the row that took the deleted row\'s place');
  // Concretely: the row that followed the deleted one is now at index 1, and it
  // is the SAME control kind the operator was on (the [remove] button).
  const nowSecond = remaining[1];
  ok(ownsActive(nowSecond), 'focus goes to the row that moved into the deleted row\'s place');
  const nowRemove = buttonIn(nowSecond, 1);
  ok(active === nowRemove,
     `focus lands on the SAME kind of control (the remove button), got: `
     + `${active && active.getAttribute && active.getAttribute('aria-label')}`);
  eq(nowRemove.getAttribute('aria-label'), 'Remove AA:BB:CC:DD:EE:33',
     'the recovered focus is on the next row, not a stale name');

  // Emptying the table must move focus to the page's own action button - the
  // table body now holds a placeholder row, which has nothing focusable.
  // Drive it the way it happens: focus the last row's [remove], delete it, and
  // the list is empty.
  const lastRow = nodeFor('#rl-table tbody').children[1];
  const lastRemove = buttonIn(lastRow, 1);
  lastRemove.focus();
  ratelimitRules = [];
  await sandbox.delRateLimit('AA:BB:CC:DD:EE:33');
  await flush();
  eq(rowCount(), 1, 'an empty list paints its placeholder row');
  ok(!nodeFor('#rl-table tbody').querySelectorAll('button').length,
     'the placeholder row carries no button');
  eq(sandbox.document.activeElement, nodeFor('#rl-add'),
     'focus falls back to the page add button when the last row is deleted');
}]);
// batch169: the language picker is a filter box plus a list. Typing filters the
// list; picking a language then re-renders the whole page. The filter TEXT was
// never cleared, so after switching language the box still showed e.g. "japan"
// while the list below held the single pinned entry - the two controls
// disagreed, and the obvious next move (clear the box to get the full list
// back) required the operator to notice a filter they had already used.
cases.push(['the language filter is reset when a language is chosen', async () => {
  const filter = nodeFor('#lang-filter');
  const sel = nodeFor('#langsel');
  filter.value = 'japan';
  sandbox.filterLangs();
  const filtered = sel.children.length;
  ok(filtered < 461, `the filter must actually narrow the list, got ${filtered}`);

  // Choosing a language runs the change handler, which applies the language.
  const realFetch = sandbox.fetch;
  sandbox.fetch = async () => ({ ok: true, status: 200, async json() { return {}; }, async text() { return '{}'; } });
  try {
    await sel.__on['change'][0]({ target: { value: 'ja' } });
    // applyI18n() starts a page load WITHOUT awaiting it. That background chain
    // calls renderDevices/renderSystem, and any of them that is still in flight
    // when this case ends would take a render ticket during the NEXT case and
    // make its direct renderX() call a no-op. Let the chain land here, while the
    // stubbed fetch is still installed.
    await flush();
    await flush();
    await flush();
    await flush();
  } finally {
    sandbox.fetch = realFetch;
  }
  eq(filter.value, '', 'the filter box must be cleared once a language is chosen');
  // The change handler also persists the language to /api/config; that path is
  // stubbed above, so nothing here depends on the network.
  eq(sel.children.length, 461, 'the full language list must be back after switching');
  // Leave the page exactly as this case found it. NO applyI18n() here: even with
  // reload=false it walks the whole page, and the language switch above already
  // bumped the render tickets - the next case drives renderDevices() directly
  // and would silently become a no-op. Only the two things this case changed
  // are restored: the filter text, and the current language.
  filter.value = '';
  sandbox.filterLangs();
  filter.blur();
  setScriptLang('en');
  await flush();
}]);
// batch164: #toast is a live region (role="status" aria-live="polite"), and it
// used to be painted by clearing every child and rebuilding the whole queue on
// each change. Two consequences that no test could see before:
//   * a screen reader re-announces the ENTIRE queue whenever one message
//     arrives or expires (three toasts -> six announcements);
//   * every rebuild replays the `toast-in` entry animation on messages that
//     were already on screen, and destroys any text the operator selected.
// The queue must therefore be reconciled by identity, like the tables and the
// cards are: a change rewrites only the node it belongs to.
cases.push(['a new toast reuses the messages already on screen', async () => {
  const box = nodeFor('#toast');
  const tag = 'b164-' + Date.now();
  sandbox.toast(tag + '-A', 'info');
  const aEl = box.children[box.children.length - 1];
  eq(aEl.textContent, tag + '-A', 'the first message is painted');

  const writesBefore = box.__writes;
  // Per-node write counter: an unchanged message must not be rewritten at all.
  // Rewriting text that reads the same still counts as a mutation in a live
  // region, so the guard has to be "did the text change", not "render ran".
  const aWritesBefore = aEl.__writes;
  sandbox.toast(tag + '-B', 'error');
  eq(box.__writes, writesBefore,
     'adding a toast must not clear the live region (that re-announces the whole queue)');
  eq(aEl.__writes, aWritesBefore,
     'a message whose text did not change must not be rewritten');
  ok(box.children[box.children.length - 2] === aEl,
     'the message already on screen must keep its node');
  const bEl = box.children[box.children.length - 1];
  eq(bEl.textContent, tag + '-B', 'the new message is appended');

  // A merged duplicate ("<text> xN") must rewrite that one node, not replace
  // it - replacing re-announces and re-animates it.
  sandbox.toast(tag + '-B', 'error');
  ok(box.children[box.children.length - 1] === bEl,
     'a merged duplicate must keep its node');
  eq(bEl.textContent, tag + '-B x2', 'the merge counter goes into that node');

  // Eviction (the queue holds TOAST_MAX) must drop only the evicted node.
  sandbox.toast(tag + '-C', 'info');
  sandbox.toast(tag + '-D', 'info');
  const texts = box.children.map((c) => c.textContent);
  eq(texts.length, 3, 'the queue never holds more than three entries');
  ok(!texts.some((x) => x.indexOf(tag + '-A') === 0), 'the oldest entry is the one evicted');
  ok(box.children.indexOf(bEl) >= 0, 'the surviving entries are the same nodes');
}]);
// batch180: a toast that is still on screen must follow a language switch.
// toast() stores the ALREADY-TRANSLATED string (`t("pm.added")` and friends),
// so a message painted before the switch keeps the old language for its whole
// 2.6 s life while every other string on the page changes around it. The case
// is worst exactly when it matters: an error toast is often on screen at the
// moment the operator gives up and switches language.
//
// The queue must therefore remember the KEY it was built from and re-render
// through t() on a language change. A message with no key (a raw server string
// or a concatenation that cannot be re-derived) keeps its text - re-deriving
// that is impossible, and silently dropping it would lose the operator's only
// notification.
cases.push(['a toast still on screen follows a language switch', async () => {
  const box = nodeFor('#toast');
  setScriptLang('en');
  sandbox.applyI18n(false);
  // Use a real key the page ships, so the assertion reads the shipped text.
  vm.runInContext('toastT("pm.added", "success");', context);
  const el = box.children[box.children.length - 1];
  const enText = el.textContent;
  ok(enText && enText.length > 0, 'the toast is painted');

  setScriptLang('zh-CN');
  sandbox.applyI18n(false);
  const zhText = el.textContent;
  ok(zhText !== enText,
     'a toast on screen must be re-translated, not left in the old language');
  eq(zhText, vm.runInContext('t("pm.added")', context),
     'the toast must read exactly like the shipped string in the new language');
  ok(box.children[box.children.length - 1] === el,
     're-translation must reuse the node (a live region must not re-announce the queue)');

  setScriptLang('en');
  sandbox.applyI18n(false);
  eq(el.textContent, enText, 'switching back restores the original text');

  // A message built at runtime carries text, not a key, so re-translating it is
  // impossible. What matters is that it is not LOST: the entry survives the
  // switch and still shows the text it was raised with. (Whether the text also
  // happens to be substitutable by t() is moot - a real server string is never a
  // key, and a mutation that routes it through t() is indistinguishable here.)
  vm.runInContext('toast("disk full at /var", "error");', context);
  const rawEl = box.children[box.children.length - 1];
  eq(rawEl.textContent, 'disk full at /var', 'the runtime message is painted verbatim');
  setScriptLang('zh-CN');
  sandbox.applyI18n(false);
  ok(rawEl.textContent && rawEl.textContent.length > 0,
     'a message with no key must not vanish across a language switch');
  eq(rawEl.textContent, 'disk full at /var',
     'a message with no key keeps the text it was raised with');
  setScriptLang('en');
  sandbox.applyI18n(false);

  // Merge must be decided by KEY, not by the rendered text: the same key raised
  // before and after a switch is the same message and has to accumulate, while
  // two different keys must never merge even when their current text collides.
  // Start from an empty queue: the entries raised above are this case's own
  // props and would otherwise be counted as extra "Rule added" entries.
  vm.runInContext('toasts.length = 0; renderToasts();', context);
  for (const l of ['en', 'zh-CN', 'en']) {
    setScriptLang(l);
    sandbox.applyI18n(false);
    vm.runInContext('toastT("pm.added", "success");', context);
  }
  const texts = box.children.map((c) => c.textContent);
  const added = texts.filter((x) => x.startsWith(vm.runInContext('t("pm.added")', context)));
  ok(added.length === 1 && added[0].endsWith(' x3'),
     'one key raised three times must merge into "<text> x3" even across language switches');
  vm.runInContext('toastT("fw.blocked", "success");', context);
  const afterDifferent = box.children.map((c) => c.textContent);
  ok(afterDifferent.some((x) => x.startsWith(vm.runInContext('t("fw.blocked")', context))),
     'a different key must stay a separate entry');
  ok(afterDifferent.some((x) => x.startsWith(vm.runInContext('t("pm.added")', context))),
     'the x3 entry must survive a later different key (merge only touches the tail)');

  // Leave the queue as this case found it for the cases that follow.
  vm.runInContext('toasts.length = 0; renderToasts();', context);
  eq(box.children.length, 0, 'the queue is left empty again');
}]);

// batch191: saving an UNRELATED setting must not resurrect an omitted DHCP pool.
// GET /api/config omits `dhcp.pool` entirely while either bound is 0
// (web_api.cpp:1818-1824). loadSettings fills the two inputs with "" - and
// saveSettings writes EVERY SET_FIELDS path back through setByPath, so those
// two empty strings became pool:["",""] . The loader accepts a present
// `pool` only as exactly [start,end] with two parseable addresses
// (config.cpp:256-275), so it answered 400 "dhcp.pool malformed ipv4 entry"
// and the WHOLE save failed - on a form the operator never touched, and with
// no field named. The fix is in setByPath's caller: an empty pool bound means
// "this pool is not configured", so the key must not be created at all.
cases.push(['an omitted DHCP pool is not resurrected as two empty strings', async () => {
  vm.runInContext('renderTicket.clear();', context);
  // DHCP disabled and no pool: the GET leaves the key out, exactly like the
  // real server does for an all-zero pool.
  configPayload = {
    adapter: 'eth0',
    gateway: { ipv4: '192.168.0.1', mask: '255.255.255.0', mac: '02:00:00:00:00:01' },
    perf: { workers: 8, max_conns: 4096 },
    vlan: {},
    mode: 'main',
    web: { port: 8080 },
    bridge: { mac_table_size: 4096 },
    dhcp: { enabled: false, lease_hours: 24, dns: [] },
    // batch222: the real GET always emits these (web_api.cpp:1859-1869), so a
    // fixture without them leaves the ULA box blank - which the loader refuses.
    ipv6: {
      enabled: false, ula_prefix: '::', prefix_len: 64, ra_lifetime_s: 1800,
      dhcpv6: { lease_seconds: 3600 },
    },
  };
  resetSettingsForm();
  await sandbox.loadSettings(true);
  eq(nodeFor('#set-dhcp-poolstart').value, '', 'an unset pool start loads as empty text');
  eq(nodeFor('#set-dhcp-poolend').value, '', 'an unset pool end loads as empty text');

  // The operator changes ONLY the worker count and saves.
  nodeFor('#set-workers').value = '4';
  configPostReply = { ok: true };
  applyStatusReply = { attempt_id: 0, completed_id: 0, ok: true, error: '' };
  applyStatusPolls = 0;
  const before = requests.length;
  await sandbox.saveSettings();
  const posts = requests.slice(before).filter(r => r.method === 'POST' && r.path === '/api/config');
  eq(posts.length, 1, 'the save must post exactly once');

  const sent = JSON.parse(posts[0].body);
  eq(sent.perf.workers, 4, 'the edit the operator made must land');
  ok(!('pool' in (sent.dhcp || {})),
     'an unset pool must stay OMITTED, not become ["",""]: ' + JSON.stringify(sent.dhcp));

  // And the three other sections the GET omits when unset must not come back
  // as empty values either.
  ok(sent.dhcp.pool_start === undefined && sent.dhcp.pool_end === undefined,
     'the compat spelling must not appear either: ' + JSON.stringify(sent.dhcp));

  configPayload = null;
  vm.runInContext('renderTicket.clear();', context);
}]);

// batch191 (second half): a CONFIGURED pool that the operator clears must
// remove the key, not send ["",""] . The loader parses both bounds
// (config.cpp:256-275 through JsonToIpv4, whose ParseIpv4 rejects an empty
// part), so two empty strings are 400 "dhcp.pool malformed ipv4 entry" and
// the whole save dies - the pool cannot be cleared at all. Omitting the key
// is the server's own "not configured" spelling (web_api.cpp:1818-1824 only
// emits it when both bounds are non-zero).
// batch192: the token box said "Token saved" without ever asking the server.
// setToken() wrote localStorage and reported success in the same breath, but
// the ONLY thing that decides whether a token is accepted is the write guard
// on the server (web_api.cpp:1587-1612: no credential configured -> 403,
// wrong or empty -> 401). So a typo, or clearing the box, produced a green
// "Token saved" and then every subsequent request quietly failed with 401 -
// the operator's next discovery was an empty page, with nothing pointing at
// the token they had just changed.
// batch193: the device sort comparator subtracted raw fields.
// `a.up_bps - b.up_bps` yields NaN as soon as either side is missing or is not
// a number, and a comparator that returns NaN breaks its contract (it must
// answer negative / zero / positive). The engine is then free to leave the
// list in ANY order. batch188 added asNumber() for exactly this class - the
// formatters got it, the comparator did not.
// batch193 (the contract itself): a comparator must answer negative, zero or
// positive. NaN is none of those, and an engine handed NaN may leave the list
// in ANY order - which is why the rendered-order assertions above can pass
// while the comparator is still broken (V8 tidies up after a single NaN).
// This case asks the comparator directly, over malformed and mixed-type data,
// so the defect cannot hide behind the engine's tolerance.
// batch194: eight of the nine dashboard tiles run their counter through fmt(),
// which picks a unit (K/M/G) for large values. tcp_accepted was the one that
// printed the raw number, so a listener that has accepted 1,234,567
// connections painted "1234567" next to neighbours reading "1.2 M". The
// counter grows for the life of the process, so every long-running instance
// reaches a value where the mismatch is visible.
// batch195: copyConsole() called navigator.clipboard.writeText() and only
// handled the PROMISE - `.then(ok, fail)`. The call itself can throw
// synchronously: WebView2 and several browsers reject the call when the
// document is not focused, and a restricted context or an extension shim can
// throw outright. A synchronous throw skipped both callbacks and escaped the
// click handler, so the operator pressed Copy and NOTHING happened - no
// confirmation, no error, and no way to tell whether the text was copied.
// batch196: setToken() wrote the candidate to localStorage OUTSIDE its own
// try block. The page is opened in the system browser (ShellExecuteW "open",
// about.cpp:134), where localStorage.setItem CAN throw: private mode, a
// storage policy, or a full quota all raise instead of returning false. The
// throw escaped the click handler, so pressing Save token did nothing at all -
// no confirmation, no error, and the credential was not stored either. The
// restore path had the same hole: if the first write succeeded but the second
// (rollback) threw, the failure that mattered was hidden.
// batch197: applyAutostart() reported success whenever the request returned.
// The endpoint answers with the state the registry ACTUALLY holds
// (web_api.cpp:1679-1682 -> main.cpp:924-925 ignores SetAutostart's result and
// re-reads IsAutostartEnabled()), so `enabled` in the body can differ from what
// the operator asked for: a policy-blocked or permission-denied registry write
// leaves the old value in place. The page already wrote that value back into
// the checkbox, but then said "saved" anyway - it painted the truth and
// contradicted it in the next breath.
// batch198: two protections had NO regression coverage at all - `noDup` (the
// user-requested double-submit guard, batch39) and `repairDriver` (a
// privileged action that raises a UAC prompt). Both rot silently: dropping
// the busy flag changes nothing visible until an operator double-clicks and
// the action runs twice.
cases.push(['a double submit is dropped while the first is in flight', async () => {
  vm.runInContext('toasts.length = 0; renderToasts();', context);
  const btn = nodeFor('#pm-add');
  btn.dataset.busy = '0';
  btn.disabled = false;

  let calls = 0;
  let release = null;
  const origFetch = sandbox.fetch;
  sandbox.fetch = async (path, opt) => {
    if (String(path) === '/api/portmap' && (opt && opt.method) === 'POST') {
      calls++;
      // Only the FIRST request is held open. If a broken guard lets a second
      // one through, it must resolve immediately - otherwise the case would
      // HANG, and a hang is silently reported as success by the runner.
      if (calls === 1) await new Promise((res) => { release = res; });
      return { ok: true, status: 200, async json() { return { ok: true }; }, async text() { return '{}'; } };
    }
    return { ok: true, status: 200, async json() { return {}; }, async text() { return '{}'; } };
  };

  nodeFor('#pm-wan').value = '8080';
  nodeFor('#pm-lanip').value = '192.168.0.10';
  nodeFor('#pm-lanport').value = '80';

  try {
    const first = sandbox.addMapping();
    eq(btn.dataset.busy, '1', 'the in-flight marker must be set');
    // Re-fill the form: a successful add clears it, and an empty field would
    // make the second call bail out in validation before the busy check runs.
    nodeFor('#pm-wan').value = '8080';
    nodeFor('#pm-lanip').value = '192.168.0.10';
    nodeFor('#pm-lanport').value = '80';
    await sandbox.addMapping();
    eq(calls, 1, 'the second click must not reach the server');
    if (release) release();
    await first;
  } finally {
    sandbox.fetch = origFetch;
  }

  eq(calls, 1, 'exactly one request in total');
  eq(btn.dataset.busy, '0', 'the in-flight marker must be cleared');

  // saveSettings is the consumer with NO inner button handling, so there the
  // wrapper's own disabled=true is the only thing protecting the button. The
  // call is driven with an immediate resolution: the point here is the guard's
  // state transitions, not the request pipeline (covered elsewhere).
  const saveBtn = nodeFor('#set-save');
  saveBtn.dataset.busy = '0';
  saveBtn.disabled = false;
  let saveCalls = 0;
  const saveFetch = sandbox.fetch;
  sandbox.fetch = async (path, opt) => {
    if (String(path) === '/api/config' && (opt && opt.method) === 'POST') saveCalls++;
    if (String(path) === '/api/config') {
      return { ok: true, status: 200, async json() { return JSON.parse(JSON.stringify(SERVER_CONFIG)); }, async text() { return '{}'; } };
    }
    return { ok: true, status: 200, async json() { return {}; }, async text() { return '{}'; } };
  };
  configPayload = JSON.parse(JSON.stringify(SERVER_CONFIG));
  const saving = sandbox.saveSettings();
  eq(saveBtn.disabled, true, 'Save must be disabled while a save is in flight');
  eq(saveBtn.dataset.busy, '1', 'Save must carry the in-flight marker');
  // A re-entry while busy must be dropped WITHOUT starting a second POST.
  await sandbox.saveSettings();
  ok(saveCalls <= 1, 'a second Save while one is in flight must not post again, got ' + saveCalls);
  await saving;
  sandbox.fetch = saveFetch;
  eq(saveBtn.disabled, false, 'Save must be usable again afterwards');
  eq(saveBtn.dataset.busy, '0', 'Save must drop the in-flight marker');

  vm.runInContext('toasts.length = 0; renderToasts();', context);
}]);

// repairDriver raises a UAC prompt. It must ask first, send exactly one
// privileged request, and not claim the driver was REPAIRED - the endpoint
// answers `requested`, not `repaired` (web_api.cpp:1646).
cases.push(['the driver repair asks first and reports only that it was requested', async () => {
  vm.runInContext('toasts.length = 0; renderToasts();', context);
  let calls = 0;
  const origFetch = sandbox.fetch;
  const realConfirm = sandbox.confirm;
  const stubFetch = async (path) => {
    if (String(path) === '/api/repair-driver') calls++;
    return { ok: true, status: 200, async json() { return { requested: true }; }, async text() { return '{"requested":true}'; } };
  };

  sandbox.confirm = () => false;
  sandbox.fetch = stubFetch;
  try { await sandbox.repairDriver(); } finally { sandbox.confirm = realConfirm; sandbox.fetch = origFetch; }
  eq(calls, 0, 'a cancelled confirmation must not raise the UAC prompt');

  sandbox.confirm = () => true;
  sandbox.fetch = stubFetch;
  try { await sandbox.repairDriver(); } finally { sandbox.confirm = realConfirm; sandbox.fetch = origFetch; }
  eq(calls, 1, 'a confirmed repair sends exactly one request');

  const texts = nodeFor('#toast').children.map(c => c.textContent);
  const requested = vm.runInContext('t("st.repair.ok")', context);
  const done = vm.runInContext('t("st.ok")', context);
  ok(texts.some(x => x.indexOf(requested) === 0),
     'the message must say the repair was REQUESTED, got: ' + JSON.stringify(texts));
  ok(!texts.some(x => x.indexOf(done) === 0),
     'a queued repair must not be announced as a completed action, got: ' + JSON.stringify(texts));

  vm.runInContext('toasts.length = 0; renderToasts();', context);
}]);

cases.push(['a refused autostart change is not reported as success', async () => {
  vm.runInContext('toasts.length = 0; renderToasts();', context);
  const cb = nodeFor('#maint-autostart');
  cb.checked = true;   // the operator just switched it on

  const origFetch = sandbox.fetch;
  sandbox.fetch = async (path, opt) => {
    if (String(path) === '/api/autostart') {
      // The server could not write the Run key and reports the real state.
      return { ok: true, status: 200, async json() { return { enabled: false }; }, async text() { return '{"enabled":false}'; } };
    }
    return { ok: true, status: 200, async json() { return {}; }, async text() { return '{}'; } };
  };
  try {
    await sandbox.applyAutostart(true);
  } finally {
    sandbox.fetch = origFetch;
  }

  eq(cb.checked, false,
     'the checkbox must show what the registry actually holds');
  const texts = nodeFor('#toast').children.map(c => c.textContent);
  const okText = vm.runInContext('t("st.ok")', context);
  ok(!texts.some(x => x.indexOf(okText) === 0),
     'a change the server did NOT apply must not be announced as success, got: ' + JSON.stringify(texts));
  ok(texts.length > 0,
     'the operator must be told the change did not take effect, got none');

  vm.runInContext('toasts.length = 0; renderToasts();', context);
}]);

// The other half: when the server confirms the requested value, the page must
// still say so - and a cancelled confirmation must not call the server at all.
cases.push(['a confirmed autostart change is reported, a cancelled one is not sent', async () => {
  vm.runInContext('toasts.length = 0; renderToasts();', context);
  const cb = nodeFor('#maint-autostart');
  cb.checked = true;
  let calls = 0;
  const origFetch = sandbox.fetch;
  sandbox.fetch = async (path) => {
    if (String(path) === '/api/autostart') {
      calls++;
      return { ok: true, status: 200, async json() { return { enabled: true }; }, async text() { return '{"enabled":true}'; } };
    }
    return { ok: true, status: 200, async json() { return {}; }, async text() { return '{}'; } };
  };
  try {
    await sandbox.applyAutostart(true);
  } finally { sandbox.fetch = origFetch; }
  eq(calls, 1, 'a confirmed change still reaches the server once');
  let texts = nodeFor('#toast').children.map(c => c.textContent);
  ok(texts.some(x => x.indexOf(vm.runInContext('t("st.ok")', context)) === 0),
     'a confirmed change must be announced, got: ' + JSON.stringify(texts));

  // Cancelled confirmation: the box must go back and NO request may be sent.
  vm.runInContext('toasts.length = 0; renderToasts();', context);
  const realConfirm = sandbox.confirm;
  sandbox.confirm = () => false;
  cb.checked = true;
  calls = 0;
  try {
    await sandbox.applyAutostart(true);
  } finally {
    sandbox.confirm = realConfirm;
  }
  eq(calls, 0, 'a cancelled confirmation must not reach the server');
  eq(cb.checked, false, 'a cancelled confirmation must restore the old state');

  vm.runInContext('toasts.length = 0; renderToasts();', context);
}]);

cases.push(['saving a token survives a storage layer that throws', async () => {
  vm.runInContext('toasts.length = 0; renderToasts();', context);
  vm.runInContext('warned401 = false;', context);
  localStorage.removeItem('vgww_token');

  const origFetch = sandbox.fetch;
  sandbox.fetch = async () => ({ ok: true, status: 200, async json() { return { ok: true }; }, async text() { return '{}'; } });

  // A storage that refuses every write, like a browser in private mode.
  const realStorage = sandbox.localStorage;
  const throwing = {
    getItem(k) { return realStorage.getItem(k); },
    setItem() { throw new Error('QuotaExceededError'); },
    removeItem(k) { realStorage.removeItem(k); },
  };
  sandbox.localStorage = throwing;

  let escaped = null;
  nodeFor('#tk').value = 'some-token';
  try {
    await sandbox.setToken();
  } catch (e) {
    escaped = e;
  } finally {
    sandbox.localStorage = realStorage;
    sandbox.fetch = origFetch;
  }

  eq(escaped, null,
     'a storage layer that throws must not escape the click handler: ' + (escaped && escaped.message));
  const texts = nodeFor('#toast').children.map(c => c.textContent);
  ok(texts.length > 0,
     'the operator must be told something when the token could not be stored, got none');
  ok(!texts.some(x => x.indexOf(vm.runInContext('t("auth.saved")', context)) === 0),
     'a token that could not be stored must not be announced as saved, got: ' + JSON.stringify(texts));

  vm.runInContext('toasts.length = 0; renderToasts();', context);
  localStorage.removeItem('vgww_token');
  vm.runInContext('warned401 = false;', context);
}]);

cases.push(['Copy reports a failure even when writing throws synchronously', async () => {
  vm.runInContext('toasts.length = 0; renderToasts();', context);
  const out = nodeFor('#cl-out');
  out.textContent = 'line one\nline two';

  const realNav = sandbox.navigator;
  sandbox.navigator = {
    clipboard: {
      writeText() { throw new Error('document is not focused'); },
    },
  };
  let escaped = null;
  try {
    sandbox.copyConsole();
  } catch (e) {
    escaped = e;
  } finally {
    sandbox.navigator = realNav;
  }
  eq(escaped, null, 'a clipboard that throws must not escape the click handler: ' + (escaped && escaped.message));

  const texts = nodeFor('#toast').children.map(c => c.textContent);
  const fail = vm.runInContext('t("cl.copyfail")', context);
  ok(texts.some(x => x.indexOf(fail) === 0),
     'the operator must be told the copy failed, got: ' + JSON.stringify(texts));
  vm.runInContext('toasts.length = 0; renderToasts();', context);
}]);

// The other half: a rejected PROMISE already worked and must keep working,
// and a successful write must still confirm.
cases.push(['Copy confirms on success and reports a rejected promise', async () => {
  const out = nodeFor('#cl-out');
  out.textContent = 'x';
  const realNav = sandbox.navigator;

  // Rejected promise.
  vm.runInContext('toasts.length = 0; renderToasts();', context);
  sandbox.navigator = { clipboard: { writeText: () => Promise.reject(new Error('denied')) } };
  try { sandbox.copyConsole(); await flush(); } finally { sandbox.navigator = realNav; }
  let texts = nodeFor('#toast').children.map(c => c.textContent);
  ok(texts.some(x => x.indexOf(vm.runInContext('t("cl.copyfail")', context)) === 0),
     'a rejected write must report failure, got: ' + JSON.stringify(texts));

  // Successful write.
  vm.runInContext('toasts.length = 0; renderToasts();', context);
  sandbox.navigator = { clipboard: { writeText: () => Promise.resolve() } };
  try { sandbox.copyConsole(); await flush(); } finally { sandbox.navigator = realNav; }
  texts = nodeFor('#toast').children.map(c => c.textContent);
  ok(texts.some(x => x.indexOf(vm.runInContext('t("cl.copied")', context)) === 0),
     'a successful write must confirm, got: ' + JSON.stringify(texts));

  // A clipboard shim that returns a non-promise must still produce an
  // outcome: calling .then on it would throw, and a silent return would leave
  // the operator guessing. A TRUTHY non-thenable is the case that separates a
  // `typeof pending.then` guard from a bare truth test - `undefined` alone
  // would make both behave the same.
  vm.runInContext('toasts.length = 0; renderToasts();', context);
  sandbox.navigator = { language: 'en', clipboard: { writeText: () => ({}) } };
  let escaped = null;
  try { sandbox.copyConsole(); } catch (e) { escaped = e; }
  sandbox.navigator = realNav;
  eq(escaped, null, 'a non-promise clipboard must not throw: ' + (escaped && escaped.message));
  texts = nodeFor('#toast').children.map(c => c.textContent);
  ok(texts.some(x => x.indexOf(vm.runInContext('t("cl.copied")', context)) === 0),
     'a synchronous clipboard reports success once the text is handed over, got: ' + JSON.stringify(texts));

  // No clipboard API at all.
  vm.runInContext('toasts.length = 0; renderToasts();', context);
  sandbox.navigator = { language: 'en' };
  try { sandbox.copyConsole(); } finally { sandbox.navigator = realNav; }
  texts = nodeFor('#toast').children.map(c => c.textContent);
  ok(texts.some(x => x.indexOf(vm.runInContext('t("cl.copyfail")', context)) === 0),
     'a browser without the clipboard API must report failure, got: ' + JSON.stringify(texts));

  vm.runInContext('toasts.length = 0; renderToasts();', context);
}]);

cases.push(['every dashboard counter uses the same number formatting', async () => {
  vm.runInContext('renderTicket.clear();', context);
  statusPayload = {
    gateway: { ip: '192.168.0.1', ipv6: '' },
    stats: {
      rx_frames: 1234567, tx_frames: 1234567, tcp_accepted: 1234567,
      rx_dropped: 1234567, host_passthrough: 1234567,
      rx_vlan_frames: 1234567, tx_vlan_frames: 1234567,
    },
    bridge: {},
  };
  await sandbox.refreshStatus();

  const cards = nodeFor('#cards');
  // The card value is the element whose text the number lands in; find each
  // tile by its label so the assertion names the tile it is about.
  // paintCards builds: div.card > (div.k label, div.v > (span value, small hint))
  const valueFor = (labelKey) => {
    const label = vm.runInContext('t(' + JSON.stringify(labelKey) + ')', context);
    for (const card of cards.children) {
      if (card.children.length === 2 && card.children[0].textContent === label) {
        const v = card.children[1];
        return v.children.length ? v.children[0].textContent : null;
      }
    }
    return undefined;
  };

  // paintCards writes the number (and, when the tile has a hint, one separator
  // space) into the value span, with the hint text in a sibling <small>.
  const number = vm.runInContext('String(fmt(1234567))', context);
  ok(number.indexOf('M') >= 0, 'the fixture must be large enough to carry a unit, got: ' + number);
  const withHint = number + ' ';

  // Only dash.tcp carries a hint; every other counter is bare.
  const hinted = { 'dash.tcp': true, 'dash.drops': true, 'dash.pass': true, 'dash.vrx': true, 'dash.vtx': true };
  for (const key of ['dash.rx', 'dash.tx', 'dash.tcp', 'dash.drops', 'dash.pass', 'dash.vrx', 'dash.vtx']) {
    const shown = valueFor(key);
    eq(shown, hinted[key] ? withHint : number,
       key + ' must use the shared counter formatting; every tile shows the same counter here, so they must agree on the number');
  }

  statusPayload = {
    gateway: { ip: '192.168.0.1', ipv6: '' },
    stats: { rx_frames: 0, tx_frames: 0, tcp_accepted: 0 },
    bridge: {},
  };
  vm.runInContext('renderTicket.clear(); window.__clientCount = null; window.__clientList = null;', context);
}]);

cases.push(['the device comparator never answers NaN', async () => {
  const pairs = [
    [{}, {}],
    [{ up_bps: 100 }, {}],
    [{ up_bps: {} }, { up_bps: 200 }],
    [{ up_bps: '20' }, { up_bps: '100' }],
    [{ down_bps: true }, { down_bps: [] }],
    [{ last_seen_s: 'x' }, {}],
  ];
  const kinds = ['up', 'down', 'seen', 'rate'];
  for (const key of kinds) {
    for (const [a, b] of pairs) {
      const r = sandbox.deviceCompare(key, a, b);
      ok(typeof r === 'number' && !Number.isNaN(r),
         'deviceCompare(' + key + ') must answer a number, got: ' + String(r) +
         ' for ' + JSON.stringify([a, b]));
    }
  }
  // And it must still order real data correctly in both directions.
  ok(sandbox.deviceCompare('up', { up_bps: 1 }, { up_bps: 2 }) < 0,
     'a smaller upload must compare negative');
  ok(sandbox.deviceCompare('seen', { last_seen_s: 5 }, { last_seen_s: 1 }) < 0,
     'the LONGER-silent client must compare first (age is negated)');
  ok(sandbox.deviceCompare('rate', { up_bps: 1, down_bps: 1 }, { up_bps: 1, down_bps: 1 }) === 0,
     'equal rates must compare zero');
}]);

cases.push(['the device sort compares numbers even when a field is missing', async () => {
  vm.runInContext('renderTicket.clear();', context);
  // Two clients with comparable traffic, plus one whose counter is absent:
  // a response with a missing field must not corrupt the whole ordering.
  clientList = [
    { ip: '10.0.0.1', mac: 'AA:AA:AA:AA:AA:01', up_bps: 100, down_bps: 0, last_seen_s: 1, lan: true },
    { ip: '10.0.0.2', mac: 'AA:AA:AA:AA:AA:02', up_bps: 300, down_bps: 0, last_seen_s: 2, lan: true },
    { ip: '10.0.0.3', mac: 'AA:AA:AA:AA:AA:03', down_bps: 0, last_seen_s: 3, lan: true },
  ];
  nodeFor('#dev-sort').value = 'up';
  nodeFor('#dev-dir').value = 'asc';
  await sandbox.renderDevices();
  // The stub's single-node querySelector returns a fresh element, so read the
  // real rows through the DOM tree the product code actually built.
  const tbody = nodeFor('#dev-table tbody');
  const order = () => tbody.children.map(tr => tr.children[0].textContent);
  const asc = order();
  eq(asc.length, 3, 'all three rows must be painted');
  eq(asc[asc.length - 1], '10.0.0.2',
     'ascending by upload must end with the largest rate, got: ' + JSON.stringify(asc));
  eq(asc[0], '10.0.0.3',
     'the client with no counter sorts as zero, so it comes first, got: ' + JSON.stringify(asc));

  // Descending must be the exact reverse of ascending - that is the promise the
  // shared direction control makes. A NaN in the comparator breaks it.
  nodeFor('#dev-dir').value = 'desc';
  await sandbox.resortDevices();
  const desc = order();
  eq(JSON.stringify(desc), JSON.stringify(asc.slice().reverse()),
     'descending must be the exact reverse of ascending, got: ' + JSON.stringify(desc));

  // A string counter (a listener that formats numbers) must compare as a
  // number, not as text: "20" must sort below "100".
  clientList = [
    { ip: '10.0.0.9', mac: 'BB:BB:BB:BB:BB:09', up_bps: '20', down_bps: 0, last_seen_s: 1, lan: true },
    { ip: '10.0.0.10', mac: 'BB:BB:BB:BB:BB:10', up_bps: '100', down_bps: 0, last_seen_s: 2, lan: true },
  ];
  nodeFor('#dev-dir').value = 'asc';
  // renderDevices() refetches; resortDevices() would repaint the OLD cache.
  await sandbox.renderDevices();
  const numeric = order();
  eq(numeric[0], '10.0.0.9',
     'a numeric STRING must sort numerically, not lexically ("20" < "100"), got: ' + JSON.stringify(numeric));

  // The other three keys must survive the same malformed data. Each one is a
  // separate branch of the comparator, and a branch that still subtracts raw
  // fields would return NaN for the very same input.
  const sortWith = async (key, list) => {
    clientList = list;
    nodeFor('#dev-sort').value = key;
    nodeFor('#dev-dir').value = 'asc';
    await sandbox.renderDevices();
    return order();
  };
  // One entry is missing BOTH counters and its age. Raw arithmetic turns each
  // of those into NaN, and a NaN comparator result lets the engine leave the
  // list in any order - so the property that has to hold is the ORDER OF THE
  // OTHER rows, not the position of the malformed one.
  const malformed = [
    { ip: '10.0.0.1', mac: 'CC:CC:CC:CC:CC:01', up_bps: 100, down_bps: 10, last_seen_s: 5, lan: true },
    { ip: '10.0.0.2', mac: 'CC:CC:CC:CC:CC:02', lan: true },
    { ip: '10.0.0.3', mac: 'CC:CC:CC:CC:CC:03', up_bps: 200, down_bps: 30, last_seen_s: 1, lan: true },
  ];

  // down_bps: 10, (missing -> 0), 30. The two real values must stay ordered
  // regardless of where the malformed row lands.
  const byDown = await sortWith('down', malformed);
  ok(byDown.indexOf('10.0.0.1') < byDown.indexOf('10.0.0.3'),
     'downlink sort must keep the two real counters in order, got: ' + JSON.stringify(byDown));
  // last_seen_s is an AGE (batch154): the comparator negates it so ascending
  // puts the LONGEST silent client first. Real ages are 5 and 1, so 10.0.0.1
  // must come before 10.0.0.3 whichever side the malformed row settles on.
  const bySeen = await sortWith('seen', malformed);
  ok(bySeen.indexOf('10.0.0.1') < bySeen.indexOf('10.0.0.3'),
     'age sort must keep the two real ages in order, got: ' + JSON.stringify(bySeen));
  // combined rate: 110, (missing -> 0), 230.
  const byRate = await sortWith('rate', malformed);
  ok(byRate.indexOf('10.0.0.1') < byRate.indexOf('10.0.0.3'),
     'combined-rate sort must keep the two real rates in order, got: ' + JSON.stringify(byRate));

  clientList = [];
  vm.runInContext('window.__clientList = null; renderTicket.clear();', context);
}]);

cases.push(['saving a token proves it before reporting success', async () => {
  vm.runInContext('toasts.length = 0; renderToasts();', context);
  vm.runInContext('warned401 = false;', context);
  localStorage.removeItem('vgww_token');
  const origFetch = sandbox.fetch;
  let probed = 0;
  let seenAuth = null;
  let probePath = null;
  let probeMethod = null;
  sandbox.fetch = async (path, opt) => {
    const h = (opt && opt.headers) || {};
    seenAuth = h['x-auth-token'] === undefined ? null : h['x-auth-token'];
    if (String(path).indexOf('/api/') === 0) {
      probed++;
      probePath = String(path);
      probeMethod = (opt && opt.method) || 'GET';
    }
    return { ok: true, status: 200, async json() { return { ok: true }; }, async text() { return '{}'; } };
  };
  try {
    nodeFor('#tk').value = 'good-token';
    await sandbox.setToken();
  } finally { sandbox.fetch = origFetch; }

  ok(probed > 0, 'saving must ASK the server, not just write localStorage');
  eq(seenAuth, 'good-token', 'the probe must carry the token being saved');
  // batch207: WHICH request proves the credential is the whole point. The
  // guard authenticates non-GET/HEAD requests only, so a GET probe returns 200
  // for ANY token - the old GET /api/config probe "verified" every typo. And
  // POST /api/config must not be used either: it is a FULL replacement, so
  // asking "is this token right?" would rewrite the configuration. Only a
  // read-only write-guarded route answers the question without a side effect.
  eq(probePath, '/api/auth/verify', 'the probe must be the read-only credential endpoint');
  eq(probeMethod, 'POST', 'the probe must be a write request, else the guard never runs');
  eq(localStorage.getItem('vgww_token'), 'good-token', 'an accepted token is stored');
  const texts = nodeFor('#toast').children.map(c => c.textContent);
  const saved = vm.runInContext('t("auth.saved")', context);
  ok(texts.some(x => x.indexOf(saved) === 0), 'a verified token reports success, got: ' + JSON.stringify(texts));
  vm.runInContext('toasts.length = 0; renderToasts();', context);
}]);

// The other half: a REJECTED token must not be reported as saved, and must
// not replace the token that still works.
cases.push(['a rejected token is not stored and not called saved', async () => {
  vm.runInContext('toasts.length = 0; renderToasts();', context);
  vm.runInContext('warned401 = false;', context);
  localStorage.setItem('vgww_token', 'good-token');
  const origFetch = sandbox.fetch;
  sandbox.fetch = async (path, opt) => {
    if (String(path).indexOf('/api/') === 0) {
      return { ok: false, status: 401, async json() { return { error: 'unauthorized' }; }, async text() { return '{"error":"unauthorized"}'; } };
    }
    return { ok: true, status: 200, async json() { return {}; }, async text() { return '{}'; } };
  };
  try {
    nodeFor('#tk').value = 'wrong-token';
    await sandbox.setToken();
  } finally { sandbox.fetch = origFetch; }

  eq(localStorage.getItem('vgww_token'), 'good-token',
     'a rejected token must NOT replace the working one');
  const texts = nodeFor('#toast').children.map(c => c.textContent);
  const saved = vm.runInContext('t("auth.saved")', context);
  ok(!texts.some(x => x.indexOf(saved) === 0),
     'a rejected token must not be announced as saved, got: ' + JSON.stringify(texts));
  const unauth = vm.runInContext('t("auth.unauthorized")', context);
  ok(texts.some(x => x.indexOf(unauth) === 0),
     'the operator must be told the token was rejected, got: ' + JSON.stringify(texts));
  localStorage.removeItem('vgww_token');
  vm.runInContext('toasts.length = 0; renderToasts();', context);
  vm.runInContext('warned401 = false;', context);
}]);

cases.push(['clearing a configured DHCP pool drops the key', async () => {
  vm.runInContext('renderTicket.clear();', context);
  configPayload = JSON.parse(JSON.stringify(SERVER_CONFIG));
  resetSettingsForm();
  await sandbox.loadSettings(true);
  eq(nodeFor('#set-dhcp-poolstart').value, '192.168.0.100', 'a configured pool loads');
  nodeFor('#set-dhcp-poolstart').value = '';
  nodeFor('#set-dhcp-poolend').value = '';
  configPostReply = { ok: true };
  applyStatusReply = { attempt_id: 0, completed_id: 0, ok: true, error: '' };
  const before = requests.length;
  await sandbox.saveSettings();
  const posts = requests.slice(before).filter(r => r.method === 'POST' && r.path === '/api/config');
  eq(posts.length, 1, 'clearing the pool must still post');
  const cleared = JSON.parse(posts[0].body);
  ok(!('pool' in cleared.dhcp),
     'clearing a CONFIGURED pool must OMIT the key, got: ' + JSON.stringify(cleared.dhcp));
  ok(!('pool_start' in cleared.dhcp) && !('pool_end' in cleared.dhcp),
     'the compat spelling must not appear either, got: ' + JSON.stringify(cleared.dhcp));
  configPayload = null;
  vm.runInContext('renderTicket.clear();', context);
}]);

// batch191 (third half): one bound cleared, the other left in place. The pair
// is unusable, so the key must be dropped rather than posted half-empty.
cases.push(['a half-filled DHCP pool is dropped, not posted', async () => {
  vm.runInContext('renderTicket.clear();', context);
  configPayload = JSON.parse(JSON.stringify(SERVER_CONFIG));
  resetSettingsForm();
  await sandbox.loadSettings(true);
  nodeFor('#set-dhcp-poolstart').value = '192.168.0.100';
  nodeFor('#set-dhcp-poolend').value = '';
  configPostReply = { ok: true };
  applyStatusReply = { attempt_id: 0, completed_id: 0, ok: true, error: '' };
  const before = requests.length;
  await sandbox.saveSettings();
  const posts = requests.slice(before).filter(r => r.method === 'POST' && r.path === '/api/config');
  eq(posts.length, 1, 'a half-cleared pool must still post');
  const half = JSON.parse(posts[0].body);
  ok(!('pool' in half.dhcp),
     'a half-filled pool must not be posted, got: ' + JSON.stringify(half.dhcp));
  configPayload = null;
  vm.runInContext('renderTicket.clear();', context);
}]);

// batch181: an apply that never reports back must NOT be announced as applied.
// POST /api/config answers {ok:true,note:'applied',apply_id:N} as soon as the
// apply is QUEUED - in UI mode QueueConfigSaveFromWeb() returns immediately and
// the real outcome arrives later through ConfigApplyStatus::Record. The page
// polls /api/config/apply-status for 20 x 250 ms and pollApplyStatus() returns
// null on timeout, treating it the same as "the old origin is gone".
// saveSettings then fell through to `toastT(appliedNote, "success")` - so a slow
// apply (UI thread busy, listener restart, port still held) told the operator the
// configuration was live when it had never been confirmed. Unknown is not success.
cases.push(['an unconfirmed apply is not reported as applied', async () => {
  configPayload = JSON.parse(JSON.stringify(SERVER_CONFIG));
  await sandbox.loadSettings(true);
  // Port unchanged, so the save takes the normal (non-port-move) path.
  nodeFor('#set-workers').value = '4';
  // Applied, but the outcome is never observed: completed_id stays at 0.
  configPostReply = { ok: true, note: 'applied', apply_id: 7 };
  applyStatusReply = { attempt_id: 7, completed_id: 0, ok: false, error: '' };
  applyStatusPolls = 0;
  vm.runInContext('toasts.length = 0; renderToasts();', context);

  const before = requests.length;
  await sandbox.saveSettings();
  const posts = requests.slice(before).filter(r => r.method === 'POST' && r.path === '/api/config');
  eq(posts.length, 1, 'the save must still post the configuration once');
  ok(applyStatusPolls > 0, 'the page must actually poll for the apply outcome');

  const texts = nodeFor('#toast').children.map(c => c.textContent);
  const applied = vm.runInContext('t("set.saved.applied")', context);
  ok(!texts.some(x => x.startsWith(applied)),
     'an apply whose outcome was never confirmed must not be announced as applied, got: ' + JSON.stringify(texts));
  ok(texts.length > 0, 'the operator must be told something - silence is worse, got none');

  configPostReply = { ok: true };
  applyStatusReply = { attempt_id: 0, completed_id: 0, ok: true, error: '' };
  applyStatusPolls = 0;
  // batch182: the pending message must NOT be painted as an error.
  // "Saved to the file, but the live apply was not confirmed" is deliberately
  // neither success nor failure: the write really happened. Rendering it with
  // the error level paints a var(--danger) red bar and, because #toast is a
  // role=status live region, a screen reader announces it as the failure it is
  // not. The page already ships a neutral .toast-info style - use it.
  const pendingKeyText = vm.runInContext('t("set.saved.pending")', context);
  // batch191: four debug console.error probes were left behind by the
  // batch181. They printed the toast text on every GREEN run - which is
  // exactly how a debug probe hides: the gate still passes, so nothing
  // flags it, and the only symptom is noise nobody reads. The assertions
  // below already carry the same information in their failure messages.
  const kids = nodeFor('#toast').children;
  const pendingEl = kids.find(c => c.textContent.indexOf(pendingKeyText) === 0);
  ok(pendingEl, 'the pending message must be on screen, got: ' + JSON.stringify(texts));
  ok(pendingEl.className.indexOf('toast-error') < 0,
     'an unconfirmed apply is not a failure - it must not be painted as one, class: ' + pendingEl.className);
  ok(pendingEl.className.indexOf('toast-info') >= 0,
     'the unconfirmed apply must use the neutral info level, class: ' + pendingEl.className);
  vm.runInContext('toasts.length = 0; renderToasts();', context);

}]);

// batch181 (the other half): when the apply DOES report back a failure, the
// operator must see that failure named - not the success toast. Both branches
// were dead code under the old stub, because the config POST never answered
// with note:'applied' and apply-status did not exist at all.
cases.push(['a failed apply is reported as a failure, not as success', async () => {
  configPayload = JSON.parse(JSON.stringify(SERVER_CONFIG));
  await sandbox.loadSettings(true);
  nodeFor('#set-workers').value = '4';
  configPostReply = { ok: true, note: 'applied', apply_id: 9 };
  applyStatusReply = { attempt_id: 9, completed_id: 9, ok: false, error: 'port 8080 is in use' };
  applyStatusPolls = 0;
  vm.runInContext('toasts.length = 0; renderToasts();', context);

  await sandbox.saveSettings();
  const texts = nodeFor('#toast').children.map(c => c.textContent);
  // The named-failure assertion comes FIRST: when both are broken, the message
  // that identifies the defect (the backend's error never arrived) is the
  // useful one - the generic "success was shown" would hide it.
  ok(texts.some(x => x.includes('port 8080 is in use')),
     'the failure the backend named must reach the operator, got: ' + JSON.stringify(texts));
  const applied = vm.runInContext('t("set.saved.applied")', context);
  ok(!texts.some(x => x.startsWith(applied)),
     'a failed apply must not be announced as applied, got: ' + JSON.stringify(texts));

  configPostReply = { ok: true };
  applyStatusReply = { attempt_id: 0, completed_id: 0, ok: true, error: '' };
  applyStatusPolls = 0;
  vm.runInContext('toasts.length = 0; renderToasts();', context);
}]);

// batch183: a rate must never render as a value that belongs to the next unit.
// fmtRate() rounds to one decimal AFTER choosing the unit from the raw value:
// 1048575 is below 1 MiB, so it takes the KiB branch, and 1048575/1024 =
// 1023.999... rounds up to the string "1024.0KiB". Two numbers one apart then
// read as "1024.0KiB" and "1.0MiB" - a whole unit apart - and "1024.0KiB" is
// a self-contradictory reading, since 1024 KiB IS 1 MiB. The rounding has to
// happen BEFORE the unit is chosen, so a value that rounds up to 1024 moves to
// the next unit instead of printing an impossible number.
// batch184: the same unit-boundary bug the rate formatter had, in the counter
// formatter. fmt() chooses its suffix from the RAW value and rounds afterwards,
// so 999999 prints "1000.0 K" instead of "1.0 M", and 999999999 prints
// "1000.0 M" instead of "1.00 G". These are the dashboard's frame counters
// (dash.rx / dash.tx / dash.drops / dash.pass / dash.vrx / dash.vtx), which grow
// monotonically for as long as the appliance runs - they WILL cross both
// boundaries in normal use, and at that moment two numbers one apart read a whole
// unit apart. Note fmt() also uses a different precision per unit (2 decimals
// for G, 1 for M and K), so the promotion threshold has to respect each one.
// batch185: a missing counter must not reach the screen as the word "undefined".
// refreshStatus() guards four of the nine tiles with `?? 0` but leaves three
// (rx_frames, tx_frames, tcp_accepted) unguarded, and paintCards() writes
// `item.v` straight into textContent. So a /api/status response without those
// keys - an older build, a truncated body, a proxy that drops nulls - paints the
// literal text "undefined" on the dashboard. The asymmetry inside ONE card list
// is the tell: either all the counters are defensive or none are, and the ones
// that already say `?? 0` prove the authors expected the key could be absent.
// batch186: paintCards() itself must never print undefined.
// batch185 patched three CALL SITES with `?? 0`, which fixed the dashboard but
// left the writer fragile: the next card anyone adds is one forgotten `??` away
// from painting "undefined" again. Every other text writer in this file already
// normalises null (makeCell 3339, the table painter 3390, the about/bridge
// setters 3903/3923) - paintCards was the only one that did not. Fix the writer,
// then the call sites stop being load-bearing.
// batch187: repainting a live tile must not strip and re-add its cue.
// paintCards() guards the layout class with `if (card.className !== "card")
// card.className = "card"`. Once a tile is live its className is "card spd",
// so that guard is TRUE on every repaint - it wipes the class list (dropping
// spd) and then classList.toggle() puts spd back. The end state is correct,
// which is why every existing assertion passed, but the element is mutated
// twice per 2-second poll: a real style recalculation and, wherever a
// transition exists, a replayed animation. The base class must be ensured
// without discarding the classes the function itself manages.
cases.push(['a live tile keeps its cue without being rewritten', async () => {
  const host = nodeFor('#cards');
  vm.runInContext('renderTicket.clear();', context);
  sandbox.paintCards(host, [{ k: 'up', v: 1, small: '', spd: true }, { k: 'down', v: 2, small: '' }]);
  const live = host.children[0];
  ok(live.className.indexOf('spd') >= 0, 'the live cue is applied, got: ' + live.className);

  // Repaint the SAME data: nothing about this tile changed.
  const before = live.__classWrites;
  sandbox.paintCards(host, [{ k: 'up', v: 1, small: '', spd: true }, { k: 'down', v: 2, small: '' }]);
  eq(live.__classWrites, before,
     'an unchanged live tile must not be restyled, got ' + (live.__classWrites - before) + ' className write(s)');

  // Turning the cue off must still work, and must not churn the base class.
  const beforeOff = live.__classWrites;
  sandbox.paintCards(host, [{ k: 'up', v: 1, small: '' }, { k: 'down', v: 2, small: '' }]);
  ok(live.className.indexOf('spd') < 0, 'the cue must clear when traffic stops, got: ' + live.className);
  ok(live.className.indexOf('card') >= 0, 'the base class must survive, got: ' + live.className);

  // batch187: if something else stripped the base class (another writer, a
  // restored snapshot), the writer must put it back - otherwise the tile loses
  // its padding/border while the cue keeps working.
  live.className = "spd";
  sandbox.paintCards(host, [{ k: 'up', v: 1, small: '', spd: true }, { k: 'down', v: 2, small: '' }]);
  ok(live.classList.contains('card'),
     'the base class must be restored when it is missing, got: ' + live.className);
  ok(live.__classWrites - beforeOff <= 1,
     'clearing the cue must be a single class change, got ' + (live.__classWrites - beforeOff));

  vm.runInContext('renderTicket.clear();', context);
}]);

cases.push(['the card writer never prints undefined', async () => {
  const host = nodeFor('#cards');
  vm.runInContext('renderTicket.clear();', context);
  // A card with no value, no hint and no label at all: exactly what a
  // half-written row or a renamed API field produces.
  sandbox.paintCards(host, [{ k: 'label', v: 7, small: '' }, { }]);
  const texts = host.children.map(c => c.children[1].textContent);
  eq(texts.length, 2, 'both cards are painted');
  ok(texts[0] === '7', 'a real value is shown as-is, got: ' + JSON.stringify(texts[0]));
  eq(texts[1], '',
     'a card with no value must render empty, not the word undefined, got: ' + JSON.stringify(texts[1]));
  const labels = host.children.map(c => c.children[0].textContent);
  ok(labels.every(x => x.indexOf('undefined') < 0),
     'no label may read undefined, got: ' + JSON.stringify(labels));
  const hints = host.children.map(c => c.children[1].children[1].textContent);
  ok(hints.every(x => x.indexOf('undefined') < 0),
     'no hint may read undefined, got: ' + JSON.stringify(hints));
  // A present hint still gets its separating space, and an absent one does not.
  sandbox.paintCards(host, [{ k: 'a', v: 1, small: '' }, { k: 'b', v: 2, small: 'u' }]);
  eq(host.children[0].children[1].textContent, '1', 'no trailing space without a hint');
  eq(host.children[1].children[1].textContent, '2 u', 'a hint keeps its separating space');
  vm.runInContext('renderTicket.clear();', context);
}]);

// batch189: a client count must come from a LIST, not from whatever .length
// happens to return. `(c.clients || []).length` guards absence but not type:
// an object or a number has no .length (so the tile reads "undefined"), and a
// STRING has one (so "abc" reads as 3 clients). Every other payload read in
// this file already uses Array.isArray - eight of them - so this pair
// (refreshStatus and renderDevices) is the odd one out.
// batch190: Escape must not steal the in-progress edit while an IME is composing.
// The two Enter wirings (ENTER_SUBMITS and the settings form) both skip the key
// while `e.isComposing || e.keyCode === 229`, because during Chinese/Japanese
// composition Enter/Escape belong to the candidate window, not to the page.
// The Escape cancel path - the third keyboard handler, added in batch175 - never
// got that guard. So a half-typed MAC whose candidates are still open is thrown
// away by an Escape that was meant to close the candidate list.
cases.push(['Escape leaves a composing IME alone', async () => {
  const saved = ratelimitRules;
  ratelimitRules = [{ mac: 'AA:BB:CC:DD:EE:09', uplink_kbps: 10, downlink_kbps: 10 }];
  vm.runInContext('renderTicket.clear();', context);
  await sandbox.loadRateLimits();
  sandbox.editRateLimit('AA:BB:CC:DD:EE:09');
  const macEl = nodeFor('#rl-mac');
  const handlers = (macEl.__on && macEl.__on.keydown) || [];
  const esc = handlers.filter((fn) => {
    let hit = false;
    fn({ key: 'Escape', preventDefault() { hit = true; } });
    return hit;
  });
  ok(handlers.length > 0, 'the MAC field must listen for keys');

  // Re-enter edit mode (the probing call above cancelled it) and check the
  // composition case: Escape during composition must be left to the IME.
  sandbox.editRateLimit('AA:BB:CC:DD:EE:09');
  ok(vm.runInContext('editingMac', context) === 'AA:BB:CC:DD:EE:09',
     'edit mode is active before the composing Escape');
  for (const fn of handlers) {
    fn({ key: 'Escape', isComposing: true, preventDefault() {} });
  }
  eq(vm.runInContext('editingMac', context), 'AA:BB:CC:DD:EE:09',
     'an Escape that belongs to the IME must not abandon the edit');
  // keyCode 229 is the legacy marker some IME paths still send.
  for (const fn of handlers) {
    fn({ key: 'Escape', keyCode: 229, preventDefault() {} });
  }
  eq(vm.runInContext('editingMac', context), 'AA:BB:CC:DD:EE:09',
     'keyCode 229 must be treated as composition too');

  // The language filter is the one input whose whole purpose is typing names,
  // so its Enter handler must skip composition too - otherwise selecting an IME
  // candidate jumps focus into the select and drops the candidates.
  const filter = nodeFor('#lang-filter');
  const fHandlers = (filter.__on && filter.__on.keydown) || [];
  ok(fHandlers.length > 0, 'the language filter must listen for Enter');
  const langsel = nodeFor('#langsel');
  const shownSel = () => {
    langsel.__focused = false;
    return langsel.__focused;
  };
  // During composition the handler must return BEFORE moving focus.
  for (const fn of fHandlers) {
    fn({ key: 'Enter', isComposing: true, preventDefault() {} });
  }
  ok(!langsel.__focused,
     'a composing Enter must not move focus out of the filter');
  for (const fn of fHandlers) {
    fn({ key: 'Enter', keyCode: 229, preventDefault() {} });
  }
  ok(!langsel.__focused,
     'keyCode 229 must not move focus either');
  // And a plain Enter still does move it - otherwise the guard ate the feature.
  for (const fn of fHandlers) {
    fn({ key: 'Enter', preventDefault() {} });
  }
  ok(langsel.__focused,
     'a plain Enter still jumps to the language list');

  // A real Escape must still cancel.
  for (const fn of handlers) fn({ key: 'Escape', preventDefault() {} });
  eq(vm.runInContext('editingMac', context), null, 'a plain Escape still cancels');

  ratelimitRules = saved;
  vm.runInContext('renderTicket.clear();', context);
}]);

cases.push(['a client count is taken from a list, not from .length', async () => {
  const savedClients = clientList.slice();
  vm.runInContext('renderTicket.clear(); window.__clientCount = null; window.__clientList = null;', context);

  for (const bad of [{}, 42, 'abc', true]) {
    clientList = bad;
    vm.runInContext('window.__clientCount = null; window.__clientList = null;', context);
    await sandbox.renderDevices();
    const count = vm.runInContext('window.__clientCount', context);
    eq(count, 0,
       'a non-list clients field must count as zero, got ' + String(count) + ' for ' + JSON.stringify(bad));
  }

  // The tile that displays the count must not read undefined either.
  clientList = {};
  vm.runInContext('window.__clientCount = null; window.__clientList = null; renderTicket.clear();', context);
  await sandbox.refreshStatus();
  const texts = nodeFor('#cards').children.map(c => c.children[1].textContent);
  ok(texts.every(x => x.indexOf('undefined') < 0),

     'the clients tile must not read undefined, got: ' + JSON.stringify(texts));
  // The clients tile is the first card refreshStatus paints, and it is painted
  // The clients tile lives in renderSystem's #host-cards, not refreshStatus's
  // #cards, and it is painted from window.__clientCount. The fallback count
  // refreshStatus computes is written into __clientCount only when it was null
  // and no renderDevices() has run yet.
  // NOTE (batch189): the `clientCount` fallback inside refreshStatus is NOT
  // reachable from this harness - refreshStatus() calls renderDevices() (which
  // fills __clientCount) before renderSystem() paints #host-cards. A sentinel
  // planted in that branch kept every case green, which is how that was proved.
  // The branch is left in place as defensive code, deliberately NOT asserted;
  // asserting it would be a test of code no path executes.
  ok(true, 'see the note above: the fallback branch is defensive, not exercised');
  // The rate-limit and port-map caches must also hold a LIST: editRateLimit()
  // calls .find on the rate-limit cache, and a non-array there is a latent
  // TypeError the moment a future caller reaches it.
  clientList = savedClients;
  ratelimitRules = { not: 'an array' };
  vm.runInContext('renderTicket.clear();', context);
  await sandbox.loadRateLimits();
  ok(Array.isArray(vm.runInContext('window.__rlRules', context)),
     'the rate-limit cache must always be an array');
  // Same for the port-map cache: loadPortMap() stores it and paintActionTable()
  // maps over a guarded copy, so a non-list answer must not reach the cache.
  portmapRules = { not: 'an array' };
  vm.runInContext('renderTicket.clear();', context);
  await sandbox.loadPortMap();
  ok(Array.isArray(vm.runInContext('window.__pmRules', context)),
     'the port-map cache must always be an array');
  portmapRules = [];
  ratelimitRules = [];

  clientList = savedClients;
  vm.runInContext('window.__clientCount = null; window.__clientList = null; renderTicket.clear();', context);
}]);

cases.push(['a missing counter shows a number, never the word undefined', async () => {
  const saved = JSON.parse(JSON.stringify(statusPayload));
  // The shape an older/partial listener would send: the tier-1 counters absent.
  statusPayload = JSON.parse(JSON.stringify(saved));
  // All three unguarded counters absent, plus one GUARDED one present so the case
  // also proves this is not a test that simply blanks every tile.
  statusPayload.stats = { rx_dropped: 7 };
  statusPayload.gateway = { ip: '192.168.50.1', ipv6: false };
  statusPayload.bridge = { enabled: false };
  statusPayload.dhcp6 = { bridge: { enabled: false } };
  vm.runInContext('renderTicket.clear(); paintCards.clear ? 0 : 0;', context);
  await sandbox.refreshStatus();

  const cards = nodeFor('#cards');
  const texts = cards.children.map(c => c.children[1].textContent);
  ok(texts.length > 0, 'the tiles must be painted');
  const bogus = texts.filter(t2 => t2.indexOf('undefined') >= 0 || t2.indexOf('NaN') >= 0);
  eq(bogus.length, 0,
     'no tile may read undefined/NaN when a counter is absent, got: ' + JSON.stringify(bogus));
  // The PRESENT counter must still show its real value - this is not a test that
  // simply blanks everything.
  ok(texts.some(t2 => t2.indexOf('7') === 0),
     'the counter that WAS sent must still be shown, got: ' + JSON.stringify(texts));

  statusPayload = saved;
  vm.runInContext('renderTicket.clear();', context);
}]);

cases.push(['a counter never prints a value that belongs to the next unit', async () => {
  const fmt = (n) => vm.runInContext('fmt(' + n + ')', context);

  // The invariant first: "1000.0" (and "1000.00") are never correct readings in
  // a scaled unit - they are the next unit spelled wrong.
  const offenders = [];
  const probe = (lo, hi, step) => {
    for (let v = lo; v <= hi; v += step) {
      const txt = String(fmt(v));
      if (/1000(\.0+)?\s*[KMG]/.test(txt)) offenders.push(v + ' -> ' + txt);
    }
  };
  // Coarse sweep of every magnitude, plus a dense sweep of each rounding window.
  probe(1000, 2e9, 100003);
  probe(1e6 - 100, 1e6 - 1, 1);
  probe(1e9 - 100, 1e9 - 1, 1);
  eq(offenders.length, 0,
     'no counter may print 1000 in a scaled unit: ' + offenders.slice(0, 4).join(', '));

  // The two boundaries themselves, as adjacent integers.
  eq(fmt(1e6 - 1), '1.0 M',
     'a value that rounds up to 1000 K is 1.0 M, got: ' + fmt(1e6 - 1));
  eq(fmt(1e9 - 1), '1.00 G',
     'a value that rounds up to 1000 M is 1.00 G, got: ' + fmt(1e9 - 1));

  // Boundaries that were already right and must stay so.
  // Below a thousand the formatter returns the NUMBER unchanged, not a string.
  // Read it through String() so the assertion is about the displayed text and
  // does not silently demand a type change the fix never intended.
  eq(String(fmt(0)), '0', 'zero is not scaled');
  eq(String(fmt(999)), '999', 'just under a thousand stays plain');
  eq(fmt(1000), '1.0 K', 'exactly a thousand');
  eq(fmt(1e6), '1.0 M', 'exactly a million');
  eq(fmt(1e9), '1.00 G', 'exactly a billion');
}]);

// batch188: a formatter must never print NaN or a JSON type name.
// fmt() and fmtRate() guard with `n || 0` / `bps || 0`, which only catches the
// FALSY values. A non-empty string, an object or `true` all pass that guard and
// then either compute NaN (printed as "NaN KiB/s") or concatenate the value
// straight into the unit ("true B/s"). The API sends numbers today, so this is
// about the shape of the guard, not a live backend bug - but the same guard is
// what makes a malformed/truncated response visible on screen as garbage rather
// than as a missing value, and the truncation case is real: JSON cut inside a
// number yields a string or breaks the parse upstream.
cases.push(['a formatter never prints NaN or a type name', async () => {
  // NOTE: the expression is pasted INTO the script source, so a JS STRING value
  // needs its own quotes inside the outer one. `fmtRate('1024')` would pass the
  // NUMBER 1024 (the quotes only delimit the outer string) and quietly stop
  // covering the string path - which is exactly the bug this case exists for.
  const call = (fn, expr) => String(vm.runInContext(fn + '(' + expr + ')', context));
  const rate = (expr) => call('fmtRate', expr);
  const cnt = (expr) => call('fmt', expr);
  const KIB = vm.runInContext('t("rate.kib")', context);
  const B = vm.runInContext('t("rate.b")', context);

  // Things a JSON field can be when it is not the number we expect.
  const badValues = ['"abc"', 'true', '{}', '[]', '"12.5x"', 'null', 'undefined', '""', '" "', 'NaN', 'Infinity', '-Infinity'];
  for (const expr of badValues) {
    const out = rate(expr);
    ok(out.indexOf('NaN') < 0, 'fmtRate(' + expr + ') must not print NaN, got: ' + JSON.stringify(out));
    ok(out.indexOf('true') < 0 && out.indexOf('false') < 0,
       'fmtRate(' + expr + ') must not print a boolean, got: ' + JSON.stringify(out));
    ok(out.indexOf('[object') < 0,
       'fmtRate(' + expr + ') must not print an object, got: ' + JSON.stringify(out));
    const out2 = cnt(expr);
    ok(out2.indexOf('NaN') < 0, 'fmt(' + expr + ') must not print NaN, got: ' + JSON.stringify(out2));
    ok(out2.indexOf('[object') < 0,
       'fmt(' + expr + ') must not print an object, got: ' + JSON.stringify(out2));
    ok(!/^true|^false/.test(out2),
       'fmt(' + expr + ') must not print a boolean, got: ' + JSON.stringify(out2));
  }

  // A numeric string is still usable data - accept it rather than blanking it.
  eq(rate('"1024"'), '1.0' + KIB, 'a numeric string still formats as a rate');
  eq(cnt('"1000"'), '1.0 K', 'a numeric string still formats as a count');
  // A value that cannot be a number falls back to zero, the same meaning the
  // existing `|| 0` guard already gives an absent field.
  eq(rate('"abc"'), '0' + B, 'an unusable value reads as zero');
  eq(cnt('"abc"'), '0', 'an unusable value reads as zero');
  // A boolean is NOT a reading: Number(true) === 1 would have made a malformed
  // field look like one byte per second (or one frame).
  eq(rate('true'), '0' + B, 'a boolean is not a rate');
  eq(cnt('true'), '0', 'a boolean is not a count');
  // An array would coerce to 0 - but that is a coincidence, not a reading.
  eq(rate('[]'), '0' + B, 'an array is not a rate');
  eq(rate('[5]'), '0' + B, 'a non-empty array is not a rate either');
}]);

cases.push(['a rate never prints a value that belongs to the next unit', async () => {
  const render = (bps) => vm.runInContext('fmtRate(' + bps + ')', context);
  const KIB = vm.runInContext('t("rate.kib")', context);
  const MIB = vm.runInContext('t("rate.mib")', context);
  const B = vm.runInContext('t("rate.b")', context);

  // The invariant comes FIRST, and it is checked over a range rather than at two
  // hand-picked points. "1024.0" can never be a correct reading in any unit -
  // it is always the next unit spelled wrong (1024 KiB IS 1 MiB) - so one sweep
  // covers every way the unit choice can go wrong, including ones a later
  // boundary assertion would short-circuit before reaching.
  const offenders = [];
  for (let v = 1024; v <= 3 * 1048576; v += 617) {
    const txt = render(v);
    if (txt.indexOf('1024.0') >= 0) offenders.push(v + ' -> ' + txt);
  // The window that can round UP into "1024.0" is narrow - about 51 counts just
  // below 1 MiB - so the coarse stride above walks straight over it. Sweep every
  // value in that window too.
  for (let v = 1048576 - 80; v < 1048576; v++) {
    const txt = render(v);
    if (txt.indexOf('1024.0') >= 0) offenders.push(v + ' -> ' + txt);
  }
  }
  eq(offenders.length, 0,
     'no unit may print "1024.0": ' + offenders.slice(0, 4).join(', '));

  // Adjacent integers must not straddle a unit boundary in the display either.
  const justUnder = render(1048576 - 1);
  eq(justUnder, '1.0' + MIB,
     'a value that rounds up to 1024 KiB must be shown as 1.0 MiB, got: ' + justUnder);

  // Boundaries that were already right and must stay so.
  eq(render(0), '0' + B, 'zero');
  eq(render(512), '512' + B, 'bytes stay bytes');
  eq(render(1023), '1023' + B, 'just under a KiB');
  eq(render(1024), '1.0' + KIB, 'exactly a KiB');
  eq(render(1048576), '1.0' + MIB, 'exactly a MiB');
}]);

// batch331: the MiB promotion threshold was wrong. fmtRate chose its unit from
// tenths of a MiB (`Math.round(bps / 104857.6) >= 10`), which promotes at
// 1 000 000 B - NOT at 1 MiB (1048576 B). So 996147 B (972.8 KiB) printed
// "1.0 MiB/s", 5.3% high, and the whole 972.8-1023.9 KiB band was unreachable:
// no input could ever produce those readings. The boundary must be where the
// KiB DISPLAY rounds to 1024.0, i.e. 1023.95 KiB = 1048524.8 B.
cases.push(['a rate below one MiB is never shown as "1.0 MiB"', async () => {
  const render = (bps) => vm.runInContext('fmtRate(' + bps + ')', context);
  const KIB = vm.runInContext('t("rate.kib")', context);
  const MIB = vm.runInContext('t("rate.mib")', context);

  // The live values the dashboard actually shows. 996147 B is 972.8 KiB and
  // used to read "1.0 MiB/s" - a 5.3% overstatement.
  eq(render(996147), '972.8' + KIB,
     '996147 B is 972.8 KiB, got: ' + render(996147));
  eq(render(1000000), '976.6' + KIB,
     '1000000 B is 976.6 KiB, got: ' + render(1000000));
  eq(render(1023 * 1024), '1023.0' + KIB,
     'the top of the KiB band stays in KiB, got: ' + render(1023 * 1024));

  // The boundary itself: the largest KiB that still rounds to 1023.9, then the
  // first value whose KiB display would be 1024.0 (so it belongs to MiB).
  eq(render(1048524), '1023.9' + KIB,
     '1048524 B rounds to 1023.9 KiB, got: ' + render(1048524));
  eq(render(1048524.8), '1.0' + MIB,
     'the first value that rounds to 1024.0 KiB is 1.0 MiB, got: ' + render(1048524.8));

  // The whole band below the boundary must never print a MiB unit - this is
  // the range the old threshold made unreachable.
  const offenders = [];
  for (let v = 1024; v < 1048524.8; v += 613) {
    const txt = render(v);
    if (txt.indexOf(MIB) >= 0) offenders.push(v + ' -> ' + txt);
  }
  eq(offenders.length, 0,
     'no rate under 1048524.8 B may print MiB: ' + offenders.slice(0, 4).join(', '));
}]);

// batch331: fmt() had no T bucket, so a counter at 1e12 printed "1000.00 G" -
// exactly the self-contradictory reading the function's own comment says it
// removes (1000 G IS 1 T). G is displayed to two decimals, so it promotes when
// ITS display rounds to 1000.00, at 999.995 G = 999995000000 - the same
// "choose the suffix from the ROUNDED display" rule K and M already follow.
cases.push(['a counter at a trillion never prints "1000.00 G"', async () => {
  const fmt = (n) => String(vm.runInContext('fmt(' + n + ')', context));

  eq(fmt(1e12), '1.00 T', 'a trillion is 1.00 T, got: ' + fmt(1e12));
  eq(fmt(5e12), '5.00 T', 'five trillion is 5.00 T, got: ' + fmt(5e12));
  // The boundary as adjacent integers: just below it is still a legal G value.
  eq(fmt(999994999999), '999.99 G',
     'the value below the T boundary is 999.99 G, got: ' + fmt(999994999999));
  eq(fmt(999995000000), '1.00 T',
     'the first value that rounds to 1000.00 G is 1.00 T, got: ' + fmt(999995000000));

  // The invariant over the whole magnitude: "1000" is never correct inside a
  // scaled unit - it is always the next unit spelled wrong.
  const offenders = [];
  for (let v = 1e9; v <= 3e12; v += 1000003) {
    const txt = fmt(v);
    if (/1000(\.0+)?\s*[KMG]/.test(txt)) offenders.push(v + ' -> ' + txt);
  }
  for (let v = 999995000000 - 200; v < 999995000000 + 200; v += 7) {
    const txt = fmt(v);
    if (/1000(\.0+)?\s*[KMG]/.test(txt)) offenders.push(v + ' -> ' + txt);
  }
  eq(offenders.length, 0,
     'no counter may print 1000 in a scaled unit: ' + offenders.slice(0, 4).join(', '));
}]);

// batch331: paintDevices() ran the scope predicate through Array.filter, and
// the predicate itself called $("#dev-scope") on every invocation. The
// neighbour table reaches 4096 rows, so a single 2 s tick issued 4096
// whole-document selector queries for a value that never changes during the
// paint. Read it once and hand it to the pure predicate.
cases.push(['painting the device table reads the scope control once per paint', async () => {
  const tbody = nodeFor('#dev-table tbody');
  nodeFor('#dev-scope').value = 'lan';
  // A full neighbour table: 4096 clients, as the product's own comment states
  // is reachable.
  clientList = [];
  for (let i = 0; i < 4096; i++) {
    clientList.push({
      ip: '10.1.' + ((i >> 8) & 0xff) + '.' + (i & 0xff),
      mac: 'AA:BB:CC:00:' + ((i >> 8) & 0xff).toString(16).padStart(2, '0') +
           ':' + (i & 0xff).toString(16).padStart(2, '0'),
      up_bps: 1000, down_bps: 1000, last_seen_s: 1, lan: (i & 1) === 0,
    });
  }

  // Count document-level selector queries during ONE paint.
  const realQuerySelector = document.querySelector;
  const seen = [];
  document.querySelector = function (sel) {
    seen.push(String(sel));
    return realQuerySelector.call(this, sel);
  };
  try {
    sandbox.window.__clientList = clientList;
    vm.runInContext('paintDevices();', context);
  } finally {
    document.querySelector = realQuerySelector;
  }

  const scopeReads = seen.filter((s) => s === '#dev-scope').length;
  eq(scopeReads, 1,
     'the scope control must be read once per paint, not once per client ' +
     '(got ' + scopeReads + ' reads for ' + clientList.length + ' clients)');
  // A per-client read would be 4096; a per-paint read is a handful, so the
  // whole paint must stay far below the row count.
  ok(seen.length < 16,
     'a paint must not issue a document query per row (got ' + seen.length + ')');

  // The filter still works: half the clients are LAN, so half the rows paint.
  eq(tbody.children.length, 2048, 'the LAN filter must still select half the rows');

  clientList = [];
  nodeFor('#dev-scope').value = 'all';
}]);

cases.push(['an empty/error row spans every column of its table', async () => {
  eq(sandbox.tableSpan('dev-table'), 6, 'dev-table span');
  eq(sandbox.tableSpan('pm-table'), 4, 'pm-table span');
  eq(sandbox.tableSpan('ban-table'), 3, 'ban-table span');
  eq(sandbox.tableSpan('rl-table'), 4, 'rl-table span');
  eq(sandbox.tableSpan('le-v6'), 4, 'le-v6 span');

  // Drive the real failure path: /api/clients refuses, renderDevices writes the
  // network-error row. Its colspan must come from the header, not a stale
  // literal. The tbody is read back from the document AFTER the paint (the
  // paintedRows cache is keyed by element identity, and an earlier case may
  // already have cached this same placeholder - reading the live node is what
  // the operator actually sees either way).
  const tbody = nodeFor('#dev-table tbody');
  tbody.textContent = '';
  const realFetch = sandbox.fetch;
  sandbox.fetch = async () => ({ ok: false, status: 500, async json() { return {}; }, async text() { return 'boom'; } });
  try {
    await sandbox.renderDevices();
  } finally {
    sandbox.fetch = realFetch;
  }
  const live = vm.runInContext("document.querySelector('#dev-table tbody')", context);
  const errCell = firstCell(live);
  ok(errCell && errCell.getAttribute('colspan') === '6',
     `devices error row must span 6 columns, got: ${tableText(live)}`);
}]);

// Let the boot-time chain (activate -> load -> refreshStatus -> renderDevices
// -> renderSystem) settle, then freeze what the page asked for on its own.
// Startup must be ONE burst: the dashboard is loaded exactly once whether the
// first paint comes from applyI18n() or from activate().
await flush();
await flush();
const startupRequests = requests.slice();

// batch170: after a save the page re-reads /api/config so the form shows what
// the server actually stored (it may normalise a value). That reload was
// fire-and-forget: `loadSettings(true)` returns a promise nobody awaited, so a
// failure inside it (the GET after the POST, a normal case right after a
// web-port change moves the listener) became an UNHANDLED REJECTION - the
// console logs an error, no toast is shown, and settingsSnapshot keeps the
// pre-save values, so the dirty badge disagrees with what is on screen.
cases.push(['a failed post-save refresh cannot become an unhandled rejection', async () => {
  configPayload = JSON.parse(JSON.stringify(SERVER_CONFIG));
  await sandbox.loadSettings(true);

  const realFetch = sandbox.fetch;
  let afterPost = false;
  sandbox.fetch = async (p, o) => {
    const path = String(p);
    if (path === '/api/config' && o && o.method === 'POST') {
      afterPost = true;
      return realFetch(p, o);
    }
    // The save landed; the follow-up read of the same endpoint fails.
    if (path === '/api/config' && afterPost) {
      return { ok: false, status: 500, async json() { return {}; }, async text() { return 'reload-boom'; } };
    }
    return realFetch(p, o);
  };
  const before = rejections.length;
  const toastsBefore = nodeFor('#toast').children.length;
  try {
    await sandbox.saveSettings();
    for (let i = 0; i < 8; i++) await flush();
    await new Promise(r => setImmediate(r));
    await new Promise(r => setImmediate(r));
  } finally {
    sandbox.fetch = realFetch;
  }
  ok(afterPost, 'the save itself must have been posted');
  eq(rejections.length, before,
     `a failed post-save refresh must be handled, unhandled: ${JSON.stringify(rejections.slice(before))}`);
  // Swallowing it with `.catch(() => {})` would also satisfy the line above, so
  // require that the operator is actually told: the refresh failure has to
  // reach the live region.
  const text = tableText(nodeFor('#toast'));
  ok(text.includes(sandbox.t('set.savefail')) && text.includes('reload-boom'),
     `a failed post-save refresh must be reported, got: ${JSON.stringify(text)}`);
}]);

// batch171: the router has FOUR parallel statements of "which pages exist":
// the `pages` array (activate()'s allow-list), the `loaders` map (what a page
// actually loads), the nav links in the markup, and the page <section> ids.
// Any one of them can fall out of step, and the failure is silent in the worst
// way: a page missing from `pages` is simply never activated (blank screen, no
// error); a page missing from `loaders` returns Promise.resolve() and never
// fills in. Nothing throws, so no test noticed. Derive all four from the real
// sources and require them to agree.
cases.push(['every advertised page is routable, loadable and painted', async () => {
  const unique = (a) => [...new Set(a)];
  const declared = vm.runInContext('pages.slice()', context);
  const loaderKeys = Object.keys(vm.runInContext('loaders', context));
  // Read the other two from the page itself - never from a list written here.
  // Strip <style> and <script> by replacing them with same-length blanks so the
  // line numbers would still line up, then read the two sets from the markup.
  const markup = html
    .replace(/<style\b[\s\S]*?<\/style\s*>/gi, (s) => ' '.repeat(s.length))
    .replace(/<script\b[\s\S]*?<\/script\s*>/gi, (s) => ' '.repeat(s.length));
  const navHrefs = unique([...markup.matchAll(/<a\b[^>]*\bhref="#([\w-]+)"/g)].map(m => m[1]));
  const sectionIds = unique([...markup.matchAll(/<section\b[^>]*\bid="page-([\w-]+)"/g)].map(m => m[1]));

  ok(declared.length > 0, 'the router must declare at least one page');
  ok(navHrefs.length > 0, 'the nav must advertise at least one page');
  ok(sectionIds.length > 0, 'the main element must contain at least one page section');

  const missingLoader = declared.filter(p => !loaderKeys.includes(p));
  eq(missingLoader.join(','), '', 'a page in the allow-list with no loader never fills in');
  const extraLoader = loaderKeys.filter(p => !declared.includes(p));
  eq(extraLoader.join(','), '', 'a loader the allow-list cannot reach is dead code');
  const missingSection = declared.filter(p => !sectionIds.includes(p));
  eq(missingSection.join(','), '', 'an activated page with no <section> shows nothing');
  const missingNav = declared.filter(p => !navHrefs.includes(p));
  eq(missingNav.join(','), '', 'a page with no nav link cannot be reached by the operator');
  const orphanSection = sectionIds.filter(p => !declared.includes(p));
  eq(orphanSection.join(','), '', 'a <section> the router cannot activate is unreachable');
}]);

// batch172: api() returns r.json() with no guard. A 200 whose body is not
// valid JSON (a truncated response while the listener is restarting, a proxy
// that injects an HTML error page, a byte-level cut) makes fetch's json()
// throw a native SyntaxError. errMsg() passes anything without the "err."/"
// "auth." prefix straight through, so the operator sees browser English
// ("Unexpected end of JSON input") in a translated page - the one thing the
// comment above errMsg() says must never happen.
cases.push(['a malformed success body is reported as a network error, not browser English', async () => {
  const realFetch = sandbox.fetch;
  sandbox.fetch = async () => ({
    ok: true,
    status: 200,
    async json() { throw new SyntaxError('Unexpected end of JSON input'); },
    async text() { return '{"gateway":{"ipv4":"192.168.0.1"'; },
  });
  // Drive api() inside the vm so the thrown value and the message the operator
  // would read are both produced by the real code, in its own realm.
  const shown = await vm.runInContext(
    '(async () => { try { await api("/api/system"); return "<no throw>"; }' +
    ' catch (e) { return errMsg(e); } })()', context);
  sandbox.fetch = realFetch;
  eq(shown, sandbox.t('err.network'),
     `a malformed body must read as a network error, got: ${JSON.stringify(shown)}`);
}]);

// batch173: all three destructive pages asked the same three words:
// "Delete this entry?" - for a port mapping, a firewall entry and a rate limit
// alike. The row buttons already carry the entry in their accessible name
// (batch161), so a screen-reader user hears which one they are on; the
// confirmation dialog - the LAST chance to notice a mis-click - threw that away
// and asked the identical question every time. Derive the text from the row.
cases.push(['a delete confirmation names the entry it is about to remove', async () => {
  const seen = [];
  const realConfirm = sandbox.confirm;
  sandbox.confirm = (msg) => { seen.push(String(msg)); return false; };  // always cancel
  try {
    // Drive the real button, not the handler with invented arguments: the row
    // text reaches the dialog through the generated onclick string, and calling
    // delMapping(7) directly would bypass exactly the thing under test.
    const clickRow = async (tableId, prefix) => {
      const row = nodeFor('#' + tableId + ' tbody').children[0];
      const btn = row.querySelectorAll('button').find(b => b.textContent &&
        String(b.getAttribute('onclick') || '').startsWith(prefix));
      ok(btn, 'the row must expose a ' + prefix + ' button');
      await vm.runInContext(btn.getAttribute('onclick'), context);
    };
    portmapRules = [{ id: 7, proto: 'tcp', wan_port: 8080, lan_ip: '192.168.0.10', lan_port: 80 }];
    await sandbox.loadPortMap();
    await clickRow('pm-table', 'delMapping(');
    bansList = [{ id: 3, kind: 'mac', value: 'AA:BB:CC:DD:EE:FF' }];
    await sandbox.loadBans();
    await clickRow('ban-table', 'delBan(');
    ratelimitRules = [{ mac: 'AA:BB:CC:DD:EE:11', uplink_kbps: 100, downlink_kbps: 200 }];
    await sandbox.loadRateLimits();
    await clickRow('rl-table', 'delRateLimit(');
  } finally {
    sandbox.confirm = realConfirm;
  }
  eq(seen.length, 3, 'each delete must ask exactly once');
  // Every prompt has to contain the data of the row it is about; the shared
  // "Delete this entry?" tail alone is what this case exists to catch.
  ok(seen[0].includes('8080') && seen[0].includes('tcp'),
     `the port-mapping prompt must name the rule, got: ${JSON.stringify(seen[0])}`);
  ok(seen[1].includes('AA:BB:CC:DD:EE:FF'),
     `the firewall prompt must name the value, got: ${JSON.stringify(seen[1])}`);
  ok(seen[2].includes('AA:BB:CC:DD:EE:11'),
     `the rate-limit prompt must name the MAC, got: ${JSON.stringify(seen[2])}`);
  eq(new Set(seen).size, 3, 'the three prompts must not be identical');
}]);

// batch174: a successful add left every field exactly as it was. The obvious
// next action - click "Add rule" again because the form still looks filled in -
// re-sends the identical rule: the server refuses it as a duplicate (or stores a
// second copy), and the operator has no way to tell whether the first one
// landed, because the form still shows it. A successful submit must leave the
// form ready for the NEXT entry, not for a repeat of this one.
cases.push(['a successful add clears the form for the next entry', async () => {
  const setValues = (ids, v) => ids.forEach(id => { nodeFor('#' + id).value = v; });

  // Port mapping: three text fields, one select.
  nodeFor('#pm-add').disabled = false;
  setValues(['pm-wan', 'pm-lanip', 'pm-lanport'], '');
  nodeFor('#pm-wan').value = '8080';
  nodeFor('#pm-lanip').value = '192.168.0.10';
  nodeFor('#pm-lanport').value = '80';
  nodeFor('#pm-proto').value = 'tcp';
  await sandbox.addMapping();
  eq(nodeFor('#pm-wan').value, '',
     'the WAN port must be cleared after a successful add');
  eq(nodeFor('#pm-lanip').value, '',
     'the LAN IP must be cleared after a successful add');
  eq(nodeFor('#pm-lanport').value, '',
     'the LAN port must be cleared after a successful add');

  // Firewall: two fields.
  nodeFor('#ban-add').disabled = false;
  nodeFor('#ban-value').value = 'AA:BB:CC:DD:EE:FF';
  await sandbox.addBan();
  eq(nodeFor('#ban-value').value, '',
     'the value must be cleared after a successful block');

  // Rate limit: three fields.
  nodeFor('#rl-add').disabled = false;
  nodeFor('#rl-mac').value = 'AA:BB:CC:DD:EE:01';
  nodeFor('#rl-up').value = '100';
  nodeFor('#rl-down').value = '200';
  await sandbox.addRateLimit();
  eq(nodeFor('#rl-mac').value, '',
     'the MAC must be cleared after a successful limit');
  eq(nodeFor('#rl-up').value, '',
     'the uplink must be cleared after a successful limit');
  eq(nodeFor('#rl-down').value, '',
     'the downlink must be cleared after a successful limit');
}]);

// batch175: hitting [Edit] filled the three fields and set editingMac, but
// nothing on screen changed - the button still said "Limit" and nothing marked
// the row or the form as being in an edit. An operator who changed their mind
// had no way out: there was no cancel, and the only exits were to reload the
// page, to hand-edit all three fields, or to submit - and submitting would
// replace the rule they had just decided not to touch.
cases.push(['entering the rate-limit edit state is visible and cancellable', async () => {
  ratelimitRules = [{ mac: 'AA:BB:CC:DD:EE:22', uplink_kbps: 100, downlink_kbps: 200 }];
  await sandbox.loadRateLimits();

  sandbox.editRateLimit('AA:BB:CC:DD:EE:22');
  eq(nodeFor('#rl-mac').value, 'AA:BB:CC:DD:EE:22', 'edit fills the MAC');
  // 1. The submit button must announce what it will now do. "Limit" would
  //    silently replace an existing rule instead of adding one.
  // The button's label lives in its data-i18n attribute (applyI18n renders it);
  // asserting the KEY is what product code actually changes, and it does not
  // depend on the stub having walked the whole markup.
  eq(nodeFor('#rl-add').getAttribute('data-i18n'), 'set.save',
     'the button must say Save while editing, so a click is not read as "add another"');

  // 2. Escape must abandon the edit: fields cleared, button back to Limit, and
  //    the next submit must be a plain add (no replace_mac on the wire).
  const esc = nodeFor('#rl-mac').__on && nodeFor('#rl-mac').__on.keydown;
  ok(Array.isArray(esc) && esc.length > 0, 'the MAC field must listen for Escape');
  let prevented = false;
  for (const fn of esc) fn({ key: 'Escape', preventDefault() { prevented = true; } });
  ok(prevented, 'Escape must be consumed, not bubble to the page');

  eq(nodeFor('#rl-mac').value, '', 'cancelling clears the MAC');
  eq(nodeFor('#rl-up').value, '', 'cancelling clears the uplink');
  eq(nodeFor('#rl-down').value, '', 'cancelling clears the downlink');
  eq(nodeFor('#rl-add').getAttribute('data-i18n'), 'rl.limit',
     'the button must read Limit again once the edit is abandoned');

  const before = requests.length;
  nodeFor('#rl-add').disabled = false;
  nodeFor('#rl-mac').value = 'AA:BB:CC:DD:EE:33';
  nodeFor('#rl-up').value = '7';
  nodeFor('#rl-down').value = '8';
  await sandbox.addRateLimit();
  const posted = requests.slice(before).filter(r => r.method === 'POST' && r.path === '/api/ratelimit');
  eq(posted.length, 1, 'the add must be one POST');
  const body = JSON.parse(posted[0].body);
  eq(body.replace_mac, undefined,
     'after cancelling, the add must not carry the abandoned replace_mac');
}]);

// batch176: batch147 deliberately drops editingMac on every re-render so a stale
// edit context cannot modify a rule the operator stopped looking at. batch175
// then gave the edit state a visible half (the button switches to "Save"). The
// two halves disagree: after a re-render editingMac is null but the button still
// says Save and the fields still hold the old values - so pressing it does a
// PLAIN ADD of the rule that was being edited, creating a duplicate instead of
// modifying it. A mode that is half-reset is worse than one that is never reset.
cases.push(['a re-render leaves no half-open edit state behind', async () => {
  ratelimitRules = [{ mac: 'AA:BB:CC:DD:EE:44', uplink_kbps: 100, downlink_kbps: 200 }];
  await sandbox.loadRateLimits();
  sandbox.editRateLimit('AA:BB:CC:DD:EE:44');
  eq(nodeFor('#rl-add').getAttribute('data-i18n'), 'set.save', 'the edit is on');

  // Any re-render (navigating away and back, or the 3 s live poll) invalidates
  // the edit context.
  await sandbox.loadRateLimits();

  eq(nodeFor('#rl-add').getAttribute('data-i18n'), 'rl.limit',
     'the button must stop offering "Save" once the edit context is gone');
  eq(nodeFor('#rl-mac').value, '',
     'the fields of the abandoned edit must not stay behind');
  eq(nodeFor('#rl-up').value, '', 'the uplink must be cleared with the context');
  eq(nodeFor('#rl-down').value, '', 'the downlink must be cleared with the context');

  // Behavioural proof: the next submit is a plain add, carrying no replace_mac.
  const before = requests.length;
  nodeFor('#rl-add').disabled = false;
  nodeFor('#rl-mac').value = 'AA:BB:CC:DD:EE:44';
  nodeFor('#rl-up').value = '5';
  nodeFor('#rl-down').value = '6';
  await sandbox.addRateLimit();
  const posted = requests.slice(before).filter(r => r.method === 'POST' && r.path === '/api/ratelimit');
  eq(posted.length, 1, 'one POST');
  eq(JSON.parse(posted[0].body).replace_mac, undefined,
     'a re-rendered edit must not silently become a replacement');
}]);

// batch177: a successful save that moves the Web port returns early - it has to,
// because the old origin is about to disappear and the follow-up read would hit
// a dead listener. But that early return also skipped the snapshot refresh, so
// settingsSnapshot kept the PRE-save values. The dirty badge then showed
// "unsaved changes" for a configuration that had just been stored, and the
// operator - who is at that moment being told to move to a new URL - sees a
// form claiming their work is unsaved.
cases.push(['a port-move save still ends the dirty state it created', async () => {
  configPayload = JSON.parse(JSON.stringify(SERVER_CONFIG));
  await sandbox.loadSettings(true);
  eq(sandbox.syncDirty(), false, 'a freshly loaded form is clean');

  // Change the port so the save takes the "the console moved" exit.
  nodeFor('#set-webport').value = '9090';
  eq(sandbox.syncDirty(), true, 'editing a field must mark the draft dirty');

  const before = requests.length;
  await sandbox.saveSettings();
  const posted = requests.slice(before).filter(r => r.method === 'POST' && r.path === '/api/config');
  eq(posted.length, 1, 'the save must be sent');
  eq(JSON.parse(posted[0].body).web.port, 9090, 'with the edited port');

  eq(sandbox.syncDirty(), false,
     'a save that succeeded must clear the dirty badge, even when it returns early for a port move');
}]);

// batch179: the page contains no <form> element at all - the four editing areas
// are plain <div class="row">. So pressing Enter in any of their inputs does
// nothing: a keyboard operator has to fill the fields, then Tab all the way to
// the submit button before the entry goes out. Every other desktop form accepts
// Enter as "submit what I just typed"; this one silently swallows it.
cases.push(['Enter submits the add forms instead of doing nothing', async () => {
  const pressEnter = (id) => {
    const el = nodeFor('#' + id);
    const handlers = (el.__on && el.__on.keydown) || [];
    ok(handlers.length > 0, id + ' must listen for keys');
    let prevented = false;
    for (const fn of handlers) fn({ key: 'Enter', preventDefault() { prevented = true; } });
    return prevented;
  };

  // Port mapping: three fields; Enter from any of them must submit once.
  portmapRules = [];
  nodeFor('#pm-add').disabled = false;
  nodeFor('#pm-wan').value = '8080';
  nodeFor('#pm-lanip').value = '192.168.0.10';
  nodeFor('#pm-lanport').value = '80';
  let before = requests.length;
  ok(pressEnter('pm-lanport'), 'Enter must be consumed, not left to the browser');
  await flush();
  eq(requests.slice(before).filter(r => r.method === 'POST' && r.path === '/api/portmap').length, 1,
     'Enter in the port-mapping row must add exactly one rule');

  // Firewall.
  bansList = [];
  nodeFor('#ban-add').disabled = false;
  nodeFor('#ban-value').value = 'AA:BB:CC:DD:EE:99';
  before = requests.length;
  ok(pressEnter('ban-value'), 'Enter must be consumed in the firewall row');
  await flush();
  eq(requests.slice(before).filter(r => r.method === 'POST' && r.path === '/api/bans').length, 1,
     'Enter in the firewall row must block exactly one entry');

  // Rate limit.
  ratelimitRules = [];
  nodeFor('#rl-add').disabled = false;
  nodeFor('#rl-mac').value = 'AA:BB:CC:DD:EE:77';
  nodeFor('#rl-up').value = '10';
  nodeFor('#rl-down').value = '20';
  before = requests.length;
  ok(pressEnter('rl-down'), 'Enter must be consumed in the rate-limit row');
  await flush();
  eq(requests.slice(before).filter(r => r.method === 'POST' && r.path === '/api/ratelimit').length, 1,
     'Enter in the rate-limit row must apply exactly one limit');
}]);

// batch179 (settings half): the settings form has twenty-odd fields and the same
// no-<form> problem. Its Enter handling must be derived from SET_FIELDS, because
// a hand-written list of ids goes stale the moment a field is added - and the
// staleness is silent (the new field simply ignores Enter).
cases.push(['Enter submits the settings form from any of its numeric fields', async () => {
  configPayload = JSON.parse(JSON.stringify(SERVER_CONFIG));
  await sandbox.loadSettings(true);

  const pressEnter = (id) => {
    const el = nodeFor('#' + id);
    const handlers = (el.__on && el.__on.keydown) || [];
    ok(handlers.length > 0, id + ' must answer Enter');
    let prevented = false;
    for (const fn of handlers) fn({ key: 'Enter', preventDefault() { prevented = true; } });
    return prevented;
  };

  // A field the hand-written list would most likely have missed: the DHCPv6
  // lease seconds, near the end of SET_FIELDS.
  nodeFor('#set-dhcp6-lease').value = '3600';
  const before = requests.length;
  ok(pressEnter('set-dhcp6-lease'), 'Enter must be consumed, not left to the browser');
  await flush();
  eq(requests.slice(before).filter(r => r.method === 'POST' && r.path === '/api/config').length, 1,
     'Enter in a settings field must save exactly once');

  // A <select> is not wired: Enter belongs to the control there.
  eq(((nodeFor('#set-mode').__on || {}).keydown || []).length, 0,
     'Enter must not be hijacked on a select');
}]);

for (const [name, fn] of cases) {
  await run(name, fn);
}

// batch209: a test suite must not be able to shrink silently. Deleting a case
// left the gate printing OK with a smaller count - the count is reported but
// never checked, so the suite could erode one case at a time all the way to
// zero while every run stayed green. This floor makes a deletion fail loudly.
// Raise it when adding cases; the message says exactly what to do.
//
// The number is a FLOOR, not an equality: adding cases must never require
// editing it, only removing them.
const MIN_CASES = 86;
if (cases.length < MIN_CASES) {
  console.error(`FAIL ${NAME}: only ${cases.length} case(s) are registered, but at least ${MIN_CASES} are required.`);
  console.error('  A case was deleted (or never registered). Restore it, or - if the deletion was');
  console.error('  intentional - lower MIN_CASES in the same commit so the removal is reviewed.');
  process.exit(1);
}

if (failures.length) {
  console.error(`FAIL ${NAME}: ${failures.length} case(s) failed:`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.log(`OK ${NAME} (${cases.length} console flow case(s) driven through the real inline script)`);
