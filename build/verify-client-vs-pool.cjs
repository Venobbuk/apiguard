'use strict';
// verify-client-vs-pool.cjs — deep pre-swap check for a VM-sensor pool.
//
// Executes your CLIENT build against EVERY VM asset of the given pool(s), exactly as a browser would
// (eval the served asset, then drive the client's guarded fetch path) through the REAL guard. Each user
// is mapped to ONE asset, so a client/pool mismatch that throws on a single asset is invisible to an
// ordinary smoke test ("some users can't load the site") — this catches it before the pool goes live.
//
// On a clean pass it writes the `verified` marker into each pool dir; vmsensor.loadDisk refuses to serve
// a pool without that marker (falling back to the always-consistent plaintext build). So this doubles as
// the gate-writer if you prefer a deeper check than vm-build-pool.cjs's build-time assertion.
//
//   Usage:  GUARD_SECRET=... VM_SECRET=... node build/verify-client-vs-pool.cjs <client.js> <poolVersion>...
//   Env:    GUARD_SECRET (required)  VM_SECRET (required)  POW_ALGO=sha256|argon2id (default sha256)
//           POOL_N (default 256)     ORIGIN (default https://localhost)
//   Exit:   0 = every asset passed (+markers written) · 1 = failures (listed) · 3 = NO VERDICT (never fired)
const fs = require('fs'), vm = require('vm'), path = require('path');
const DIR = path.resolve(__dirname, '..');            // repo root (this file lives in build/)

const clientFile = process.argv[2]; const versions = process.argv.slice(3);
if (!clientFile || !versions.length) { console.error('usage: GUARD_SECRET=.. VM_SECRET=.. node build/verify-client-vs-pool.cjs <client.js> <poolVersion>...'); process.exit(3); }
const secret = process.env.GUARD_SECRET, vmsec = process.env.VM_SECRET;
if (!secret || !vmsec) { console.error('error: GUARD_SECRET and VM_SECRET env vars are required (never hardcode them)'); process.exit(3); }
process.env.POW_ALGO = process.env.POW_ALGO || 'sha256';
const POOL_N = parseInt(process.env.POOL_N || '256', 10);
const ORIGIN = process.env.ORIGIN || 'https://localhost';

const apiguard = require(path.join(DIR, 'core.js'));
let buildChallengers = null; try { ({ buildChallengers } = require(path.join(DIR, 'challengers.js'))); } catch (_) { /* optional */ }
let hashwasm = null; try { hashwasm = require('hash-wasm'); } catch (_) { /* only needed for POW_ALGO=argon2id */ }
const G = apiguard({ secret, protect: '/api/', powBits: { normal: 16, max: 28 },
  risk: { powAt: 30, sliderAt: 55, captchaAt: 70, blockAt: 90, churnThreshold: 15, fanoutThreshold: 20 },
  challengers: buildChallengers ? buildChallengers(secret) : {} });
const vs = require(path.join(DIR, 'vmsensor.js'));
const src = fs.readFileSync(clientFile, 'utf8');
const { origin, hostname } = new URL(ORIGIN);

function stubWin(asset, ident) {
  const ctxOf = (p, h) => ({ method: 'GET', path: p, ip: ident.ip, headers: Object.assign({}, h || {}), fingerprint: ident.fp });
  const win = { hashwasm, TextEncoder, TextDecoder, Uint8Array, Promise, setTimeout, clearTimeout, console: { log() {}, warn() {}, error() {} }, performance: { now: () => Date.now() }, crypto: require('crypto').webcrypto, WebAssembly, JSON, Math, String, Array, Object, Function, parseInt, parseFloat, isNaN, Number, Date, RegExp, Error, TypeError, encodeURIComponent, decodeURIComponent,
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'), atob: (s) => Buffer.from(s, 'base64').toString('binary'),
    localStorage: { _: {}, getItem(k) { return this._[k] == null ? null : this._[k]; }, setItem(k, v) { this._[k] = String(v); }, removeItem(k) { delete this._[k]; } }, sessionStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    location: { pathname: '/', href: origin + '/', hostname: hostname, origin: origin },
    navigator: { userAgent: 'Mozilla/5.0 Chrome/128', webdriver: false, hardwareConcurrency: 8, languages: ['en'], platform: 'Win32', plugins: { length: 3 } }, screen: { width: 1920, height: 1080, colorDepth: 24 },
    document: { createElement: (t) => ({ tag: t, style: {}, getContext: () => null, setAttribute() {}, appendChild() {}, addEventListener() {} }), head: { appendChild() {} }, body: { appendChild() {} }, documentElement: { appendChild() {} }, addEventListener() {}, querySelector: () => null, visibilityState: 'visible' }, addEventListener() {}, removeEventListener() {} };
  win.window = win; win.self = win; win.globalThis = win;
  const headersOf = (init) => { const h = {}; const H = (init && init.headers) || {}; for (const k in H) h[k.toLowerCase()] = String(H[k]); return h; };
  const resp = (status, obj, text) => ({ ok: status < 400, status, headers: { get: () => null }, json: () => Promise.resolve(obj), text: () => Promise.resolve(text != null ? text : JSON.stringify(obj)), clone() { return this; } });
  win.fetch = function (u, init) { const p = String(u).replace(/^https?:\/\/[^/]+/, '');
    if (p.startsWith('/apiguard/vm/mine.js')) return Promise.resolve(resp(200, null, asset));
    if (p.startsWith('/__ag/challenge')) { const tgt = decodeURIComponent(p.split('path=')[1] || ''); return Promise.resolve(resp(200, G.challenge(ctxOf(tgt, headersOf(init))))); }
    if (p.startsWith('/api/')) { const d = G.verdict(ctxOf(p, headersOf(init))); const fin = (v) => { if (v.allow) return resp(200, { ok: true }); const b = { action: v.action, error: v.action, reasons: v.reasons }; if (v.challenge) { b.challenge = v.challenge; b.token = v.token; b.needChallenge = true; } return resp(v.status || 401, b); }; return (d && d.then) ? d.then(fin) : Promise.resolve(fin(d)); }
    return Promise.resolve(resp(404, {})); };
  return win;
}

(async () => {
  let tested = 0; const fails = [];
  for (const ver of versions) {
    const info = vs.init(ver, POOL_N, vmsec); const N = (info && info.N) || POOL_N;
    let verFails = 0;
    for (let i = 0; i < N; i++) {
      const asset = vs.asset(i); if (!asset) { fails.push(ver + '#' + i + ': no asset'); verFails++; continue; }
      const win = stubWin(asset, { ip: '203.0.113.' + (1 + (i % 250)), fp: 'F' + ver + i });
      try { vm.runInNewContext(src, win, { timeout: 10000, filename: 'client' }); } catch (e) { fails.push(ver + '#' + i + ': boot ' + e.message.slice(0, 60)); verFails++; continue; }
      await new Promise(r => setTimeout(r, 40)); tested++;
      let err = null;
      try { const r = await Promise.race([win.fetch('/api/watchdog').then(r => r.status, e => 'REJ ' + (e && e.message)), new Promise(r => setTimeout(() => r('TIMEOUT'), 8000))]); if (typeof r === 'string') err = r; }
      catch (e) { err = 'THROW ' + (e && e.message); }
      if (err) { fails.push(ver + '#' + i + ': ' + String(err).slice(0, 70)); verFails++; }
    }
    // clean pass -> write the marker vmsensor.loadDisk requires, but ONLY for a real disk pool. If no
    // vmpool/<ver>/ dir exists, init() ran against the in-memory plaintext fallback (which needs no marker)
    // — report the clean pass without a spurious marker-write failure.
    if (!verFails) {
      const pdir = path.join(DIR, 'vmpool', ver);
      if (fs.existsSync(pdir)) { try { fs.writeFileSync(path.join(pdir, 'verified'), new Date().toISOString() + '\n'); } catch (e) { fails.push(ver + ': marker write failed ' + (e && e.message)); } }
      else console.error('note: no disk pool dir for ' + ver + ' — verified the in-memory fallback build (no marker written)');
    }
  }
  console.log(JSON.stringify({ client: clientFile, versions, tested, failures: fails.length, examples: fails.slice(0, 10) }));
  if (!tested) { console.log('NO VERDICT — instrument never fired'); process.exit(3); }
  process.exit(fails.length ? 1 : 0);
})();
