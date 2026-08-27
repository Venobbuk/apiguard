'use strict';
// P5b — VM SENSOR server module. Rotating pool of polymorphic VMs (P0-P4 proven), each served as a static
// asset; verify a client's VM-token in O(1) via the in-memory baseline (NEVER shipped).
//   Integrity (P1): baseline_i = fnv( toString(vm_i) + NATIVE ). Node V8 and browser V8 normalize
//   Function.prototype.toString IDENTICALLY (VERIFIED), incl. JSON.parse's native string — so the server
//   self-computes the exact seed a CLEAN browser folds. A hooked/instrumented client folds a different seed
//   -> wrong token -> mismatch. Binding: the token folds inputsFor(nonce,seq) -> a forged counter mismatches.
//   POOL MODEL: init() prefers a PRE-BUILT, OBFUSCATED disk pool (apiguard/vmpool/<version>/, made by
//   vm-build-pool.cjs — obf coat P4 + manifest baselines); if absent it falls back to an in-memory PLAINTEXT
//   build so the sensor still works in dev. Either way expected() uses the PLAINTEXT gen (obf is transparent,
//   P4), and the baseline matches whichever source (plaintext or obf) the client actually folds.
const crypto = require('crypto'), fs = require('fs'), path = require('path');
const { generate } = require('./vm-gen.cjs');

const fnv = s => { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; };
const NATIVE = Function.prototype.toString.call(JSON.parse);  // "function parse() { [native code] }" — node===browser (verified)
const PROGRAM = [
  { op:'LOADIN',in:0,r:0 },{ op:'LOADIN',in:1,r:1 },{ op:'LOADIN',in:2,r:2 },
  { op:'PUSHIMM',r:3,v:0x9E37 },{ op:'XOR',a:0,b:3 },{ op:'ADDMUL',a:0,b:1 },
  { op:'ROTL',a:0,b:2 },{ op:'XOR',a:0,b:2 },{ op:'FOLD_INTEGRITY',r:0 },{ op:'OUT',r:0 },
];
function seedOf(version, i){ return crypto.createHash('sha256').update(version + '|' + i).digest('hex'); }
function inputsFor(nonce, seq){ return [ fnv(String(nonce || '')) & 0xffff, (seq | 0) & 0xffff, 0x55 ]; }

let POOL = null;
// in-memory PLAINTEXT build (dev fallback): baseline from the plaintext source.
function buildMem(version, N){
  const assets = new Array(N), verifiers = new Array(N), gens = new Array(N);
  for (let i = 0; i < N; i++){
    const g = generate(seedOf(version, i), PROGRAM);
    assets[i] = 'window.__ag_vm=' + g.src + ';window.__ag_bc=[' + Array.from(g.bc).join(',') + '];window.__ag_vi=' + i + ';';
    gens[i] = g;
    verifiers[i] = fnv(((0, eval)(g.src)).toString() + NATIVE) >>> 0;
  }
  return { version, N, assets, verifiers, gens, obf: false };
}
// load a PRE-BUILT OBFUSCATED disk pool: assets + manifest baselines; re-derive gens for expected().
function loadDisk(version){
  const dir = path.join(__dirname, 'vmpool', version);
  const mani = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const N = mani.N, assets = new Array(N), verifiers = new Array(N), gens = new Array(N);
  for (let i = 0; i < N; i++){
    assets[i] = fs.readFileSync(path.join(dir, 'vm-' + i + '.js'), 'utf8');
    gens[i] = generate(seedOf(version, i), PROGRAM);   // plaintext gen for expected() (obf is transparent)
    verifiers[i] = mani.baselines[i] >>> 0;            // baseline of the OBFUSCATED source (what the client folds)
  }
  return { version, N, assets, verifiers, gens, obf: true };
}
// ROTATION GRACE (2026-08-26): on a rebuild to a NEW version, keep the PREVIOUS pool verifiable for a window
// so already-loaded clients (still running the prev VM) are not blocked under enforce until they reload.
let POOL_PREV = null, _graceUntil = 0;
const GRACE_MS = 15 * 60 * 1000;
const _verPools = new Map();   // version -> lazily disk-loaded pool, for cross-rollover verify grace
let _verSecret = '';
const VER_GRACE_DAYS = 3;      // accept a REAL client still folding an asset up to this many dated versions back
function init(version, N, secret){
  const _new = (() => { try { return loadDisk(version); } catch (e) { return buildMem(version, N); } })();
  _new.secret = secret || ''; _verSecret = _new.secret;
  if (POOL && POOL.version !== _new.version) { POOL_PREV = POOL; _graceUntil = Date.now() + GRACE_MS; }   // rotated -> grace the old pool
  POOL = _new;
  return { version: POOL.version, N: POOL.N, obf: POOL.obf };
}
function _loadVer(version){
  if (POOL && POOL.version === version) return POOL;
  if (_verPools.has(version)) return _verPools.get(version);
  let p = null; try { p = loadDisk(version); p.secret = _verSecret; } catch (e) { p = null; }
  _verPools.set(version, p); if (_verPools.size > 8) _verPools.delete(_verPools.keys().next().value);
  return p;
}
function _recentVersions(){
  const out = []; if (!POOL || !/^[0-9]{8}$/.test(String(POOL.version || ''))) return out;
  const v = String(POOL.version), base = Date.UTC(+v.slice(0, 4), +v.slice(4, 6) - 1, +v.slice(6, 8));
  for (let k = 1; k <= VER_GRACE_DAYS; k++) out.push(new Date(base - k * 86400000).toISOString().slice(0, 10).replace(/-/g, ''));
  return out;   // recent dated versions BEFORE the current one
}
function _idxFor(pool, sessionKey){ return fnv(pool.secret + '|' + pool.version + '|' + String(sessionKey || '')) % pool.N; }
function _expPool(pool, i, inputs){ return (pool && i >= 0 && i < pool.N) ? (pool.gens[i].expected(inputs, pool.verifiers[i]) >>> 0) : null; }
// verify a session's token against the CURRENT pool, or the PREVIOUS pool during a rotation grace window.
// Behaviour is identical to verify(indexFor(key),..) whenever no rotation has happened (POOL_PREV null).
function verifySession(sessionKey, inputs, clientToken){
  const tok = clientToken >>> 0;
  if (POOL) { const e = _expPool(POOL, _idxFor(POOL, sessionKey), inputs); if (e != null && e === tok) return true; }
  if (POOL_PREV && Date.now() < _graceUntil) { const e = _expPool(POOL_PREV, _idxFor(POOL_PREV, sessionKey), inputs); if (e != null && e === tok) return true; }
  // CROSS-ROLLOVER grace: a real client may still fold a recent dated version's asset (daily version + a
  // restart orphans POOL_PREV). Try the last VER_GRACE_DAYS on-disk versions. A FORGED client fails ALL
  // versions, so this rescues only legit staleness; replay stays gated by the P5a monotonic counter.
  for (const ver of _recentVersions()){
    const p = _loadVer(ver); if (!p) continue;
    const e = _expPool(p, _idxFor(p, sessionKey), inputs); if (e != null && e === tok) return true;
  }
  return false;
}
function indexFor(sessionKey){ return POOL ? (fnv(POOL.secret + '|' + POOL.version + '|' + String(sessionKey || '')) % POOL.N) : -1; }
function asset(i){ return (POOL && i >= 0 && i < POOL.N) ? POOL.assets[i] : null; }
function expected(i, inputs){ if (!POOL || i < 0 || i >= POOL.N) return null; return POOL.gens[i].expected(inputs, POOL.verifiers[i]) >>> 0; }
function verify(i, inputs, clientToken){ const e = expected(i, inputs); return e != null && e === (clientToken >>> 0); }
module.exports = { init, asset, expected, verify, verifySession, indexFor, inputsFor, fnv, NATIVE, PROGRAM, seedOf,
  get version(){ return POOL && POOL.version; }, get N(){ return POOL && POOL.N; }, get obf(){ return POOL && POOL.obf; } };
