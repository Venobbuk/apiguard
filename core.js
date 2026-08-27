'use strict';
/*
 * apiguard/core.js  — v1
 * Framework-agnostic API-protection core. Node built-in `crypto` ONLY. Zero external deps.
 *
 * v1 scope (SPEC.md §7): rotating signed token + rate-limit + risk scorer + invisible
 * adaptive proof-of-work. NO WASM (v2), NO interactive challenge widgets (v3).
 *
 * Factory: apiguard(config) -> guard = {
 *     verdict(ctx)      decide allow/pow/block for an incoming protected request
 *     challenge(ctx)    mint a {token, challenge} pair for the /__ag/challenge endpoint
 *     mint: { token, challenge, pow }   low-level mint/verify helpers (also used by tests)
 *     verifyToken, verifyPow, solvePow, tierOf, scoreRisk, store, config
 * }
 * ctx = { method, path, ip, headers, fingerprint }
 *
 * Adapters (adapter-http.js / adapter-express.js) are lazily attached as guard.block /
 * guard.express when present, so core stays usable standalone and the adapters stay
 * independently requireable.
 */

const crypto = require('crypto');

// Optional behavioral rebroadcast scorer (pure, dependency-free). Lazily/defensively required so core
// stays usable if the file is absent — scoreRebroadcast then simply abstains (fail-safe, additive).
let rebroadcastMod = null;
try { rebroadcastMod = require('./rebroadcast'); } catch (_) { /* optional */ }

// ----------------------------------------------------------------------------
// small crypto / encoding helpers
// ----------------------------------------------------------------------------
function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64url(s) {
  return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}
function sha256(msg) {
  return crypto.createHash('sha256').update(msg).digest(); // Buffer(32)
}
// count leading zero BITS across a byte buffer (hashcash difficulty measure)
function leadingZeroBits(buf) {
  let count = 0;
  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i];
    if (byte === 0) { count += 8; continue; }
    let mask = 0x80;
    while (mask && (byte & mask) === 0) { count++; mask >>= 1; }
    break;
  }
  return count;
}

// ----------------------------------------------------------------------------
// ENV-BINDING (anti-lift) — additive. See SPEC_APIGUARD_30ALGO_ENVBIND.md.
// ORDER-LOCKED pool of probe ids, MUST stay byte-identical to client.js ENV_PROBE_IDS (v1).
// The server never runs a probe (it is not a browser); it only (a) SELECTS which subset the client
// must run — a per-nonce pseudo-random ORDER+SUBSET seeded by HMAC(secret,nonce) — and (b) SCORES the
// returned outputs structurally: arity, sig-binding to the nonce, a known-bad DENYLIST of tokens only
// a headless/node stub emits, cross-probe self-consistency, low-entropy, and anti-replay. Automation/
// tamper tokens DOMINATE the weight. Everything is fail-safe and, by default, OBSERVE-ONLY (logs, never
// blocks) — the reveal-gate lesson: never false-block real users; tune from real logs before enforcing.
const ENV_POOL_IDS = [
  'wd','tGetCtx','tAddEv','tToString','chromeShape','permInconsist','glSoftware','xConsist','stackShape',
  'langsEmpty','hcMem','canvas2d','canvasEmptyChk','glVendor','glRenderer','glParams','glExts',
  'glShaderPrec','glRenderHash','webgpu','audioHash','audioParams','perfRes','perfJitter','mathULP',
  'errStack','apiBitmap','jsQuirks','intlHash','screenDPR','tz','uaCH','prefers','codecs','measureText',
  'cssComputed','storageSurface','connection','plugins','touchPointer','perfMemConsist','dateLocale',
  'glSpoof', // FIX 1 (2026-08-25): appended (order-locked; client ENV_PROBES has glSpoof as its LAST id)
];
const ENV_SUBSET_DEFAULT = 8; // operator-LOCKED 2026-08-13: 8 of the pool per challenge.
// FIX 2 (2026-08-25): pin the highest-signal, lowest-false-positive probes into EVERY subset so the
// 8-of-N sampling can never dilute them below threshold. Any pinned id absent from the pool is ignored.
const ENV_PINNED_IDS = ['wd', 'glSoftware', 'chromeShape', 'stackShape', 'glSpoof'];
// Known-bad output tokens -> weights. These are values ONLY a headless/node/stub or a tampered runtime
// produces; a real browser emits their clean counterparts ('wd0','tg0','glHW','ce0','st0','pm0','xc0'…).
// Tamper/automation dominate. Tokens like 'gpu0','chNA','auNA','glNA','cnNA' are COMMON on real browsers
// and are deliberately NOT here (would false-block). NA/absence is never itself an anomaly.
const ENV_DENY = {
  wd1: 60,                                   // FIX 2 (2026-08-25): navigator.webdriver===true is NEVER a
                                             //   real-user value (only WebDriver/CDP sets it) -> hard-
                                             //   escalate: >=envDenyThreshold(55) so it STANDS ALONE.
                                             //   (was 35, which needed a 2nd tell in the same 8-subset.)
  glSpoof: 60,                               // FIX 1 (2026-08-25): hardware GPU string over a software
                                             //   capability vector = internal contradiction a real GPU
                                             //   can never produce -> stands alone (near-zero false pos).
  tg1: 30, ta1: 30, ts1: 28,                 // native-fn tamper (getContext/addEventListener/toString)
  glSW: 30, glLLVM: 30, glSOFT: 26,          // software GL renderer
  cvEmpty: 30, ce1: 30,                      // empty canvas
  st1: 30,                                   // node-shaped error stack
  pm1: 15,                                   // permission API inconsistency
  cr0: 14,                                   // UA claims Chrome but window.chrome missing
  xc1: 16,                                   // UA/GL/platform cross contradiction
  lg1: 12,                                   // empty navigator.languages
  hc1: 10,                                   // hardwareConcurrency == 0
  pmem1: 8,                                  // Chrome UA without performance.memory
};
// outputs that indicate "probe could not run / stubbed" — many of these together = a stub tell.
const ENV_NULLISH = { nil: 1, err: 1, to: 1, perr: 1, unk: 1, '': 1, stub: 1 };

// Deterministic per-nonce subset+order. Uses a keyed hash (caller passes hmac) so only the server can
// compute it; returns `k` DISTINCT ids from ENV_POOL_IDS in a nonce-shuffled order. Reproducible on
// both emission (challenge) and verification (verdict) for the same nonce.
function envSeqFromNonce(hmac, nonce, k) {
  k = Math.max(1, Math.min(ENV_POOL_IDS.length, k || ENV_SUBSET_DEFAULT));
  let pool = null;
  try {
    const idx = ENV_POOL_IDS.map((_, i) => i);
    // Fisher-Yates driven by a keyed keystream over the nonce (extend the hash as needed).
    let ks = hmac('envseq|' + String(nonce));
    let p = 0;
    const nextByte = () => {
      if (p >= ks.length) { ks = hmac('envseq|' + String(nonce) + '|' + p); p = 0; }
      return ks[p++];
    };
    for (let i = idx.length - 1; i > 0; i--) {
      const j = nextByte() % (i + 1);
      const t = idx[i]; idx[i] = idx[j]; idx[j] = t;
    }
    // FIX 2 (2026-08-25): PIN the highest-signal probes into every subset, then fill the remaining
    // slots from the nonce-shuffled pool (skipping already-pinned ids). Pinned-first ordering is
    // reproduced identically on emission (challenge) and verification (scoreEnv), so arity/sig stay
    // consistent. Result: wd/glSoftware/chromeShape/stackShape/glSpoof run on EVERY request -> a single
    // unambiguous automation tell (wd1=60 or glSpoof=60) crosses threshold on its own, no dilution.
    const pinned = ENV_PINNED_IDS.filter((id) => ENV_POOL_IDS.indexOf(id) >= 0).slice(0, k);
    const pinnedSet = new Set(pinned);
    const fillers = idx.map((i) => ENV_POOL_IDS[i]).filter((id) => !pinnedSet.has(id));
    pool = pinned.concat(fillers).slice(0, k);
  } catch (e) { pool = ENV_POOL_IDS.slice(0, k); }
  return pool;
}

// ----------------------------------------------------------------------------
// pluggable store — in-memory default. Redis adapter can implement this same
// surface (takeToken / hasNonce / addNonce / track / recordFail / sweep).
// ----------------------------------------------------------------------------
function MemoryStore(opts) {
  opts = opts || {};
  const windowMs = opts.windowMs || 60000;   // churn / fanout / rate observation window
  const failDecayMs = opts.failDecayMs || 300000; // failed-challenge memory decays after 5 min idle
  const loginFailDecayMs = opts.loginFailDecayMs || 600000; // failed-LOGIN memory decays after 10 min idle
  const buckets = new Map();     // rateId -> { tokens, last }
  const nonces = new Map();      // nonce  -> expiresAt
  const envNonces = new Map();   // #1: nonce -> expiresAt for tokens minted UNDER an env demand (needEnv)
  const identities = new Map();  // ip     -> { fps:Map, paths:Map, events:[], failCount, failResetAt }

  function ident(ip) {
    let d = identities.get(ip);
    if (!d) { d = { fps: new Map(), paths: new Map(), events: [], failCount: 0, failResetAt: 0, solvedUntil: 0, badUntil: 0, loginFailCount: 0, loginFailResetAt: 0, pat: [], envBoundUntil: 0, envSig: null }; identities.set(ip, d); }
    if (!d.pat) d.pat = []; // ADDITIVE: back-fill for any pre-existing identity object shape
    if (d.envBoundUntil === undefined) { d.envBoundUntil = 0; d.envSig = null; } // ADDITIVE back-fill (env-session grant)
    return d;
  }
  function prune(map, cutoff) {
    for (const [k, ts] of map) if (ts < cutoff) map.delete(k);
  }

  return {
    // --- token bucket (per identity) --------------------------------------
    takeToken(id, capacity, refillPerMs, now) {
      let b = buckets.get(id);
      if (!b) { b = { tokens: capacity, last: now }; buckets.set(id, b); }
      const elapsed = now - b.last;
      b.tokens = Math.min(capacity, b.tokens + elapsed * refillPerMs);
      b.last = now;
      if (b.tokens >= 1) { b.tokens -= 1; return { allowed: true, remaining: b.tokens, capacity }; }
      return { allowed: false, remaining: b.tokens, capacity };
    },

    // --- replay nonce set (peek + burn are SEPARATE on purpose) -----------
    hasNonce(nonce, now) {
      const exp = nonces.get(nonce);
      if (exp === undefined) return false;
      if (exp < now) { nonces.delete(nonce); return false; }
      return true;
    },
    addNonce(nonce, expiresAt) { nonces.set(nonce, expiresAt); },
    // #1 (2026-08-25): mark/query a token nonce minted UNDER an env demand (needEnv true) — to catch a
    // client that got the env block but stripped x-ag-env (the only way to dodge glSpoof).
    markEnvNonce(nonce, expiresAt) { envNonces.set(nonce, expiresAt); },
    wasEnvNonce(nonce, now) { const e = envNonces.get(nonce); if (e == null) return false; if (e <= now) { envNonces.delete(nonce); return false; } return true; },
    // #1: continuous-dodge timer. noteEnvDodge returns ms since the streak's first dodge (starts it if unset);
    // clearEnvDodge resets it. Only a PERSISTENT stripper accrues past the grace; a transient timeout resets.
    noteEnvDodge(ip, now) { const d = ident(ip); if (!d.envDodgeSince) d.envDodgeSince = now; return now - d.envDodgeSince; },
    clearEnvDodge(ip) { const d = identities.get(ip); if (d && d.envDodgeSince) d.envDodgeSince = 0; },

    // --- risk tracking -----------------------------------------------------
    track(ip, ev) {
      const d = ident(ip);
      const cutoff = ev.ts - windowMs;
      prune(d.fps, cutoff);
      prune(d.paths, cutoff);
      if (ev.fingerprint != null) d.fps.set(ev.fingerprint, ev.ts);
      if (ev.path != null) d.paths.set(ev.path, ev.ts);
      d.events.push(ev.ts);
      while (d.events.length && d.events[0] < cutoff) d.events.shift();
      if (d.failResetAt && ev.ts > d.failResetAt) d.failCount = 0; // decay
      return {
        distinctFingerprints: d.fps.size,
        distinctPaths: d.paths.size,
        rateInWindow: d.events.length,
        failCount: d.failCount,
        solvedUntil: d.solvedUntil,
        badUntil: d.badUntil,
      };
    },
    recordFail(ip, now) {
      const d = ident(ip);
      if (d.failResetAt && now > d.failResetAt) d.failCount = 0;
      d.failCount += 1;
      d.failResetAt = now + failDecayMs;
      return d.failCount;
    },
    // NEW (anti-rebroadcast): a lightweight per-identity request-pattern ring — {ts,path} of recent
    // protected hits, capped at `maxEvents` and window-pruned. Mirrors track() but keeps the raw
    // inter-arrival TIMES + paths so rebroadcast.js can measure cadence/fan-out/repeat-coverage. Cheap:
    // a bounded array push + shift. Never throws on shape; back-fills d.pat for old identity objects.
    trackPattern(ip, ev, maxEvents) {
      const d = ident(ip);
      const cap = maxEvents || 512;
      d.pat.push({ ts: ev.ts, path: ev.path });
      const cutoff = ev.ts - windowMs;
      while (d.pat.length && d.pat[0].ts < cutoff) d.pat.shift();
      if (d.pat.length > cap) d.pat.splice(0, d.pat.length - cap);
      return d.pat.length;
    },
    // read-only: the in-window {ts,path} events for an identity (does NOT create one). Used by
    // guard.scoreRebroadcast; returns [] for an unknown identity so the scorer simply abstains.
    patternEvents(ip, now) {
      const d = identities.get(ip);
      if (!d || !d.pat) return [];
      const cutoff = now - windowMs;
      return d.pat.filter((e) => e.ts >= cutoff);
    },
    // NEW (login boundary): a SEPARATE failed-LOGIN counter per IP, independent of the interactive
    // challenge failCount above. The host calls recordLoginFail on a wrong password/passkey. Mirrors
    // recordFail with its own decay window so a burst of bad logins raises the login-captcha gate
    // WITHOUT polluting the API-tier fail signal (which is about failed apiguard challenges, not creds).
    recordLoginFail(ip, now) {
      const d = ident(ip);
      if (d.loginFailResetAt && now > d.loginFailResetAt) d.loginFailCount = 0;
      d.loginFailCount += 1;
      d.loginFailResetAt = now + loginFailDecayMs;
      return d.loginFailCount;
    },
    // read-only peek — does NOT create/track an identity; applies the decay window so a cooled-off
    // identity reads 0. Used by login-captcha.needsCaptcha to decide whether to show the captcha.
    loginFailCount(ip, now) {
      const d = identities.get(ip);
      if (!d) return 0;
      if (d.loginFailResetAt && now > d.loginFailResetAt) return 0;
      return d.loginFailCount || 0;
    },
    // after passing an interactive challenge (slider/captcha), trust this identity for a window:
    // clears its accumulated fails and marks it solved so it isn't re-challenged every request.
    markSolved(ip, until) { const d = ident(ip); d.solvedUntil = until; d.failCount = 0; },
    // OPPOSITE of markSolved: flag an identity high-risk until `until` (e.g. it hit a honeypot). Also
    // clears any solve-grace so a bot cannot launder a trap hit with a previously-passed challenge.
    markBad(ip, until) { const d = ident(ip); d.badUntil = until; d.solvedUntil = 0; },

    // ENV-SESSION grant (probe-once-per-session rework 2026-08-14) — mirrors markSolved/solvedUntil: after
    // an identity returns a CLEAN env probe payload once, trust its environment for the grant window so the
    // challenge builder can OMIT the env block (client runs zero heavy probes) until it lapses. The grant
    // lives server-side (nothing for a lifted client to steal); a dirty/headless env never earns one, so it
    // keeps getting env demanded and stays detectably wrong. Keyed by identity (ip), same as markSolved.
    bindEnvSession(ip, envSig, until) { const d = ident(ip); d.envBoundUntil = until; d.envSig = envSig || null; },
    hasEnvSession(ip, now) { const d = identities.get(ip); return !!(d && d.envBoundUntil && d.envBoundUntil > now); },

    // FIX 3 (2026-08-25): UNION scoring memory. Accumulate the set of env deny-tokens an identity has EVER
    // emitted within the tracking window and return the running union. This defeats per-request sampling
    // dilution AND a RACY spoof (e.g. puppeteer-stealth's webgl.vendor evasion fires ~2/3 of page-loads):
    // once a heavy token (glSpoof/wd1) is seen even once, the identity's union score stays >= threshold for
    // the window, so it is escalated on EVERY subsequent request regardless of that request's own subset.
    // token -> expiry(ms); pruned lazily. Keyed by identity (ip), same as the other trust/flag maps.
    trackEnvFlags(ip, tokens, until, now) {
      const d = ident(ip);
      d.envFlags = d.envFlags || new Map();
      for (const [tk, exp] of d.envFlags) if (exp <= now) d.envFlags.delete(tk);
      if (tokens && tokens.length) for (const tk of tokens) d.envFlags.set(tk, until);
      return Array.from(d.envFlags.keys());
    },

    // --- housekeeping ------------------------------------------------------
    sweep(now) {
      for (const [k, exp] of nonces) if (exp < now) nonces.delete(k);
      for (const [ip, d] of identities) {
        const cutoff = now - windowMs;
        prune(d.fps, cutoff); prune(d.paths, cutoff);
        while (d.events.length && d.events[0] < cutoff) d.events.shift();
        if (d.pat) { while (d.pat.length && d.pat[0].ts < cutoff) d.pat.shift(); }
        if (d.fps.size === 0 && d.paths.size === 0 && d.events.length === 0 &&
            (!d.pat || d.pat.length === 0) &&
            (!d.failResetAt || now > d.failResetAt) &&
            (!d.loginFailResetAt || now > d.loginFailResetAt) &&
            (!d.envBoundUntil || now > d.envBoundUntil) &&   // keep a granted identity until its env-session lapses (else re-probe fires early)
            (!d.envFlags || d.envFlags.size === 0) &&   // FIX 3: keep an identity while its union deny-flags live
            (!d.badUntil || now > d.badUntil)) identities.delete(ip);   // keep a flagged identity until its ban lapses
      }
    },
    _debug() { return { buckets, nonces, identities }; },
  };
}

// ----------------------------------------------------------------------------
// factory
// ----------------------------------------------------------------------------
function apiguard(config) {
  config = config || {};
  if (!config.secret || typeof config.secret !== 'string' || config.secret.length < 16) {
    throw new Error('apiguard: config.secret is required (>=16 chars, high-entropy server secret)');
  }

  const cfg = {
    secret: config.secret,
    // ROTATION GRACE (additive; default OFF): during a weekly secret rotation, tokens/PoW minted under
    // the PREVIOUS secret are still ACCEPTED (never minted) until `prevSecretUntil`. Lets rotate.sh swap
    // the secret with ZERO user-visible re-challenge blip. Absent -> exactly the old single-secret path.
    prevSecret: (config.prevSecret && String(config.prevSecret).length >= 16) ? config.prevSecret : null,
    prevSecretUntil: config.prevSecretUntil || 0, // 0 = accept prev until it's removed (no time bound)
    protect: config.protect || '/api/',
    exempt: config.exempt || [],
    tokenTtlMs: config.tokenTtlMs || 120000,
    clockSkewMs: config.clockSkewMs || 5000,
    rpm: config.rpm || 120,
    powTtlMs: config.powTtlMs || 120000,
    powBits: { normal: 16, max: 24, ...(config.powBits || {}) },
    // PoW PRIMITIVE selector (2026-08-24, memory-hard rework). 'sha256' (DEFAULT) = the exact legacy
    // leading-zero-bits hashcash — this file stays behaviorally byte-identical for every existing caller.
    // 'argon2id' = single-eval memory-hard PoW (server mints locked {salt,memKB,iters,par,expiry,sig};
    // client runs ONE argon2id and returns its output; server recomputes once + constant-time compares).
    // Flip via config.powAlgo or the POW_ALGO env var. The SHA-256 path is NEVER removed.
    powAlgo: (function () {
      const v = String(config.powAlgo || (typeof process !== 'undefined' && process.env && process.env.POW_ALGO) || 'sha256').toLowerCase();
      return v === 'argon2id' ? 'argon2id' : 'sha256';
    })(),
    // Argon2id difficulty tiers (memKB is the memory-hardness / difficulty knob and is HMAC-locked in the
    // challenge sig, so a client can never downgrade it). NORMAL: 4MB/t3/p1 (~24ms node, <60ms browser).
    // FLAGGED: 32MB/t3/p1 (~184ms node) — CAPPED at 32MB; never issue more to an unknown/mobile client.
    powArgon: {
      normal: { memKB: 4096, iters: 3, par: 1 },
      max: { memKB: 32768, iters: 3, par: 1 },
      ...(config.powArgon || {}),
    },
    // node module id for the server-side argon2id recompute (lazy-required only when powAlgo='argon2id'
    // AND an argon PoW is actually verified — never on the boot path, keeping core zero-dep by default).
    argonModulePath: config.argonModulePath || 'hash-wasm',
    // sha256 difficulty handed to a client that must FALL BACK (its argon2id failed to load/run). Only a
    // sha256-mode server accepts it; in argon2id mode it is rejected — the fallback exists to guarantee the
    // client never HANGS boot, not to weaken the gate. See client.envbind.js solveArgon().
    powFallbackBits: config.powFallbackBits != null ? config.powFallbackBits : 16,
    // risk thresholds & signal weights (all tunable)
    risk: {
      powAt: 30,        // score >= powAt     -> tier 1 (invisible PoW)
      sliderAt: 55,     // score >= sliderAt  -> tier 2 (slider challenge)
      captchaAt: 70,    // score >= captchaAt -> tier 3 (motion captcha)
      blockAt: 90,      // score >= blockAt   -> tier 4 (block)
      churnThreshold: 3,   // distinct fingerprints per IP in window before churn penalty
      fanoutThreshold: 8,  // distinct paths per IP in window before fanout penalty
      solvedGraceMs: 1800000, // after passing a slider/captcha, this identity is trusted for 30 min
      honeypotScore: 100,     // score assigned to an identity that hit a honeypot (100 -> tier 4 block; lower to land on captcha/slider)
      honeypotBanMs: 21600000,// how long a honeypot flag lasts (6h). Its NEXT requests escalate for this long.
      ...(config.risk || {}),
    },
    // Anti-rebroadcast behavioral detector (additive; see rebroadcast.js). `enabled` defaults ON but is
    // inert unless the scorer module is present AND an identity accrues machine-volume traffic — so it
    // never touches a normal request. All thresholds pass straight through to rebroadcast.js DEFAULTS.
    rebroadcast: Object.assign({ enabled: true }, config.rebroadcast || {}),
    // Host-provided INTERACTIVE challenge minters/verifiers, keeping core zero-dep:
    //   challengers.slider  = { mint(ctx) -> obj, verify(sub) -> {ok} }
    //   challengers.captcha = { mint(ctx) -> obj, verify(sub) -> {ok} }
    challengers: config.challengers || {},
    failOpen: config.failOpen !== false, // default true
    now: config.now || Date.now,
    header: {
      token: 'x-ag-token',
      pow: 'x-ag-pow',
      fp: 'x-ag-fp',
      force: 'x-ag-force-score',   // TEST-ONLY: honored only when cfg.testForce is true (see verdict)
      ...(config.header || {}),
    },
    // TEST-ONLY deterministic tier forcing. Default OFF; production NEVER sets it. When on, an
    // `x-ag-force-score` header overrides the risk score EXCEPT when the identity is inside its
    // solve-grace (recently_solved) — so a post-solve retry still genuinely drops to tier 0, proving
    // the real markSolved path rather than faking a bypass. Lets an off-live harness drive each tier.
    testForce: config.testForce === true,
    challengePath: config.challengePath || '/__ag/challenge',
    // Behind a trusted reverse proxy (nginx), read the real client IP from a header the proxy sets,
    // instead of the socket (which is the proxy itself → every user collapses into one identity).
    trustProxy: config.trustProxy || false,
    realIpHeader: config.realIpHeader || 'x-real-ip',
    // ENV-BINDING flag (anti-lift). DEFAULT 'off' -> the feature is INERT and this file is BEHAVIORALLY
    // byte-identical to pre-envbind core.js: challenge() runs the exact old code path, verdict() skips the
    // env block, and scoreEnv/envSeq are never reached. 'observe' -> emit the probe subset, score the
    // returned envSig, and LOG it, but NEVER change allow/block. 'enforce' -> additionally fold a CAPPED
    // env anomaly into the risk ladder so a bad env ESCALATES (PoW/slider/captcha), never a sole hard-deny.
    // Set via config.envbind or the ENVBIND env var at deploy (ENVBIND=observe to turn on).
    envbind: (function () {
      const v = String(config.envbind || (typeof process !== 'undefined' && process.env && process.env.ENVBIND) || 'off').toLowerCase();
      return (v === 'off' || v === 'observe' || v === 'enforce' || v === '1') ? (v === '1' ? 'enforce' : v) : 'off';
    })(),
    envSubset: config.envSubset || ENV_SUBSET_DEFAULT,
    envReplayTtlMs: config.envReplayTtlMs || 600000,   // an envSig is "seen" for 10 min for replay checks
    envEnforceCap: config.envEnforceCap != null ? config.envEnforceCap : 90, // max env points added to risk in enforce (>=90 so a pure-env stub can reach blockAt)
    envDenyThreshold: config.envDenyThreshold != null ? config.envDenyThreshold : 55, // env only folds into risk at/above this — real-browser soft flags (<=45) add NOTHING
    // PROBE-ONCE-PER-SESSION (2026-08-14): after a CLEAN env payload, the identity is env-bound for this
    // long; while bound, challenge() OMITS the env block so the client runs zero heavy probes. 5 min.
    envBoundMs: config.envBoundMs != null ? config.envBoundMs : 300000,
    // A clean env earns the grant only when its anomaly score is <= this (default 0 = a spotless real
    // browser only; a dirty/stub env never earns a probe-free window). Kept strict on purpose (anti-lift).
    envBindMaxScore: config.envBindMaxScore != null ? config.envBindMaxScore : 0,
    // #1 (2026-08-25): close the env-strip dodge. 'off' | 'observe' (log-only, default) | 'enforce' (block).
    // Flip live with AG_ENVDODGE=enforce. Observe first: the count on real clients MUST be zero before enforcing.
    envDodge: config.envDodge || process.env.AG_ENVDODGE || 'observe',
    // #1 grace: only escalate a dodge CONTINUOUS past this (default 3x tokenTtl = 6min). A transient client
    // env-probe timeout (client proceeds with no x-ag-env) recovers within one 2min token cycle -> never
    // reaches grace; a stripped bot dodges forever. Reset by any clean (present/bound) request.
    envDodgeGraceMs: config.envDodgeGraceMs != null ? config.envDodgeGraceMs : 360000,
    envHeader: (config.header && config.header.env) || 'x-ag-env',
  };
  // config.powBits.max is the SINGLE ceiling knob; default aggressive end (24).
  if (cfg.powBits.max < cfg.powBits.normal) cfg.powBits.max = cfg.powBits.normal;
  // Argon2id: hard-cap the FLAGGED memory at 32MB (anti-lift doctrine: never mint a heavier memory-hard
  // challenge than 32MB to an unknown/mobile client). Also floor normal <= max.
  if (cfg.powArgon.max.memKB > 32768) cfg.powArgon.max.memKB = 32768;
  if (cfg.powArgon.max.memKB < cfg.powArgon.normal.memKB) cfg.powArgon.max.memKB = cfg.powArgon.normal.memKB;

  const store = config.store && typeof config.store === 'object'
    ? config.store
    : MemoryStore(config.storeOpts);

  const now = () => cfg.now();
  const hmac = (msg) => crypto.createHmac('sha256', cfg.secret).update(msg).digest();
  // previous-secret verifier for the rotation grace window (null unless cfg.prevSecret set). Minting
  // ALWAYS uses the current secret; only VERIFICATION falls back to prev while the grace is active.
  const prevHmac = cfg.prevSecret ? (msg) => crypto.createHmac('sha256', cfg.prevSecret).update(msg).digest() : null;
  const prevActive = () => !!prevHmac && (!cfg.prevSecretUntil || now() < cfg.prevSecretUntil);
  const capacity = cfg.rpm;
  const refillPerMs = cfg.rpm / 60000;

  // Build the behavioral scorer once (pure; thresholds from cfg.rebroadcast merged over module DEFAULTS).
  // Null when the module is absent or disabled -> scoreRebroadcast abstains and verdict adds nothing.
  const rebroadcastScorer = (rebroadcastMod && cfg.rebroadcast.enabled)
    ? rebroadcastMod.makeRebroadcastScorer(cfg.rebroadcast) : null;
  const rebroadcastMax = (rebroadcastScorer && rebroadcastScorer.config.maxEvents) || 512;

  // scoreRebroadcast(ip) -> { signal, verdict:'abstain'|'clear'|'flag', reasons, metrics }. Fail-safe:
  // ABSTAINS (signal 0) if the scorer/store isn't available or throws — never invents a flag, never
  // breaks the host. This is the READ side; the WRITE side (store.trackPattern) happens in verdict().
  function scoreRebroadcast(ip) {
    try {
      if (!rebroadcastScorer || !store.patternEvents) {
        return { signal: 0, verdict: 'abstain', reasons: ['detector_unavailable'], metrics: { n: 0 } };
      }
      const events = store.patternEvents(ip, now());
      const stats = rebroadcastMod.computeStats(events, now(), rebroadcastScorer.config.windowMs);
      return rebroadcastScorer.score(stats);
    } catch (e) {
      return { signal: 0, verdict: 'abstain', reasons: ['rebroadcast_error'], error: e && e.message, metrics: { n: 0 } };
    }
  }

  // ---- ENV-BINDING scoring (additive; fail-safe; OBSERVE by default) ------------------------------
  // Small in-process replay memory: envSig -> { nonce, ip, exp }. A well-formed real-browser envSig is
  // single-use per nonce; the SAME sig re-seen under a different nonce or IP is a replay/lift tell.
  const _envSeen = new Map();
  function _envReplayPrune(t) { if (_envSeen.size > 4096) { for (const [k, v] of _envSeen) if (v.exp < t) _envSeen.delete(k); } }
  function envSeq(nonce) { return envSeqFromNonce(hmac, nonce, cfg.envSubset); }
  // scoreEnv: parse the x-ag-env payload, re-derive the expected probe seq from the nonce, and grade.
  // Returns { present, score(0..100), flags:[...], seq, n }. NEVER throws. Absent env -> score 0
  // (present:false) so a cached page / old client / off-mode is never penalised.
  function scoreEnv(rawB64, nonce, ip, t) {
    const seq = envSeq(nonce);
    const out = { present: false, score: 0, flags: [], seq, n: 0 };
    try {
      if (!rawB64) { out.flags.push('env_absent'); return out; }
      let payload = null;
      try { payload = JSON.parse(fromB64url(rawB64).toString('utf8')); } catch (e) { payload = null; }
      if (!payload || !Array.isArray(payload.outs) || typeof payload.sig !== 'string') {
        out.present = true; out.score = 40; out.flags.push('env_malformed'); return out;
      }
      out.present = true;
      out.sig = payload.sig;   // record the env sig so a clean env can key its probe-once grant
      const outs = payload.outs.map((x) => String(x == null ? 'nil' : x));
      out.n = outs.length;
      let score = 0; const flags = [];

      // (a) STRUCTURE: arity must match the seq we asked for.
      if (outs.length !== seq.length) { score += 35; flags.push('env_arity(' + outs.length + '/' + seq.length + ')'); }

      // (b) BINDING: envSig must be sha256(nonce|outs).slice(0,24). A mismatch = tampered/forged/replayed
      // against a different nonce (the probe seq is nonce-derived, so this ties env to THIS token).
      let sigOk = false;
      try {
        const expect = sha256(String(nonce == null ? '' : nonce) + '|' + outs.join('|')).toString('hex').slice(0, 24);
        sigOk = (expect === payload.sig);
      } catch (e) { sigOk = false; }
      if (!sigOk) { score += 30; flags.push('env_sig_bad'); }

      // (c) DENYLIST: tokens only a headless/node/tampered runtime emits. Tamper/automation dominate.
      const hit = [];
      for (const o of outs) { if (Object.prototype.hasOwnProperty.call(ENV_DENY, o)) { score += ENV_DENY[o]; hit.push(o); } }
      if (hit.length) flags.push('env_deny(' + hit.join(',') + ')');
      out.denyHits = hit.slice(); // FIX 3 (2026-08-25): exposed so verdict can UNION deny tokens per identity

      // (d) LOW-ENTROPY / stub tell: most outputs nullish, or almost no distinct values across a full
      // subset -> a stub that returns constant/empty for everything.
      let nullish = 0; const distinct = new Set();
      for (const o of outs) { if (ENV_NULLISH[o]) nullish++; distinct.add(o); }
      if (outs.length >= 5 && distinct.size <= 2) { score += 30; flags.push('env_lowentropy(d=' + distinct.size + ')'); }
      if (outs.length >= 4 && nullish >= Math.ceil(outs.length * 0.6)) { score += 25; flags.push('env_nullish(' + nullish + '/' + outs.length + ')'); }

      // (e) ANTI-REPLAY: same sig re-seen under a different nonce or a different IP -> lift/replay.
      try {
        _envReplayPrune(t);
        const prev = _envSeen.get(payload.sig);
        if (prev) {
          if (prev.nonce !== nonce) { score += 25; flags.push('env_replay_nonce'); }
          else if (prev.ip !== ip) { score += 25; flags.push('env_replay_ip'); }
        } else {
          _envSeen.set(payload.sig, { nonce, ip, exp: t + cfg.envReplayTtlMs });
        }
      } catch (e) { /* replay memory best-effort */ }

      out.score = Math.max(0, Math.min(100, score));
      out.flags = flags;
      return out;
    } catch (e) {
      out.flags.push('env_error'); out.error = e && e.message; return out;
    }
  }

  // constant-time compare of a provided base64url signature vs an expected Buffer
  function safeEqualB64(providedB64, expectedBuf) {
    let provided;
    try { provided = fromB64url(providedB64); } catch { return false; }
    if (provided.length !== expectedBuf.length) return false;
    return crypto.timingSafeEqual(provided, expectedBuf);
  }

  // ---- token -------------------------------------------------------------
  function mintToken(o) {
    o = o || {};
    const ts = o.ts != null ? o.ts : now();
    const nonce = o.nonce || b64url(crypto.randomBytes(16));
    const path = o.path || '';
    const fingerprint = o.fingerprint || '';
    const sig = b64url(hmac(`${ts}.${nonce}.${path}.${fingerprint}`));
    return `${ts}.${nonce}.${sig}`;
  }
  function verifyToken(tokenStr, bind) {
    if (!tokenStr || typeof tokenStr !== 'string') return { status: 'missing' };
    const parts = tokenStr.split('.');
    if (parts.length !== 3) return { status: 'bad_sig' };
    const [tsS, nonce, sig] = parts;
    const ts = Number(tsS);
    if (!Number.isFinite(ts) || !nonce || !sig) return { status: 'bad_sig' };
    const msg = `${ts}.${nonce}.${bind.path || ''}.${bind.fingerprint || ''}`;
    let sigOk = safeEqualB64(sig, hmac(msg));
    if (!sigOk && prevActive()) sigOk = safeEqualB64(sig, prevHmac(msg)); // accept previous secret during grace
    if (!sigOk) return { status: 'bad_sig' };
    const t = now();
    if (ts - t > cfg.clockSkewMs) return { status: 'expired', nonce, ts }; // future-dated
    if (t - ts > cfg.tokenTtlMs) return { status: 'expired', nonce, ts };
    return { status: 'ok', nonce, ts };
  }

  // ---- proof of work (self-implemented hashcash; ALTCHA-shaped object) ----
  // NOTE: SPEC.md §7 explicitly specifies leading-zero-BITS hashcash
  // (sha256(salt+counter) has `bits` leading zero bits). ALTCHA's on-wire
  // protocol actually ships a target-hash + maxnumber; we follow the spec's
  // explicit definition. The challenge object keeps ALTCHA-compatible field
  // names (algorithm/salt) plus our HMAC `sig` that locks the difficulty.
  function mintChallenge(bits, o) {
    o = o || {};
    const salt = o.salt || crypto.randomBytes(16).toString('hex');
    const expiry = o.expiry != null ? o.expiry : now() + cfg.powTtlMs;
    const sig = b64url(hmac(`${salt}|${bits}|${expiry}`));
    return { algorithm: 'SHA-256', salt, bits, expiry, sig };
  }
  // ---- argon2id memory-hard PoW (single-eval; behind powAlgo='argon2id') ----------------------------
  // The server MINTS {algorithm,salt,memKB,iters,par,expiry,sig} with sig=HMAC over ALL params (incl memKB,
  // the difficulty knob — so a client cannot downgrade it). The client runs ONE argon2id(salt,lockedParams)
  // and returns {..params.., output}. Verify = HMAC-check locked params (free; rejects forgery) + expiry +
  // ONE-TIME-SALT reject-reuse + recompute argon2id once + constant-time compare. Recompute is async
  // (hash-wasm is Promise-based), so verifyArgonPow returns a Promise and verdict awaits ONLY this branch.
  let _argon2idFn = null, _argonLoadErr = null;
  function argonEval(saltHex, memKB, iters, par) {
    if (_argonLoadErr) return Promise.reject(_argonLoadErr);
    if (!_argon2idFn) {
      try { _argon2idFn = require(cfg.argonModulePath).argon2id; }
      catch (e) { _argonLoadErr = e; return Promise.reject(e); }
    }
    // salt param derives deterministically from the minted salt hex — client mirrors this exactly, so the
    // single-eval hash is reproducible on both sides with NO extra wire field. password = the salt hex.
    const s = String(saltHex).slice(0, 16);
    const b = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) b[i] = s.charCodeAt(i) || 48;
    try {
      return Promise.resolve(_argon2idFn({
        password: String(saltHex), salt: b, parallelism: par, iterations: iters,
        memorySize: memKB, hashLength: 32, outputType: 'hex',
      }));
    } catch (e) { return Promise.reject(e); }
  }
  // one-time salt memory (single-eval has no nonce search, so the minted salt IS the anti-replay token).
  const _powSeen = new Map(); // salt -> expiryMs
  function _powSaltSeen(salt, expMs) {
    try {
      const t = now();
      if (_powSeen.size > 8192) { for (const [k, v] of _powSeen) if (v < t) _powSeen.delete(k); }
      if (_powSeen.has(salt)) return true;
      _powSeen.set(salt, expMs || (t + cfg.powTtlMs));
      return false;
    } catch (_) { return false; } // fail-open on the replay check — never break the gate over bookkeeping
  }
  // score -> argon tier (two named tiers, matching the validated prototype). NORMAL below powAt; FLAGGED
  // (capped 32MB) at/above. Server recompute cost stays predictable (one of two fixed points), unlike a
  // linearly-interpolated memKB which would make verify cost vary per request.
  function argonParamsFor(score) {
    const n = cfg.powArgon.normal, m = cfg.powArgon.max;
    if (score < cfg.risk.powAt) return { memKB: n.memKB, iters: n.iters, par: n.par };
    return { memKB: m.memKB, iters: m.iters, par: m.par };
  }
  function mintArgonChallenge(params, o) {
    o = o || {};
    const salt = o.salt || crypto.randomBytes(16).toString('hex');
    const expiry = o.expiry != null ? o.expiry : now() + cfg.powTtlMs;
    const memKB = params.memKB, iters = params.iters, par = params.par;
    const sig = b64url(hmac(`${salt}|${memKB}|${iters}|${par}|${expiry}`));
    // fallbackBits lets a client whose argon2id fails to load solve a sha256 hashcash instead so its boot
    // never hangs (a sha256-mode server accepts it; an argon2id-mode server rejects it — intentional).
    return { algorithm: 'argon2id', salt, memKB, iters, par, expiry, sig, fallbackBits: cfg.powFallbackBits };
  }
  // Unified mint used by challenge()/verdict: picks the primitive from cfg.powAlgo. For the default
  // 'sha256' it returns EXACTLY mintChallenge(bitsFor(score)) — byte-identical to the legacy path.
  function mkPowChallenge(score) {
    return cfg.powAlgo === 'argon2id'
      ? mintArgonChallenge(argonParamsFor(score))
      : mintChallenge(bitsFor(score));
  }
  // async verifier for an argon2id solution. Returns a Promise<{ok,reason,...}>; NEVER rejects.
  function verifyArgonPow(sol) {
    if (!sol || sol.salt == null || sol.memKB == null || sol.iters == null || sol.par == null ||
        sol.expiry == null || sol.sig == null || sol.output == null) {
      return Promise.resolve({ ok: false, reason: 'pow_missing' });
    }
    const memKB = Number(sol.memKB), iters = Number(sol.iters), par = Number(sol.par), expiry = Number(sol.expiry);
    if (![memKB, iters, par, expiry].every(Number.isFinite)) return Promise.resolve({ ok: false, reason: 'pow_bad_sig' });
    // difficulty (incl memKB) is HMAC-locked — a client cannot forge a cheaper memory/iteration/parallelism.
    const powMsg = `${sol.salt}|${memKB}|${iters}|${par}|${expiry}`;
    let powSigOk = safeEqualB64(sol.sig, hmac(powMsg));
    if (!powSigOk && prevActive()) powSigOk = safeEqualB64(sol.sig, prevHmac(powMsg)); // rotation grace
    if (!powSigOk) return Promise.resolve({ ok: false, reason: 'pow_bad_sig' });
    if (now() > expiry) return Promise.resolve({ ok: false, reason: 'pow_expired' });
    // sane bounds: never recompute an absurd memKB (a DoS guard, even though sig is already valid). Cap 32MB.
    if (memKB < 8 || memKB > 32768 || iters < 1 || iters > 16 || par < 1 || par > 4) {
      return Promise.resolve({ ok: false, reason: 'pow_bad_sig' });
    }
    // ONE-TIME salt: a captured valid solution cannot be replayed. Burn AFTER sig+expiry pass (so only a
    // genuinely server-minted salt is ever recorded) and BEFORE the recompute (so grinding a wrong output
    // can't reuse the salt). A 401 hands the client a fresh challenge, so this never wedges a real client.
    if (_powSaltSeen(String(sol.salt), expiry)) return Promise.resolve({ ok: false, reason: 'pow_replay' });
    return argonEval(String(sol.salt), memKB, iters, par).then((expected) => {
      const a = Buffer.from(String(sol.output), 'utf8'), b = Buffer.from(String(expected), 'utf8');
      const good = a.length === b.length && crypto.timingSafeEqual(a, b);
      return good ? { ok: true, reason: 'pow_ok', algo: 'argon2id' } : { ok: false, reason: 'pow_insufficient' };
    }, (e) => ({ ok: false, reason: 'pow_error', error: e && e.message }));
  }
  // node-side reference solver for the argon2id single-eval PoW (mirrors the browser client). Async.
  function solveArgonPow(ch) {
    return argonEval(String(ch.salt), Number(ch.memKB), Number(ch.iters), Number(ch.par))
      .then((output) => ({ algorithm: 'argon2id', salt: ch.salt, memKB: ch.memKB, iters: ch.iters, par: ch.par, expiry: ch.expiry, sig: ch.sig, output }));
  }

  function verifyPow(sol) {
    // argon2id solutions are detected by their algorithm tag (or the presence of memKB) and verified async.
    if (sol && (sol.algorithm === 'argon2id' || sol.output != null || sol.memKB != null)) return verifyArgonPow(sol);
    if (!sol || sol.salt == null || sol.bits == null || sol.expiry == null ||
        sol.sig == null || sol.counter == null) {
      return { ok: false, reason: 'pow_missing' };
    }
    const bits = Number(sol.bits);
    const expiry = Number(sol.expiry);
    if (!Number.isInteger(bits) || bits < 0 || bits > 256) return { ok: false, reason: 'pow_bad_sig' };
    // difficulty is HMAC-locked: client cannot forge a lower `bits`
    const powMsg = `${sol.salt}|${sol.bits}|${sol.expiry}`;
    let powSigOk = safeEqualB64(sol.sig, hmac(powMsg));
    if (!powSigOk && prevActive()) powSigOk = safeEqualB64(sol.sig, prevHmac(powMsg)); // grace: prev secret
    if (!powSigOk) return { ok: false, reason: 'pow_bad_sig' };
    if (now() > expiry) return { ok: false, reason: 'pow_expired' };
    const digest = sha256(String(sol.salt) + String(sol.counter));
    const lz = leadingZeroBits(digest);
    if (lz < bits) return { ok: false, reason: 'pow_insufficient' };
    return { ok: true, reason: 'pow_ok', leadingZeroBits: lz };
  }
  // reference solver (mirrors the client worker); used by tests & any server-side need
  function solvePow(salt, bits, maxIter) {
    maxIter = maxIter || 1 << 28;
    for (let c = 0; c < maxIter; c++) {
      if (leadingZeroBits(sha256(String(salt) + String(c))) >= bits) return c;
    }
    throw new Error('solvePow: exceeded maxIter for bits=' + bits);
  }

  // ---- risk --------------------------------------------------------------
  function scoreRisk(sig) {
    // sig = { tokenStatus, rate, track:{distinctFingerprints,distinctPaths,failCount,solvedUntil}, clientBits }
    const t = sig.track || {};
    // hit a honeypot -> decisive bot tell. Short-circuit to a high score so this identity's NEXT
    // requests escalate (block by default). Checked BEFORE recently_solved so a bot that passed a
    // challenge once cannot launder away a later trap hit.
    if (t.badUntil && t.badUntil > now()) {
      return { score: Math.max(0, Math.min(100, cfg.risk.honeypotScore)), reasons: ['flagged_honeypot'] };
    }
    // recently passed a slider/captcha -> trusted for the grace window; don't re-challenge.
    if (t.solvedUntil && t.solvedUntil > now()) return { score: 0, reasons: ['recently_solved'] };
    let s = 0; const reasons = [];
    switch (sig.tokenStatus) {
      case 'missing': s += 40; reasons.push('sig_token_missing'); break;
      case 'expired': s += 30; reasons.push('sig_token_stale'); break;
      case 'bad_sig': s += 55; reasons.push('sig_token_bad'); break;
      case 'replay': s += 60; reasons.push('sig_token_replay'); break;
      // 'ok' -> 0
    }
    const used = sig.rate ? (1 - sig.rate.remaining / sig.rate.capacity) : 0;
    if (used > 0.8) { s += Math.round((used - 0.8) * 100); reasons.push('sig_rate_high'); } // up to +20
    if (t.distinctFingerprints > cfg.risk.churnThreshold) {
      s += Math.min(30, (t.distinctFingerprints - cfg.risk.churnThreshold) * 10);
      reasons.push('sig_fp_churn');
    }
    if (t.distinctPaths > cfg.risk.fanoutThreshold) {
      s += Math.min(20, (t.distinctPaths - cfg.risk.fanoutThreshold) * 5);
      reasons.push('sig_endpoint_fanout');
    }
    if (t.failCount > 0) { s += Math.min(40, t.failCount * 10); reasons.push('sig_failed_challenges'); }
    // behavioral rebroadcast signal (additive; 0 unless an identity mirrors the whole feed at machine
    // cadence — see rebroadcast.js). Optional field: absent/0 for every existing caller, so no behaviour
    // change for anyone but a proven full-feed mirror.
    if (sig.rebroadcast > 0) { s += sig.rebroadcast; reasons.push('sig_rebroadcast'); }
    if (sig.external > 0) { s += sig.external; reasons.push('sig_acct_cadence'); }   // per-account cadence+breadth firehose signal (2026-08-12)
    // client-reported bot signal (x-ag-bt). SPOOFABLE, so a modest capped nudge — catches the lazy
    // majority of headless tools that ship the tells; never a sole basis for a block.
    if (sig.clientBits) {
      let n = 0, b = sig.clientBits >>> 0; while (b) { n += b & 1; b >>>= 1; }
      if (n > 0) { s += Math.min(25, n * 3); reasons.push('sig_client_bot'); }
    }
    return { score: Math.max(0, Math.min(100, s)), reasons };
  }
  function tierOf(score) {
    if (score >= cfg.risk.blockAt) return 4;    // block
    if (score >= cfg.risk.captchaAt) return 3;  // motion captcha
    if (score >= cfg.risk.sliderAt) return 2;   // slider
    if (score >= cfg.risk.powAt) return 1;      // invisible PoW
    return 0;                                   // invisible / token-only
  }
  function bitsFor(score) {
    const { normal, max } = cfg.powBits;
    if (score < cfg.risk.powAt) return normal;
    const span = Math.max(1, 100 - cfg.risk.powAt);
    const frac = Math.min(1, (score - cfg.risk.powAt) / span);
    return Math.min(max, Math.round(normal + (max - normal) * frac));
  }

  // ---- path matching -----------------------------------------------------
  function matches(rule, path) {
    if (!rule) return false;
    const arr = Array.isArray(rule) ? rule : [rule];
    for (const r of arr) {
      if (r instanceof RegExp) { if (r.test(path)) return true; }
      else if (typeof r === 'string') { if (path.startsWith(r)) return true; }
    }
    return false;
  }
  function isProtected(path) { return matches(cfg.protect, path); }
  function isExempt(path) { return matches(cfg.exempt, path); }

  // ---- header extraction -------------------------------------------------
  function h(ctx, name) {
    const headers = ctx.headers || {};
    // node lowercases header keys; be defensive anyway
    if (headers[name] !== undefined) return headers[name];
    const lower = name.toLowerCase();
    for (const k in headers) if (k.toLowerCase() === lower) return headers[k];
    return undefined;
  }
  function readPow(ctx) {
    const raw = h(ctx, cfg.header.pow);
    if (!raw) return null;
    try { return JSON.parse(fromB64url(raw).toString('utf8')); }
    catch { try { return JSON.parse(raw); } catch { return null; } }
  }
  function encodePow(sol) { return b64url(Buffer.from(JSON.stringify(sol), 'utf8')); }

  // ---- challenge (served by /__ag/challenge) -----------------------------
  function challenge(ctx) {
    const path = (ctx && ctx.path) || '';
    const fp = (ctx && ctx.fingerprint) || '';
    const ip = (ctx && ctx.ip) || '';
    let score = 0;
    try {
      const track = store.track(ip, { fingerprint: fp, path, ts: now() });
      score = scoreRisk({ tokenStatus: 'ok', track, rate: null }).score;
    } catch { /* best-effort risk for difficulty; never fail the mint */ }
    const bits = bitsFor(score);
    // OFF (default): the EXACT pre-envbind code path — mintToken generates its own nonce, no `env` field.
    // This branch keeps the file behaviorally byte-identical to today's live core.js when the flag is unset.
    if (cfg.envbind === 'off') {
      return {
        token: mintToken({ path, fingerprint: fp }),
        challenge: mkPowChallenge(score),
        tokenTtlMs: cfg.tokenTtlMs,
      };
    }
    // ON (observe/enforce): pre-generate the nonce so the env probe subset can be bound to THIS token's
    // nonce, and emit the per-nonce subset (ids only, never code). The client attaches x-ag-env only when
    // it receives this `env` block, so an off-mode/old server leaves the request path unchanged.
    const nonce = b64url(crypto.randomBytes(16));
    const resp = {
      token: mintToken({ path, fingerprint: fp, nonce }),
      challenge: mkPowChallenge(score),
      tokenTtlMs: cfg.tokenTtlMs,
    };
    // PROBE-ONCE-PER-SESSION: demand the env probe block ONLY when this identity has no live env grant.
    // While a grant is live the client receives NO env block → runs zero heavy probes (the rework's whole
    // point). A dirty/headless env never earned a grant, so it keeps getting env demanded here. Fail-safe:
    // any store/throw → demand env (the safe default). Absent-env in verdict is score 0, so omitting it
    // never penalises the granted user.
    let needEnv = true;
    try { needEnv = !(store.hasEnvSession && store.hasEnvSession(ip, now())); } catch (_) { needEnv = true; }
    if (needEnv) { try { resp.env = { v: 1, seq: envSeq(nonce) }; } catch (e) { /* never fail the mint over env */ }
      try { store.markEnvNonce && store.markEnvNonce(nonce, now() + cfg.tokenTtlMs); } catch (_) { /* #1: mark this token env-demanded; best-effort */ } }
    return resp;
  }

  // ---- verdict (the decision) -------------------------------------------
  function verdict(ctx) {
    try {
      ctx = ctx || {};
      const path = ctx.path || '';
      if (isExempt(path)) return { allow: true, action: 'exempt', status: 200, reasons: ['exempt'] };
      if (!isProtected(path)) return { allow: true, action: 'pass', status: 200, reasons: ['not_protected'] };

      // #2 ADMIN EXEMPTION — server-trusted (ctx.admin from _who.role==='admin' via req.__agAdmin, a
      // server property not a header → unforgeable). A logged-in admin debugging with ANY tool
      // (CDP/puppeteer/curl) is never risk/env/PoW-escalated. A bot cannot set it (needs a real admin session).
      if (ctx.admin) return { allow: true, action: 'admin_exempt', status: 200, tier: 0, score: 0, reasons: ['admin_exempt'] };

      const fp = ctx.fingerprint || h(ctx, cfg.header.fp) || '';
      const ip = ctx.ip || '';
      const rateId = ip + '|' + fp;
      const t = now();

      // 1) rate-limit backstop (counts every protected attempt; cheap, pre-crypto)
      const rl = store.takeToken(rateId, capacity, refillPerMs, t);
      if (!rl.allowed) {
        return { allow: false, action: 'rate_limited', status: 429, tier: 4, score: 100,
          reasons: ['rate_limited'], retryAfterMs: Math.ceil((1 - rl.remaining) / refillPerMs) };
      }

      // 2) token
      const tokenStr = h(ctx, cfg.header.token);
      const tok = verifyToken(tokenStr, { path, fingerprint: fp });

      // 3) replay peek (do NOT burn here — burn only on final allow, so a
      //    pow-retry with the same fresh token is not falsely flagged)
      let tokenStatus = tok.status;
      if (tokenStatus === 'ok' && store.hasNonce(tok.nonce, t)) tokenStatus = 'replay';

      // 4) risk signals
      const track = store.track(ip, { fingerprint: fp, path, ts: t });
      const clientBits = parseInt(h(ctx, 'x-ag-bt'), 10) || 0;   // client bot-signal detector (spoofable)
      // 4b) behavioral rebroadcast: record this hit's {ts,path} and score the identity's recent pattern.
      // Fail-safe and additive — any missing method / throw yields signal 0 (no effect). Only a machine-
      // volume full-feed mirror produces a non-zero signal; a fast human abstains or scores clear.
      let rebroadcastSignal = 0;
      try {
        if (store.trackPattern) store.trackPattern(ip, { ts: t, path }, rebroadcastMax);
        if (rebroadcastScorer) { const rb = scoreRebroadcast(ip); if (rb && rb.signal > 0) rebroadcastSignal = rb.signal; }
      } catch (_) { rebroadcastSignal = 0; }
      const scored = scoreRisk({ tokenStatus, rate: rl, track, clientBits, rebroadcast: rebroadcastSignal, external: Number(ctx.acctSignal) || 0 });
      let score = scored.score;
      let riskReasons = scored.reasons;
      // TEST-ONLY deterministic forcing (cfg.testForce). Applied only when NOT recently_solved, so the
      // markSolved -> tier-0 retry path is proven for real, never bypassed. Inert in production (flag off).
      if (cfg.testForce && riskReasons.indexOf('recently_solved') === -1) {
        const forced = parseInt(h(ctx, cfg.header.force), 10);
        if (Number.isFinite(forced)) {
          score = Math.max(0, Math.min(100, forced));
          riskReasons = riskReasons.concat(['test_forced_score']);
        }
      }
      // ---- ENV-BINDING (anti-lift): score the env probe outputs, bound to the token nonce. ----
      // OBSERVE (default): compute + LOG only; NEVER changes allow/block. ENFORCE: fold a CAPPED anomaly
      // into the ladder so a bad env ESCALATES (PoW/slider/captcha), never a sole hard-deny. OFF: skip.
      // Fail-safe: any throw leaves the gate exactly as it was. Placed AFTER test-force so an enforce
      // add is not clobbered by the harness's forced score.
      if (cfg.envbind !== 'off') {
        try {
          const envNonce = (tok && tok.nonce) || (typeof tokenStr === 'string' ? (tokenStr.split('.')[1] || '') : '');
          const envInfo = scoreEnv(h(ctx, cfg.envHeader), envNonce, ip, t);
          // FIX 3 (2026-08-25): UNION scoring. Accumulate every deny-token this identity has emitted in the
          // window and score the running UNION. A per-request subset can miss a tell (dilution) or a racy
          // spoof can be absent this request — but once seen, the union keeps the identity escalated.
          let unionScore = envInfo.score, unionTokens = envInfo.denyHits || [];
          try {
            if (store.trackEnvFlags && envInfo.present) {
              const union = store.trackEnvFlags(ip, envInfo.denyHits || [], t + cfg.envBoundMs, t);
              unionTokens = union;
              let us = 0; for (const tk of union) if (Object.prototype.hasOwnProperty.call(ENV_DENY, tk)) us += ENV_DENY[tk];
              unionScore = Math.max(0, Math.min(100, us));
            }
          } catch (_) { unionScore = envInfo.score; }
          // PROBE-ONCE (grant): a spotless env earns a short-TTL server-side grant → challenges omit the env
          // block → client stops re-probing. FIX 3 GUARD: only grant when the request ACTUALLY sampled the
          // pinned heavy tells (wd, glSoftware, glSpoof) clean AND the identity has no accumulated deny-flag
          // — so a lucky sparse subset can no longer whitelist a headless session. (With FIX 2 pinning the
          // heavy probes are always in seq, so a genuine clean browser still earns the grant normally.)
          let granted = false;
          try {
            const seqSet = new Set(envInfo.seq || []);
            const heavyClean = ['wd', 'glSoftware', 'glSpoof'].every((id) => seqSet.has(id));
            const noUnionDeny = unionScore < cfg.envDenyThreshold;
            if (envInfo.present && envInfo.score <= cfg.envBindMaxScore && heavyClean && noUnionDeny && store.bindEnvSession) {
              store.bindEnvSession(ip, envInfo.sig, t + cfg.envBoundMs); granted = true;
            }
          } catch (_) { /* grant is best-effort; never breaks the gate */ }
          let bound = false; try { bound = !!(store.hasEnvSession && store.hasEnvSession(ip, t)); } catch (_) { bound = false; }
          try {
            console.log('[envbind] mode=%s score=%d union=%d present=%s granted=%s bound=%s flags=%s union_tokens=%s seq=%s ip=%s path=%s',
              cfg.envbind, envInfo.score, unionScore, envInfo.present, granted, bound, (envInfo.flags.join('|') || '-'),
              (unionTokens.join(',') || '-'), envInfo.seq.join(','), ip || '-', path);
          } catch (_) { /* logging best-effort */ }
          // #1 (2026-08-25): CLOSE THE ENV-STRIP DODGE. env-demanded token + present=false + unbound =
          // a client that stripped x-ag-env. Real clients send env once (-> bound) then ride bound=true;
          // a grant-lapse token was minted needEnv=false so it is never marked. False-positive-free.
          try {
            const envDemandedTok = (tokenStatus === "ok") && tok && tok.nonce && store.wasEnvNonce && store.wasEnvNonce(tok.nonce, t);
            if (envDemandedTok && !envInfo.present && !bound) {
              const dodgedMs = (store.noteEnvDodge ? store.noteEnvDodge(ip, t) : 0);   // ms of CONTINUOUS dodging (reset by any clean request)
              const persisted = dodgedMs >= cfg.envDodgeGraceMs;                        // transient client env-timeout recovers < grace; a stripped bot persists
              if (cfg.envDodge === "enforce" && persisted) {
                score = Math.max(0, Math.min(100, Math.max(score, cfg.risk.blockAt)));
                riskReasons = riskReasons.concat(["env_dodge_strip"]);
              }
              if (cfg.envDodge !== "off") {
                console.log("[envdodge] mode=%s %s ip=%s path=%s nonce=%s dodgedMs=%d graceMs=%d present=%s bound=%s",
                  cfg.envDodge, ((cfg.envDodge === "enforce" && persisted) ? "BLOCK" : "watch"), ip || "-", path, String(tok.nonce).slice(0, 8), dodgedMs, cfg.envDodgeGraceMs, envInfo.present, bound);
              }
            } else if (store.clearEnvDodge && (envInfo.present || bound)) {
              store.clearEnvDodge(ip);   // clean request -> reset the dodge streak (a real client that recovered from a timeout)
            }
          } catch (_) { /* #1 dodge check must never break the gate */ }
          if (cfg.envbind === 'enforce' && envInfo.present && riskReasons.indexOf('recently_solved') === -1) {
            // escalate on the MAX of this request's score and the identity's running union score.
            const effective = Math.max(envInfo.score, unionScore);
            const add = (effective >= cfg.envDenyThreshold) ? Math.min(cfg.envEnforceCap, effective) : 0;  // only a GENUINE deny escalates; real-browser soft flags don't
            if (add > 0) { score = Math.max(0, Math.min(100, score + add)); riskReasons = riskReasons.concat(['sig_envbind(' + add + ')']); }
          }
        } catch (e) { /* envbind must never break the gate */ }
      }
      const tier = tierOf(score);
      const baseReasons = riskReasons.concat(['token_' + tokenStatus]);
      const mkChallenge = () => ({ challenge: mkPowChallenge(score),
        token: mintToken({ path, fingerprint: fp }) });

      // TARPIT: deliberately slow the response as suspicion rises. Zero for a normal visitor (score<=60),
      // ramping to seconds for a scraper — so automated scraping crawls while a human never notices.
      const delayMs = score > 60 ? Math.min(8000, (score - 60) * 150) : 0;

      // 5) hard block (tier 4)
      if (tier >= 4) {
        return { allow: false, action: 'block', status: 403, tier, score, tokenStatus, delayMs,
          reasons: baseReasons.concat(['risk_block']) };
      }

      // 6) token not usable -> hand back a fresh token + challenge (401)
      if (tokenStatus !== 'ok') {
        store.recordFail(ip, t);
        return { allow: false, action: 'pow', status: 401, tier, score, tokenStatus, delayMs,
          reasons: baseReasons.concat(['need_token']), ...mkChallenge() };
      }

      // 6b) tier 3 -> motion captcha (interactive). Host provides the minter; if absent, falls through
      //     to the PoW path below (a hard invisible PoW instead of a visible captcha).
      if (tier === 3 && cfg.challengers.captcha && cfg.challengers.captcha.mint) {
        store.recordFail(ip, t);
        return { allow: false, action: 'captcha', status: 401, tier, score, tokenStatus, delayMs,
          reasons: baseReasons.concat(['need_captcha']), challenge: cfg.challengers.captcha.mint(ctx) };
      }
      // 6c) tier 2 -> slider (interactive). Same fallthrough behaviour if no minter configured.
      if (tier === 2 && cfg.challengers.slider && cfg.challengers.slider.mint) {
        store.recordFail(ip, t);
        return { allow: false, action: 'slider', status: 401, tier, score, tokenStatus, delayMs,
          reasons: baseReasons.concat(['need_slider']), challenge: cfg.challengers.slider.mint(ctx) };
      }

      // 7) tier 0 -> token alone suffices
      if (tier === 0) {
        store.addNonce(tok.nonce, tok.ts + cfg.tokenTtlMs); // burn on allow
        return { allow: true, action: 'allow', status: 200, tier, score, tokenStatus: 'ok',
          reasons: baseReasons.concat(['allow_token_only']) };
      }

      // 8) tier 1 -> invisible PoW required. verifyPow returns an object for sha256 (sync, unchanged) or a
      // Promise for argon2id (async recompute). `decide` finishes the verdict identically for both; when
      // the primitive is async we return the Promise and the adapter awaits ONLY that thenable — the
      // default sha256 path stays fully synchronous (an object, not a Promise) for every existing caller.
      const sol = readPow(ctx);
      const rawPv = sol ? verifyPow(sol) : { ok: false, reason: 'pow_missing' };
      const decide = (pv) => {
        if (!pv.ok) {
          store.recordFail(ip, t);
          return { allow: false, action: 'pow', status: 401, tier, score, tokenStatus, delayMs,
            reasons: baseReasons.concat([pv.reason]), ...mkChallenge() };
        }
        store.addNonce(tok.nonce, tok.ts + cfg.tokenTtlMs); // burn on allow
        return { allow: true, action: 'allow', status: 200, tier, score, tokenStatus: 'ok',
          reasons: baseReasons.concat(['pow_ok']) };
      };
      if (rawPv && typeof rawPv.then === 'function') {
        return rawPv.then(decide, () => decide({ ok: false, reason: 'pow_error' }));
      }
      return decide(rawPv);

    } catch (err) {
      if (cfg.failOpen) {
        return { allow: true, action: 'allow', status: 200,
          reasons: ['guard_error_fail_open'], error: err && err.message };
      }
      return { allow: false, action: 'block', status: 503,
        reasons: ['guard_error_fail_closed'], error: err && err.message };
    }
  }

  // Called by the host's /__ag/verify endpoint after a slider/captcha submission. Verifies via the
  // configured challenger and, on success, TRUSTS this identity for the grace window (markSolved),
  // so its next requests drop to tier 0 and it isn't re-challenged.
  function solveChallenge(ctx, type, submission) {
    try {
      const ch = cfg.challengers[type];
      if (!ch || !ch.verify) return { ok: false, reason: 'no_verifier' };
      const r = ch.verify(submission) || { ok: false, reason: 'verify_null' };
      if (r.ok) store.markSolved((ctx && ctx.ip) || '', now() + cfg.risk.solvedGraceMs);
      return r;
    } catch (e) { return { ok: false, reason: 'verify_error', error: e && e.message }; }
  }

  // Called by the host when a request hits a honeypot path (see honeypots.js isHoneypot). Flags this
  // identity high-risk for cfg.risk.honeypotBanMs so its NEXT protected requests escalate (block by
  // default). Best-effort + fail-safe: a store without markBad or any throw never breaks the host.
  function flagHoneypot(ctx) {
    try {
      const ip = (ctx && ctx.ip) || '';
      const until = now() + cfg.risk.honeypotBanMs;
      if (store.markBad) store.markBad(ip, until);
      return { flagged: true, ip, until };
    } catch (e) { return { flagged: false, error: e && e.message }; }
  }

  const guard = {
    verdict,
    challenge,
    solveChallenge,
    flagHoneypot,
    // login-boundary fail signal (additive; used by login-captcha.js). Thin, fail-safe wrappers over
    // the store so the host calls guard.recordLoginFail(ip) on a wrong password and never has to reach
    // into store internals. A store lacking these methods (or any throw) degrades to a no-op / 0.
    recordLoginFail: (ip) => { try { return store.recordLoginFail ? store.recordLoginFail(ip, now()) : 0; } catch (_) { return 0; } },
    loginFailCount: (ip) => { try { return store.loginFailCount ? store.loginFailCount(ip, now()) : 0; } catch (_) { return 0; } },
    // mint helpers
    mint: { token: mintToken, challenge: mintChallenge, pow: { solve: solvePow, encode: encodePow } },
    // exposed internals (tests / adapters / future tiers)
    verifyToken, verifyPow, solvePow, scoreRisk, scoreRebroadcast, tierOf, bitsFor,
    isProtected, isExempt, readPow, encodePow,
    // argon2id memory-hard PoW (behind powAlgo='argon2id') — exposed for tests/harness/node reference solve
    mintArgonChallenge, argonParamsFor, solveArgonPow, mkPowChallenge,
    scoreEnv, envSeq,   // ENV-BINDING (anti-lift) — exposed for tests/harness
    store, config: cfg,
  };

  // lazily attach adapters if present (so guard.block / guard.express() "just work")
  try { guard.block = require('./adapter-http')(guard).block; } catch (_) { /* adapter optional */ }
  try { guard.express = () => require('./adapter-express')(guard); } catch (_) { /* adapter optional */ }

  return guard;
}

apiguard.MemoryStore = MemoryStore;
apiguard.leadingZeroBits = leadingZeroBits;
apiguard.b64url = b64url;
apiguard.fromB64url = fromB64url;
module.exports = apiguard;
