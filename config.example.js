'use strict';
/*
 * apiguard/config.example.js — documented example config for v1.
 * Copy, set a real secret from the environment, tune per site.
 *
 *   const guard = require('./core')(require('./config.example'));
 *   // raw http:  if (await guard.block(req, res)) return;
 *   // express:   app.use(guard.express());
 */

module.exports = {
  // REQUIRED. High-entropy server secret (>=16 chars). Keep it out of source control.
  // This is the key the rotating HMAC token + PoW difficulty signature are signed with.
  // Rotating this value instantly invalidates every outstanding token (the "rotation"
  // lever from SPEC §6 — v1 rotates by swapping this secret; v2 adds the WASM variant).
  secret: process.env.GUARD_SECRET || 'CHANGE-ME-use-a-32+char-random-secret',

  // Which paths are protected. String prefix, RegExp, or an array mixing both.
  // Everything not matching is passed straight through (guard is a no-op).
  protect: '/api/',

  // Paths to always let through even under `protect` (health checks, webhooks, etc.).
  exempt: ['/api/health'],

  // Rotating signed-token TTL. Short = more rotation pressure on an attacker, but a
  // client must mint a fresh token more often. Token nonces are single-use (replay-proof).
  tokenTtlMs: 120000,        // 2 minutes
  clockSkewMs: 5000,         // tolerance for a slightly-fast client clock

  // Rate limit: token-bucket per identity (IP + fingerprint). `rpm` is both the
  // steady rate and the burst capacity.
  rpm: 120,

  // ---- Adaptive proof-of-work (invisible; difficulty scales with risk) ----
  powTtlMs: 120000,          // how long an issued challenge stays valid
  powBits: {
    normal: 16,              // baseline difficulty for a normal visitor (~milliseconds)
    // SINGLE ceiling knob. Defaulted to the aggressive end. Raising it hurts a
    // flagged scraper (seconds of CPU per request) but also a false-positive human,
    // so this is the operator's pain/heat tradeoff (SPEC §9.2).
    max: 24,
  },

  // ---- Risk policy (score 0..100 -> tier). Tiers 2/3 are v2/v3; v1 uses 0/1/4. ----
  risk: {
    powAt: 30,               // score >= powAt  -> tier 1 (require invisible PoW)
    blockAt: 80,             // score >= blockAt-> tier 4 (block)
    churnThreshold: 3,       // distinct fingerprints per IP (in-window) before churn penalty
    fanoutThreshold: 8,      // distinct paths per IP (in-window) before fanout penalty
  },

  // If the guard itself throws, allow the request rather than take the site down.
  // Flip to false per site once the guard is trusted in production.
  failOpen: true,

  // Store for rate/nonce/risk state. Default in-memory (single instance).
  // For multi-instance sites, pass a Redis-backed object implementing the same
  // surface as core.js MemoryStore (takeToken / hasNonce / addNonce / track /
  // recordFail / sweep). Redis adapter itself is out of v1 scope.
  // store: myRedisStore,
  storeOpts: {
    windowMs: 60000,         // observation window for churn/fanout/rate signals
    failDecayMs: 300000,     // failed-challenge memory decays after 5 min idle (risk cools)
  },

  // Header names the client and adapters agree on (rarely changed).
  header: { token: 'x-ag-token', pow: 'x-ag-pow', fp: 'x-ag-fp' },

  // PoW-challenge endpoint the client fetches from.
  challengePath: '/__ag/challenge',

  // Optional: inject a clock for testing (defaults to Date.now).
  // now: () => Date.now(),
};
