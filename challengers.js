'use strict';
/*
 * apiguard/challengers.js — wires the host-provided INTERACTIVE challenge minters/verifiers
 * that core.js calls for tier 2 (slider) and tier 3 (motion captcha), keeping core.js zero-dep.
 *
 *   const { buildChallengers } = require('./challengers');
 *   const guard = apiguard({ secret, protect:'/api/', challengers: buildChallengers(secret) });
 *
 * Contract (see core.js verdict + solveChallenge):
 *   challengers.slider  = { mint(ctx) -> puzzleObj,  verify(sub) -> {ok,reason} }
 *   challengers.captcha = { mint(ctx) -> captchaObj, verify(sub) -> {ok,reason} }
 *
 * The mint OUTPUT is what the server returns to the client in the 401 body (`challenge`).
 * It MUST carry everything the client needs to (a) render the widget and (b) post back a
 * submission that verify() can check WITHOUT server-side per-challenge state:
 *   slider  mint  -> { id, w, h, gapX, gapY, pieceSize, seed, sig, expiry }
 *           verify sub <- { id, gapX, gapY, expiry, sig, answerX, trail }   (answerX+trail from user)
 *   captcha mint  -> { id, image, color, expiry, sig }   (plaintext answer is NEVER sent; sig commits it)
 *           verify sub <- { id, expiry, sig, answer }                       (answer typed by user)
 * Both are stateless: the HMAC `sig` (signed with `secret`) is the committed truth, so nothing
 * needs to be remembered between mint and verify — which is what lets this run behind >1 instance.
 *
 * NOTE: makeCcMotion lazily require()s `captcha-canvas` only when a captcha is actually minted.
 * That package (+ its native skia-canvas peer) must resolve at runtime — it lives under
 * apiguard/node_modules on the server and apiguard/build/node_modules locally. A verify-only
 * caller (or the slider) never pulls it in.
 */

const { makeCcMotion, verifyCcMotion } = require('./motion-captcha-cc');
const { makePuzzle, verifyPuzzle } = require('./slider');

/**
 * buildChallengers(secret, opts) -> { slider, captcha }
 *   opts.slider  = per-puzzle options passed to makePuzzle/verifyPuzzle (tolerances, size, ttl…)
 *   opts.captcha = per-captcha options passed to makeCcMotion/verifyCcMotion (charset, size, ttl…)
 * `ctx` (the request context core.js hands to mint) is available for future per-request tuning
 * (e.g. harder puzzle for a higher-risk ctx); v1 mints uniformly.
 */
function buildChallengers(secret, opts) {
  if (!secret || typeof secret !== 'string' || secret.length < 16) {
    throw new Error('buildChallengers: secret required (>=16 chars, same server secret apiguard is signed with)');
  }
  opts = opts || {};
  const sliderOpts = opts.slider || {};
  const captchaOpts = opts.captcha || {};
  // SINGLE-USE BURN (2026-08-24, operator bar "never replayed"): slider/captcha sigs are stateless =
  // replayable within their TTL. Pulse is single-instance, so remember each SOLVED challenge id until its
  // expiry and REJECT a second use. Only a PASS is burned; a submission with no id fails open (already verified).
  const _seen = new Map();  // id -> expiryMs
  function _sweep(now) { for (const [k, exp] of _seen) if (exp < now) _seen.delete(k); }
  function _once(sub, r) {
    if (!r || !r.ok) return r;
    const idk = (sub && sub.id != null) ? String(sub.id) : null;
    if (!idk) return r;
    const now = Date.now();
    if (_seen.has(idk)) return { ok: false, reason: 'challenge_replayed' };
    _seen.set(idk, (Number(sub.expiry) || (now + 120000)));
    if (_seen.size > 4096) _sweep(now);
    return r;
  }
  return {
    slider: {
      mint(ctx) { return makePuzzle(secret, sliderOpts); },                 // ctx reserved for per-risk tuning
      verify(sub) { return _once(sub, verifyPuzzle(secret, sub, sliderOpts)); },
    },
    captcha: {
      mint(ctx) { return makeCcMotion(secret, captchaOpts); },
      verify(sub) { return _once(sub, verifyCcMotion(secret, sub, captchaOpts)); },
    },
  };
}

module.exports = { buildChallengers };
