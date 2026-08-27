'use strict';
/*
 * apiguard/watermark.js — per-session tracing so leaked/scraped API data points back to the session
 * that pulled it. CONSERVATIVE by design: it NEVER perturbs a meaningful value (no price/score/number
 * is ever changed). Node built-in `crypto` only.
 *
 * TWO layers, in increasing intrusiveness. Layer A ships on its own; Layer B is OPT-IN per operator-
 * named field and is off unless the host explicitly calls it.
 *
 *  ── Layer A — opaque per-session id in a response HEADER (SAFE, always on where wired) ────────────
 *     sid = HMAC(secret, 'sid|' + session)  (stable per session, unguessable, reveals nothing about
 *     the user). Echoed as `x-ag-sid`. If a JSON dump leaks WITH its headers/log line, the sid maps
 *     back to the session. Cost: zero data risk (headers never touch the body).
 *
 *  ── Layer B — deterministic ORDER watermark on an ORDER-AGNOSTIC array (OPT-IN, provably non-lossy) ─
 *     For an array whose element ORDER carries no meaning (the operator must vouch this per field),
 *     we reorder it by a per-session permutation. The MULTISET of elements is identical — every value,
 *     every field, every number is byte-for-byte unchanged; only the sequence differs. A later capture
 *     of that ordering can be matched back to a session (forensics). We do NOT apply this to any Pulse
 *     field here: which Pulse arrays are truly order-agnostic is the OPERATOR's call (see the honest
 *     note at the bottom). Confidence for the leak-tracing CLAIM is L2 (mechanism proven; not yet
 *     tested against a real leak).
 *
 * What this CAN prove: which SESSION a leak came from, IF the sid header (A) or the ordering (B)
 * survived the copy. What it CANNOT: a scraper that strips the header, or re-sorts the array by an
 * obvious key, erases the mark. This is attribution/deterrence, NOT prevention. State that plainly.
 */

const crypto = require('crypto');

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function watermark(config) {
  config = config || {};
  const secret = config.secret;
  if (!secret || typeof secret !== 'string' || secret.length < 16) {
    throw new Error('watermark: config.secret required (>=16 chars, high-entropy server secret)');
  }
  const headerName = config.headerName || 'x-ag-sid';
  const sidLen = config.sidLen || 20; // base64url chars of the HMAC to expose
  const hmac = (msg) => crypto.createHmac('sha256', secret).update(msg).digest();

  // ── Layer A ────────────────────────────────────────────────────────────────
  // session = any stable per-session string the host has (a session-cookie value, a user+device id,
  // the ag_gate cookie, etc.). Opaque and stable: same session -> same sid; different -> different.
  function sessionId(session) {
    return b64url(hmac('sid|' + String(session == null ? '' : session))).slice(0, sidLen);
  }
  // Convenience: set the header on a Node res (safe no-op if headers already sent).
  function applyHeader(res, session) {
    try { if (res && !res.headersSent) res.setHeader(headerName, sessionId(session)); } catch (e) {}
    return sessionId(session);
  }

  // ── Layer B (opt-in) — order-permutation watermark ──────────────────────────
  // factorial as BigInt (exact for any n).
  function fact(n) { let f = 1n; for (let i = 2n; i <= BigInt(n); i++) f *= i; return f; }

  // Lehmer decode: rank in [0, n!) -> a permutation (array of the indices 0..n-1 in permuted order).
  function permutationFromRank(rank, n) {
    const idx = []; for (let i = 0; i < n; i++) idx.push(i);
    const out = []; let r = ((rank % fact(n)) + fact(n)) % fact(n);
    for (let i = n; i >= 1; i--) {
      const f = fact(i - 1);
      const j = Number(r / f); r = r % f;
      out.push(idx.splice(j, 1)[0]);
    }
    return out;
  }
  // Lehmer encode: a permutation (indices) -> its rank in [0, n!). Inverse of permutationFromRank.
  function rankFromPermutation(perm) {
    const n = perm.length;
    const avail = []; for (let i = 0; i < n; i++) avail.push(i);
    let rank = 0n;
    for (let i = 0; i < n; i++) {
      const pos = avail.indexOf(perm[i]);
      rank += BigInt(pos) * fact(n - 1 - i);
      avail.splice(pos, 1);
    }
    return rank;
  }
  // the per-session rank for an array of length n. Uses a full 256-bit HMAC reduced mod n!.
  function sessionRank(session, n) {
    if (n < 2) return 0n;
    const big = BigInt('0x' + hmac('perm|' + String(session) + '|' + n).toString('hex'));
    return big % fact(n);
  }

  /**
   * permuteBySession(arr, session) -> a NEW array: the SAME elements (identical multiset, values
   * untouched) in a per-session order. Pure; does not mutate `arr`. Apply ONLY to order-agnostic arrays.
   */
  function permuteBySession(arr, session) {
    if (!Array.isArray(arr) || arr.length < 2) return Array.isArray(arr) ? arr.slice() : arr;
    const perm = permutationFromRank(sessionRank(session, arr.length), arr.length);
    return perm.map((i) => arr[i]);
  }

  /**
   * Forensics: given an OBSERVED ordering expressed as the original indices of each element
   * (the host recovers these via a stable per-element id), return the candidate sessions whose
   * per-session rank matches. Small n -> many collisions (narrows, doesn't prove) -> L2.
   *   observedIndices : e.g. [3,0,2,1] meaning leaked[0]=original[3], ...
   *   candidateSessions: array of session strings to test
   */
  function matchOrderToSessions(observedIndices, candidateSessions) {
    const n = observedIndices.length;
    if (n < 2) return { rank: '0', candidates: candidateSessions.slice(), n };
    const rank = rankFromPermutation(observedIndices);
    const candidates = candidateSessions.filter((s) => sessionRank(s, n) === rank);
    return { rank: rank.toString(), candidates, n, bitsOfEvidence: Math.log2(Number(fact(n))) };
  }

  return {
    headerName,
    sessionId,
    applyHeader,
    // Layer B (opt-in)
    permuteBySession,
    matchOrderToSessions,
    _internal: { permutationFromRank, rankFromPermutation, sessionRank, fact },
  };
}

module.exports = watermark;
