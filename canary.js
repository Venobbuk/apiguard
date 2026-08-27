'use strict';
/*
 * apiguard/canary.js — PER-USER data canary so a rebroadcast of the live feed traces to the exact
 * account that leaked it. Builds on watermark.js (which does the per-SESSION x-ag-sid header + the
 * proven non-lossy order permutation) and adds three per-USER marks, weakest to strongest:
 *
 *   (a) OPAQUE PER-USER ID in a response HEADER  (x-ag-uid = HMAC(secret,'canary-uid|'+user)).
 *       Survives a copy that keeps headers/log lines. DEFEATED by simply dropping the header.
 *       Reveals nothing about the user (opaque HMAC slice). Confidence when it survives: MEDIUM.
 *
 *   (b) PER-USER DETERMINISTIC ORDER of an ORDER-AGNOSTIC array (reuses watermark.permuteBySession /
 *       matchOrderToSessions — PROVEN non-lossy: identical multiset, not one value changed, only the
 *       sequence differs). The operator must vouch the field's order carries no meaning. DEFEATED by
 *       re-sorting on any obvious key. Small n = low entropy (many users collide) -> WEAK / L2.
 *
 *   (c) HONEYTOKEN (the STRONGEST, and the only one that is UNSTRIPPABLE if they don't know it exists):
 *       canaryRowFor(user) emits a unique, benign DECOY record. The host injects it into ONLY that
 *       user's copy of the feed. A normal user never notices one extra innocuous row. If that exact row
 *       appears in a rebroadcast, the leaker is the one user whose decoy it is — they cannot strip a
 *       mark they cannot distinguish from real data. It is deterministic (HMAC of the user) so
 *       traceLeak can invert it against a candidate list.
 *
 * HONEST FRAMING: (a) and (b) are ATTRIBUTION / DETERRENCE — they trace a leak, they do not prevent one,
 * and a scraper that strips the header and re-sorts the array erases both. (c) defeats stripping only
 * for as long as the decoy is indistinguishable from real rows; once an attacker learns the schema of
 * the decoy they can filter it. Rotate the decoy shape. The leak-TRACING claim is L2 (mechanism proven,
 * not yet matched against a real-world leak); the round-trip MECHANISM (mark -> leak -> trace, non-lossy)
 * is proven L6 in canary-dryrun.cjs.
 *
 * Node built-in `crypto` only. Pure/side-effect-free except mark()'s optional res.setHeader.
 */

const crypto = require('crypto');
const watermark = require('./watermark');

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function canary(config) {
  config = config || {};
  const secret = config.secret;
  if (!secret || typeof secret !== 'string' || secret.length < 16) {
    throw new Error('canary: config.secret required (>=16 chars, high-entropy server secret)');
  }
  const headerName = config.headerName || 'x-ag-uid';
  const uidLen = config.uidLen || 20;         // base64url chars of the per-user HMAC exposed in the header
  const honeyIdLen = config.honeyIdLen || 16; // length of the decoy's identifying token
  const orderField = config.orderField || null; // name of an order-AGNOSTIC array field to permute (opt-in)
  // honeytoken shape: { field:'id', build(user, honeyId) -> record }. If absent, a minimal default decoy
  // is emitted; the host SHOULD pass build() so the decoy blends into its real feed schema.
  const honey = config.honeytoken || null;
  const honeyField = (honey && honey.field) || 'id';

  const hmac = (msg) => crypto.createHmac('sha256', secret).update(msg).digest();
  // reuse the PROVEN watermark mechanism for (b), keyed by the USER string (namespaced by watermark's
  // own 'perm|' prefix, independent of any per-session sid).
  const wm = watermark({ secret });

  // (a) opaque per-user id (namespaced apart from watermark's 'sid|' header).
  function userTag(user) {
    return b64url(hmac('canary-uid|' + String(user == null ? '' : user))).slice(0, uidLen);
  }

  // (c) deterministic per-user honeytoken id, and the full decoy record.
  function honeyId(user) {
    return b64url(hmac('canary-honey|' + String(user == null ? '' : user))).slice(0, honeyIdLen);
  }
  function canaryRowFor(user) {
    const hid = honeyId(user);
    if (honey && typeof honey.build === 'function') {
      const row = honey.build(String(user), hid) || {};
      // guarantee the identifying field is the deterministic honeyId so traceLeak can invert it,
      // even if the host's build() forgot to set it.
      if (row[honeyField] == null) row[honeyField] = hid;
      return row;
    }
    // default benign decoy: an innocuous, clearly-fake-to-us-but-plausible row keyed by honeyId.
    return { [honeyField]: hid, __canary: true, label: 'ref-' + hid };
  }

  /**
   * mark(res, user, payload) -> { uid, payload }
   * NON-DESTRUCTIVE: sets the x-ag-uid header (best-effort, no-op if headers sent / no res) and, IF an
   * orderField is configured and present as an array of length>=2, returns a SHALLOW CLONE whose that
   * one field is reordered per-user (multiset identical). Every other field, and `payload` itself, is
   * left byte-for-byte untouched. Does NOT inject the honeytoken — that is the host's call (it must add
   * canaryRowFor(user) to only that user's array), so mark() never fabricates data behind the host's back.
   */
  function mark(res, user, payload) {
    const uid = userTag(user);
    try { if (res && !res.headersSent && typeof res.setHeader === 'function') res.setHeader(headerName, uid); } catch (e) {}
    let out = payload;
    if (orderField && payload && typeof payload === 'object' &&
        Array.isArray(payload[orderField]) && payload[orderField].length >= 2) {
      out = Array.isArray(payload) ? payload.slice() : Object.assign({}, payload);
      out[orderField] = wm.permuteBySession(payload[orderField], String(user));
    }
    return { uid, payload: out };
  }

  /**
   * traceLeak(observed, candidateUsers) -> attribution report.
   *   observed = {
   *     uid?          : the x-ag-uid value recovered from the leak (if it survived),
   *     records?      : array of leaked rows (to hunt for a honeytoken by its identifying field),
   *     orderIndices? : the leaked ordering expressed as ORIGINAL indices (host maps each leaked
   *                     element back to its pre-permutation index via a stable per-element id),
   *   }
   *   candidateUsers : the pool of accounts to test against (honeyId/userTag are one-way HMACs, so
   *                    tracing requires a candidate list — you confirm a suspect, you don't decrypt).
   *
   * Returns { method, confidence, candidates, byHoneytoken, byUid, byOrder } where `method`/`candidates`
   * reflect the STRONGEST signal that fired (honeytoken > uid > order).
   */
  function traceLeak(observed, candidateUsers) {
    observed = observed || {};
    const cands = Array.isArray(candidateUsers) ? candidateUsers.map(String) : [];

    // (c) honeytoken — strongest, unstrippable if unknown to the attacker.
    let byHoneytoken = [];
    if (Array.isArray(observed.records) && observed.records.length) {
      byHoneytoken = cands.filter((u) => {
        const rid = canaryRowFor(u)[honeyField];
        return observed.records.some((r) => r && r[honeyField] === rid);
      });
    }
    // (a) uid header — medium; strippable.
    let byUid = [];
    if (observed.uid != null) byUid = cands.filter((u) => userTag(u) === observed.uid);

    // (b) order permutation — weak; strippable and low-entropy for small n.
    let byOrder = { candidates: [], bitsOfEvidence: 0, n: 0 };
    if (Array.isArray(observed.orderIndices) && observed.orderIndices.length >= 2) {
      const m = wm.matchOrderToSessions(observed.orderIndices, cands);
      byOrder = { candidates: m.candidates, bitsOfEvidence: m.bitsOfEvidence || 0, n: m.n };
    }

    let method = 'none', candidates = [], confidence = 'none';
    if (byHoneytoken.length) { method = 'honeytoken'; candidates = byHoneytoken; confidence = 'strong (honeytoken — unstrippable if unknown)'; }
    else if (byUid.length) { method = 'uid'; candidates = byUid; confidence = 'medium (uid header survived; strippable)'; }
    else if (byOrder.candidates.length) { method = 'order'; candidates = byOrder.candidates; confidence = 'weak (order match, ~' + byOrder.bitsOfEvidence.toFixed(1) + ' bits; strippable)'; }

    return { method, confidence, candidates, byHoneytoken, byUid, byOrder };
  }

  return {
    headerName,
    userTag,
    honeyId,
    canaryRowFor,
    mark,
    traceLeak,
    _internal: { watermark: wm },
  };
}

module.exports = canary;
