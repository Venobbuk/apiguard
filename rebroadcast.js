'use strict';
/*
 * apiguard/rebroadcast.js — PURE behavioral scorer for "this identity is re-broadcasting the feed".
 *
 * Companion to core.js: core keeps a lightweight per-identity ring of {ts,path} events (store.trackPattern)
 * and calls this module to turn that ring into a risk SIGNAL that folds into the existing tier ladder.
 * Kept as a separate, dependency-free, side-effect-free module so it can be unit-proven on synthetic
 * traces (rebroadcast-dryrun.cjs) WITHOUT a store, a socket, or a clock.
 *
 * WHAT WE ARE TRYING TO CATCH (operator's words): a logged-in account that resells the live feed by
 * pulling (near) the WHOLE feed, repeatedly, at machine cadence — never idling, near-zero think-time
 * variance, broad endpoint fan-out on a steady interval. The tell is MACHINE VOLUME + REGULARITY +
 * REPEATED FULL-FEED COVERAGE, *not* raw speed.
 *
 * WHAT WE DELIBERATELY DO NOT CATCH (operator: "don't block real users moving fast"): a human who
 * clicks fast. A human hits a FEW endpoints, in an IRREGULAR rhythm, and PAUSES (reads, thinks). Any
 * one of those breaks the machine signature, so a fast human scores 0. When the sample is too small to
 * judge, we ABSTAIN (verdict 'abstain', signal 0) rather than guess — a check that can only say
 * flag/clear will eventually lie (doctrine R8).
 *
 * HONEST CAVEATS:
 *   - FALSE-POSITIVE FLOOR: a legitimately automated-but-authorised client (an official polling
 *     dashboard, a partner integration) that mirrors the whole feed on a fixed timer looks EXACTLY like
 *     a rebroadcaster to any behavioral test — same volume, same cadence, same coverage. Behaviour alone
 *     cannot separate "authorised mirror" from "unauthorised mirror". Allowlist known good machine
 *     clients by identity; this detector is for the UNKNOWN full-feed mirror. It raises risk (→ challenge
 *     first, block only at the top tier); it is deterrence + friction, not proof of wrongdoing.
 *   - An attacker who KNOWS the thresholds can evade by injecting jitter/idle and capping volume — at
 *     which point they are no longer mirroring the whole feed at machine cadence, i.e. the friction did
 *     its job (slowed them below a useful rebroadcast rate). Confidence for the "is a rebroadcaster"
 *     CLAIM is L2 (behavioral inference); the MECHANISM (firehose trips, bursty human does not) is L6.
 */

// ---- defaults (all tunable via core cfg.rebroadcast) -----------------------
const DEFAULTS = {
  windowMs: 60000,   // observation window
  minEvents: 30,     // below this in-window we ABSTAIN — too little to tell a machine from a keen human
  cvMax: 0.40,       // max coefficient-of-variation of inter-arrival gaps to count as "flat cadence"
  fanoutMin: 8,      // >= this many DISTINCT endpoints in-window = "broad" (whole feed, not one page)
  repeatMin: 3,      // events/distinctPaths >= this = each endpoint pulled repeatedly (mirroring loops)
  idleFactorMax: 4,  // largest gap <= idleFactorMax * meanGap = "never really idles" (no human pause)
  signal: 50,        // risk points added when the machine signature is met (enough to move a tier)
  maxEvents: 512,    // ring cap the store keeps per identity (memory bound)
};

/**
 * computeStats(events, now, windowMs) -> pure metrics over the in-window slice.
 *   events: array of { ts:Number, path:String } (any order; we sort by ts).
 * Returns { n, meanGapMs, cv, distinctPaths, repeats, idleMaxMs, spanMs }.
 */
function computeStats(events, now, windowMs) {
  const cutoff = now - windowMs;
  const win = (events || []).filter((e) => e && e.ts >= cutoff).sort((a, b) => a.ts - b.ts);
  const n = win.length;
  if (n === 0) return { n: 0, meanGapMs: 0, cv: 0, distinctPaths: 0, repeats: 0, idleMaxMs: 0, spanMs: 0 };
  const paths = new Set();
  const gaps = [];
  let idleMax = 0;
  for (let i = 0; i < n; i++) {
    if (win[i].path != null) paths.add(win[i].path);
    if (i > 0) { const g = win[i].ts - win[i - 1].ts; gaps.push(g); if (g > idleMax) idleMax = g; }
  }
  let meanGap = 0, cv = 0;
  if (gaps.length) {
    meanGap = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    if (meanGap > 0) {
      const varr = gaps.reduce((a, g) => a + (g - meanGap) * (g - meanGap), 0) / gaps.length;
      cv = Math.sqrt(varr) / meanGap;
    }
  }
  const distinctPaths = paths.size;
  return {
    n,
    meanGapMs: Math.round(meanGap),
    cv: Number(cv.toFixed(4)),
    distinctPaths,
    repeats: distinctPaths ? Number((n / distinctPaths).toFixed(2)) : n,
    idleMaxMs: idleMax,
    spanMs: win[n - 1].ts - win[0].ts,
  };
}

/**
 * makeRebroadcastScorer(config) -> { score(stats), config, computeStats }
 * score(stats) -> { signal, verdict:'abstain'|'clear'|'flag', reasons, metrics }
 *   - 'abstain' when the instrument can't tell (too few events) — signal 0, never a flag.
 *   - 'flag' only when ALL machine conditions hold at once. Any single human trait -> 'clear'.
 */
function makeRebroadcastScorer(config) {
  const cfg = Object.assign({}, DEFAULTS, config || {});

  function score(stats) {
    const m = stats || { n: 0 };
    // ABSTAIN: not enough signal to distinguish a rebroadcaster from an enthusiastic human.
    if (m.n < cfg.minEvents) {
      return { signal: 0, verdict: 'abstain', reasons: ['insufficient_sample(n=' + m.n + '<' + cfg.minEvents + ')'], metrics: m };
    }
    const regular = m.cv <= cfg.cvMax;                                   // flat, low-variance cadence
    const broad = m.distinctPaths >= cfg.fanoutMin;                      // whole feed, not one page
    const repeated = m.repeats >= cfg.repeatMin;                         // pulled in loops (mirroring)
    const noIdle = m.meanGapMs > 0 && m.idleMaxMs <= cfg.idleFactorMax * m.meanGapMs; // never pauses

    const reasons = [];
    if (regular) reasons.push('flat_cadence(cv=' + m.cv + '<=' + cfg.cvMax + ')');
    else reasons.push('irregular_cadence(cv=' + m.cv + ')');
    if (broad) reasons.push('broad_fanout(' + m.distinctPaths + '>=' + cfg.fanoutMin + ')');
    else reasons.push('narrow_fanout(' + m.distinctPaths + ')');
    if (repeated) reasons.push('repeated_sweeps(repeats=' + m.repeats + '>=' + cfg.repeatMin + ')');
    else reasons.push('single_pass(repeats=' + m.repeats + ')');
    if (noIdle) reasons.push('no_idle(idleMax=' + m.idleMaxMs + '<=' + cfg.idleFactorMax + 'x' + m.meanGapMs + ')');
    else reasons.push('has_idle(idleMax=' + m.idleMaxMs + ')');

    const machineLike = regular && broad && repeated && noIdle;
    if (machineLike) {
      return { signal: cfg.signal, verdict: 'flag', reasons: ['rebroadcast_machine_cadence'].concat(reasons), metrics: m };
    }
    return { signal: 0, verdict: 'clear', reasons: ['human_or_partial'].concat(reasons), metrics: m };
  }

  return { score, config: cfg, computeStats: (events, now) => computeStats(events, now, cfg.windowMs) };
}

module.exports = { makeRebroadcastScorer, computeStats, DEFAULTS };
