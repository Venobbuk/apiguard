/*
 * apiguard/signals-client.js — browser bot/automation SIGNAL DETECTOR (zero-dependency)
 *
 * Self-contained. Does NOT touch core.js / client.js / adapter-*.js / server.js / pulse.
 * Integrated later by the operator (see the two integration points at the bottom of this file).
 *
 * Browser export:  window.agSignals(win) -> { score, flags, bits }
 *   score  0..100  bot-likelihood (0 = looks fully human, 100 = definitely automated)
 *   flags  string[]  the indicator names that fired
 *   bits   integer   compact bitmask of the fired flags (travels as header x-ag-bt)
 *
 * Node export (server side):  scoreClientSignal(reportedBits) -> { contribution, flags, ... }
 *   maps the reported bitmask to a MODEST additive risk contribution for core.js scoreRisk().
 *
 * ── HONEST THREAT MODEL (read before trusting any of this) ────────────────────────────────
 * Everything here runs on the ATTACKER's machine, so every bit is SPOOFABLE: a competent
 * scraper zeroes navigator.webdriver, injects window.chrome, fakes plugins, and can simply
 * send x-ag-bt: 0. Therefore:
 *   - This is a MODEST additive signal, never the sole basis of a block. That is enforced on
 *     the server by scoreClientSignal() capping its contribution low (see CAP below).
 *   - Its real job is catching the LAZY MAJORITY — vanilla Selenium/Puppeteer/Playwright/
 *     PhantomJS/headless-Chrome that ships with the tells intact. It buys signal for free; it
 *     is not a wall. The durable levers stay PoW + rate-limit + server-side JA4 (SPEC §2/§8).
 * No secret is salted or encoded here on purpose — it is pure detection, meant to be readable.
 * ──────────────────────────────────────────────────────────────────────────────────────────
 */
(function (root, factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api;   // Node: full api
  if (typeof window !== 'undefined') { try { window.agSignals = api.agSignals; window.agSignals.api = api; } catch (e) {} }
})(this, function () {
  'use strict';

  // The wire header that carries `bits`. Short, sibling to x-ag-token / x-ag-pow / x-ag-fp.
  var HEADER = 'x-ag-bt';

  // ── Flag registry ────────────────────────────────────────────────────────────────────────
  // ONE source of truth shared by the client scorer AND the Node mapper, so the two copies of
  // "what does bit N mean" can never desync (engineering doctrine §law: a fact in two places).
  //   name   flag id (also the string emitted in `flags`)
  //   bit    1<<index — stays well under 2^31 so `bits` is always a safe 32-bit int
  //   weight client-side bot-likelihood contribution (points), summed then clamped to 100
  // Strong tells (webdriver / automation globals / headless UA) are individually near-decisive;
  // soft tells are small so no single environment quirk of a REAL user tips the score.
  var FLAGS = [
    { name: 'webdriver',               bit: 1 << 0,  weight: 40 },
    { name: 'automation_global',       bit: 1 << 1,  weight: 40 },
    { name: 'headless_ua',             bit: 1 << 2,  weight: 35 },
    { name: 'no_plugins',              bit: 1 << 3,  weight: 10 },
    { name: 'no_mimetypes',            bit: 1 << 4,  weight: 8  },
    { name: 'no_languages',            bit: 1 << 5,  weight: 15 },
    { name: 'no_chrome_object',        bit: 1 << 6,  weight: 15 },
    { name: 'swiftshader_webgl',       bit: 1 << 7,  weight: 25 },
    { name: 'no_hardware_concurrency', bit: 1 << 8,  weight: 10 },
    { name: 'no_device_memory',        bit: 1 << 9,  weight: 5  },
    { name: 'permissions_mismatch',    bit: 1 << 10, weight: 15 },
    { name: 'screen_anomaly',          bit: 1 << 11, weight: 20 },
    { name: 'dpr_anomaly',             bit: 1 << 12, weight: 5  },
    { name: 'no_pdf_viewer',           bit: 1 << 13, weight: 8  },
    { name: 'touch_mismatch',          bit: 1 << 14, weight: 10 },
    { name: 'no_interaction',          bit: 1 << 15, weight: 12 },
  ];
  var BY_NAME = {};
  for (var _i = 0; _i < FLAGS.length; _i++) BY_NAME[FLAGS[_i].name] = FLAGS[_i];

  function nowMs() { try { return Date.now(); } catch (e) { return 0; } }
  function safe(fn, dflt) { try { var v = fn(); return v; } catch (e) { return dflt; } }

  // ── Interaction-liveness state (per window) ────────────────────────────────────────────────
  // A real user emits at least one pointer/scroll/key/touch event within a few seconds; a pure
  // scraper emits none. We install PASSIVE, capturing listeners once per window and record only
  // a boolean + a start timestamp — no coordinates, nothing sensitive.
  //
  // FALSE-POSITIVE GUARD (important): a genuine user who simply hasn't moved yet in the first
  // ~100ms after load must NOT be punished. So `no_interaction` fires ONLY after a grace period
  // (default 4000ms) AND only while still un-interacted. The instant any interaction happens the
  // flag can never fire again (state.interacted latches true) — i.e. it DECAYS/clears, per spec.
  var _live = (typeof WeakMap !== 'undefined') ? new WeakMap() : null;
  var _liveFallback = null; // single-window fallback if WeakMap is unavailable

  function watch(win) {
    if (!win || typeof win !== 'object') return null;
    var st = _live ? _live.get(win) : _liveFallback;
    if (st) return st;
    st = { start: nowMs(), interacted: false, permMismatch: false, _permStarted: false };
    if (_live) _live.set(win, st); else _liveFallback = st;
    try {
      var mark = function () { st.interacted = true; };
      var evs = ['mousemove', 'pointermove', 'pointerdown', 'mousedown', 'scroll',
                 'wheel', 'keydown', 'touchstart', 'click'];
      if (win.addEventListener) {
        for (var i = 0; i < evs.length; i++) {
          try { win.addEventListener(evs[i], mark, { passive: true, capture: true }); }
          catch (e) { try { win.addEventListener(evs[i], mark, true); } catch (e2) {} }
        }
      }
    } catch (e) {}
    return st;
  }

  // ── Permissions inconsistency (async, non-blocking) ─────────────────────────────────────────
  // Classic headless tell: Notification.permission === 'denied' while
  // navigator.permissions.query({name:'notifications'}) reports 'prompt'. That query is a
  // Promise, so we CANNOT read it synchronously. We kick it off here and cache the verdict on the
  // liveness state; the NEXT agSignals() call (e.g. the next protected fetch) picks it up. This
  // keeps agSignals() fully synchronous and never blocks a page.
  function watchPermissions(win, st) {
    try {
      var nav = win.navigator;
      if (!nav || !nav.permissions || !nav.permissions.query || !st || st._permStarted) return;
      st._permStarted = true;
      var q = nav.permissions.query({ name: 'notifications' });
      if (!q || typeof q.then !== 'function') return;
      q.then(function (res) {
        try {
          var notif = win.Notification && win.Notification.permission;
          if (notif === 'denied' && res && res.state === 'prompt') st.permMismatch = true;
        } catch (e) {}
      }).catch(function () {});
    } catch (e) {}
  }

  // Known automation / instrumentation globals (present on window unless deliberately scrubbed).
  var AUTOMATION_KEYS = [
    '__webdriver_evaluate', '__selenium_evaluate', '__webdriver_script_function',
    '__webdriver_script_func', '__webdriver_script_fn', '__fxdriver_evaluate',
    '__driver_unwrapped', '__webdriver_unwrapped', '__driver_evaluate',
    '__selenium_unwrapped', '__fxdriver_unwrapped', '_Selenium_IDE_Recorder',
    '_selenium', 'calledSelenium', 'callSelenium', '__nightmare', '__phantomas',
    'callPhantom', '_phantom', 'phantom', 'domAutomation', 'domAutomationController',
    '__$webdriverAsyncExecutor', 'webdriver', '__lastWatirAlert', '__lastWatirConfirm',
    '__lastWatirPrompt', 'spawn', 'emit', 'Buffer', // (Buffer/spawn/emit: Electron/node-context leak)
  ];

  // ── The scorer ──────────────────────────────────────────────────────────────────────────────
  function collect(win, opts) {
    opts = opts || {};
    win = win || (typeof window !== 'undefined' ? window : {});
    var nav = safe(function () { return win.navigator; }) || {};
    var doc = safe(function () { return win.document; }) || {};
    var ua = safe(function () { return String(nav.userAgent || ''); }) || '';

    var st = watch(win);
    watchPermissions(win, st);

    var bits = 0, score = 0, flags = [];
    function fire(name) {
      var f = BY_NAME[name];
      if (!f || (bits & f.bit)) return; // already fired — never double-count
      bits |= f.bit; score += f.weight; flags.push(name);
    }

    // 1) navigator.webdriver === true (the single loudest legitimate-API tell)
    try { if (nav.webdriver === true) fire('webdriver'); } catch (e) {}

    // 2) automation / instrumentation globals: explicit keys + cdc_ / $cdc_ scan on win & document
    try {
      for (var a = 0; a < AUTOMATION_KEYS.length; a++) {
        var key = AUTOMATION_KEYS[a];
        // navigator.webdriver is handled above; here we only care about window-level keys
        if (key === 'webdriver') continue;
        try { if (key in win && win[key] != null) { fire('automation_global'); break; } } catch (e) {}
      }
    } catch (e) {}
    try {
      var scanNames = Object.getOwnPropertyNames(win);
      for (var s = 0; s < scanNames.length; s++) {
        if (/^\$?cdc_|_selenium|webdriver|domautomation/i.test(scanNames[s])) { fire('automation_global'); break; }
      }
    } catch (e) {}
    try {
      var docNames = Object.getOwnPropertyNames(doc);
      for (var d = 0; d < docNames.length; d++) {
        if (/^\$?cdc_|selenium|webdriver/i.test(docNames[d])) { fire('automation_global'); break; }
      }
    } catch (e) {}

    // 3) headless / non-browser engine markers in the UA string
    try { if (/HeadlessChrome|Electron|PhantomJS|SlimerJS|jsdom/i.test(ua)) fire('headless_ua'); } catch (e) {}

    // Is this claiming to be desktop Chrome? (gates several Chrome-specific checks below)
    var isChrome = /Chrome\/|CriOS\//.test(ua) && !/Edg\/|Edge\/|OPR\/|OPT\//.test(ua);
    var isMobileUA = /Mobi|Android|iPhone|iPad|iPod|Windows Phone/i.test(ua);
    var isChromeDesktop = isChrome && !isMobileUA;

    // 4) empty plugins / mimeTypes (common in headless; NOTE also possible on locked-down/privacy
    //    browsers and some mobile — hence low weight, never decisive alone)
    try { if (nav.plugins && typeof nav.plugins.length === 'number' && nav.plugins.length === 0) fire('no_plugins'); } catch (e) {}
    try { if (nav.mimeTypes && typeof nav.mimeTypes.length === 'number' && nav.mimeTypes.length === 0) fire('no_mimetypes'); } catch (e) {}

    // 5) navigator.languages empty or missing
    try {
      var langs = nav.languages;
      if (langs == null || (typeof langs.length === 'number' && langs.length === 0)) fire('no_languages');
    } catch (e) {}

    // 6) missing window.chrome on a Chrome UA
    try { if (isChrome && !win.chrome) fire('no_chrome_object'); } catch (e) {}

    // 7) WebGL renderer is a software rasterizer (headless tell)
    try {
      var rnd = readWebglRenderer(win, doc);
      if (rnd && /swiftshader|llvmpipe|mesa offscreen|software|angle \(software|microsoft basic render/i.test(rnd)) {
        fire('swiftshader_webgl');
      }
    } catch (e) {}

    // 8) hardwareConcurrency 0/absent
    try {
      var hc = nav.hardwareConcurrency;
      if (hc === undefined || hc === null || hc === 0) fire('no_hardware_concurrency');
    } catch (e) {}

    // 9) deviceMemory absent — but Firefox/Safari NEVER implement deviceMemory, so flagging its
    //    absence there would false-positive every real Firefox/Safari user. Only meaningful when
    //    the UA claims Chrome (where the API is expected). Low weight regardless.
    try { if (isChrome && nav.deviceMemory === undefined) fire('no_device_memory'); } catch (e) {}

    // 10) permissions inconsistency (verdict computed async on a PRIOR call; see watchPermissions)
    try { if (st && st.permMismatch === true) fire('permissions_mismatch'); } catch (e) {}

    // 11) screen anomalies: zero-sized screen or zero outer window (common in headless)
    try {
      var sc = win.screen;
      if (!sc || sc.width === 0 || sc.height === 0) fire('screen_anomaly');
      else if (win.outerWidth === 0 || win.outerHeight === 0) fire('screen_anomaly');
    } catch (e) {}

    // 12) devicePixelRatio anomaly — ONLY the impossible values (<=0, NaN, non-number). Fractional
    //     ratios like 1.25/1.5/2 are perfectly normal HiDPI and must never fire this.
    try {
      var dpr = win.devicePixelRatio;
      if (typeof dpr !== 'number' || !isFinite(dpr) || dpr <= 0) fire('dpr_anomaly');
    } catch (e) {}

    // 13) navigator.pdfViewerEnabled === false on desktop Chrome (real desktop Chrome ships it true)
    try {
      if (isChromeDesktop && 'pdfViewerEnabled' in nav && nav.pdfViewerEnabled === false) fire('no_pdf_viewer');
    } catch (e) {}

    // 14) touch mismatch: a "mobile" UA with no touch capability at all
    try {
      var maxTP = nav.maxTouchPoints || 0;
      var hasTouch = ('ontouchstart' in win) || maxTP > 0;
      if (isMobileUA && !hasTouch) fire('touch_mismatch');
    } catch (e) {}

    // 15) interaction liveness — see watch(): fires only after grace, clears forever on any input
    try {
      if (st) {
        var graceMs = (opts.graceMs != null) ? opts.graceMs : 4000;
        var t = (opts.nowMs != null) ? opts.nowMs : nowMs();
        if (!st.interacted && (t - st.start) >= graceMs) fire('no_interaction');
      }
    } catch (e) {}

    if (score < 0) score = 0;
    if (score > 100) score = 100;
    return { score: score, flags: flags, bits: bits >>> 0 };
  }

  function readWebglRenderer(win, doc) {
    try {
      if (!doc || !doc.createElement) return '';
      var cv = doc.createElement('canvas');
      var gl = (cv.getContext && (cv.getContext('webgl') || cv.getContext('experimental-webgl') || cv.getContext('webgl2')));
      if (!gl) return '';
      var out = '';
      try {
        var ext = gl.getExtension && gl.getExtension('WEBGL_debug_renderer_info');
        if (ext) out += String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '');
        out += ' ' + String((gl.getParameter && gl.getParameter(gl.RENDERER)) || '');
      } catch (e) {
        try { out += String((gl.getParameter && gl.getParameter(gl.RENDERER)) || ''); } catch (e2) {}
      }
      return out;
    } catch (e) { return ''; }
  }

  // ── Public browser entry point ────────────────────────────────────────────────────────────
  // agSignals(win[, opts]) -> { score, flags, bits }
  // opts (all optional, mainly for testing): { graceMs, nowMs }
  function agSignals(win, opts) { return collect(win, opts); }
  agSignals.watch = watch;          // exposed so client.js can install liveness listeners EARLY
  agSignals.HEADER = HEADER;
  agSignals.FLAGS = FLAGS;

  // ── Node / server-side mapper ────────────────────────────────────────────────────────────
  // scoreClientSignal(reportedBits) -> { contribution, flags, rawClientScore, spoofable, header }
  //
  // ⚠️ SPOOFABLE (repeated because it matters): the client controls x-ag-bt. A smart scraper
  // sends 0 (or a hand-picked "human-looking" value). NEVER block on this alone. We therefore:
  //   - CAP the additive contribution at CAP points (default 25 of the 0..100 risk scale), and
  //   - discount the raw client score by FACTOR, so even a "everything-fired" report adds only a
  //     nudge that pushes a borderline identity toward the existing PoW threshold (core powAt=30),
  //     never past the block threshold (blockAt=80) by itself.
  // Effect: the honest majority of lazy headless scrapers (which DON'T spoof) eat a real penalty;
  // a determined attacker who zeroes it simply gets no bonus signal from us and is judged on the
  // unspoofable server-side inputs (token/rate/JA4) exactly as before.
  var CAP = 25;
  var FACTOR = 0.35;
  function scoreClientSignal(reportedBits) {
    var bits = Number(reportedBits);
    if (!isFinite(bits) || bits < 0) bits = 0;
    bits = bits >>> 0;
    var raw = 0, flags = [];
    for (var i = 0; i < FLAGS.length; i++) {
      if (bits & FLAGS[i].bit) { raw += FLAGS[i].weight; flags.push(FLAGS[i].name); }
    }
    if (raw > 100) raw = 100;
    var contribution = Math.min(CAP, Math.round(raw * FACTOR));
    return {
      contribution: contribution,     // add this to core.js scoreRisk() total
      flags: flags,                   // for logging / observability
      rawClientScore: raw,            // the un-capped client self-report (0..100), for logs only
      spoofable: true,                // ALWAYS true — a reminder to callers, never trust as sole basis
      header: HEADER,
    };
  }

  return {
    agSignals: agSignals,
    scoreClientSignal: scoreClientSignal,
    FLAGS: FLAGS,
    HEADER: HEADER,
    watch: watch,
  };
});
