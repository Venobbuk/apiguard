/*
 * apiguard/slider.js — v3 tier-2 SLIDER CAPTCHA (self-contained, zero-dependency)
 *
 * A GeeTest-style "drag the puzzle piece into the gap" challenge. Two sides in one
 * UMD file (mirrors client.js): Node `crypto` server helpers + a browser canvas widget.
 * NOTHING here touches core.js / client.js / server.js / adapter-*.js / pulse — it is a
 * standalone module the caller wires in later (see the header of slider-test.cjs / report).
 *
 *   SERVER (Node):
 *     makePuzzle(secret, opts)      -> { id, w, h, gapX, gapY, pieceSize, seed, sig, expiry }
 *     verifyPuzzle(secret, sub,opt) -> { ok, reason, metrics }
 *
 *   BROWSER:
 *     renderSlider(win, container, puzzle, onSolve)
 *        draws a procedural canvas puzzle + draggable piece, records the pointer trail,
 *        and on release calls onSolve({ id, gapX, gapY, expiry, sig, answerX, trail }).
 *
 * ---------------------------------------------------------------------------
 * DESIGN DECISION — is gapX (the answer) sent to the client?  YES, and here is why.
 * ---------------------------------------------------------------------------
 * The client renders the puzzle entirely on its own canvas from procedural data (no
 * server image). To draw the GAP silhouette it must know WHERE the gap is — i.e. gapX.
 * There is no way to render a gap at a secret position purely client-side: whatever the
 * client can draw, the attacker can read. So hiding gapX behind a seed would be security
 * theatre (the client would just recompute it). We therefore send gapX in the clear and
 * LOCK it with an HMAC `sig = HMAC(secret, id|gapX|gapY|expiry)` — mirroring how core.js
 * signs the PoW `salt|bits|expiry`. That stops the client TAMPERING with the target
 * (moving the goalposts), but it does NOT stop a bot from simply reporting answerX==gapX.
 *
 * That is fine, and intended: the position match is a WEAK, secondary gate. The REAL
 * security is the BEHAVIORAL DRAG-TRAIL check in verifyPuzzle — a bot that teleports the
 * piece to gapX with a 2-point / perfectly-linear / constant-velocity / instant trail is
 * rejected. Per SPEC.md §8: "Interactive image/text challenges are defeatable by 2026 AI
 * solvers — the durable lever is the behavioral check, not the picture." This file is
 * built to that doctrine: the image deters, the trail decides.
 * ---------------------------------------------------------------------------
 */
(function (root, factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api;   // Node
  if (typeof window !== 'undefined') window.apiguardSlider = api;              // Browser
})(this, function () {
  'use strict';

  // crypto is Node-only; the browser widget never signs/verifies, it only replays `sig`.
  var nodeCrypto = (typeof require === 'function' && typeof window === 'undefined')
    ? require('crypto') : null;

  // ---- tunables (every threshold is here so the operator can tune false-positives) ----
  var DEFAULTS = {
    w: 320,               // board width  (px)  — answer space for gapX is 0..w
    h: 180,               // board height (px)
    pieceSize: 44,        // puzzle piece / gap edge (px)
    edgeMargin: 12,       // keep the gap away from the extreme edges
    minGapFrac: 0.35,     // gap never sits in the left third (the piece starts there)
    ttlMs: 120000,        // challenge lifetime

    // --- acceptance thresholds ---
    tolerance: 8,         // |answerX - gapX| must be <= this (px). Weak/secondary gate.
    minPoints: 8,         // fewer points than this = a teleport, not a drag
    minDurationMs: 180,   // faster than this across the whole drag = superhuman
    maxDurationMs: 60000, // slower than this = stale / abandoned (very lenient)
    minNetProgressPx: 12, // the piece has to actually travel
    minYJitterStd: 0.20,  // std-dev of pointer Y; a machine holds a perfectly flat line
    minVelCoV: 0.15,      // coeff. of variation of segment speed; a machine holds it constant
  };

  // ---- tiny helpers ----------------------------------------------------------
  function _now() { return Date.now(); }
  function b64url(buf) {
    return Buffer.from(buf).toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function fromB64url(s) {
    return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  }
  // canonical signing message — identical string on mint and verify so HMAC matches
  function _sigMsg(id, gapX, gapY, expiry) {
    return String(id) + '|' + String(gapX) + '|' + String(gapY) + '|' + String(expiry);
  }
  function _hmac(secret, msg) {
    return nodeCrypto.createHmac('sha256', secret).update(msg).digest(); // Buffer(32)
  }
  function _safeEqualB64(providedB64, expectedBuf) {
    var p;
    try { p = fromB64url(providedB64); } catch (e) { return false; }
    if (p.length !== expectedBuf.length) return false;
    return nodeCrypto.timingSafeEqual(p, expectedBuf);
  }
  // deterministic 32-bit seed from an id string (so the client draws a stable board)
  function _seedFromId(id) {
    var h = 2166136261 >>> 0;
    var s = String(id);
    for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
    return h >>> 0;
  }
  function _mulberry32(a) {
    return function () {
      a |= 0; a = (a + 0x6D2B79F5) | 0;
      var t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // ==========================================================================
  // SERVER: makePuzzle
  // ==========================================================================
  function makePuzzle(secret, opts) {
    if (!nodeCrypto) throw new Error('makePuzzle is server-side only (needs Node crypto)');
    if (!secret || String(secret).length < 16) throw new Error('makePuzzle: secret must be >= 16 chars');
    opts = opts || {};
    var C = Object.assign({}, DEFAULTS, opts);
    var now = (typeof opts.now === 'function') ? opts.now() : (opts.now != null ? opts.now : _now());

    var id = (opts.id) || b64url(nodeCrypto.randomBytes(12));
    var seed = _seedFromId(id);
    var rnd = _mulberry32(seed);

    var w = C.w, h = C.h, pieceSize = C.pieceSize;
    // gapX sits in [max(edge, w*minGapFrac) .. w - pieceSize - edge]; gapY vertically centred-ish
    var loX = Math.max(C.edgeMargin, Math.floor(w * C.minGapFrac));
    var hiX = w - pieceSize - C.edgeMargin;
    if (hiX <= loX) hiX = loX + 1;
    var gapX = (opts.gapX != null) ? opts.gapX : Math.round(loX + rnd() * (hiX - loX));
    var loY = C.edgeMargin;
    var hiY = h - pieceSize - C.edgeMargin;
    if (hiY <= loY) hiY = loY + 1;
    var gapY = (opts.gapY != null) ? opts.gapY : Math.round(loY + rnd() * (hiY - loY));

    var expiry = (opts.expiry != null) ? opts.expiry : now + C.ttlMs;
    var sig = b64url(_hmac(secret, _sigMsg(id, gapX, gapY, expiry)));

    // NOTE: gapX IS included (see file header). It is HMAC-locked by `sig`.
    return { id: id, w: w, h: h, gapX: gapX, gapY: gapY, pieceSize: pieceSize,
      seed: seed, sig: sig, expiry: expiry };
  }

  // ==========================================================================
  // SERVER: behavioral trail check — the REAL security
  // ==========================================================================
  // Returns { ok, reason, metrics }. Every rejection names WHY. Follows house-rule R8:
  // it ABSTAINS ('trail_unusable') when the instrument can't even read the trail, rather
  // than silently passing or failing.
  function checkTrail(trail, opts) {
    var C = Object.assign({}, DEFAULTS, opts || {});
    if (!Array.isArray(trail)) return { ok: false, reason: 'trail_missing', metrics: null };
    var n = trail.length;
    if (n < C.minPoints) return { ok: false, reason: 'trail_too_few_points', metrics: { n: n } };

    // validate shape + monotonic non-decreasing time
    var xs = new Array(n), ys = new Array(n), ts = new Array(n);
    for (var i = 0; i < n; i++) {
      var p = trail[i];
      if (!p || typeof p.x !== 'number' || typeof p.y !== 'number' || typeof p.t !== 'number'
        || !isFinite(p.x) || !isFinite(p.y) || !isFinite(p.t)) {
        return { ok: false, reason: 'trail_unusable', metrics: { badIndex: i } }; // NO-VERDICT-ish
      }
      xs[i] = p.x; ys[i] = p.y; ts[i] = p.t;
      if (i > 0 && ts[i] < ts[i - 1]) return { ok: false, reason: 'trail_bad_timing', metrics: { at: i } };
    }

    var dur = ts[n - 1] - ts[0];
    var netX = xs[n - 1] - xs[0];

    // duration window
    if (dur < C.minDurationMs) return { ok: false, reason: 'trail_too_fast', metrics: { dur: dur } };
    if (dur > C.maxDurationMs) return { ok: false, reason: 'trail_too_slow', metrics: { dur: dur } };
    // actual travel
    if (netX < C.minNetProgressPx) return { ok: false, reason: 'trail_no_progress', metrics: { netX: netX } };

    // Y jitter — a real hand never holds a pixel-flat line; a scripted drag does
    var yStd = _std(ys);
    if (yStd < C.minYJitterStd) return { ok: false, reason: 'trail_no_y_jitter', metrics: { yStd: yStd } };

    // segment speeds -> coefficient of variation. Constant velocity == machine.
    var speeds = [];
    for (i = 1; i < n; i++) {
      var dt = ts[i] - ts[i - 1];
      if (dt <= 0) continue;               // simultaneous samples: skip, don't divide by zero
      speeds.push(Math.abs(xs[i] - xs[i - 1]) / dt);
    }
    if (speeds.length < 3) return { ok: false, reason: 'trail_too_few_points', metrics: { usable: speeds.length } };
    var sMean = _mean(speeds);
    if (sMean <= 0) return { ok: false, reason: 'trail_no_progress', metrics: { sMean: sMean } };
    var vCoV = _std(speeds) / sMean;
    if (vCoV < C.minVelCoV) return { ok: false, reason: 'trail_constant_velocity', metrics: { vCoV: vCoV } };

    return { ok: true, reason: 'ok',
      metrics: { n: n, dur: dur, netX: netX, yStd: round3(yStd), vCoV: round3(vCoV) } };
  }
  function _mean(a) { var s = 0; for (var i = 0; i < a.length; i++) s += a[i]; return a.length ? s / a.length : 0; }
  function _std(a) {
    if (a.length < 2) return 0;
    var m = _mean(a), v = 0;
    for (var i = 0; i < a.length; i++) { var d = a[i] - m; v += d * d; }
    return Math.sqrt(v / a.length);
  }
  function round3(x) { return Math.round(x * 1000) / 1000; }

  // ==========================================================================
  // SERVER: verifyPuzzle
  // ==========================================================================
  function verifyPuzzle(secret, sub, opts) {
    if (!nodeCrypto) throw new Error('verifyPuzzle is server-side only (needs Node crypto)');
    opts = opts || {};
    var C = Object.assign({}, DEFAULTS, opts);
    if (!sub || typeof sub !== 'object') return { ok: false, reason: 'missing_submission' };

    var id = sub.id, gapX = sub.gapX, gapY = sub.gapY, expiry = sub.expiry,
      sig = sub.sig, answerX = sub.answerX, trail = sub.trail;
    if (id == null || gapX == null || gapY == null || expiry == null || sig == null || answerX == null) {
      return { ok: false, reason: 'missing_fields' };
    }

    // 1) sig valid (timing-safe) — locks gapX/gapY/expiry, client can't move the target
    var expected = _hmac(secret, _sigMsg(id, gapX, gapY, expiry));
    if (!_safeEqualB64(sig, expected)) return { ok: false, reason: 'bad_sig' };

    // 2) not expired
    var now = (typeof opts.now === 'function') ? opts.now() : (opts.now != null ? opts.now : _now());
    if (now > Number(expiry)) return { ok: false, reason: 'expired' };

    // 3) position match (weak, secondary gate — see file header)
    var off = Math.abs(Number(answerX) - Number(gapX));
    if (!(off <= C.tolerance)) return { ok: false, reason: 'wrong_position', metrics: { off: off } };

    // 4) behavioral trail (the REAL security)
    var tr = checkTrail(trail, C);
    if (!tr.ok) return { ok: false, reason: tr.reason, metrics: tr.metrics };

    return { ok: true, reason: 'ok', metrics: tr.metrics };
  }

  // ==========================================================================
  // BROWSER: renderSlider — procedural canvas puzzle + draggable piece + trail
  // ==========================================================================
  function _puzzlePath(ctx, x, y, s) {
    // rounded square with a round tab on the right and a notch on top (a "puzzle" look)
    var r = Math.max(4, s * 0.14), t = s * 0.28;         // corner radius, tab radius
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + s * 0.5 - t * 0.7, y);                // top edge up to notch
    ctx.arc(x + s * 0.5, y, t * 0.7, Math.PI, 0, true);  // top notch (inward)
    ctx.lineTo(x + s - r, y);
    ctx.arcTo(x + s, y, x + s, y + r, r);
    ctx.lineTo(x + s, y + s * 0.5 - t);                  // right edge up to tab
    ctx.arc(x + s, y + s * 0.5, t, -Math.PI / 2, Math.PI / 2, false); // right tab (outward)
    ctx.lineTo(x + s, y + s - r);
    ctx.arcTo(x + s, y + s, x + s - r, y + s, r);
    ctx.lineTo(x + r, y + s);
    ctx.arcTo(x, y + s, x, y + s - r, r);
    ctx.lineTo(x, y + r);
    ctx.arcTo(x, y, x + r, y, r);
    ctx.closePath();
  }

  function _drawBackground(ctx, puzzle) {
    var rnd = _mulberry32(puzzle.seed >>> 0);
    var w = puzzle.w, h = puzzle.h;
    // base gradient
    var g = ctx.createLinearGradient(0, 0, w, h);
    var hue = Math.floor(rnd() * 360);
    g.addColorStop(0, 'hsl(' + hue + ',45%,55%)');
    g.addColorStop(1, 'hsl(' + ((hue + 60) % 360) + ',45%,38%)');
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, w, h);
    // scatter translucent shapes so the gap has visual context to line up against
    for (var i = 0; i < 14; i++) {
      ctx.globalAlpha = 0.10 + rnd() * 0.18;
      ctx.fillStyle = rnd() > 0.5 ? '#ffffff' : '#000000';
      var cx = rnd() * w, cy = rnd() * h, rr = 8 + rnd() * 34;
      ctx.beginPath();
      if (rnd() > 0.5) { ctx.arc(cx, cy, rr, 0, Math.PI * 2); }
      else { ctx.rect(cx, cy, rr, rr); }
      ctx.fill();
    }
    ctx.globalAlpha = 1;
  }

  // renderSlider(win, container, puzzle, onSolve)
  function renderSlider(win, container, puzzle, onSolve) {
    var doc = win.document;
    var w = puzzle.w, h = puzzle.h, s = puzzle.pieceSize;
    var maxX = w - s;                                   // piece x travels 0..maxX
    if (puzzle.gapX > maxX) maxX = puzzle.gapX;         // safety

    var wrap = doc.createElement('div');
    wrap.style.cssText = 'position:relative;width:' + w + 'px;font-family:sans-serif;user-select:none;-webkit-user-select:none;touch-action:none;';

    var canvas = doc.createElement('canvas');
    canvas.width = w; canvas.height = h;
    canvas.style.cssText = 'display:block;border-radius:6px;cursor:pointer;';
    wrap.appendChild(canvas);

    var hint = doc.createElement('div');
    hint.textContent = 'Drag the piece into the gap';
    hint.style.cssText = 'font-size:12px;color:#555;text-align:center;margin-top:6px;';
    wrap.appendChild(hint);

    container.appendChild(wrap);
    var ctx = canvas.getContext('2d');

    var pieceX = 0, dragging = false, grabDX = 0, trail = [], t0 = 0, done = false;

    function draw() {
      _drawBackground(ctx, puzzle);
      // gap silhouette (the hole to fill)
      ctx.save();
      _puzzlePath(ctx, puzzle.gapX, puzzle.gapY, s);
      ctx.fillStyle = 'rgba(0,0,0,0.45)';
      ctx.fill();
      ctx.lineWidth = 1.5; ctx.strokeStyle = 'rgba(255,255,255,0.5)';
      ctx.stroke();
      ctx.restore();
      // moving piece (kept at the gap's Y, only X changes)
      ctx.save();
      _puzzlePath(ctx, pieceX, puzzle.gapY, s);
      ctx.fillStyle = 'rgba(255,255,255,0.9)';
      ctx.fill();
      ctx.lineWidth = 1.5; ctx.strokeStyle = 'rgba(0,0,0,0.35)';
      ctx.stroke();
      ctx.restore();
    }

    function evtXY(e) {
      var rect = canvas.getBoundingClientRect();
      var cx = (e.touches && e.touches[0]) ? e.touches[0].clientX : e.clientX;
      var cy = (e.touches && e.touches[0]) ? e.touches[0].clientY : e.clientY;
      return { x: cx - rect.left, y: cy - rect.top };
    }
    function nowMs() {
      return (win.performance && win.performance.now) ? win.performance.now() : Date.now();
    }

    function onDown(e) {
      if (done) return;
      var p = evtXY(e);
      // grab only if starting on the piece row (lenient hit-box)
      if (p.x >= pieceX - 8 && p.x <= pieceX + s + 8 && p.y >= puzzle.gapY - 8 && p.y <= puzzle.gapY + s + 8) {
        dragging = true; grabDX = p.x - pieceX; t0 = nowMs(); trail = [];
        trail.push({ x: p.x, y: p.y, t: 0 });
        e.preventDefault();
      }
    }
    function onMove(e) {
      if (!dragging || done) return;
      var p = evtXY(e);
      pieceX = Math.max(0, Math.min(maxX, p.x - grabDX));
      trail.push({ x: p.x, y: p.y, t: nowMs() - t0 });
      draw();
      e.preventDefault();
    }
    function onUp(e) {
      if (!dragging || done) return;
      dragging = false; done = true;
      var p = evtXY(e);
      trail.push({ x: p.x, y: p.y, t: nowMs() - t0 });
      draw();
      // answerX = the piece's left X on release; server compares to gapX within tolerance
      var submission = {
        id: puzzle.id, gapX: puzzle.gapX, gapY: puzzle.gapY,
        expiry: puzzle.expiry, sig: puzzle.sig,
        answerX: Math.round(pieceX), trail: trail,
      };
      hint.textContent = 'Verifying…';
      try { onSolve(submission); } catch (err) { /* caller owns error handling */ }
    }

    // mouse + touch
    canvas.addEventListener('mousedown', onDown);
    win.addEventListener('mousemove', onMove);
    win.addEventListener('mouseup', onUp);
    canvas.addEventListener('touchstart', onDown, { passive: false });
    win.addEventListener('touchmove', onMove, { passive: false });
    win.addEventListener('touchend', onUp);

    draw();

    // return a small handle so the caller can tear down / reset
    return {
      destroy: function () {
        canvas.removeEventListener('mousedown', onDown);
        win.removeEventListener('mousemove', onMove);
        win.removeEventListener('mouseup', onUp);
        canvas.removeEventListener('touchstart', onDown);
        win.removeEventListener('touchmove', onMove);
        win.removeEventListener('touchend', onUp);
        if (wrap.parentNode) wrap.parentNode.removeChild(wrap);
      },
      element: wrap,
    };
  }

  return {
    // server
    makePuzzle: makePuzzle,
    verifyPuzzle: verifyPuzzle,
    checkTrail: checkTrail,
    // browser
    renderSlider: renderSlider,
    // internals (tests / tuning)
    _sigMsg: _sigMsg, _seedFromId: _seedFromId, DEFAULTS: DEFAULTS,
  };
});
