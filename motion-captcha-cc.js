'use strict';
/*
 * apiguard/motion-captcha-cc.js — Tier-3 "motion CAPTCHA" (captcha-canvas edition). UMD.
 *
 * SELF-CONTAINED. Does NOT touch core.js / client.js / adapter-*.js / server.js.
 * Server side uses ONLY Node built-in `crypto` + the `captcha-canvas` package
 * (lazily required, so a browser bundle / a verify-only caller never loads its
 * native `skia-canvas` peer dep). Browser side uses ONLY plain JS + <canvas> +
 * requestAnimationFrame — no external assets, no packages.
 *
 * ── The approved design (operator-demoed + locked) ────────────────────────────
 * captcha-canvas draws a distorted 4-char code (+ faint decoys + a light trace)
 * in a COLOUR the server rolls at random per challenge. That same colour is sent
 * to the client, which paints a live MOVING-NOISE layer in EXACTLY that colour on
 * top of the static code (requestAnimationFrame — never a gif/mp4). Because the
 * noise is the same colour as the ink, any single frozen frame is camouflage:
 * there is no colour separation for an OCR to threshold on. A human separates the
 * STILL code from the MOVING noise by motion and reads it.
 *
 * ── Security model (stateless) ────────────────────────────────────────────────
 *   makeCcMotion(secret, opts) -> { id, image, color, expiry, sig }
 *     answer = 4 chars from an unambiguous charset (crypto.randomBytes-seeded).
 *              It is NEVER placed in the returned object — only the image PIXELS
 *              show it, and `sig` commits it.
 *     image  = data:image/png;base64,... rendered by captcha-canvas in `color`.
 *     color  = the rolled hue (dark, saturated → reads on white). Sent so the
 *              client paints the noise in the identical colour.
 *     sig    = HMAC(secret, `id|answer|expiry`) as base64url (mirrors core.js).
 *   verifyCcMotion(secret, { id, expiry, sig, answer }) -> { ok, reason }
 *     normalises the typed answer (uppercase/trim/strip ws), recomputes
 *     HMAC(secret, `id|<typed>|expiry`), timing-safe compares vs `sig`, checks
 *     expiry with a clock skew. No per-id storage: the sig IS the committed answer.
 *
 * ── Honest limits (do NOT sell this as a wall) ────────────────────────────────
 *   • Still-image OCR / 2captcha screenshot relay: RAISED (noise = ink colour,
 *     one frame has no colour cue) but a strong AI-OCR can still read the static
 *     distorted glyphs under the noise — captcha-canvas is a static image.
 *   • VIDEO capture + temporal median across frames averages the moving noise
 *     away and recovers the static code. This tier is a SPEED-BUMP, not a wall.
 *   • The durable defence stays apiguard's behavioural stack (PoW + rate-limit +
 *     risk score). This widget is the last, visible tier.
 *   • Accessibility: reading requires seeing motion + colour. Low-vision, colour-
 *     blind, and motion-sensitive/vestibular users need an ALTERNATIVE path
 *     (audio code, email/SMS step-up, support escalation) — provide one.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node: crypto + a LAZY loader for captcha-canvas (lazy so merely requiring this file to call
    // verifyCcMotion doesn't pull in the native lib).
    module.exports = factory(require('crypto'), function () { return require('captcha-canvas'); });
  } else {
    // Browser: no crypto, no canvas lib. Only the render half is usable.
    root.CcMotionCaptcha = factory(null, null);
  }
})(typeof self !== 'undefined' ? self : this, function (nodeCrypto, loadCaptchaCanvas) {

  // Unambiguous charset — no 0/O, no 1/I/L. Length-4 codes a human won't confuse.
  var DEFAULT_CHARSET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

  // ── shared helpers ────────────────────────────────────────────────────────
  function b64url(buf) {
    return Buffer.from(buf).toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function fromB64url(s) {
    s = String(s).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return Buffer.from(s, 'base64');
  }
  function normAnswer(s) { return String(s == null ? '' : s).toUpperCase().replace(/\s+/g, ''); }

  // ── SERVER (Node) ─────────────────────────────────────────────────────────
  function requireCrypto() {
    if (!nodeCrypto) throw new Error('motion-captcha-cc: server functions require Node crypto');
    return nodeCrypto;
  }
  function hmac(secret, msg) {
    return requireCrypto().createHmac('sha256', secret).update(msg).digest();
  }

  // Unbiased pick from a charset using rejection sampling over random bytes.
  function randomCode(charset, len) {
    var C = requireCrypto();
    var n = charset.length;
    var max = 256 - (256 % n); // largest multiple of n <= 256; reject the tail to avoid modulo bias
    var out = '';
    while (out.length < len) {
      var bytes = C.randomBytes(len - out.length);
      for (var i = 0; i < bytes.length && out.length < len; i++) {
        if (bytes[i] < max) out += charset.charAt(bytes[i] % n);
      }
    }
    return out;
  }

  // HSL -> #rrggbb. h in [0,360), s,l in [0,1].
  function hslToHex(h, s, l) {
    var c = (1 - Math.abs(2 * l - 1)) * s;
    var hp = h / 60;
    var x = c * (1 - Math.abs((hp % 2) - 1));
    var r = 0, g = 0, b = 0;
    if (hp >= 0 && hp < 1) { r = c; g = x; }
    else if (hp < 2) { r = x; g = c; }
    else if (hp < 3) { g = c; b = x; }
    else if (hp < 4) { g = x; b = c; }
    else if (hp < 5) { r = x; b = c; }
    else { r = c; b = x; }
    var m = l - c / 2;
    function hx(v) { var q = Math.round((v + m) * 255); q = q < 0 ? 0 : q > 255 ? 255 : q; return ('0' + q.toString(16)).slice(-2); }
    return '#' + hx(r) + hx(g) + hx(b);
  }

  // Roll a readable-on-white colour: any hue, decent saturation, kept dark.
  function rollColor() {
    var C = requireCrypto();
    var buf = C.randomBytes(3);
    var hue = Math.floor((buf[0] / 256) * 360);          // 0..359
    var sat = 0.55 + (buf[1] / 256) * 0.25;              // 0.55..0.80
    var lit = 0.30 + (buf[2] / 256) * 0.14;              // 0.30..0.44 (dark → contrast on white)
    return hslToHex(hue, sat, lit);
  }

  /**
   * makeCcMotion(secret, opts) -> { id, image, color, expiry, sig }
   * The plaintext answer is NEVER in the returned object (only pixels + sig).
   */
  function makeCcMotion(secret, opts) {
    if (!secret || typeof secret !== 'string' || secret.length < 16) {
      throw new Error('motion-captcha-cc: secret required (>=16 chars, high-entropy server secret)');
    }
    opts = opts || {};
    var charset = opts.charset || DEFAULT_CHARSET;
    var len = opts.len || 4;
    var ttlMs = opts.ttlMs != null ? opts.ttlMs : 120000;
    var now = (opts.now || Date.now)();
    var W = opts.width || 520, H = opts.height || 200;

    var color = opts.color || rollColor();               // rolled per challenge (or forced for tests)
    var answer = randomCode(charset, len);
    var id = b64url(requireCrypto().randomBytes(9));
    var expiry = now + ttlMs;
    var sig = b64url(hmac(secret, id + '|' + answer + '|' + expiry));

    // Draw the code in `color` with captcha-canvas (the last approved look): large glyphs, faint
    // decoys, light trace — same colour as the noise so a still frame is camouflage.
    var cc = loadCaptchaCanvas();
    var gen = new cc.CaptchaGenerator()
      .setDimension(H, W)                                // captcha-canvas takes (height, width)
      .setCaptcha({
        text: answer,
        size: opts.textSize || 135,
        color: color,
        skew: opts.skew === true,
        rotate: opts.rotate != null ? opts.rotate : 3,
        opacity: 1
      })
      .setDecoy({
        color: color,
        opacity: opts.decoyOpacity != null ? opts.decoyOpacity : 0.15,
        total: opts.decoyTotal != null ? opts.decoyTotal : 8,
        size: opts.decoySize || 34
      })
      .setTrace({
        color: color,
        size: opts.traceSize || 2,
        opacity: opts.traceOpacity != null ? opts.traceOpacity : 0.5
      });
    var image = 'data:image/png;base64,' + Buffer.from(gen.generateSync()).toString('base64');

    return { id: id, image: image, color: color, expiry: expiry, sig: sig };
  }

  /**
   * verifyCcMotion(secret, { id, expiry, sig, answer }) -> { ok, reason }
   * Stateless. Normalises the typed answer, recomputes the HMAC, timing-safe compares.
   */
  function verifyCcMotion(secret, sub, opts) {
    opts = opts || {};
    var skew = opts.clockSkewMs != null ? opts.clockSkewMs : 5000;
    var now = (opts.now || Date.now)();
    if (!secret || typeof secret !== 'string') return { ok: false, reason: 'bad_input' };
    if (!sub || typeof sub !== 'object') return { ok: false, reason: 'bad_input' };
    var id = sub.id, expiry = sub.expiry, sig = sub.sig, answer = sub.answer;
    if (id == null || expiry == null || sig == null || answer == null) return { ok: false, reason: 'bad_input' };
    var exp = Number(expiry);
    if (!Number.isFinite(exp)) return { ok: false, reason: 'bad_input' };
    if (now > exp + skew) return { ok: false, reason: 'expired' };

    var typed = normAnswer(answer);
    if (!typed) return { ok: false, reason: 'answer_mismatch' };

    var expected = hmac(secret, id + '|' + typed + '|' + expiry);
    var provided;
    try { provided = fromB64url(sig); } catch (e) { return { ok: false, reason: 'bad_sig' }; }
    if (provided.length !== expected.length) return { ok: false, reason: 'bad_sig' };
    if (!requireCrypto().timingSafeEqual(provided, expected)) return { ok: false, reason: 'answer_mismatch' };
    return { ok: true, reason: 'ok' };
  }

  // ── BROWSER RENDER ────────────────────────────────────────────────────────
  // Default theme = neutral SLATE (host overrides via the CSS vars below).
  var STYLE_ID = 'ag-cc-motion-style';
  var CSS =
    '.ag-cc{--ag-accent:#475569;--ag-accent2:#64748b;--ag-card:#ffffff;--ag-text:#0f172a;' +
      '--ag-mut:#64748b;--ag-bd:#e2e8f0;--ag-field:#f8fafc;' +
      'box-sizing:border-box;width:100%;max-width:420px;margin:0 auto;padding:20px;' +
      'background:var(--ag-card);color:var(--ag-text);border:1px solid var(--ag-bd);' +
      'border-radius:16px;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;' +
      'box-shadow:0 6px 24px rgba(15,23,42,.08)}' +
    '.ag-cc *{box-sizing:border-box}' +
    '.ag-cc__chip{display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;' +
      'border-radius:10px;background:var(--ag-field);border:1px solid var(--ag-bd);color:var(--ag-accent)}' +
    '.ag-cc__chip svg{width:20px;height:20px;display:block}' +
    '.ag-cc__title{margin:10px 0 2px;font-size:16px;font-weight:650;line-height:1.2}' +
    '.ag-cc__title span{color:var(--ag-mut);font-weight:500;font-size:13px}' +
    '.ag-cc__instr{margin:0 0 12px;font-size:12.5px;color:var(--ag-mut);line-height:1.4}' +
    '.ag-cc__instr span{opacity:.8}' +
    '.ag-cc__canvas{display:block;width:100%;max-width:520px;height:auto;aspect-ratio:520/200;' +
      'border-radius:12px;background:#fff;border:1px solid var(--ag-bd)}' +
    '.ag-cc__row{display:flex;gap:8px;margin-top:12px}' +
    '.ag-cc__input{flex:1;min-width:0;font-size:18px;letter-spacing:6px;text-transform:uppercase;' +
      'text-align:center;font-weight:600;padding:10px 12px;border-radius:10px;border:1px solid var(--ag-bd);' +
      'background:var(--ag-field);color:var(--ag-text);outline:none}' +
    '.ag-cc__input:focus{border-color:var(--ag-accent)}' +
    '.ag-cc__btn{padding:10px 14px;border-radius:10px;border:1px solid var(--ag-bd);' +
      'background:var(--ag-field);color:var(--ag-text);cursor:pointer;font-size:14px;font-weight:600;white-space:nowrap}' +
    '.ag-cc__btn:hover{border-color:var(--ag-accent2)}' +
    '.ag-cc__btn--go{background:var(--ag-accent);border-color:var(--ag-accent);color:#fff}' +
    '.ag-cc__btn--go:hover{background:var(--ag-accent2);border-color:var(--ag-accent2)}' +
    '.ag-cc__foot{margin-top:12px;text-align:center;font-size:11px;color:var(--ag-mut);opacity:.75}';

  var LOCK_SVG =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<rect x="4" y="10.5" width="16" height="10" rx="2.2"></rect>' +
    '<path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"></path></svg>';

  function injectStyle(doc) {
    if (doc.getElementById(STYLE_ID)) return;
    var st = doc.createElement('style');
    st.id = STYLE_ID;
    st.textContent = CSS;
    (doc.head || doc.documentElement).appendChild(st);
  }

  /**
   * renderCcMotion(win, container, challenge, onSolve, opts) -> handle{ destroy(), canvas, input }
   *   challenge = { id, image, color, expiry, sig }  (from makeCcMotion, minus answer)
   *   onSolve   = fn({ id, expiry, sig, answer })     called on Verify / Enter
   *   opts.onRefresh = fn()                           called on the ↻ New button
   *   opts.density   = noise fraction (default 0.06 of canvas area)
   */
  function renderCcMotion(win, container, ch, onSolve, opts) {
    opts = opts || {};
    var doc = win.document;
    injectStyle(doc);

    var color = ch && ch.color ? ch.color : '#475569';
    var W = opts.width || 520, H = opts.height || 200;

    // Visible copy is CONFIGURABLE. Defaults are deliberately GENERIC — they never
    // name the mechanism (no "motion"/"运动"), so the UI does not tell an attacker
    // how to attack it. A host may override for locale/brand but should keep it generic.
    function esc(s) { return String(s).replace(/[&<>]/g, function (c) { return c === '&' ? '&amp;' : c === '<' ? '&lt;' : '&gt;'; }); }
    var titleZh = opts.titleZh != null ? opts.titleZh : '安全验证';
    var titleEn = opts.titleEn != null ? opts.titleEn : 'Security verification';
    var instrZh = opts.instrZh != null ? opts.instrZh : '请读出并输入下方验证码';
    var instrEn = opts.instrEn != null ? opts.instrEn : 'Type the verification code below';

    var card = doc.createElement('div');
    card.className = 'ag-cc';
    card.setAttribute('data-ag-cc', '1');
    card.innerHTML =
      '<div class="ag-cc__chip">' + LOCK_SVG + '</div>' +
      '<div class="ag-cc__title">' + esc(titleZh) + ' <span>/ ' + esc(titleEn) + '</span></div>' +
      '<p class="ag-cc__instr">' + esc(instrZh) + ' <span>/ ' + esc(instrEn) + '</span></p>' +
      '<canvas class="ag-cc__canvas"></canvas>' +
      '<div class="ag-cc__row">' +
        '<input class="ag-cc__input" type="text" inputmode="latin" autocomplete="off" ' +
          'autocapitalize="characters" spellcheck="false" aria-label="验证码 / captcha code">' +
        '<button type="button" class="ag-cc__btn ag-cc__btn--new">↻ 换一张</button>' +
        '<button type="button" class="ag-cc__btn ag-cc__btn--go">验证</button>' +
      '</div>' +
      '<div class="ag-cc__foot">Powered by apiguard</div>';
    container.appendChild(card);

    var canvas = card.querySelector('.ag-cc__canvas');
    var input = card.querySelector('.ag-cc__input');
    var btnNew = card.querySelector('.ag-cc__btn--new');
    var btnGo = card.querySelector('.ag-cc__btn--go');

    var dpr = win.devicePixelRatio || 1;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    var ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);

    // Load the static code image (the answer lives in these pixels).
    var img = new win.Image();
    var imgReady = false;
    img.onload = function () { imgReady = true; };
    img.src = ch.image;

    // Moving-noise field: specks in EXACTLY `color`, drifting + wrapping every frame.
    // Same colour as the ink → no per-frame colour separation; motion reveals the still code.
    var density = opts.density != null ? opts.density : 0.9;    // ~90% coverage: still frame is camouflage
    var speckSize = opts.speckSize || 11;                       // chunks break up the glyph strokes
    var speed = opts.speed || 1.4;
    var N = Math.max(300, Math.round(density * W * H / (speckSize * speckSize)));
    var parts = new Array(N);
    for (var i = 0; i < N; i++) {
      var ang = Math.random() * Math.PI * 2;
      parts[i] = { x: Math.random() * W, y: Math.random() * H,
        vx: Math.cos(ang) * speed, vy: Math.sin(ang) * speed };
    }

    var running = true, raf;
    function frame() {
      if (!running) return;
      ctx.clearRect(0, 0, W, H);
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, W, H);
      if (imgReady) ctx.drawImage(img, 0, 0, W, H);   // the STILL distorted code
      ctx.fillStyle = color;                          // noise in the identical ink colour
      for (var i = 0; i < N; i++) {
        var p = parts[i];
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0) p.x += W; else if (p.x >= W) p.x -= W;
        if (p.y < 0) p.y += H; else if (p.y >= H) p.y -= H;
        ctx.fillRect(p.x, p.y, speckSize, speckSize);
      }
      raf = win.requestAnimationFrame(frame);
    }
    raf = win.requestAnimationFrame(frame);

    function submit() {
      onSolve({ id: ch.id, expiry: ch.expiry, sig: ch.sig, answer: normAnswer(input.value) });
    }
    function refresh() { if (typeof opts.onRefresh === 'function') opts.onRefresh(); }
    btnGo.addEventListener('click', submit);
    btnNew.addEventListener('click', refresh);
    input.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); submit(); } });
    input.focus();

    return {
      canvas: canvas, input: input, card: card,
      destroy: function () {
        running = false;
        if (win.cancelAnimationFrame) win.cancelAnimationFrame(raf);
        if (card.parentNode) card.parentNode.removeChild(card);
      }
    };
  }

  return {
    // server
    makeCcMotion: makeCcMotion,
    verifyCcMotion: verifyCcMotion,
    // browser
    renderCcMotion: renderCcMotion,
    // exposed internals (tests / integration)
    _internal: {
      DEFAULT_CHARSET: DEFAULT_CHARSET, normAnswer: normAnswer,
      b64url: b64url, fromB64url: fromB64url, hslToHex: hslToHex, rollColor: rollColor,
      randomCode: randomCode
    }
  };
});
