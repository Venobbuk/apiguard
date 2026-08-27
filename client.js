/*
 * apiguard/client.js — v1  (browser, zero-dependency)
 *
 * On load it transparently wraps window.fetch so that requests to protected paths:
 *   1. fetch a PoW challenge + short-lived signed token from /__ag/challenge
 *   2. solve the hashcash PoW in a Web Worker (main thread stays responsive)
 *   3. attach the token + PoW solution + device fingerprint as headers
 *   4. retry once transparently on a 401 "needChallenge" response
 * No visible UI in v1.
 *
 * A manual API is also exposed: window.apiguard.fetch(url, opts), .fingerprint(),
 * .solve(salt, bits), .refresh().
 *
 * The pure crypto helpers are also exported for Node (module.exports) so the server
 * test-suite can prove the browser's SHA-256 / PoW is byte-for-byte server-verifiable.
 */
(function (root, factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api; // Node: pure helpers
  if (typeof window !== 'undefined') api._install(window);                    // Browser: auto-wrap
})(this, function () {
  'use strict';

  // ---- SHA-256 (returns Uint8Array(32)); shared by fingerprint, worker, fallback ----
  var K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];
  function _sha256bytes(input) {
    var bytes = (typeof input === 'string')
      ? new TextEncoder().encode(input)
      : input;
    var l = bytes.length;
    var withOne = l + 1;
    var k = (56 - (withOne % 64) + 64) % 64;
    var total = withOne + k + 8;
    var buf = new Uint8Array(total);
    buf.set(bytes, 0);
    buf[l] = 0x80;
    var bitLen = l * 8;
    var hi = Math.floor(bitLen / 0x100000000);
    var lo = bitLen >>> 0;
    buf[total - 8] = (hi >>> 24) & 0xff; buf[total - 7] = (hi >>> 16) & 0xff;
    buf[total - 6] = (hi >>> 8) & 0xff;  buf[total - 5] = hi & 0xff;
    buf[total - 4] = (lo >>> 24) & 0xff; buf[total - 3] = (lo >>> 16) & 0xff;
    buf[total - 2] = (lo >>> 8) & 0xff;  buf[total - 1] = lo & 0xff;
    var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    var w = new Array(64);
    function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
    for (var i = 0; i < total; i += 64) {
      for (var t = 0; t < 16; t++) {
        w[t] = (buf[i + 4 * t] << 24) | (buf[i + 4 * t + 1] << 16) | (buf[i + 4 * t + 2] << 8) | (buf[i + 4 * t + 3]);
      }
      for (t = 16; t < 64; t++) {
        var s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
        var s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (t = 0; t < 64; t++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ ((~e) & g);
        var temp1 = (h + S1 + ch + K[t] + w[t]) | 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var temp2 = (S0 + maj) | 0;
        h = g; g = f; f = e; e = (d + temp1) | 0; d = c; c = b; b = a; a = (temp1 + temp2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    var out = new Uint8Array(32);
    for (i = 0; i < 8; i++) {
      out[4 * i] = (H[i] >>> 24) & 0xff; out[4 * i + 1] = (H[i] >>> 16) & 0xff;
      out[4 * i + 2] = (H[i] >>> 8) & 0xff; out[4 * i + 3] = H[i] & 0xff;
    }
    return out;
  }
  function _leadingZeroBits(buf) {
    var count = 0;
    for (var i = 0; i < buf.length; i++) {
      var byte = buf[i];
      if (byte === 0) { count += 8; continue; }
      var mask = 0x80;
      while (mask && (byte & mask) === 0) { count++; mask >>= 1; }
      break;
    }
    return count;
  }
  function _hex(buf) {
    var s = '';
    for (var i = 0; i < buf.length; i++) s += (buf[i] + 0x100).toString(16).slice(1);
    return s;
  }
  // reference solver (also the worker body)
  function solvePow(salt, bits, maxIter) {
    maxIter = maxIter || (1 << 28);
    for (var c = 0; c < maxIter; c++) {
      if (_leadingZeroBits(_sha256bytes(String(salt) + String(c))) >= bits) return c;
    }
    throw new Error('solvePow: exceeded maxIter');
  }

  // ---- payload scramble (mirror of scramble.js; MUST stay byte-identical) ----
  // key = SHA-256('ag-scramble|v1|'+token); keystream = SHA-256-CTR(seed || uint32be(n)); XOR + base64.
  // Uses THIS file's pure _sha256bytes (proven == Node crypto in test.js case (h)), so the browser
  // unscrambles exactly what scramble.js scrambled server-side, with no key exchange.
  var SCRAMBLE_PREFIX = 'ag-scramble|v1|';
  function _u32be(n) { var b = new Uint8Array(4); b[0] = (n >>> 24) & 255; b[1] = (n >>> 16) & 255; b[2] = (n >>> 8) & 255; b[3] = n & 255; return b; }
  function _concatBytes(a, b) { var o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o; }
  function _keystream(seed, len) {
    var out = new Uint8Array(len), off = 0, ctr = 0;
    while (off < len) {
      var block = _sha256bytes(_concatBytes(seed, _u32be(ctr >>> 0)));
      var n = Math.min(32, len - off);
      for (var i = 0; i < n; i++) out[off + i] = block[i];
      off += n; ctr++;
    }
    return out;
  }
  function _b64enc(bytes) {
    var s = ''; for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return (typeof btoa !== 'undefined') ? btoa(s) : Buffer.from(bytes).toString('base64');
  }
  function _b64dec(b64) {
    var bin = (typeof atob !== 'undefined') ? atob(b64) : Buffer.from(b64, 'base64').toString('binary');
    var out = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 255;
    return out;
  }
  function scramble(str, material) {
    var seed = _sha256bytes(SCRAMBLE_PREFIX + String(material == null ? '' : material));
    var plain = new TextEncoder().encode(String(str));
    var ks = _keystream(seed, plain.length), out = new Uint8Array(plain.length);
    for (var i = 0; i < plain.length; i++) out[i] = plain[i] ^ ks[i];
    return _b64enc(out);
  }
  function unscramble(b64, material) {
    var seed = _sha256bytes(SCRAMBLE_PREFIX + String(material == null ? '' : material));
    var enc = _b64dec(String(b64));
    var ks = _keystream(seed, enc.length), out = new Uint8Array(enc.length);
    for (var i = 0; i < enc.length; i++) out[i] = enc[i] ^ ks[i];
    return new TextDecoder().decode(out);
  }

  // ---- fingerprint (canvas + webgl + screen + ua + persistent uuid) ----
  function fingerprintFrom(win) {
    win = win || (typeof window !== 'undefined' ? window : {});
    var parts = [];
    try { parts.push(win.navigator && win.navigator.userAgent || ''); } catch (e) {}
    try { parts.push((win.navigator && win.navigator.language) || ''); } catch (e) {}
    try { parts.push(win.screen ? [win.screen.width, win.screen.height, win.screen.colorDepth].join('x') : ''); } catch (e) {}
    try { parts.push(String(new Date().getTimezoneOffset())); } catch (e) {}
    // canvas
    try {
      var cv = win.document.createElement('canvas'); cv.width = 200; cv.height = 40;
      var g2 = cv.getContext('2d');
      g2.textBaseline = 'top'; g2.font = "14px 'Arial'";
      g2.fillStyle = '#f60'; g2.fillRect(0, 0, 100, 20);
      g2.fillStyle = '#069'; g2.fillText('apiguard-fp', 2, 2);
      parts.push(cv.toDataURL());
    } catch (e) {}
    // webgl
    try {
      var gl = win.document.createElement('canvas').getContext('webgl');
      var dbg = gl.getExtension('WEBGL_debug_renderer_info');
      parts.push(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) + '~' + gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL));
    } catch (e) {}
    // persistent uuid
    var uuid = '';
    try {
      uuid = win.localStorage.getItem('__ag_uid');
      if (!uuid) {
        uuid = (win.crypto && win.crypto.randomUUID) ? win.crypto.randomUUID()
          : _hex(_sha256bytes(String(Math.random()) + Date.now())).slice(0, 32);
        win.localStorage.setItem('__ag_uid', uuid);
      }
    } catch (e) {}
    parts.push(uuid);
    return _hex(_sha256bytes(parts.join('||'))).slice(0, 32);
  }

  function _install(win) {
    var CFG = win.APIGUARD_CONFIG || {};
    var protect = CFG.protect || '/api/';
    var challengePath = CFG.challengePath || '/__ag/challenge';
    var H = Object.assign({ token: 'x-ag-token', pow: 'x-ag-pow', fp: 'x-ag-fp' }, CFG.header || {});
    var origFetch = win.fetch ? win.fetch.bind(win) : null;
    var FP = null;
    function fp() { return FP || (FP = fingerprintFrom(win)); }

    // ---- WASM PoW VM solver (v2) ----
    // SHA-256 hashcash solved inside a tiny WebAssembly module: ~20x faster than the old JS worker and
    // far harder to reverse. No more Function.toString() worker hack (which broke under obfuscation).
    // Falls back to the JS main-thread solver if WASM is unavailable. Normal users are tier 0 and never
    // solve at all, so even the main thread never janks for them.
    var wasmUrl = CFG.wasmUrl || '/apiguard.wasm';
    var _wasmP = null;
    function _loadWasm() {
      if (_wasmP) return _wasmP;
      var imp = { env: { abort: function () { throw new Error('ag'); } } };
      try {
        if (win.WebAssembly && win.fetch) {
          var arr = function () { return origFetch(wasmUrl, { credentials: 'same-origin' }).then(function (r) { return r.arrayBuffer(); }).then(function (b) { return win.WebAssembly.instantiate(b, imp); }); };
          _wasmP = win.WebAssembly.instantiateStreaming
            ? win.WebAssembly.instantiateStreaming(origFetch(wasmUrl, { credentials: 'same-origin' }), imp).catch(arr)
            : arr();
        } else { _wasmP = Promise.reject(new Error('no-wasm')); }
      } catch (e) { _wasmP = Promise.reject(e); }
      return _wasmP;
    }
    function solveWithWasm(salt, bits) {
      return _loadWasm().then(function (res) {
        var ex = res.instance.exports;
        var enc = new win.TextEncoder().encode(salt);
        new Uint8Array(ex.memory.buffer).set(enc, ex.saltPtr());
        var c = ex.solve(enc.length, bits, 0xFFFFFFF);
        if (c < 0) throw new Error('no-solution');
        return c;
      }).catch(function () { return solvePow(salt, bits); }); // JS main-thread fallback
    }

    function isProtected(url) {
      try {
        var u = new win.URL(url, win.location.href);
        if (u.origin !== win.location.origin) return false; // only same-origin
        return u.pathname.indexOf(protect) === 0 || protect === '*';
      } catch (e) { return false; }
    }

    // fetch a challenge+token for a path, solve it, return headers to attach
    function obtain(pathname, given) {
      var p = given
        ? Promise.resolve(given)
        : origFetch(challengePath + '?path=' + encodeURIComponent(pathname), {
            headers: setFp({}), credentials: 'same-origin',
          }).then(function (r) { return r.json(); });
      return p.then(function (data) {
        var ch = data.challenge;
        return solveWithWasm(ch.salt, ch.bits).then(function (counter) {
          var sol = { salt: ch.salt, bits: ch.bits, expiry: ch.expiry, sig: ch.sig, counter: counter };
          var headers = {};
          headers[H.token] = data.token;
          headers[H.pow] = _b64url(JSON.stringify(sol));
          headers[H.fp] = fp();
          return headers;
        });
      });
    }
    // Marker header the server sets when a body is scrambled (default 'x-ag-enc'); overridable via config.
    var ENC_HEADER = (CFG.encHeader || 'x-ag-enc').toLowerCase();
    // If a guarded response is marked scrambled, decode it into a fresh clean-JSON Response transparently.
    // Fail-safe: no token / no marker / any error -> return the original response untouched (fail-open).
    function maybeUnscramble(res, token) {
      try {
        if (!token || !res || !res.headers || typeof res.headers.get !== 'function') return res;
        if (res.headers.get(ENC_HEADER) !== '1') return res;
        return res.clone().text().then(function (scr) {
          var clean;
          try { clean = unscramble(scr, token); } catch (e) { return res; }
          var h;
          try { h = new win.Headers(res.headers); h.delete(ENC_HEADER); h.set('content-type', 'application/json; charset=utf-8'); } catch (e) { h = undefined; }
          try { return new win.Response(clean, { status: res.status, statusText: res.statusText, headers: h }); }
          catch (e) { return res; }
        }).catch(function () { return res; });
      } catch (e) { return res; }
    }
    function setFp(h) { h[H.fp] = fp(); return h; }
    function _b64url(str) {
      var b = win.btoa(unescape(encodeURIComponent(str)));
      return b.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    // ---- INTERACTIVE challenges: tier 2 (slider) / tier 3 (motion captcha) ----
    // A 401 whose body carries action:'slider'|'captcha' means the server wants a HUMAN gesture.
    // We render the matching widget in a centered modal overlay, and on the user's solve POST the
    // submission to /__ag/verify. On {ok:true} the server has markSolved this identity (tier 0 for the
    // grace window), so the ORIGINAL request is retried once and now passes transparently.
    //
    // The widget code is NOT bundled into this client (keeps it small + lets the captcha stay a
    // separate rotating asset). It is lazy-<script>-injected the first time a challenge appears:
    //   captcha -> window.CcMotionCaptcha  (motion-captcha-cc.js)
    //   slider  -> window.apiguardSlider   (slider.js)
    // The host serves those two files; URLs are overridable via APIGUARD_CONFIG.
    var verifyPath = CFG.verifyPath || '/__ag/verify';
    var LIB = {
      captcha: { url: CFG.captchaUrl || '/apiguard-captcha.js', global: 'CcMotionCaptcha' },
      slider: { url: CFG.sliderUrl || '/apiguard-slider.js', global: 'apiguardSlider' },
    };
    var _libP = {};
    function ensureLib(type) {
      var meta = LIB[type];
      if (win[meta.global]) return Promise.resolve(win[meta.global]);
      if (_libP[type]) return _libP[type];
      _libP[type] = new Promise(function (resolve, reject) {
        try {
          var s = win.document.createElement('script');
          s.src = meta.url; s.async = true;
          s.onload = function () { win[meta.global] ? resolve(win[meta.global]) : reject(new Error('ag-lib-missing')); };
          s.onerror = function () { _libP[type] = null; reject(new Error('ag-lib-load-failed')); };
          (win.document.head || win.document.documentElement).appendChild(s);
        } catch (e) { reject(e); }
      });
      return _libP[type];
    }
    function postVerify(type, submission) {
      return origFetch(verifyPath, {
        method: 'POST',
        headers: setFp({ 'content-type': 'application/json' }),
        credentials: 'same-origin',
        body: JSON.stringify({ type: type, submission: submission }),
      }).then(function (r) { return r.json().catch(function () { return { ok: false }; }); });
    }
    // A minimal, dependency-free centered modal. The widget itself paints inside `container`.
    function makeOverlay(onCancel) {
      var doc = win.document;
      var ov = doc.createElement('div');
      ov.setAttribute('data-ag-overlay', '1');
      ov.setAttribute('role', 'dialog');
      ov.setAttribute('aria-modal', 'true');
      ov.setAttribute('aria-label', '安全验证 / Security verification');
      ov.style.cssText = 'position:fixed;inset:0;z-index:2147483000;display:flex;align-items:center;' +
        'justify-content:center;background:rgba(15,23,42,.55);padding:16px;' +
        'font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;';
      var box = doc.createElement('div');
      box.style.cssText = 'position:relative;max-width:560px;width:100%;display:flex;flex-direction:column;align-items:center;';
      var container = doc.createElement('div');
      container.style.cssText = 'width:100%;display:flex;justify-content:center;';
      var msg = doc.createElement('div');
      msg.setAttribute('aria-live', 'polite');
      msg.style.cssText = 'text-align:center;color:#fff;font-size:13px;margin-top:10px;min-height:18px;';
      var close = doc.createElement('button');
      close.type = 'button';
      close.setAttribute('aria-label', 'Close / 关闭');
      close.innerHTML = '&times;';
      close.style.cssText = 'position:absolute;top:-14px;right:-14px;width:32px;height:32px;border-radius:50%;' +
        'border:none;background:#0f172a;color:#fff;font-size:20px;line-height:30px;cursor:pointer;z-index:1;';
      box.appendChild(close); box.appendChild(container); box.appendChild(msg);
      ov.appendChild(box);
      var cancelled = false;
      function cleanup() { win.document.removeEventListener('keydown', onKey); if (ov.parentNode) ov.parentNode.removeChild(ov); }
      function doCancel() { if (cancelled) return; cancelled = true; cleanup(); if (typeof onCancel === 'function') onCancel(); }
      function onKey(e) { if (e.key === 'Escape') doCancel(); }
      close.addEventListener('click', doCancel);
      ov.addEventListener('click', function (e) { if (e.target === ov) doCancel(); });
      win.document.addEventListener('keydown', onKey);
      (doc.body || doc.documentElement).appendChild(ov);
      return { overlay: ov, container: container, setMsg: function (t) { msg.textContent = t || ''; }, cleanup: cleanup };
    }
    // Show a challenge; resolve(true) once the server verifies it (identity now trusted), resolve(false)
    // if the user cancels or the widget lib can't load. `refetch()` -> Promise<freshChallenge|null>, used
    // to re-render on a wrong answer / refresh (both widgets are one-shot once solved/submitted).
    function solveInteractive(type, firstChallenge, refetch) {
      return ensureLib(type).then(function (lib) {
        return new Promise(function (resolve) {
          var ui = makeOverlay(function () { resolve(false); });
          var handle = null, busy = false;
          function renderChallenge(ch) {
            if (!ch) { ui.setMsg('无法加载验证 / Could not load challenge'); return; }
            if (handle && handle.destroy) { try { handle.destroy(); } catch (e) {} }
            if (type === 'captcha') {
              handle = lib.renderCcMotion(win, ui.container, ch, onSolve, { onRefresh: getFresh });
            } else {
              handle = lib.renderSlider(win, ui.container, ch, onSolve);
            }
          }
          function onSolve(submission) {
            if (busy) return; busy = true;
            ui.setMsg('验证中… / Verifying…');
            postVerify(type, submission).then(function (vr) {
              busy = false;
              if (vr && vr.ok) { ui.cleanup(); resolve(true); }
              else { ui.setMsg('验证失败，请重试 / Incorrect, please try again'); getFresh(); }
            }).catch(function () { busy = false; ui.setMsg('网络错误，请重试 / Network error, retry'); });
          }
          function getFresh() {
            if (typeof refetch !== 'function') return;
            refetch().then(function (ch) { renderChallenge(ch); }).catch(function () { ui.setMsg('网络错误 / Network error'); });
          }
          renderChallenge(firstChallenge);
        });
      }).catch(function () { return false; });
    }

    function guardedFetch(input, init) {
      init = init || {};
      var url = (typeof input === 'string') ? input : (input && input.url) || '';
      if (!origFetch || !isProtected(url)) return origFetch(input, init);
      var pathname = new win.URL(url, win.location.href).pathname;

      function withHeaders(extra) {
        var merged = Object.assign({}, init, {
          headers: Object.assign({}, init.headers || {}, extra),
        });
        var tok = extra && extra[H.token];
        // single choke-point: transparently unscramble any x-ag-enc:1 body BEFORE the app sees it, using
        // the SAME token we attached (the server keyed the scramble on it). index.html gets clean JSON;
        // a raw curl/DevTools fetch WITHOUT this client sees only the scrambled base64 body.
        return origFetch(input, merged).then(function (res) { return maybeUnscramble(res, tok); });
      }
      // Re-issue the guarded request and hand back the fresh interactive challenge from its 401 body
      // (so a wrong answer / ↻ New gets a brand-new puzzle/captcha, not a re-used one).
      function refetch() {
        return obtain(pathname).then(function (h) {
          return withHeaders(h).then(function (r) {
            if (r.status !== 401) return null;
            return r.clone().json().then(function (b) { return (b && b.challenge) || null; }).catch(function () { return null; });
          });
        });
      }
      return obtain(pathname).then(function (headers) {
        return withHeaders(headers).then(function (res) {
          if (res.status !== 401) return res;
          return res.clone().json().then(function (body) {
            if (!body) return res;
            var action = body.action || body.error;
            // tier 2/3: human gesture required -> render widget, verify, then retry once
            if (action === 'slider' || action === 'captcha') {
              return solveInteractive(action, body.challenge, refetch).then(function (ok) {
                if (!ok) return res;                                   // user gave up / lib failed
                return obtain(pathname).then(function (h2) { return withHeaders(h2); }); // now tier 0
              });
            }
            // tier 1 / stale token: server handed back a (harder) PoW challenge — solve + retry once
            if (body.needChallenge) {
              return obtain(pathname, body).then(function (h2) { return withHeaders(h2); });
            }
            return res;
          }).catch(function () { return res; });
        });
      });
    }

    if (origFetch) win.fetch = guardedFetch;
    win.apiguard = {
      fetch: guardedFetch,
      fingerprint: fp,
      solve: solveWithWasm,
      refresh: function () { FP = null; return fp(); },
      _config: { protect: protect, challengePath: challengePath, header: H },
    };
  }

  return {
    _sha256bytes: _sha256bytes,
    _leadingZeroBits: _leadingZeroBits,
    _hex: _hex,
    solvePow: solvePow,
    fingerprintFrom: fingerprintFrom,
    scramble: scramble,
    unscramble: unscramble,
    _install: _install,
  };
});
