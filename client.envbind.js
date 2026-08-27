/*
 * apiguard/client.js — v1  (browser, zero-dependency)  [+ ENV-BINDING anti-lift, additive]
 *
 * On load it transparently wraps window.fetch so that requests to protected paths:
 *   1. fetch a PoW challenge + short-lived signed token from /__ag/challenge
 *   2. solve the hashcash PoW in a Web Worker / WASM (main thread stays responsive)
 *   3. attach the token + PoW solution + device fingerprint as headers
 *   4. [NEW] if the challenge carried an `env` probe sequence, run exactly that subset of the
 *      30-algorithm env-binding pool, bind the concatenated outputs to the token's nonce, and
 *      attach it as the `x-ag-env` header — so a lifted/replayed/stubbed client is detectable.
 *   5. retry once transparently on a 401 "needChallenge" response
 * No visible UI in v1.
 *
 * ENV-BINDING is PURELY ADDITIVE and FAIL-SAFE: if the server sends no `env`, or any probe throws,
 * or the runner times out, the request proceeds EXACTLY as before with no `x-ag-env` header. The
 * probe runner is fully wrapped in try/catch so a throw can never break page boot (loadHot is
 * fragile — a client throw must never stop the app rendering).
 *
 * A manual API is also exposed: window.apiguard.fetch(url, opts), .fingerprint(),
 * .solve(salt, bits), .refresh(), .envProbe(seq, nonce) [NEW, for tests].
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
    var _subtle = (typeof crypto !== 'undefined' && crypto.subtle) || (win && win.crypto && win.crypto.subtle);
    return _subtle.importKey('raw', seed, { name: 'AES-CTR' }, false, ['decrypt']).then(function (k) {
      return _subtle.decrypt({ name: 'AES-CTR', counter: new Uint8Array(16), length: 128 }, k, enc);
    }).then(function (buf) { return new TextDecoder().decode(new Uint8Array(buf)); });
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
      var gl = _glCtx(win);   // reuse the cached context (was a 9th leaked context)
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

  // ==========================================================================
  // ENV-BINDING probe pool (the "30 algorithms" — ~50 curated) + runner.  ADDITIVE.
  //
  // Each probe is {id, w(weight hint, unused client-side), fn(win)->short string | Promise<string>}.
  // Automation / tamper probes are FIRST-CLASS and emit SEMANTIC tokens the honest (non-browser)
  // server can denylist directly ('wd1','tf1','glSW','cvEmpty','st1','pm1','xc1'). Entropy probes
  // (render/audio/engine/env) emit a 12-hex hash of their raw output — the server can't recompute
  // them but scores them structurally (arity, non-empty, low-entropy/duplication) and binds them to
  // the token nonce for anti-replay. CURATED FOR STABILITY: NO font-enumeration, NO WebRTC-IP, NO
  // speechSynthesis-voices (they drift across browser updates and would false-block real users).
  // Every fn is defensive; the runner also wraps each call in try/catch + a timeout, so a probe can
  // never throw into the request path.
  // ==========================================================================
  function _envShort(s) { try { return _hex(_sha256bytes(String(s))).slice(0, 12); } catch (e) { return 'err'; } }
  function _isNativeFn(fn) {
    try { return /\{\s*\[native code\]\s*\}/.test(Function.prototype.toString.call(fn)); } catch (e) { return true; }
  }
  var _glCacheDone = false, _glCache = null;
  function _glCtx(win) {
    // CACHE one shared context per page-load. Creating a fresh WebGL context per gl probe
    // (9 per run) with no loseContext exhausts the browser's context pool -> GPU crash ->
    // real-browser tab reload loop (headless/software-GL tolerates it). Fix 2026-08-24.
    if (_glCacheDone) return _glCache;
    _glCacheDone = true;
    try {
      var c = win.document.createElement('canvas');
      _glCache = c.getContext('webgl') || c.getContext('experimental-webgl') || null;
    } catch (e) { _glCache = null; }
    return _glCache;
  }

  var ENV_PROBES = [
    // ---------- AUTOMATION / TAMPER (first-class; semantic tokens) ----------
    { id: 'wd', w: 5, fn: function (win) {
        try {
          var n = win.navigator; if (!n) return 'wdNA';
          if (n.webdriver === true) return 'wd1';
          if ('webdriver' in n && n.webdriver) return 'wd1';
          return 'wd0';
        } catch (e) { return 'wdNA'; }
    } },
    // tamper on natives we do NOT wrap (fetch IS wrapped by us -> excluded to avoid self-flagging).
    { id: 'tGetCtx', w: 5, fn: function (win) {
        try { return _isNativeFn(win.HTMLCanvasElement.prototype.getContext) ? 'tg0' : 'tg1'; } catch (e) { return 'tgNA'; }
    } },
    { id: 'tAddEv', w: 5, fn: function (win) {
        try { return _isNativeFn(win.EventTarget.prototype.addEventListener) ? 'ta0' : 'ta1'; } catch (e) { return 'taNA'; }
    } },
    { id: 'tToString', w: 4, fn: function (win) {
        try { return _isNativeFn(Function.prototype.toString) ? 'ts0' : 'ts1'; } catch (e) { return 'tsNA'; }
    } },
    { id: 'chromeShape', w: 3, fn: function (win) {
        try {
          var ua = (win.navigator && win.navigator.userAgent) || '';
          var isChrome = /Chrome|CriOS|Chromium|Edg/.test(ua);
          if (!isChrome) return 'crNA';
          if (win.chrome && typeof win.chrome === 'object') return 'cr1';
          return 'cr0'; // UA claims Chrome but window.chrome missing -> headless tell
        } catch (e) { return 'crNA'; }
    } },
    { id: 'permInconsist', w: 3, fn: function (win) {
        try {
          var n = win.navigator;
          var hasPermApi = !!(n && n.permissions && typeof n.permissions.query === 'function');
          var notif = (typeof win.Notification !== 'undefined') ? win.Notification.permission : null;
          // headless Chrome classic tell: Notification.permission === 'denied' while permissions API absent,
          // or Notification present but permissions API missing on a Chrome UA.
          if (notif === 'denied' && !hasPermApi) return 'pm1';
          if (typeof win.Notification !== 'undefined' && !hasPermApi && /Chrome/.test((n && n.userAgent) || '')) return 'pm1';
          return 'pm0';
        } catch (e) { return 'pmNA'; }
    } },
    { id: 'glSoftware', w: 5, fn: function (win) {
        try {
          var gl = _glCtx(win); if (!gl) return 'glNA';
          var dbg = gl.getExtension('WEBGL_debug_renderer_info');
          var r = dbg ? String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || '') : String(gl.getParameter(gl.RENDERER) || '');
          var low = r.toLowerCase();
          if (low.indexOf('swiftshader') >= 0) return 'glSW';
          if (low.indexOf('llvmpipe') >= 0) return 'glLLVM';
          if (low.indexOf('software') >= 0 || low.indexOf('microsoft basic render') >= 0) return 'glSOFT';
          if (low.indexOf('angle') >= 0 && low.indexOf('software') >= 0) return 'glSW';
          return 'glHW';
        } catch (e) { return 'glNA'; }
    } },
    { id: 'xConsist', w: 4, fn: function (win) {
        try {
          var n = win.navigator || {};
          var ua = String(n.userAgent || '');
          var plat = String(n.platform || '');
          var gl = _glCtx(win);
          var vend = '';
          if (gl) { var dbg = gl.getExtension('WEBGL_debug_renderer_info'); vend = dbg ? String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) || '') : ''; }
          var vlow = vend.toLowerCase();
          // contradiction: UA says Windows but GL vendor says Apple, or UA says Mac but GL vendor Intel/NVIDIA on Windows driver strings, etc.
          var uaWin = /Windows/.test(ua), uaMac = /Macintosh|Mac OS X/.test(ua), uaLin = /Linux|X11/.test(ua) && !/Android/.test(ua);
          var glApple = vlow.indexOf('apple') >= 0;
          if (uaWin && glApple) return 'xc1';
          if (uaMac && (vlow.indexOf('mesa') >= 0)) return 'xc1';
          if (uaMac && /Win/.test(plat)) return 'xc1';
          if (uaWin && /Linux|Mac/.test(plat)) return 'xc1';
          return 'xc0';
        } catch (e) { return 'xcNA'; }
    } },
    { id: 'stackShape', w: 3, fn: function (win) {
        try {
          var s = ''; try { null.x(); } catch (e) { s = String(e && e.stack || ''); }
          if (/\bat .*\((?:node:|internal\/|.*\/node_modules\/)/.test(s)) return 'st1'; // node-ish stack
          if (/\.js:\d+:\d+/.test(s) && /^\s*at /m.test(s) && s.indexOf('http') === -1 && s.indexOf('<anonymous>') === -1 && typeof win.document === 'undefined') return 'st1';
          return 'st0';
        } catch (e) { return 'stNA'; }
    } },
    { id: 'langsEmpty', w: 2, fn: function (win) {
        try {
          var n = win.navigator || {};
          var ls = n.languages;
          if (!ls || (ls.length === 0)) return 'lg1'; // empty languages -> headless tell
          return 'lg0';
        } catch (e) { return 'lgNA'; }
    } },
    { id: 'hcMem', w: 2, fn: function (win) {
        try {
          var n = win.navigator || {};
          var hc = ('hardwareConcurrency' in n) ? n.hardwareConcurrency : -1;
          if (hc === 0) return 'hc1';
          return _envShort([hc, n.deviceMemory, n.maxTouchPoints].join(','));
        } catch (e) { return 'hcNA'; }
    } },

    // ---------- RENDER ----------
    { id: 'canvas2d', w: 2, fn: function (win) {
        try {
          var cv = win.document.createElement('canvas'); cv.width = 240; cv.height = 60;
          var g = cv.getContext('2d'); if (!g) return 'cvNA';
          g.textBaseline = 'alphabetic'; g.font = "16px 'Arial'";
          var grd = g.createLinearGradient(0, 0, 240, 0);
          grd.addColorStop(0, '#f60'); grd.addColorStop(1, '#069');
          g.fillStyle = grd; g.fillRect(0, 0, 240, 60);
          g.fillStyle = '#e33'; g.fillText('apiguard☁ env 30✦', 4, 40);
          g.strokeStyle = 'rgba(0,90,180,.7)'; g.arc(120, 30, 18, 0, Math.PI * 1.7); g.stroke();
          var data = cv.toDataURL();
          if (!data || data.length < 64) return 'cvEmpty';
          // all-blank canvas produces a known tiny/constant dataURL -> tell
          return _envShort(data);
        } catch (e) { return 'cvNA'; }
    } },
    { id: 'canvasEmptyChk', w: 3, fn: function (win) {
        try {
          var cv = win.document.createElement('canvas'); cv.width = 16; cv.height = 16;
          var g = cv.getContext('2d'); if (!g) return 'ceNA';
          var d = cv.toDataURL();
          // a truly blank 16x16 canvas has a well-known dataURL; headless stubs often return '' or 'data:,'
          if (!d || d === 'data:,' || d.length < 32) return 'ce1';
          return 'ce0';
        } catch (e) { return 'ceNA'; }
    } },
    { id: 'glVendor', w: 2, fn: function (win) {
        try { var gl = _glCtx(win); if (!gl) return 'glvNA'; var dbg = gl.getExtension('WEBGL_debug_renderer_info'); return _envShort(dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR)); } catch (e) { return 'glvNA'; }
    } },
    { id: 'glRenderer', w: 2, fn: function (win) {
        try { var gl = _glCtx(win); if (!gl) return 'glrNA'; var dbg = gl.getExtension('WEBGL_debug_renderer_info'); return _envShort(dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER)); } catch (e) { return 'glrNA'; }
    } },
    { id: 'glParams', w: 2, fn: function (win) {
        try {
          var gl = _glCtx(win); if (!gl) return 'glpNA';
          var ps = ['MAX_TEXTURE_SIZE','MAX_RENDERBUFFER_SIZE','MAX_VERTEX_ATTRIBS','MAX_VARYING_VECTORS','MAX_VERTEX_UNIFORM_VECTORS','MAX_FRAGMENT_UNIFORM_VECTORS','MAX_COMBINED_TEXTURE_IMAGE_UNITS','ALIASED_LINE_WIDTH_RANGE','MAX_VIEWPORT_DIMS'];
          var out = [];
          for (var i = 0; i < ps.length; i++) { try { out.push(gl.getParameter(gl[ps[i]])); } catch (e) { out.push('x'); } }
          return _envShort(out.join(','));
        } catch (e) { return 'glpNA'; }
    } },
    { id: 'glExts', w: 2, fn: function (win) {
        try { var gl = _glCtx(win); if (!gl) return 'glxNA'; var ex = gl.getSupportedExtensions() || []; return _envShort(ex.slice().sort().join(',')); } catch (e) { return 'glxNA'; }
    } },
    { id: 'glShaderPrec', w: 2, fn: function (win) {
        try {
          var gl = _glCtx(win); if (!gl) return 'gspNA';
          var out = [];
          var stages = [gl.VERTEX_SHADER, gl.FRAGMENT_SHADER];
          var precs = [gl.HIGH_FLOAT, gl.MEDIUM_FLOAT, gl.LOW_FLOAT, gl.HIGH_INT];
          for (var i = 0; i < stages.length; i++) for (var j = 0; j < precs.length; j++) {
            var p = gl.getShaderPrecisionFormat(stages[i], precs[j]);
            out.push(p ? [p.rangeMin, p.rangeMax, p.precision].join('/') : 'x');
          }
          return _envShort(out.join(','));
        } catch (e) { return 'gspNA'; }
    } },
    { id: 'glRenderHash', w: 2, fn: function (win) {
        try {
          var gl = _glCtx(win); if (!gl) return 'grhNA';
          var buf = new Uint8Array(4 * 8 * 8);
          gl.clearColor(0.2, 0.4, 0.6, 1.0); gl.clear(gl.COLOR_BUFFER_BIT);
          gl.readPixels(0, 0, 8, 8, gl.RGBA, gl.UNSIGNED_BYTE, buf);
          return _envShort(_hex(_sha256bytes(buf)));
        } catch (e) { return 'grhNA'; }
    } },
    { id: 'webgpu', w: 1, fn: function (win) {
        try { return (win.navigator && win.navigator.gpu) ? 'gpu1' : 'gpu0'; } catch (e) { return 'gpuNA'; } // gpu0 is COMMON on real browsers -> NOT denylisted
    } },

    // ---------- AUDIO (async) ----------
    { id: 'audioHash', w: 2, fn: function (win) {
        try {
          var OAC = win.OfflineAudioContext || win.webkitOfflineAudioContext;
          if (!OAC) return Promise.resolve('auNA');
          var ctx = new OAC(1, 4096, 44100);
          var osc = ctx.createOscillator(); osc.type = 'triangle'; osc.frequency.value = 10000;
          var comp = ctx.createDynamicsCompressor();
          try { comp.threshold.value = -50; comp.knee.value = 40; comp.ratio.value = 12; comp.attack.value = 0; comp.release.value = 0.25; } catch (e) {}
          osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
          return new Promise(function (resolve) {
            var done = false;
            ctx.oncomplete = function (ev) {
              if (done) return; done = true;
              try {
                var ch = ev.renderedBuffer.getChannelData(0);
                var acc = 0; for (var i = 0; i < ch.length; i += 97) acc += Math.abs(ch[i]);
                resolve(_envShort(acc.toString()));
              } catch (e) { resolve('auERR'); }
            };
            ctx.startRendering();
            setTimeout(function () { if (!done) { done = true; resolve('auTO'); } }, 900);
          });
        } catch (e) { return Promise.resolve('auNA'); }
    } },
    { id: 'audioParams', w: 1, fn: function (win) {
        try {
          var AC = win.AudioContext || win.webkitAudioContext || win.OfflineAudioContext || win.webkitOfflineAudioContext;
          if (!AC) return 'apNA';
          // sampleRate via OfflineAudioContext (no autoplay / no user-gesture needed)
          var OAC = win.OfflineAudioContext || win.webkitOfflineAudioContext;
          var sr = OAC ? (new OAC(1, 1, 44100)).sampleRate : 'x';
          return _envShort(String(sr));
        } catch (e) { return 'apNA'; }
    } },

    // ---------- TIMING / ENGINE ----------
    { id: 'perfRes', w: 2, fn: function (win) {
        try {
          if (!win.performance || !win.performance.now) return 'prNA';
          var mn = Infinity, prev = win.performance.now();
          for (var i = 0; i < 60; i++) { var t = win.performance.now(); var d = t - prev; if (d > 0 && d < mn) mn = d; prev = t; }
          if (!isFinite(mn)) mn = 0;
          // bucket the resolution (clamped/coarsened timers are a headless/hardened tell); keep only the magnitude
          var bucket = mn <= 0.006 ? 'sub5us' : mn < 0.02 ? '5us' : mn < 0.2 ? '100us' : mn < 1.5 ? '1ms' : 'coarse';
          return 'pr:' + bucket;
        } catch (e) { return 'prNA'; }
    } },
    { id: 'perfJitter', w: 1, fn: function (win) {
        try {
          if (!win.performance || !win.performance.now) return 'pjNA';
          var deltas = [], prev = win.performance.now();
          for (var i = 0; i < 40; i++) { var s = 0; for (var j = 0; j < 500; j++) s += j * 1.0001; var t = win.performance.now(); deltas.push(Math.round((t - prev) * 1000)); prev = t; }
          return _envShort(deltas.join(','));
        } catch (e) { return 'pjNA'; }
    } },
    { id: 'mathULP', w: 2, fn: function (win) {
        try {
          var v = [Math.sin(1e300), Math.tan(1e300), Math.exp(21), Math.atan2(2, 3), Math.acosh(1.5), Math.pow(Math.PI, -100), Math.cbrt(64), Math.expm1(1), Math.sinh(1), Math.log1p(0.5)];
          return _envShort(v.map(function (x) { return x.toExponential(15); }).join(','));
        } catch (e) { return 'muNA'; }
    } },
    { id: 'errStack', w: 1, fn: function (win) {
        try {
          var s = new Error('x').stack || '';
          var kind = /at Object\.|at eval|@debugger|@\S+:\d+/.test(s) ? (/@/.test(s) ? 'spider' : 'v8jsc') : (/^\s*at /m.test(s) ? 'v8' : /@/.test(s) ? 'spider' : 'unk');
          return 'es:' + kind + ':' + _envShort(s.split('\n').length + '|' + (s.split('\n')[0] || ''));
        } catch (e) { return 'esNA'; }
    } },
    { id: 'apiBitmap', w: 2, fn: function (win) {
        try {
          var names = ['fetch','Promise','WeakRef','BigInt','Proxy','Reflect','structuredClone','queueMicrotask','requestIdleCallback','ResizeObserver','IntersectionObserver','BroadcastChannel','OffscreenCanvas','SharedArrayBuffer','Atomics','WebAssembly','ReadableStream','TextEncoderStream','CompressionStream','reportError'];
          var b = 0; for (var i = 0; i < names.length; i++) { if (typeof win[names[i]] !== 'undefined') b |= (1 << i); }
          return 'ab:' + (b >>> 0).toString(16);
        } catch (e) { return 'abNA'; }
    } },
    { id: 'jsQuirks', w: 1, fn: function (win) {
        try {
          var q = [];
          q.push((0.1 + 0.2).toString());
          q.push((1/3).toString());
          q.push(([1,5,2,10,4].sort()).join(''));
          q.push((typeof Symbol.asyncIterator));
          q.push(Object.prototype.toString.call(win.navigator));
          q.push(String(1e21));
          return _envShort(q.join('|'));
        } catch (e) { return 'jqNA'; }
    } },
    { id: 'intlHash', w: 2, fn: function (win) {
        try {
          if (!win.Intl) return 'inNA';
          var d = new win.Intl.DateTimeFormat().resolvedOptions();
          var nf = new win.Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(-1234567.89);
          var sv = (win.Intl.supportedValuesOf ? (win.Intl.supportedValuesOf('timeZone') || []).length : -1);
          return _envShort([d.locale, d.timeZone, d.calendar, d.numberingSystem, nf, sv].join('|'));
        } catch (e) { return 'inNA'; }
    } },

    // ---------- ENVIRONMENT ----------
    { id: 'screenDPR', w: 2, fn: function (win) {
        try {
          var s = win.screen || {};
          return _envShort([s.width, s.height, s.availWidth, s.availHeight, s.colorDepth, s.pixelDepth, win.devicePixelRatio, (s.orientation && s.orientation.type)].join('x'));
        } catch (e) { return 'sdNA'; }
    } },
    { id: 'tz', w: 2, fn: function (win) {
        try {
          var off = new Date().getTimezoneOffset();
          var zn = ''; try { zn = win.Intl ? new win.Intl.DateTimeFormat().resolvedOptions().timeZone : ''; } catch (e) {}
          return _envShort(off + '|' + zn + '|' + new Date(0).toString());
        } catch (e) { return 'tzNA'; }
    } },
    { id: 'uaCH', w: 2, fn: function (win) {
        try {
          var n = win.navigator || {};
          if (!n.userAgentData) return 'chNA'; // absent on Firefox/Safari -> COMMON, not denylisted
          var d = n.userAgentData;
          var brands = (d.brands || []).map(function (b) { return b.brand + b.version; }).join(',');
          return _envShort([brands, d.mobile, d.platform].join('|'));
        } catch (e) { return 'chNA'; }
    } },
    { id: 'prefers', w: 1, fn: function (win) {
        try {
          if (!win.matchMedia) return 'pfNA';
          var q = ['(prefers-color-scheme: dark)','(prefers-reduced-motion: reduce)','(prefers-contrast: more)','(pointer: fine)','(hover: hover)','(display-mode: standalone)'];
          var b = 0; for (var i = 0; i < q.length; i++) { try { if (win.matchMedia(q[i]).matches) b |= (1 << i); } catch (e) {} }
          return 'pf:' + b.toString(16);
        } catch (e) { return 'pfNA'; }
    } },
    { id: 'codecs', w: 1, fn: function (win) {
        try {
          var v = win.document.createElement('video');
          var a = win.document.createElement('audio');
          var t = [
            v.canPlayType('video/mp4; codecs="avc1.42E01E"'), v.canPlayType('video/webm; codecs="vp9"'),
            v.canPlayType('video/webm; codecs="vp8"'), v.canPlayType('video/mp4; codecs="hev1"'),
            a.canPlayType('audio/mpeg'), a.canPlayType('audio/ogg; codecs="opus"'), a.canPlayType('audio/aac')
          ];
          return _envShort(t.join(','));
        } catch (e) { return 'cdNA'; }
    } },
    { id: 'measureText', w: 1, fn: function (win) {
        try {
          var cv = win.document.createElement('canvas'); var g = cv.getContext('2d'); if (!g) return 'mtNA';
          g.font = '32px monospace';
          var m1 = g.measureText('mmmmmmmmmmlli 中文');
          g.font = '32px sans-serif';
          var m2 = g.measureText('WwWwWw—–');
          return _envShort([m1.width, m1.actualBoundingBoxAscent, m1.actualBoundingBoxDescent, m2.width].join(','));
        } catch (e) { return 'mtNA'; }
    } },
    { id: 'cssComputed', w: 1, fn: function (win) {
        try {
          if (!win.getComputedStyle || !win.document || !win.document.body) return 'csNA';
          var el = win.document.createElement('div');
          el.style.cssText = 'position:absolute;left:-9999px;accent-color:auto;font:caption;width:1ch';
          (win.document.body || win.document.documentElement).appendChild(el);
          var cs = win.getComputedStyle(el);
          var v = [cs.fontFamily, cs.fontSize, cs.accentColor, cs.width].join('|');
          try { el.parentNode.removeChild(el); } catch (e) {}
          return _envShort(v);
        } catch (e) { return 'csNA'; }
    } },
    { id: 'storageSurface', w: 1, fn: function (win) {
        try {
          var b = 0;
          if (win.localStorage) b |= 1; if (win.sessionStorage) b |= 2;
          if (win.indexedDB) b |= 4; if (win.caches) b |= 8;
          if (win.navigator && win.navigator.storage) b |= 16;
          return 'ss:' + b.toString(16);
        } catch (e) { return 'ssNA'; }
    } },
    { id: 'connection', w: 1, fn: function (win) {
        try {
          var c = win.navigator && (win.navigator.connection || win.navigator.mozConnection);
          if (!c) return 'cnNA'; // absent on Safari/Firefox -> common
          return _envShort([c.effectiveType, c.downlink, c.rtt, c.saveData].join(','));
        } catch (e) { return 'cnNA'; }
    } },
    { id: 'plugins', w: 1, fn: function (win) {
        try {
          var p = win.navigator && win.navigator.plugins;
          if (!p) return 'plNA';
          var names = []; for (var i = 0; i < p.length; i++) names.push(p[i].name);
          return 'pl:' + p.length + ':' + _envShort(names.sort().join(','));
        } catch (e) { return 'plNA'; }
    } },
    { id: 'touchPointer', w: 1, fn: function (win) {
        try {
          var n = win.navigator || {};
          var b = 0; if ('ontouchstart' in win) b |= 1; if (n.maxTouchPoints > 0) b |= 2; if (win.PointerEvent) b |= 4;
          return 'tp:' + b.toString(16) + ':' + (n.maxTouchPoints | 0);
        } catch (e) { return 'tpNA'; }
    } },
    { id: 'perfMemConsist', w: 2, fn: function (win) {
        try {
          var n = win.navigator || {};
          var isChrome = /Chrome|Chromium|Edg/.test(String(n.userAgent || '')) && !/OPR|Firefox/.test(String(n.userAgent || ''));
          var hasPM = !!(win.performance && win.performance.memory);
          // Chrome ships performance.memory; a "Chrome" UA WITHOUT it is a common headless/spoof tell (soft).
          if (isChrome && !hasPM) return 'pmem1';
          return 'pmem0';
        } catch (e) { return 'pmemNA'; }
    } },
    { id: 'dateLocale', w: 1, fn: function (win) {
        try { return _envShort([new Date(1234567890000).toString(), new Date(1234567890000).toLocaleString(), (12345.678).toLocaleString()].join('|')); } catch (e) { return 'dlNA'; }
    } },
    // FIX 1 (2026-08-25): WebGL renderer-string vs capability self-consistency. Catches puppeteer-extra
    // -stealth's `webgl.vendor` evasion, which spoofs UNMASKED_RENDERER/VENDOR to a HARDWARE GPU string
    // (default "Intel Iris OpenGL Engine" / "Intel Inc.") while the ACTUAL GL capability vector stays
    // SwiftShader's. A genuine GPU can NEVER present a hardware name over a software capability vector, so
    // this is an internal contradiction => near-zero false positive. Two independent catch paths:
    //   (P1) modern Chrome ALWAYS reports UNMASKED_RENDERER in the canonical ANGLE-wrapped form
    //        "ANGLE (vendor, renderer, driver)" for BOTH hardware and SwiftShader. A Chrome UA presenting a
    //        hardware-GPU name that is NOT ANGLE-wrapped (and not admitting software) is a forged string.
    //   (P2) capability signature: the string claims a hardware GPU, does not admit software, yet the caps
    //        match the software-rasterizer signature (small 8192 limits + S3TC&ASTC&ETC all present, which
    //        real desktop GPUs lack ASTC/ETC and real mobile GPUs lack S3TC — only a SW emulator has all 3).
    // Consistent real HW (HW name + HW caps) and consistent SW (SwiftShader name -> caught by glSoftware as
    // glSW, NOT here) both return the clean 'gls0'.
    { id: 'glSpoof', w: 5, fn: function (win) {
        try {
          var n = win.navigator || {};
          var ua = String(n.userAgent || '');
          var isChrome = /Chrome\//.test(ua) && !/(Firefox|FxiOS|Edg\/|OPR\/)/.test(ua);
          var gl = _glCtx(win); if (!gl) return 'glNA';
          var dbg = gl.getExtension('WEBGL_debug_renderer_info');
          var rend = String((dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER)) || '');
          var vend = String((dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR)) || '');
          var s = (rend + ' ' + vend).toLowerCase();
          var hwClaim = /(intel|nvidia|geforce|amd|radeon|apple|mali|adreno|iris|quadro|vega|rtx|gtx|powervr|nvs|tesla)/.test(s);
          var swName = /(swiftshader|llvmpipe|software|basic render|mesa offscreen|softpipe|virgl)/.test(s);
          var angleWrapped = /^angle \(/.test(rend.toLowerCase());
          if (!hwClaim || swName) return 'gls0'; // no hardware claim, or it honestly admits software
          // (P1) Chrome hardware name without the canonical ANGLE wrapper => forged.
          if (isChrome && !angleWrapped) return 'glSpoof';
          // (P2) capability signature check (independent of the string form).
          var swCaps = false;
          try {
            var mts = gl.getParameter(gl.MAX_TEXTURE_SIZE) | 0;
            var mvd = gl.getParameter(gl.MAX_VIEWPORT_DIMS);
            var vp0 = (mvd && mvd.length) ? (mvd[0] | 0) : 0;
            var ex = gl.getSupportedExtensions() || [];
            var has = function (x) { return ex.indexOf(x) >= 0; };
            var allCompressed = has('WEBGL_compressed_texture_s3tc') && has('WEBGL_compressed_texture_astc') && has('WEBGL_compressed_texture_etc');
            var smallLimits = (mts > 0 && mts <= 8192) && (vp0 > 0 && vp0 <= 8192);
            swCaps = allCompressed && smallLimits; // SW rasterizer emulates every compressed format at small limits
          } catch (e) { swCaps = false; }
          if (swCaps) return 'glSpoof';
          return 'gls0';
        } catch (e) { return 'glNA'; }
    } }
  ];

  // Fast id -> probe map (built once).
  var ENV_BY_ID = {};
  (function () { for (var i = 0; i < ENV_PROBES.length; i++) ENV_BY_ID[ENV_PROBES[i].id] = ENV_PROBES[i]; })();

  // Run a server-selected probe sequence, bind to the token nonce, return the x-ag-env payload object.
  // FAIL-SAFE: never throws. Each probe is wrapped + timed; an unknown id -> 'unk'; a hang -> 'to'.
  // Returns Promise<{ v, outs:[...], sig }> or Promise<null> on total failure / empty seq.
  // Per page-load cache of probe OUTPUTS: the environment doesn't change between requests, so once a
  // probe is computed we reuse its value. This makes env-on-EVERY-request free (only the nonce-bound
  // sig is recomputed per request). Fresh nonce => fresh sig => replay-proof; cached outputs => fast.
  var _envOutCache = {};
  function runEnvProbes(win, seq, nonce) {
    return new Promise(function (resolve) {
      try {
        if (!seq || !seq.length) return resolve(null);
        var results = new Array(seq.length);
        var pending = seq.length;
        var settled = false;
        function finish() {
          if (settled) return; settled = true;
          try {
            var outs = results.map(function (r) { return (r == null ? 'nil' : String(r)); });
            var sig = _envShort(String(nonce == null ? '' : nonce) + '|' + outs.join('|'));
            // longer bind: 24 hex of sha256 over nonce|outs so collision/forgery is hard
            var full = _hex(_sha256bytes(String(nonce == null ? '' : nonce) + '|' + outs.join('|'))).slice(0, 24);
            resolve({ v: 1, outs: outs, sig: full });
          } catch (e) { resolve(null); }
        }
        // hard overall cap so envbind can never delay a request more than ~1.2s
        var capTimer = setTimeout(function () {
          for (var i = 0; i < results.length; i++) if (results[i] === undefined) results[i] = 'to';
          finish();
        }, 1200);
        seq.forEach(function (id, idx) {
          function set(val) {
            if (results[idx] !== undefined) return;
            results[idx] = val;
            if (val !== 'to' && val !== undefined) _envOutCache[id] = val;   // cache stable output
            if (--pending <= 0) { clearTimeout(capTimer); finish(); }
          }
          if (_envOutCache[id] !== undefined) { set(_envOutCache[id]); return; }   // FAST PATH: reuse cached output
          var probe = ENV_BY_ID[id];
          if (!probe) { set('unk'); return; }
          var v;
          try { v = probe.fn(win); } catch (e) { set('err'); return; }
          if (v && typeof v.then === 'function') {
            var pt = setTimeout(function () { set('to'); }, 950);
            v.then(function (r) { clearTimeout(pt); set(r); }, function () { clearTimeout(pt); set('perr'); });
          } else {
            set(v);
          }
        });
      } catch (e) { resolve(null); }
    });
  }

  function _install(win) {
    var CFG = win.APIGUARD_CONFIG || {};
    var protect = CFG.protect || '/api/';
    var challengePath = CFG.challengePath || '/__ag/challenge';
    var H = Object.assign({ token: 'x-ag-token', pow: 'x-ag-pow', fp: 'x-ag-fp', env: 'x-ag-env', ctr: 'x-ag-ctr', vmt: 'x-ag-vmt' }, CFG.header || {});
    var _cbase = (Math.floor(Math.random() * 0xffffffff)).toString(36);  // per-tab base -> two legit tabs never collide
    var _cseq = 0;                                                        // monotonic per tab; a replayed request reuses an old seq
    var origFetch = win.fetch ? win.fetch.bind(win) : null;
    // P5b VM SENSOR: load THIS session's assigned pool VM once. Fail-open — on 204/error no vmt is ever sent.
    var _vmReady = false;
    function _fnv(s){ var h = 2166136261; for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }
    (function _loadVM(){ try { origFetch('/apiguard/vm/mine.js', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.status === 200 ? r.text() : ''; })
      .then(function (t) { if (t && t.length > 20) { try { (0, eval)(t); _vmReady = (typeof win.__ag_vm === 'function'); } catch (e) {} } })
      .catch(function () {}); } catch (e) {} })();
    function _vmToken(nonce, seq){ try {
      if (!_vmReady || typeof win.__ag_vm !== 'function') return '';
      var integrityOf = function () { return _fnv(String(win.__ag_vm) + Function.prototype.toString.call(JSON.parse)); };
      var IN = [ _fnv(String(nonce || '')) & 0xffff, (seq | 0) & 0xffff, 0x55 ];
      return String(win.__ag_vm(win.__ag_bc || [], IN, integrityOf) >>> 0);
    } catch (e) { return ''; } }
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
    var _solveGate = Promise.resolve();   // serialize wasm solves: ONE shared instance/memory, concurrent solves would corrupt the salt
    function solveWithWasm(salt, bits) {
      var run = function () {
        return _loadWasm().then(function (res) {
          var ex = res.instance.exports;
          var enc = new win.TextEncoder().encode(salt);
          new Uint8Array(ex.memory.buffer).set(enc, ex.saltPtr());
          var c = ex.solve(enc.length, bits, 0xFFFFFFF);
          if (c < 0) throw new Error('no-solution');
          return c;
        }).catch(function () { return solvePow(salt, bits); }); // JS main-thread fallback
      };
      var p = _solveGate.then(run, run);   // chain after the previous solve so salt-write+solve stay atomic
      _solveGate = p.catch(function () {});
      return p;
    }

    // ---- ARGON2id memory-hard PoW solver (single-eval; only when the server mints algorithm:'argon2id') ----
    // hash-wasm's argon2 UMD (~29KB, embedded wasm) is LAZY-loaded via a <script> tag the FIRST time an
    // argon2id challenge actually arrives — never on the boot path, so a tier-0 user (the vast majority,
    // who never solve any PoW) pays nothing. The whole solve is wrapped in try/catch: on ANY failure
    // (load error, no DOM, no WASM, OOM) it FALLS THROUGH to the existing SHA-256 hashcash so the solve
    // promise ALWAYS settles and page boot can NEVER hang on a low-RAM / old browser.
    var argonUrl = CFG.argonUrl || '/apiguard-argon2.js';
    var _argonP = null;
    function _loadArgon() {
      if (_argonP) return _argonP;
      _argonP = new Promise(function (resolve, reject) {
        try {
          if (win.hashwasm && win.hashwasm.argon2id) return resolve(win.hashwasm);
          var doc = win.document;
          if (!doc || !doc.createElement) return reject(new Error('no-dom'));
          var s = doc.createElement('script');
          s.src = argonUrl; s.async = true;
          s.onload = function () { (win.hashwasm && win.hashwasm.argon2id) ? resolve(win.hashwasm) : reject(new Error('argon-missing')); };
          s.onerror = function () { reject(new Error('argon-load-failed')); };
          (doc.head || doc.documentElement).appendChild(s);
        } catch (e) { reject(e); }
      });
      return _argonP;
    }
    // build the argon2 salt param deterministically from the minted salt hex — byte-identical to the server
    // (core.js argonEval): first 16 chars of the hex string as bytes, so the single-eval hash reproduces
    // on both sides with no extra wire field. password = the full salt hex.
    function _argonSaltBytes(saltHex) {
      var s = String(saltHex).slice(0, 16); var b = new Uint8Array(16);
      for (var i = 0; i < 16; i++) b[i] = s.charCodeAt(i) || 48;
      return b;
    }
    function solveArgon(ch) {
      return _loadArgon().then(function (hw) {
        return hw.argon2id({
          password: String(ch.salt), salt: _argonSaltBytes(ch.salt),
          parallelism: ch.par, iterations: ch.iters, memorySize: ch.memKB,
          hashLength: 32, outputType: 'hex',
        });
      }).then(function (output) {
        return { algorithm: 'argon2id', salt: ch.salt, memKB: ch.memKB, iters: ch.iters,
          par: ch.par, expiry: ch.expiry, sig: ch.sig, output: output };
      }).catch(function () {
        // FALLBACK — argon2id unavailable/failed. Never hang: solve a cheap SHA-256 hashcash instead so the
        // request proceeds. A sha256-mode server accepts this; an argon2id-mode server rejects it (401 ->
        // fresh challenge), but the page stays alive and responsive either way. This is the boot-hang guard.
        var bits = (ch.fallbackBits != null ? ch.fallbackBits : 16);
        return solveWithWasm(ch.salt, bits).then(function (counter) {
          return { salt: ch.salt, bits: bits, expiry: ch.expiry, sig: ch.sig, counter: counter, _fallback: 'sha256' };
        });
      });
    }

    function isProtected(url) {
      try {
        var u = new win.URL(url, win.location.href);
        if (u.origin !== win.location.origin) return false; // only same-origin
        return u.pathname.indexOf(protect) === 0 || protect === '*';
      } catch (e) { return false; }
    }

    // ---- ENV-BINDING: run the server-selected probe subset, bound to the token nonce. ADDITIVE. ----
    // Server sends `data.env = { v, seq:[ids] }`. We run those probes, hash the outputs against the
    // token's nonce, and return the base64url(JSON) payload for the x-ag-env header. If there is no
    // env block (current live server), or anything fails, we resolve null and attach NOTHING — the
    // request then proceeds byte-identically to the pre-envbind client. Never throws.
    function envHeaderFor(data) {
      try {
        var env = data && data.env;
        if (!env || !env.seq || !env.seq.length) return Promise.resolve(null);
        var nonce = '';
        try { nonce = String(data.token || '').split('.')[1] || ''; } catch (e) { nonce = ''; }
        return runEnvProbes(win, env.seq, nonce).then(function (payload) {
          if (!payload) return null;
          try { return _b64url(JSON.stringify(payload)); } catch (e) { return null; }
        }).catch(function () { return null; });
      } catch (e) { return Promise.resolve(null); }
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
        // Pick the PoW primitive the server minted: argon2id (memory-hard, single-eval) or the legacy
        // sha256 hashcash. Both resolve to a `sol` object encoded into the x-ag-pow header unchanged.
        var solveP = (ch && ch.algorithm === 'argon2id')
          ? solveArgon(ch)
          : solveWithWasm(ch.salt, ch.bits).then(function (counter) {
              return { salt: ch.salt, bits: ch.bits, expiry: ch.expiry, sig: ch.sig, counter: counter };
            });
        return solveP.then(function (sol) {
          // Run env probes in PARALLEL with nothing (PoW already solved); attach x-ag-env if produced.
          return envHeaderFor(data).then(function (envHdr) {
            var headers = {};
            headers[H.token] = data.token;
            headers[H.pow] = _b64url(JSON.stringify(sol));
            headers[H.fp] = fp();
            if (envHdr) headers[H.env] = envHdr;   // additive; absent when server sent no env block
            return headers;
          });
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
          return unscramble(scr, token).then(function (clean) {
            var h;
            try { h = new win.Headers(res.headers); h.delete(ENC_HEADER); h.set('content-type', 'application/json; charset=utf-8'); } catch (e) { h = undefined; }
            try { return new win.Response(clean, { status: res.status, statusText: res.statusText, headers: h }); }
            catch (e) { return res; }
          }).catch(function () { return res; });
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
        var _cs = ++_cseq;
        try { merged.headers[H.ctr] = _cbase + '.' + _cs; } catch (e) {}  // TIER-2 replay counter (server checks under COUNTER_MODE)
        try { var _tk = extra && extra[H.token]; var _vt = _vmToken(_tk ? String(_tk).split('.')[1] : '', _cs); if (_vt) merged.headers[H.vmt] = _vt; } catch (e) {}  // P5b VM-token (folds integrity + binds the counter)
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
      solveArgon: solveArgon,   // NEW: argon2id single-eval solver (test/harness hook)
      refresh: function () { FP = null; return fp(); },
      envProbe: function (seq, nonce) { return runEnvProbes(win, seq, nonce); }, // NEW: test hook
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
    runEnvProbes: runEnvProbes,
    ENV_PROBE_IDS: ENV_PROBES.map(function (p) { return p.id; }),
    _install: _install,
  };
});
