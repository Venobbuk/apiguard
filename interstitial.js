'use strict';
/*
 * apiguard/interstitial.js — reusable, self-contained "verifying your browser" first-visit GATE.
 *
 * A branded, bilingual interstitial that stands in front of a site's HTML on the FIRST top-level
 * navigation (per browser, per TTL). It reuses the existing pow.wasm: the gate page solves an
 * HMAC-signed PoW challenge (minted server-side at page-serve time), POSTs the solution, and on
 * success the server sets a short-lived signed cookie so every later navigation skips the gate.
 *
 * Design goals (operator doctrine):
 *   - ZERO external deps. Server: Node built-in `crypto` only (via the passed guard). Client: plain
 *     browser JS inlined in the page (WASM primary, compact JS SHA-256 fallback — both byte-for-byte
 *     server-verifiable, same code family as client.js proven in test.js case (h)).
 *   - FLIP-SWITCH, default OFF. enabled:false => shouldGate() always false => ZERO behaviour change.
 *   - FAIL-OPEN. Any throw in the gate path lets the request continue to the app; the gate never
 *     hard-fails a site. (A guard/mint/verify bug must never take the site down.)
 *   - Reusable across Pulse / HKPL / Mimi / Studio: it only needs a `guard` (for mint/verify) and a
 *     `secret` (for the cookie HMAC), plus tunable ttl/bits/cookieName.
 *
 * Host surface (see the exports at the bottom):
 *   const gate = require('./interstitial')({ guard, secret, enabled:false, ttlMs, bits, cookieName });
 *   // ONE-LINE wiring in the request handler, before the app serves any HTML:
 *   if (await gate.handle(req, res, urlObj)) return;   // true = gate served / verify answered
 *   // ...or use the granular primitives: shouldGate(req,url), page(url), handleVerify(req,res).
 *
 * Verify endpoint: POST <verifyPath> (default /__ag/gate/verify) with the PoW solution JSON.
 * Cookie: <cookieName>=<exp>.<hmac(exp)>  (HttpOnly; server-verified; TTL tunable, default 12h).
 *
 * The visual style MATCHES the locked motion-captcha (neutral SLATE, system-ui, contained card,
 * bilingual + generic wording, NO purple). Responsive (mobile / pad / desktop) + dark-scheme aware.
 */

const crypto = require('crypto');

// ---------------------------------------------------------------------------
// small helpers (mirror core.js encodings so the cookie HMAC matches its style)
// ---------------------------------------------------------------------------
function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64url(s) {
  return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}
function parseCookies(header) {
  const out = {};
  if (!header || typeof header !== 'string') return out;
  const parts = header.split(';');
  for (let i = 0; i < parts.length; i++) {
    const idx = parts[i].indexOf('=');
    if (idx < 0) continue;
    const k = parts[i].slice(0, idx).trim();
    const v = parts[i].slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

// ---------------------------------------------------------------------------
// the gate PAGE (self-contained). SHABLOCK is the compact SHA-256 + hashcash
// solver reused verbatim from client.js's proven family (server-verifiable),
// used only as a JS fallback when WASM is unavailable. WASM is the primary path.
// ---------------------------------------------------------------------------
const SHABLOCK = `
var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function _sha(input){var bytes=(typeof input==='string')?new TextEncoder().encode(input):input;
var l=bytes.length,withOne=l+1,k=(56-(withOne%64)+64)%64,total=withOne+k+8,buf=new Uint8Array(total);
buf.set(bytes,0);buf[l]=0x80;var bitLen=l*8,hi=Math.floor(bitLen/0x100000000),lo=bitLen>>>0;
buf[total-8]=(hi>>>24)&0xff;buf[total-7]=(hi>>>16)&0xff;buf[total-6]=(hi>>>8)&0xff;buf[total-5]=hi&0xff;
buf[total-4]=(lo>>>24)&0xff;buf[total-3]=(lo>>>16)&0xff;buf[total-2]=(lo>>>8)&0xff;buf[total-1]=lo&0xff;
var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],w=new Array(64);
function rotr(x,n){return(x>>>n)|(x<<(32-n));}
for(var i=0;i<total;i+=64){for(var t=0;t<16;t++){w[t]=(buf[i+4*t]<<24)|(buf[i+4*t+1]<<16)|(buf[i+4*t+2]<<8)|(buf[i+4*t+3]);}
for(t=16;t<64;t++){var s0=rotr(w[t-15],7)^rotr(w[t-15],18)^(w[t-15]>>>3),s1=rotr(w[t-2],17)^rotr(w[t-2],19)^(w[t-2]>>>10);
w[t]=(w[t-16]+s0+w[t-7]+s1)|0;}
var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
for(t=0;t<64;t++){var S1=rotr(e,6)^rotr(e,11)^rotr(e,25),ch=(e&f)^((~e)&g),temp1=(h+S1+ch+K[t]+w[t])|0,
S0=rotr(a,2)^rotr(a,13)^rotr(a,22),maj=(a&b)^(a&c)^(b&c),temp2=(S0+maj)|0;
h=g;g=f;f=e;e=(d+temp1)|0;d=c;c=b;b=a;a=(temp1+temp2)|0;}
H[0]=(H[0]+a)|0;H[1]=(H[1]+b)|0;H[2]=(H[2]+c)|0;H[3]=(H[3]+d)|0;H[4]=(H[4]+e)|0;H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+h)|0;}
var out=new Uint8Array(32);for(i=0;i<8;i++){out[4*i]=(H[i]>>>24)&0xff;out[4*i+1]=(H[i]>>>16)&0xff;out[4*i+2]=(H[i]>>>8)&0xff;out[4*i+3]=H[i]&0xff;}return out;}
function _lz(buf){var count=0;for(var i=0;i<buf.length;i++){var byte=buf[i];if(byte===0){count+=8;continue;}var mask=0x80;while(mask&&(byte&mask)===0){count++;mask>>=1;}break;}return count;}
function solveJS(salt,bits){for(var c=0;c<0xFFFFFFF;c++){if(_lz(_sha(String(salt)+String(c)))>=bits)return c;}throw new Error('no-sol');}
`;

/**
 * buildPage(challenge, cfg) -> full self-contained HTML string.
 * `challenge` = { salt, bits, expiry, sig } from guard.mint.challenge(bits).
 * All dynamic values are injected as a JSON literal + string substitutions (no template-time XSS
 * surface: challenge fields are server-minted hex/base64/ints, never user input).
 */
function buildPage(challenge, cfg) {
  const CH = JSON.stringify({ salt: challenge.salt, bits: challenge.bits, expiry: challenge.expiry, sig: challenge.sig });
  const T = cfg.text;
  // Neutral SLATE theme — same palette family as motion-captcha-cc.js (NO purple).
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<title>${esc(T.heading)}</title>
<style>
:root{--ag-accent:#475569;--ag-accent2:#64748b;--ag-card:#ffffff;--ag-text:#0f172a;--ag-mut:#64748b;--ag-bd:#e2e8f0;--ag-bg1:#f1f5f9;--ag-bg2:#e2e8f0;--ag-field:#f8fafc}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;min-height:100%;display:flex;align-items:center;justify-content:center;padding:20px;
  font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:var(--ag-text);
  background:radial-gradient(1200px 600px at 50% -10%,var(--ag-bg1),var(--ag-bg2));}
.ag-card{width:100%;max-width:440px;background:var(--ag-card);border:1px solid var(--ag-bd);border-radius:18px;
  padding:34px 28px;text-align:center;box-shadow:0 10px 40px rgba(15,23,42,.10)}
.ag-chip{display:inline-flex;align-items:center;justify-content:center;width:52px;height:52px;border-radius:14px;
  background:var(--ag-field);border:1px solid var(--ag-bd);color:var(--ag-accent);margin-bottom:14px}
.ag-chip svg{width:26px;height:26px;display:block}
.ag-spin{width:34px;height:34px;margin:6px auto 18px;border-radius:50%;
  border:3px solid var(--ag-bd);border-top-color:var(--ag-accent);animation:ag-rot .9s linear infinite}
@keyframes ag-rot{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.ag-spin{animation-duration:2.4s}}
.ag-h{margin:0 0 8px;font-size:18px;font-weight:650;line-height:1.35}
.ag-sub{margin:0 0 4px;font-size:13.5px;color:var(--ag-mut);line-height:1.55}
.ag-status{margin-top:16px;font-size:12px;color:var(--ag-mut);min-height:16px}
.ag-foot{margin-top:20px;font-size:11px;color:var(--ag-mut);opacity:.7}
.ag-nojs{margin-top:14px;font-size:12.5px;color:#b91c1c}
@media (max-width:420px){.ag-card{padding:26px 18px;border-radius:14px}.ag-h{font-size:16.5px}}
@media (prefers-color-scheme:dark){
  :root{--ag-accent:#94a3b8;--ag-accent2:#cbd5e1;--ag-card:#0f172a;--ag-text:#e2e8f0;--ag-mut:#94a3b8;
    --ag-bd:#1e293b;--ag-bg1:#0b1220;--ag-bg2:#020617;--ag-field:#111827}
  .ag-card{box-shadow:0 10px 40px rgba(0,0,0,.45)}
}
</style>
</head>
<body>
<main class="ag-card" role="status" aria-live="polite" aria-label="${esc(T.aria)}">
  <div class="ag-chip" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10.5" width="16" height="10" rx="2.2"></rect><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"></path></svg></div>
  <div class="ag-spin" aria-hidden="true"></div>
  <h1 class="ag-h">${esc(T.heading)}</h1>
  <p class="ag-sub">${esc(T.subtext)}</p>
  <div class="ag-status" id="ag-status"></div>
  <noscript><div class="ag-nojs">${esc(T.noscript)}</div></noscript>
  <div class="ag-foot">Powered by apiguard</div>
</main>
<script>
(function(){
"use strict";
var CH=${CH};
var VERIFY=${JSON.stringify(cfg.verifyPath)};
var WASM=${JSON.stringify(cfg.wasmUrl)};
var MSG=${JSON.stringify(cfg.text.msg)};
var statusEl=document.getElementById('ag-status');
function setStatus(t){if(statusEl)statusEl.textContent=t;}
${SHABLOCK}
function loadWasm(){var imp={env:{abort:function(){throw new Error('ag');}}};
  return fetch(WASM,{credentials:'same-origin'}).then(function(r){return r.arrayBuffer();})
    .then(function(b){return WebAssembly.instantiate(b,imp);});}
function solveWasm(salt,bits){return loadWasm().then(function(res){var ex=res.instance.exports;
  var enc=new TextEncoder().encode(salt);new Uint8Array(ex.memory.buffer).set(enc,ex.saltPtr());
  var c=ex.solve(enc.length,bits,0xFFFFFFF);if(c<0)throw new Error('no-sol');return c;});}
function solve(salt,bits){
  try{ if(typeof WebAssembly==='object'){ return solveWasm(salt,bits).catch(function(){return solveJS(salt,bits);}); } }catch(e){}
  return new Promise(function(res,rej){ try{res(solveJS(salt,bits));}catch(e){rej(e);} });
}
var tries=0;
function go(){
  setStatus(MSG.verifying);
  Promise.resolve().then(function(){return solve(CH.salt,CH.bits);}).then(function(counter){
    return fetch(VERIFY,{method:'POST',headers:{'content-type':'application/json'},credentials:'same-origin',
      body:JSON.stringify({salt:CH.salt,bits:CH.bits,expiry:CH.expiry,sig:CH.sig,counter:counter})});
  }).then(function(r){return r.json();}).then(function(j){
    if(j&&j.ok){setStatus(MSG.ok);setTimeout(function(){location.reload();},250);}
    else{tries++;setStatus(MSG.retry);if(tries<5)setTimeout(go,700);else setStatus(MSG.fail);}
  }).catch(function(){tries++;if(tries<5)setTimeout(go,1200);else setStatus(MSG.fail);});
}
go();
})();
</script>
</body>
</html>`;
}

function esc(s) {
  return String(s).replace(/[&<>"]/g, function (c) {
    return c === '&' ? '&amp;' : c === '<' ? '&lt;' : c === '>' ? '&gt;' : '&quot;';
  });
}

// ---------------------------------------------------------------------------
// factory
// ---------------------------------------------------------------------------
function interstitial(config) {
  config = config || {};
  const guard = config.guard;
  if (!guard || !guard.mint || !guard.mint.challenge || !guard.verifyPow) {
    throw new Error('interstitial: config.guard must be an apiguard instance (needs mint.challenge + verifyPow)');
  }
  const secret = config.secret || (guard.config && guard.config.secret);
  if (!secret || typeof secret !== 'string' || secret.length < 16) {
    throw new Error('interstitial: config.secret required (>=16 chars) or guard.config.secret must be set');
  }

  const cfg = {
    enabled: config.enabled === true,          // DEFAULT OFF
    ttlMs: config.ttlMs || 12 * 60 * 60 * 1000, // 12h
    bits: config.bits || 18,                    // ~few seconds on the gate page
    cookieName: config.cookieName || 'ag_gate',
    verifyPath: config.verifyPath || '/__ag/gate/verify',
    wasmUrl: config.wasmUrl || '/apiguard.wasm',
    secure: config.secure === true,             // add ; Secure (enable on https prod)
    sameSite: config.sameSite || 'Lax',
    now: config.now || Date.now,
    failOpen: config.failOpen !== false,        // default true
    // extra host exemptions (string prefix or RegExp), added to the built-ins
    exempt: config.exempt || [],
    text: Object.assign({
      heading: '正在验证您的浏览器… / Verifying your browser…',
      subtext: '这是一次快速安全检查，并非网站变慢。/ A quick security check — not a slow site.',
      aria: '安全检查 / Security check',
      noscript: '请启用 JavaScript 以完成验证。/ Please enable JavaScript to continue.',
      msg: {
        verifying: '正在验证… / Verifying…',
        ok: '验证完成 / Verified',
        retry: '重试中… / Retrying…',
        fail: '验证未完成，请刷新页面。/ Could not verify — please refresh.',
      },
    }, config.text || {}),
  };

  const now = () => cfg.now();
  const hmac = (msg) => crypto.createHmac('sha256', secret).update(msg).digest();

  // ---- signed gate cookie: value = "<exp>.<b64url(hmac('ag_gate|'+exp))>" ----
  function signCookie(exp) {
    return exp + '.' + b64url(hmac('ag_gate|' + exp));
  }
  function verifyCookieValue(val) {
    if (!val || typeof val !== 'string') return false;
    const dot = val.indexOf('.');
    if (dot < 0) return false;
    const expS = val.slice(0, dot);
    const sig = val.slice(dot + 1);
    const exp = Number(expS);
    if (!Number.isFinite(exp)) return false;
    if (now() > exp) return false; // expired
    let provided;
    try { provided = fromB64url(sig); } catch (e) { return false; }
    const expected = hmac('ag_gate|' + expS);
    if (provided.length !== expected.length) return false;
    try { return crypto.timingSafeEqual(provided, expected); } catch (e) { return false; }
  }
  function setCookieHeader() {
    const exp = now() + cfg.ttlMs;
    const maxAge = Math.floor(cfg.ttlMs / 1000);
    let c = cfg.cookieName + '=' + signCookie(exp) + '; Path=/; Max-Age=' + maxAge +
      '; HttpOnly; SameSite=' + cfg.sameSite;
    if (cfg.secure) c += '; Secure';
    return c;
  }
  function hasValidCookie(req) {
    const jar = parseCookies(req && req.headers && req.headers.cookie);
    return verifyCookieValue(jar[cfg.cookieName]);
  }

  // ---- exemptions: never gate these ----
  function isExempt(path) {
    if (!path) return true;
    if (path.startsWith('/api/')) return true;
    if (path === '/login') return true;
    if (path.startsWith('/__ag/')) return true;
    if (path === '/apiguard.wasm') return true;
    if (/^\/apiguard[-.]/.test(path)) return true;      // /apiguard-*.js, /apiguard.wasm
    if (path === '/favicon.ico' || path.startsWith('/favicon')) return true;
    for (let i = 0; i < cfg.exempt.length; i++) {
      const r = cfg.exempt[i];
      if (r instanceof RegExp) { if (r.test(path)) return true; }
      else if (typeof r === 'string') { if (path.startsWith(r)) return true; }
    }
    return false;
  }

  // Only gate TOP-LEVEL HTML navigations (a document load), never assets / fetch / XHR.
  // Primary signal: Sec-Fetch-Dest: document (sent by every modern browser on a nav). Fallback for
  // older clients: GET whose Accept advertises text/html and is not an explicit fetch dest.
  function isTopLevelHtmlNav(req) {
    const h = (req && req.headers) || {};
    const method = (req && req.method) || 'GET';
    if (method !== 'GET') return false;
    const dest = h['sec-fetch-dest'];
    if (dest !== undefined) return dest === 'document';
    const accept = h['accept'] || '';
    return accept.indexOf('text/html') !== -1;
  }

  // ---- public: should this request be shown the gate page? ----
  function shouldGate(req, urlObj) {
    try {
      if (!cfg.enabled) return false;                 // flip-switch OFF => never gate
      const path = (urlObj && urlObj.pathname) || (req && req.url) || '/';
      if (isExempt(path)) return false;
      if (!isTopLevelHtmlNav(req)) return false;
      if (hasValidCookie(req)) return false;          // already verified within TTL
      return true;
    } catch (e) { return false; }                     // fail-open
  }

  // ---- public: build the gate HTML for a request (mints a fresh challenge) ----
  function page(/* urlObj */) {
    const challenge = guard.mint.challenge(cfg.bits);
    return buildPage(challenge, cfg);
  }

  // ---- public: handle POST <verifyPath>. returns true if it handled the request ----
  function handleVerify(req, res, urlObj) {
    return new Promise((resolve) => {
      try {
        const path = (urlObj && urlObj.pathname) || (req && req.url) || '';
        if (!cfg.enabled) return resolve(false);
        if (req.method !== 'POST' || path !== cfg.verifyPath) return resolve(false);
        let body = '';
        req.on('data', (d) => { body += d; if (body.length > 4096) req.destroy(); });
        req.on('end', () => {
          let ok = false, reason = 'bad_input';
          try {
            const sol = JSON.parse(body || '{}');
            const v = guard.verifyPow(sol);
            ok = !!(v && v.ok);
            reason = (v && v.reason) || reason;
          } catch (e) { reason = 'bad_json'; }
          const headers = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' };
          if (ok) headers['set-cookie'] = setCookieHeader();
          const out = Buffer.from(JSON.stringify({ ok, reason }), 'utf8');
          headers['content-length'] = out.length;
          res.writeHead(ok ? 200 : 400, headers);
          res.end(out);
          resolve(true);
        });
        req.on('error', () => resolve(true));
      } catch (e) {
        // fail-open: if our verify path itself throws, don't hang the request
        try { res.writeHead(400, { 'content-type': 'application/json' }); res.end('{"ok":false,"reason":"gate_error"}'); } catch (_) {}
        resolve(true);
      }
    });
  }

  // ---- public: one-line composed handler. true = handled (return from host). ----
  async function handle(req, res, urlObj) {
    try {
      if (!cfg.enabled) return false;
      if (await handleVerify(req, res, urlObj)) return true;   // POST verify
      if (!shouldGate(req, urlObj)) return false;
      const html = page(urlObj);                               // may throw -> fail-open below
      const raw = Buffer.from(html, 'utf8');
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'content-length': raw.length,
        'cache-control': 'no-store, must-revalidate',
      });
      res.end(raw);
      return true;
    } catch (e) {
      if (cfg.failOpen) return false;   // let the app serve instead of hard-failing
      try {
        res.writeHead(503, { 'content-type': 'text/plain' });
        res.end('gate error');
      } catch (_) {}
      return true;
    }
  }

  return {
    shouldGate,
    page,
    handleVerify,
    handle,
    setCookieHeader,
    // introspection for tests / hosts
    _internal: { isExempt, isTopLevelHtmlNav, verifyCookieValue, signCookie, hasValidCookie, cfg },
  };
}

module.exports = interstitial;
module.exports._buildPage = buildPage;
