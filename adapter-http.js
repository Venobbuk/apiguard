'use strict';
/*
 * apiguard/adapter-http.js — v1
 * Wraps Node's raw `http` server. Zero external deps.
 *
 *   const guard = require('./core')({ secret: process.env.GUARD_SECRET, protect:'/api/' });
 *   // in your request handler, first line:
 *   if (await guard.block(req, res)) return;   // true = handled (401/429/403/challenge)
 *
 * Also serves the PoW-challenge endpoint (GET /__ag/challenge?path=/api/foo).
 */

// JA3-style TLS fingerprint (OBSERVE-only). Lazily/defensively required so the adapter stays
// usable if the file is absent — ja3.observe then simply does not run. NEVER blocks, NEVER
// changes a verdict; wrapped in try/catch at the call site as a second belt.
let ja3Mod = null;
try { ja3Mod = require('./ja3'); } catch (_) { /* optional, OBSERVE-only */ }

module.exports = function httpAdapter(guard) {
  const cfg = guard.config;

  function clientIp(req) {
    // Behind a trusted reverse proxy (e.g. nginx sets X-Real-IP), the socket address is the PROXY
    // (127.0.0.1) for every user — which would collapse all traffic into one identity and false-trip
    // per-IP rate/churn. Only when `trustProxy` is set do we read the proxy's real-IP header; otherwise
    // socket only (a client can forge X-Forwarded-For, so never trust it unless a proxy you control sets it).
    if (cfg.trustProxy) {
      const hdr = (cfg.realIpHeader || 'x-real-ip').toLowerCase();
      const v = req.headers && (req.headers[hdr] || req.headers['x-forwarded-for']);
      if (v) return String(v).split(',')[0].trim();
    }
    return (req.socket && (req.socket.remoteAddress || '')) || '';
  }

  function ctxFrom(req, urlObj) {
    const ip = clientIp(req);
    return {
      method: req.method,
      path: urlObj.pathname,
      ip,
      headers: req.headers || {},
      fingerprint: (req.headers && req.headers[cfg.header.fp]) || '',
      acctSignal: (req && req.__agAcctSignal) | 0,     // server-trusted per-account cadence signal (forge-proof: a req property, not a header)
      admin: !!(req && req.__agAdmin),                 // #2: server-trusted admin exemption (forge-proof: a req property set from _who.role, not a header)
    };
  }

  function send(res, status, obj) {
    const body = Buffer.from(JSON.stringify(obj), 'utf8');
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'content-length': body.length,
      'cache-control': 'no-store',
    });
    res.end(body);
  }

  function handleChallenge(req, res, urlObj) {
    const path = urlObj.searchParams.get('path') || '';
    const ctx = ctxFrom(req, urlObj);
    ctx.path = path; // challenge is minted for the target path the client will call
    const out = guard.challenge(ctx);
    send(res, 200, out);
    return true;
  }

  // returns Promise<boolean>: true = request handled here (do not continue)
  function block(req, res) {
    return new Promise((resolve) => {
      let urlObj;
      try {
        urlObj = new URL(req.url, 'http://' + (req.headers.host || 'local'));
      } catch {
        urlObj = { pathname: req.url || '/', searchParams: new URLSearchParams() };
      }

      // challenge endpoint
      if (urlObj.pathname === cfg.challengePath) {
        try { return resolve(handleChallenge(req, res, urlObj)); }
        catch (e) {
          if (cfg.failOpen) return resolve(false);
          send(res, 503, { error: 'guard_error' }); return resolve(true);
        }
      }

      const ctx = ctxFrom(req, urlObj);

      // --- JA3-style TLS fingerprint OBSERVE. Additive, log-only, never affects the verdict below.
      // Double-wrapped (ja3.observe is itself try/catch'd) so a missing/garbage X-TLS-* header can
      // never throw into the request path. Runs on every protected request that reaches the guard.
      if (ja3Mod) { try { ja3Mod.observe(ctx.headers); } catch (_) { /* OBSERVE must never break serving */ } }

      // verdict is synchronous for the default sha256 PoW (returns an object). For the argon2id memory-hard
      // primitive the tier-1 branch recomputes async and returns a Promise; await ONLY that thenable so the
      // sha256 path is unchanged (no microtask deferral) for every existing caller.
      const afterVerdict = function (d) {
        if (d.allow) return resolve(false); // let the app handle it

        // TARPIT: delay the rejection as suspicion rises (d.delayMs is 0 for normal visitors) so a scraper
        // that keeps hitting the wall crawls, while a human — who never reaches this path — is unaffected.
        const sendReject = function () {
          const headers = {};
          if (d.action === 'rate_limited' && d.retryAfterMs) {
            headers['retry-after'] = String(Math.ceil(d.retryAfterMs / 1000));
          }
          // `action` names the tier explicitly (slider/captcha/pow/block/rate_limited) so the client can
          // branch without inferring; `error` kept as an alias for backward-compat.
          const body = { action: d.action, error: d.action, reasons: d.reasons };
          if (d.challenge) { body.challenge = d.challenge; body.token = d.token; body.needChallenge = true; }
          const raw = Buffer.from(JSON.stringify(body), 'utf8');
          res.writeHead(d.status, Object.assign({
            'content-type': 'application/json; charset=utf-8',
            'content-length': raw.length,
            'cache-control': 'no-store',
          }, headers));
          res.end(raw);
          resolve(true);
        };
        if (d.delayMs && d.delayMs > 0) { const to = setTimeout(sendReject, d.delayMs); if (to.unref) to.unref(); }
        else sendReject();
      };

      const dv = guard.verdict(ctx);
      if (dv && typeof dv.then === 'function') { dv.then(afterVerdict); return; }
      return afterVerdict(dv);
    });
  }

  return { block, handleChallenge, ctxFrom };
};
