'use strict';
/*
 * apiguard/adapter-express.js — v1
 * Express / Connect middleware. Zero external deps (peer: express, provided by the host app).
 *
 *   const guard = require('./core')({ secret: process.env.GUARD_SECRET, protect:'/api/' });
 *   app.use(guard.express());
 *
 * The single middleware also serves the PoW-challenge endpoint
 * (GET /__ag/challenge?path=/api/foo).
 */

module.exports = function expressAdapter(guard) {
  const cfg = guard.config;

  function ctxFrom(req) {
    // req.ip requires app.set('trust proxy', ...) to be meaningful; default to socket.
    const ip = req.ip || (req.socket && req.socket.remoteAddress) ||
      (req.connection && req.connection.remoteAddress) || '';
    const path = req.path || (req.url ? req.url.split('?')[0] : '/');
    return {
      method: req.method,
      path,
      ip,
      headers: req.headers || {},
      fingerprint: (req.headers && req.headers[cfg.header.fp]) || '',
    };
  }

  return function apiguardMiddleware(req, res, next) {
    const path = req.path || (req.url ? req.url.split('?')[0] : '/');

    // challenge endpoint
    if (path === cfg.challengePath) {
      try {
        const targetPath = (req.query && req.query.path) || '';
        const ctx = ctxFrom(req); ctx.path = targetPath;
        return res.status(200).set('cache-control', 'no-store').json(guard.challenge(ctx));
      } catch (e) {
        if (cfg.failOpen) return next();
        return res.status(503).json({ error: 'guard_error' });
      }
    }

    const d = guard.verdict(ctxFrom(req));
    if (d.allow) return next();

    res.set('cache-control', 'no-store');
    if (d.action === 'rate_limited' && d.retryAfterMs) {
      res.set('retry-after', String(Math.ceil(d.retryAfterMs / 1000)));
    }
    const body = { error: d.action, reasons: d.reasons };
    if (d.challenge) { body.challenge = d.challenge; body.token = d.token; body.needChallenge = true; }
    return res.status(d.status).json(body);
  };
};
