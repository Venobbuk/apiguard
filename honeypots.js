'use strict';
/*
 * apiguard/honeypots.js — decoy endpoints that a REAL user never hits, feeding the risk engine.
 *
 * Idea: publish a handful of tempting-but-fake paths (advertised only where automation looks: a
 * robots.txt Disallow list, an invisible link, "internal/export" API names). A human browsing the
 * real UI never requests them. A scraper enumerating URLs, harvesting Disallow lines, or fuzzing
 * "export/internal" endpoints DOES — and that request marks its IP high-risk, so its NEXT real
 * request escalates (block/tarpit by default) via apiguard's existing store + scoreRisk.
 *
 * This module is intentionally tiny and STATELESS: it only knows the path list + how to recognise
 * one + how to emit a robots.txt that advertises them. The actual flagging lives in core.js
 * (store.markBad + guard.flagHoneypot); the host calls guard.flagHoneypot(ctx) when isHoneypot(path).
 *
 *   const hp = require('./honeypots').makeHoneypots();       // or pass your own list
 *   if (hp.isHoneypot(url.pathname)) { guard.flagHoneypot(ctx); return serveDecoy(res); }
 *   if (url.pathname === '/robots.txt') return sendText(res, hp.robotsTxt());
 *
 * DESIGN NOTES / honest limits:
 *   - Match is EXACT-PATH (not prefix) on purpose: a prefix trap risks catching a real route that
 *     grows under the same root and flagging genuine users. Exact paths = zero false-positive surface.
 *   - Do NOT put a honeypot on any path the real front-end or a legit crawler visits. Keep names
 *     obviously "internal/backup/export" so only someone poking where they shouldn't trips it.
 *   - robots.txt advertising is a double-edged lure: polite crawlers (Googlebot) OBEY Disallow and
 *     stay away (good — no false flag); hostile scrapers often READ Disallow to find the juicy URLs
 *     and get trapped. A scraper that ignores robots entirely still trips the /api/_internal-style
 *     names via fuzzing. Neither path catches a normal human.
 */

// A mix of the three lures: fake "internal/export" API names, classic recon paths (git/wp/backup),
// and an invisible-link path the host can hide in the page for link-harvesting bots.
const DEFAULT_HONEYPOTS = [
  '/api/_internal',
  '/api/export-all',
  '/api/v1/users/export',
  '/api/admin/dump',
  '/admin/backup.zip',
  '/.git/config',
  '/wp-login.php',
  '/do-not-follow',        // hide as an invisible <a> in the app shell for link-harvesters
];

/**
 * makeHoneypots(list) -> { paths, isHoneypot(path), robotsTxt(opts) }
 *   list = optional array of exact paths (defaults to DEFAULT_HONEYPOTS).
 */
function makeHoneypots(list) {
  const set = new Set((Array.isArray(list) && list.length ? list : DEFAULT_HONEYPOTS)
    .filter((p) => typeof p === 'string' && p.charAt(0) === '/'));
  const paths = Array.from(set);

  function isHoneypot(path) {
    if (!path || typeof path !== 'string') return false;
    const q = path.split('?')[0].split('#')[0];   // ignore query/fragment
    return set.has(q);
  }

  // robots.txt that Disallows every honeypot (the lure) plus an optional real Disallow list the host
  // wants respected. Extra real Sitemap/Disallow lines can be appended via opts.
  function robotsTxt(opts) {
    opts = opts || {};
    const extraDisallow = Array.isArray(opts.disallow) ? opts.disallow : [];
    const lines = ['User-agent: *'];
    for (const p of paths) lines.push('Disallow: ' + p);
    for (const d of extraDisallow) if (typeof d === 'string') lines.push('Disallow: ' + d);
    if (opts.sitemap) lines.push('Sitemap: ' + opts.sitemap);
    return lines.join('\n') + '\n';
  }

  // an invisible anchor the host can inject into its shell so link-harvesting crawlers follow it into
  // the trap while a sighted human never sees or clicks it. aria-hidden + not focusable.
  function invisibleLinkHtml(pathname) {
    const p = pathname || '/do-not-follow';
    return '<a href="' + p + '" rel="nofollow" aria-hidden="true" tabindex="-1" ' +
      'style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden">.</a>';
  }

  return { paths, isHoneypot, robotsTxt, invisibleLinkHtml };
}

module.exports = { makeHoneypots, DEFAULT_HONEYPOTS };
