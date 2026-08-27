'use strict';
/*
 * apiguard/scramble.js — LIGHTWEIGHT, reversible per-session obfuscation of a JSON response STRING, so
 * the raw /api payload is NOT clean text in DevTools/curl. This is OBFUSCATION, NOT confidentiality:
 * a fast XOR keystream, no heavy crypto. It raises the cost of casually reading/scraping the JSON; it
 * does not make the data secret from someone running our real client or reversing the blackbox.
 *
 * ── KEY (symmetric, no secret on the client) ────────────────────────────────────────────────────────
 *   key = SHA-256('ag-scramble|v1|' + token)
 *   The client ALREADY holds `token` (it fetched + attaches x-ag-token on every guarded request); the
 *   server sees the SAME token on that request's header — so both derive the identical keystream with
 *   ZERO key exchange and no core/adapter changes. The token is HMAC-signed by the server secret, so a
 *   scraper cannot forge one → cannot get a scrambled body it can key. (Client.js re-implements this
 *   exact keystream with its own pure SHA-256, proven byte-identical to Node's in test.js case (h).)
 *
 * ── KEYSTREAM ───────────────────────────────────────────────────────────────────────────────────────
 *   seed        = SHA-256(utf8('ag-scramble|v1|' + material))            (32 bytes)
 *   block(n)    = SHA-256( seed(32 bytes) || uint32be(n) )               (SHA-256-CTR)
 *   ks[j]       = block(floor(j/32))[j mod 32]
 *   scramble    = base64( plainBytes[j] XOR ks[j] )   (standard base64; transportable as the body text)
 *   unscramble  = utf8( base64dec(str)[j] XOR ks[j] )  — exact inverse.
 *
 * ── HONEST CAVEATS (see report) ─────────────────────────────────────────────────────────────────────
 *   Broken by (Path 1) reversing the obfuscated client to recover this keystream — CONTAINED by the
 *   weekly blackbox rotation (rotate.sh); or (Path 2) simply running our real client / replaying the
 *   token flow, which by design yields clean data (that's a logged-in user). It STOPS casual DevTools/
 *   curl reading of the JSON and raises scraping cost; it is NOT unbreakable. Pair with canary.js, which
 *   traces whoever DOES break it back to their account.
 */

const crypto = require('crypto');

const PREFIX = 'ag-scramble|v1|';

function sha256(buf) { return crypto.createHash('sha256').update(buf).digest(); } // Buffer(32)

// keystream seed for a given key material (the token, by default).
function deriveKey(material) {
  return sha256(Buffer.from(PREFIX + String(material == null ? '' : material), 'utf8')); // Buffer(32)
}

// Generate `len` keystream bytes from a 32-byte seed via SHA-256-CTR.
function keystream(seed, len) {
  const out = Buffer.allocUnsafe(len);
  let off = 0, ctr = 0;
  while (off < len) {
    const ctrBuf = Buffer.allocUnsafe(4); ctrBuf.writeUInt32BE(ctr >>> 0, 0);
    const block = sha256(Buffer.concat([seed, ctrBuf])); // 32 bytes
    const n = Math.min(32, len - off);
    block.copy(out, off, 0, n);
    off += n; ctr++;
  }
  return out;
}

// scramble(plainString, keyMaterial) -> base64 string of XOR'd UTF-8 bytes.
function scramble(str, keyMaterial) {
  const seed = Buffer.isBuffer(keyMaterial) && keyMaterial.length === 32 ? keyMaterial : deriveKey(keyMaterial);
  const c = crypto.createCipheriv('aes-256-ctr', seed, Buffer.alloc(16, 0));
  return Buffer.concat([c.update(Buffer.from(String(str), 'utf8')), c.final()]).toString('base64');
}

// unscramble(base64String, keyMaterial) -> original UTF-8 string. Exact inverse of scramble().
function unscramble(str, keyMaterial) {
  const seed = Buffer.isBuffer(keyMaterial) && keyMaterial.length === 32 ? keyMaterial : deriveKey(keyMaterial);
  const d = crypto.createDecipheriv('aes-256-ctr', seed, Buffer.alloc(16, 0));
  return Buffer.concat([d.update(Buffer.from(String(str), 'base64')), d.final()]).toString('utf8');
}

/**
 * makeServerScrambler(opts) -> { header, scrambleBody(bodyString, ctx) }
 *   header : the marker header name (default 'x-ag-enc') the client keys off to know it must unscramble.
 *   scrambleBody(bodyString, ctx) -> { body, headers, scrambled }
 *     ctx.headers must carry the request's token header (default 'x-ag-token'); ctx.token also accepted.
 *     If no token is present (e.g. an unauthenticated/edge response), it PASSES THROUGH unchanged and
 *     scrambled:false — never breaks a response it cannot key. Fail-safe: any throw returns passthrough.
 */
function makeServerScrambler(opts) {
  opts = opts || {};
  const header = opts.header || 'x-ag-enc';
  const tokenHeader = (opts.tokenHeader || 'x-ag-token').toLowerCase();
  function tokenOf(ctx) {
    if (!ctx) return '';
    if (ctx.token) return ctx.token;
    const h = ctx.headers || {};
    if (h[tokenHeader] !== undefined) return h[tokenHeader];
    for (const k in h) if (k.toLowerCase() === tokenHeader) return h[k];
    return '';
  }
  function scrambleBody(bodyString, ctx) {
    try {
      const token = tokenOf(ctx);
      if (!token) return { body: bodyString, headers: {}, scrambled: false };
      const body = scramble(bodyString, token);
      const headers = {}; headers[header] = '1';
      return { body, headers, scrambled: true };
    } catch (e) {
      return { body: bodyString, headers: {}, scrambled: false, error: e && e.message };
    }
  }
  return { header, scrambleBody, tokenOf };
}

module.exports = { PREFIX, deriveKey, keystream, scramble, unscramble, makeServerScrambler };
