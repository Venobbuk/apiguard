# apiguard

Self-hosted, zero-dependency **adaptive API protection**. It makes direct/scraped API
access **slow, CPU-expensive, detectable, and costly to reverse-engineer** — while a normal
user feels nothing. No Cloudflare, no vendor, no SaaS. Node built-in `crypto` only in the core.

---

## ⚠️ Read this first — the honest threat model

This does **NOT** make your API unscrapable. Nothing client-side can. The client runs on the
attacker's machine; anything it computes can be reproduced. Two attacker paths always exist:

1. **Extract the algorithm** — deobfuscate the JS and re-implement the token/PoW.
2. **Run the real client** — drive a real browser so *your own code* mints valid tokens.

apiguard does not pretend to close these. It **raises the cost** and **contains the damage**:

- **Environment-binding** makes *lifting* the client into a headless/Node/dirty runtime
  detectable (a real browser scores clean; a stub scores as a bot). It does **not** stop a real
  GPU browser driven by automation — there the environment is genuine.
- **Adaptive proof-of-work** (optionally memory-hard **argon2id**) makes each *flagged* request
  cost real CPU, so volume scraping becomes uneconomical. Normal users solve nothing.
- **Rotating signed token + single-use nonce + monotonic counter** kill replay.
- **Rate-limit + tarpit + risk scoring** cap the damage no matter how a token was obtained.
- **The rendered data is already in the browser** — a screenshot or DevTools defeats any client
  guard. This protects the *bulk API*, not the pixels.

**The win is economics — "not worth their effort," not "impossible."** Deploy it with that
framing. If you tell your users it's unbreakable, this README will make you a liar.

---

## What's in the box (each layer raises attacker cost)

| file | role |
|---|---|
| `core.js` | framework-agnostic engine: token mint/verify, risk score, PoW verify, tier decision, env-binding scorer. **Zero deps.** |
| `adapter-http.js` / `adapter-express.js` | drop-in wiring for raw `http` / Express |
| `client.js` | minimal browser client: wraps `fetch`, solves PoW, attaches headers |
| `client.envbind.js` | full browser client: + environment probes + VM-token fold + counter |
| `signals-client.js` | standalone headless/automation signal detector (spoofable, modest additive signal) |
| `scramble.js` | optional AES-CTR response scrambling for flagged identities |
| `vmsensor.js` / `vm-gen.cjs` / `vm-build-pool.cjs` | polymorphic bytecode **VM sensor** (integrity self-fold, encrypted read-once bytecode, daily-rotating obfuscated pool) |
| `honeypots.js` / `rebroadcast.js` / `challengers.js` | trap paths, full-feed-mirror detector, interactive-challenge glue |
| `interstitial.js` / `slider.js` / `motion-captcha-cc.js` / `watermark.js` / `canary.js` | optional tier-2/3 UI + leak forensics |
| `build/` | the obfuscation + PoW-WASM build pipeline |

## Quick wiring

```js
// raw http (one line at your gate)
const guard = require('./apiguard/core')({ secret: process.env.GUARD_SECRET, protect: '/api/', rpm: 120 });
if (await guard.block(req, res)) return;

// express
app.use(require('./apiguard/core')({ secret: process.env.GUARD_SECRET }).express());
```

```html
<!-- front end: auto-wraps fetch, no other changes -->
<script src="/apiguard/client.js"></script>
```

Config lives in one object per site — see `config.example.js`. `failOpen: true` (default) means
a guard bug can never take your site down.

## Difficulty tiers

Normal user → tier 0, token only (nothing to solve). Risk score escalates per request:
invisible PoW → slider → motion captcha → block/tarpit. Risk **decays**, so a flagged-but-legit
user cools back to invisible. PoW difficulty is **HMAC-locked** — a client can't downgrade it.

## Rotation (the "raise RE cost" engine)

`build/build-client.cjs` produces a fresh double-obfuscated client on a schedule; `vm-build-pool.cjs`
pre-builds a rotating pool of polymorphic VMs. Each rotation invalidates in-progress reverse
engineering. A grace window keeps the previous variant valid so users never see a re-challenge blip.

## Security notes for adopters

- **Bring your own secret.** `config.secret` (≥16 chars, high-entropy) is per-deployment and must
  never be committed. The VM baseline is computed server-side and never shipped.
- The mechanism is public (this repo); your **security rests on your secret + rotation**, not on
  the code being hidden (Kerckhoffs). That is by design.
- `signals-client.js` and any client bitmask are **spoofable** — never block on them alone; the
  server caps their contribution.

## License

MIT — see `LICENSE`. Provided as-is, with the threat model above. It is a deterrent, not a wall.
