# SPEC — Pulse Tier-3 sensor: per-session polymorphic VM stack (baxia-flavored, pool model)

## Goal
Upgrade the anti-lift sensor from a single static `javascript-obfuscator` build (crack-once-forever) to a
rotating pool of polymorphic VMs where a crack is **expensive** (obfuscation + integrity fold) AND
**perishable** (rotation). Not to hide code (impossible — runs on the attacker's machine) but to make
lifting/headless/traced clients mint **wrong tokens** that the server rejects, and to make any single crack
worthless by the next rotation.

## The four layers — ALL built and used (operator: "I want them all")
1. **Per-session VM generator** (PoC PROVEN, `gen-poc.cjs`: 0.1ms emit, correct exec, silent corruption on
   tamper, per-session polymorphism). Used to pre-build a **POOL** of N VMs offline → minimal origin load.
2. **Encrypted bytecode** — the VM's program is XOR/stream-encrypted and decrypted **one basic-block at a
   time** into a small buffer that's overwritten (read-once; a memory dump never holds the whole program).
   This is the "bytecode" layer (the PoC's plaintext Uint8Array becomes ciphertext).
3. **Integrity fold** — at runtime the VM hashes its own dispatch (`Function.prototype.toString`) + the
   natives it depends on (fetch/XHR/crypto.subtle/performance.now are `[native code]`) + a dispatch-timing
   sample, and **folds that into the token — never branches on it.** Any hook/patch/trace/breakpoint shifts
   the fold → token silently wrong → server 401. No throw, no log (silent = the point).
4. **Outer obfuscation coat** — the existing double-pass `javascript-obfuscator` (CFF 0.9, base64 stringArray)
   wrapped over each generated VM. Reuse as-is; it's the last coat, not the structure.

## Pool + rotation (minimal server load — the operator's constraint)
- Pre-build **N=2,000–10,000** VMs offline (measured: 10k ≈ 2s, 14.5MB static assets; each client loads ONE
  ~1.5KB VM). Served as versioned **static CDN-cacheable assets** → origin does ZERO generation per request.
- Per session: origin assigns a **signed pool index** (O(1)); client loads `vm-<i>.js` from cache.
- Per request: client's VM computes the token fold; origin verifies via `pool[i].reference` (O(1), ~3µs).
- **Rotation:** regenerate the whole pool on a cron (daily). A cracked member decays within a day; at Pulse's
  traffic a member covers ~1–2 sessions before re-roll ≈ per-session non-amortization in practice.
- Harvest resistance: harvesting the pool needs ~92k rate-limited sessions (coupon-collector) — caught by the
  cadence detector + env-enforce long before completion. See [[pulse_envbind_enforce_breaks_client_2026-08-25]].

## Server side
The generator (server/offline) knows each pool member's opcode map + program + integrity seed, so it verifies
any session's token **without running the emitted JS** (independent reference path) — the same shape as the
argon2/scramble round-trips already proven byte-identical. Store `pool[i] = {srcAssetUrl, verify(inputs)}`.

## Integration into apiguard (Tier-2 request signing)
Current: server mints an HMAC token + the client attaches it + the env-fp (x-ag-env). New: the token the client
attaches is **computed through its served pool VM** (fold of nonce | counter | env-digest), so the token is
only mintable by an untampered VM in a real browser. Add the **monotonic per-session counter** (the missing
Tier-2 piece) so a stolen token can't be fanned out. Keep crypto.subtle HMAC native (not in the VM).

## Phased build — each phase dry-run + L6-tested, gated
- **Phase 0 — generator** ✅ DONE (`gen-poc.cjs`, `gen-pool.cjs` proven).
- **Phase 1 — integrity fold wired to a REAL token** + prove tamper(hook/patch/trace) → server rejects. (dry-run)
- **Phase 2 — encrypted bytecode** (block-decrypt, read-once). (dry-run: decode == plaintext exec)
- **Phase 3 — pool build + daily rotation cron + server per-pool verify** (O(1), byte-identical to client).
- **Phase 4 — outer `javascript-obfuscator` coat** on each pool VM; size/CSP check.
- **Phase 5 — wire into apiguard**: monotonic counter + ticket, VM-computed token, server verify; behind a
  flag (VM_SENSOR=observe→enforce) with a kill-switch back to today's client. Fail-open on any error.
- **Phase 6 — harsh corporate UAT**: real-browser L6 (mint+verify), tamper attempts (hooked fetch/subtle →
  reject), harvest test (rate-limit trips), rotation test (yesterday's VM rejected), speed (no regression).

## Honest ceiling (contract)
Buys time, not secrecy. A determined human cracks one session in a real browser; this makes it non-amortizable
(rotation) + tamper-evident (fold) + headless-blocked (env-enforce + counter). Enterprise scale (millions of
sessions) → the pool amortizes → buy baxia. At Pulse's tier this is sufficient and correct.

## Constraints
Pure-JS (CSP-safe, mini-program-safe); NO Wasm/QuickJS (import-bridge + 150KB); NO bytenode (V8 bytecode is
Node-only, can't run in a browser); minimal origin load (pool, not per-session edge emit); every detection
folds silently into the token (never throw/log/branch); kill-switch to the current client at all times.
