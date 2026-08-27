---
title: SPEC
type: note
permalink: projects/apiguard/spec
---

# apiguard — reusable adaptive API-protection module

**Status:** L1 spec, awaiting operator sign-off. No code until this is approved.
**Author:** built for the operator, 2026-08-10.
**Scope:** a drop-in module reused across the operator's sites (Pulse, HKPL, Mimi, Studio, …) that makes
direct API access by scraping **slow, CPU-expensive, detectable, and months-costly to reverse-engineer.**

---

## 0. Goal and explicit NON-goal

- **Goal:** normal users feel nothing; a scraper is forced off the cheap path and onto one that costs
  real CPU per request, trips detection, and requires months of reverse-engineering that a rotation
  schedule keeps invalidating.
- **NON-goal (stated honestly, not marketing):** this does **NOT** make direct API access impossible.
  It cannot. The client runs on the attacker's machine; anything it does can be reproduced. Two attacker
  paths always exist:
  1. **Extract the algorithm** — deobfuscate the JS/WASM and re-implement the token+PoW in Python.
  2. **Run our real client** — drive a headless/real browser so *our own code* mints valid tokens,
     bypassing reverse-engineering entirely. Obfuscation does nothing against this path.
- **What each path is handled by:**
  - Path 1 (extract) → RE-hardening: WASM VM + obfuscation + **rotation** (the "months" engine).
  - Path 2 (run our client) → PoW-difficulty-on-risk + rate-limit + CrowdSec reputation + data
    minimization (these cap the damage no matter how the token was obtained).
- **The real win is economics:** "not worth their effort," not "impossible."

---

## 1. Open-source we build ON (compose, don't reinvent)

| piece | role | why this one |
|---|---|---|
| **ALTCHA** (MIT) | proof-of-work challenge protocol + server verify + widget | embeddable per-request, self-hosted, no vendor, tunable difficulty |
| **Anubis** (OSS) | optional edge PoW gateway for non-Node / blanket cover | purpose-built to stop scrapers/AI crawlers |
| **CrowdSec** (OSS) | crowd-sourced IP reputation + auto-ban | the threat-intel network we cannot build alone |
| **BotD** + **FingerprintJS** (OSS) | client bot signals + device fingerprint | feeds the risk score |
| **JA4+** (FoxIO, OSS) | TLS/HTTP fingerprint at nginx to catch headless | server-side, unspoofable by client JS |
| **SafeLine 雷池** or **BunkerWeb** (OSS) | edge WAF + challenge, China-friendly | since Cloudflare is out |

**apiguard = the thin glue + risk-policy engine over these.** We own the policy; we reuse the mechanisms.

---

## 2. What WE add (the layers, each raises RE cost)

1. **Rotating signed token** — HMAC over `(ts, nonce, path, fingerprint)`, short TTL, server secret
   rotates. Kills `curl`/Python instantly.
2. **Adaptive proof-of-work (on ALTCHA)** — every protected request carries a solved PoW whose
   **difficulty = f(risk)**. Normal user ≈ 16 bits (~ms). Flagged identity ramps to 22–26 bits
   (seconds of CPU **per request**) → volume scraping becomes economically dead. **This is the
   "most CPU cost for them" lever.**
3. **WASM-wrapped critical logic** — token-mint + PoW + an environment checksum compiled to a small
   Rust→WASM module with control-flow obfuscation / a mini-VM, split so JS alone can't mint a token
   without calling WASM. RE of obfuscated WASM is dramatically harder than JS. **This is the core
   "months" maker.**
4. **Obfuscated + rotating client** — `client.js` (loader + WASM glue + signal collection) obfuscated
   (self-defending, control-flow-flattening, string rotation, debug-protection) and **rebuilt on a
   schedule** with a changing layout AND a changing algorithm variant. Each rotation invalidates the
   attacker's RE work. **Rotation is what turns "days" into "months" — a moving target, not one hard nut.**
5. **Risk scoring** — combines BotD signals, fingerprint churn, rate, token freshness/replay, JA4,
   timing entropy, failed challenges → one score that drives PoW difficulty + challenge tier + CrowdSec.
6. **Interactive challenge tiers** — slider → animated/distorted → block, popped only at high risk.
7. **Rate-limit + data minimization** — backstops that cap damage regardless of token path.

---

## 3. The adaptive ladder (normal = nothing, unusual = escalate)

| tier | trigger (risk band) | visitor sees | attacker cost |
|---|---|---|---|
| 0 invisible | normal | nothing (token only) | — |
| 1 PoW | slightly off | nothing; browser solves PoW (~ms) | CPU × volume |
| 2 slider | rate spike / token stale / fp churn | slider puzzle | behavioral drag check |
| 3 hard | failed t2 / headless / replay | animated distorted text / dynamic image | per-request solve |
| 4 block/tarpit | persistent | slow/deny | wasted time |

Risk **decays** — a flagged-but-legit user cools back to invisible. A real human basically never sees t2+.

---

## 4. Module shape (generic, zero-dep JS glue)

```
apiguard/
  core.js            # framework-agnostic: risk scorer, token verify, PoW verify, tier decision. Node crypto only.
  adapter-http.js    # raw http (Pulse)         -> guard.block(req,res)
  adapter-express.js # Express (HKPL, Mimi)     -> app.use(guard.express())
  sidecar.js         # standalone auth_request service (any language backend, via nginx)
  client.js          # loader: fetch-wrapper, WASM glue, signal collection, challenge widgets
  wasm/              # Rust source + built .wasm (token-mint + PoW + env checksum)
  build/             # obfuscation + rotation pipeline (produces rotated client.js + wasm + server variant)
  config.example.js
  SPEC.md  (this)
```

- **Config object per site:** `{ secret, protect:'/api/', rpm, powBits:{normal,max}, tiers:[...], exempt:[...], failOpen:true, store:'memory'|'redis', crowdsec:{...} }`
- **Fail-open switch** so a guard bug never takes a site down (default open; flip closed per site).
- **Pluggable store** for risk/rate state: in-memory default, Redis only for multi-instance sites.

---

## 5. Wiring per site (1–3 lines)

- **Pulse (raw http, one existing gate at server.js:178):**
  ```js
  const guard = require('./apiguard')({ secret: process.env.GUARD_SECRET, protect:'/api/', rpm:120 });
  if (await guard.block(req,res)) return;   // one line
  ```
- **Express sites:** `app.use(guard.express())`
- **Any language (Python Studio):** run `sidecar.js`, add 3 lines to that site's nginx (`auth_request`).
- **Front-end (any):** `<script src="/apiguard/client.js"></script>` — auto-wraps `fetch`, no other changes.

---

## 6. The rotation pipeline (the "months" engine)

- A build script produces a **matched pair**: obfuscated `client.js` + `.wasm` + the server-side token
  variant they correspond to. Server accepts the current + previous variant (grace window).
- **Rotate on a schedule** (operator-chosen; default weekly) and **immediately on alarm** (a spike of
  failed tokens = someone probing → rotate now, invalidating their in-progress RE).
- Honest cost: this introduces a **build step** to sites that currently have none (Pulse is hand-scp'd).
  That build step is the price of the WASM + obfuscation + rotation. Accepted as part of this module.

---

## 7. Build plan (layered, usable early)

- **v1** — core + rotating token + rate-limit + risk scorer + **invisible adaptive PoW** (ALTCHA). No UI.
  Delivers "normal = nothing, bots = expensive." Wired into Pulse first. *(≈ 2–3 days)*
- **v2** — WASM-wrap the token+PoW; obfuscation + rotation pipeline. This is the RE-months layer. *(≈ 3–4 days)*
- **v3** — slider (behavioral) + hard challenge widgets as risk tiers. *(≈ 2–3 days)*
- **v4** — CrowdSec + JA4 at the edge; sidecar for non-Node sites. *(ops + ≈ 2 days)*

Each version ships and is wired before the next starts (operator's "work the list one at a time").

---

## 8. Honest caveats & proof levels

- RE-hardening (WASM+obf+rotation) raises path-1 cost to **months IF rotation outpaces the attacker** —
  it is not a permanent wall. L0 claim until measured against a real RE attempt.
- Path-2 (run our client in a real browser) is **not** stopped by any of §2.3–2.4; it is *contained* by
  PoW-difficulty + rate-limit + CrowdSec + minimization. State this to anyone who expects "unbreakable."
- Interactive image/text challenges (t3) are defeatable by 2026 AI solvers — they **deter**, not block.
  The durable levers are **PoW** and the **behavioral** check, not the picture.
- Every "it's protected" claim in this project stays at its true level: L2 (in code) ≠ L6 (a real
  scraper measured failing). We grade by trying to break it, not by shipping it.

---

## 9. Needs operator decision before build

1. **Rotation cadence** (weekly default? faster?) and whether to auto-rotate-on-alarm.
2. **PoW difficulty ceiling** for flagged identities (higher = more attacker pain, but also more heat on
   a false-positive human — tradeoff).
3. **Which site is the pilot** (recommend Pulse — it has the single gate and the most valuable data).
4. **Accept the build step** on Pulse (WASM + obfuscation + rotation ends the hand-scp'd-html simplicity).

---
## PASSWORD + DEVICE-ID MODE (operator decision 2026-08-11 — supersedes "passkey required")
Windows passkey UX proved too blocking (Edge routes platform passkeys through "Microsoft Password Manager",
which was unreachable during enrollment). Operator: "make it simple on windows... we lock in with our server."
DECISION: **drop the required Microsoft passkey/Hello; login = username + password; the device lock is OUR
server-side device-id (canvas/WebGL/screen/UA + stored `__ag_uid`), NOT a WebAuthn credential.**
- New authguard config `passkeyMode: 'required' | 'off'` (default keeps 'required' for other sites; Pulse = 'off').
- In `'off'`: loginBegin/Finish require ONLY username+password (no WebAuthn assertion). On password-correct →
  bind/check the **device-id allowlist** (default **1**, admin-grants more) + **concurrent cap** + issue session.
  First login from a device auto-binds its device-id; a login from device #(N+1) is refused (`device_limit`).
- The anti-sharing enforcement is UNCHANGED — it always ran on the device-id + concurrent cap, never on the
  passkey. The passkey only added phish/copy resistance to the credential itself.
- Admin key-lifecycle (remark / expiry / reset / grant) now operates on the **device-id records** in this mode
  (the device-id IS "the key"). Passkey remains OPTIONAL (a site can set `passkeyMode:'required'`).
- HONEST: the device-id is a strong SIGNAL, not a hardware seal (browser-JS, spoofable by a determined
  attacker). It stops casual sharing/resale cold (a shared password is useless on a 2nd device). The only
  cryptographically-uncopyable Windows lock = a native TPM helper (out of scope, optional later).
- **REMOVE ALL PASSKEYS (operator 2026-08-11):** `passkeyMode:'off'` for Pulse and every site — no WebAuthn
  anywhere. Existing enrolled credentials (if any) are ignored/removable; login never invokes navigator.credentials.
- **PER-TYPE DEVICE LIMIT (operator 2026-08-11, clarified):** the allowance is PER DEVICE-TYPE, not a flat
  total. DEFAULT **1 mobile + 1 desktop** per user (their phone + their computer). Binding a 2nd device of a
  type already at its limit → refused (`device_limit_<type>`, bilingual). Types from the UA: phone/tablet →
  `mobile`; Windows/Mac/Linux → `desktop`. Per-user, per-type limits are admin-settable (e.g. desktop:2 for
  a work+home PC; mobile:0 to forbid). So a real user's phone+laptop both work, but a 2nd phone (a shared
  device) is blocked. (Operator may instead choose 4 finer buckets phone/windows/mac/linux @1 each — looser,
  up to 4 devices; default is the tighter mobile/desktop.)
- **PER-KEY PLATFORM PIN (operator 2026-08-11):** on top of the per-type limit, each device-id key stores its
  AUTO-DETECTED platform (phone/windows/mac/linux) shown to admin, and the admin can PIN a key to a specific
  platform (`allowedPlatform`, default null = any): a login on that key from a mismatched platform is refused
  (`platform_mismatch`, bilingual). Enforcement is server-side but UA-based — a strong signal, not unspoofable.

## Per-user auth + device-lock (operator spec, 2026-08-10)
- **User management**: an admin web UI to create/edit/delete users and set each user's device limit.
- **Default admin**: username `venobbuk`. Password is SET BY THE OPERATOR and stored ONLY as a bcrypt/scrypt
  HASH (never plaintext, never in this file or memory). Force a change-on-first-login prompt.
- **Device-lock = WebAuthn platform passkeys (the STRONG method we discussed — NOT a browser cookie).**
  Each enrolled device is a hardware-bound credential (TPM / Secure Enclave / Windows Hello); the private
  key never leaves the device and can't be copied, exported, or shared. Login = username/password + a
  WebAuthn assertion from an enrolled device. A cookie is only a session convenience on top, never the lock.
- **Device limit**: DEFAULT **2 devices per user**, admin-configurable per user. Enrolling a device beyond
  the limit is refused until the admin raises it or the user removes a device.
- Enforcement: a stolen password alone cannot log in (no enrolled passkey); a shared account shows up as
  >limit devices / new hardware and is blocked + flagged. Ties into the risk engine (a login from an
  unenrolled device = high risk).
- Replaces the shared `888888` site password. Pairs with per-user rate-limits + pagination + watermarking.
- **Login / device-enrollment UX (bilingual EN + 中文)**: when a user signs in on a new device, the flow
  clearly tells them, in both languages:
  - "此账户将绑定到您的设备。/ This account will be locked to this device."
  - "您还可绑定 N 台设备。/ You have N device(s) remaining." (N = limit − enrolled)
  - When at the limit: "已达设备上限，请移除一台或联系管理员。/ Device limit reached — remove one or contact the admin."
  So the user understands the device-lock is intentional and knows their remaining slots before enrolling.
- **Device identity = the WebAuthn credential, NOT a MAC address.** MAC is explicitly rejected (multi-NIC,
  VPN, virtual adapters make it a mess, and browsers can't read it anyway). Each device is identified by
  its hardware-bound WebAuthn credential ID (Secure Enclave / TPM / Windows Hello) — unique per device,
  independent of the network, uncopyable. A canvas/WebGL/hardware device fingerprint + stored UUID is kept
  ONLY as a secondary detection signal, never as the lock.
- **Server stores each device's credential (PUBLIC key + credential ID + metadata) → admin recovery.**
  The private key never leaves the device (uncopyable), but the server keeps the registration record, so
  the admin UI can: list a user's enrolled devices (id, type, enrolled/last-used), REMOVE one device
  (revoke → frees a slot → user re-enrolls on a new device — the recovery path for a lost phone / new
  device / reinstall), or RESET all devices (fresh start). Revocation is instant; the old passkey stops
  working immediately. No user ever gets permanently locked out — the admin can always re-enroll them.
- **DECISION (FINAL, operator-agreed 2026-08-10 after researching the 2026 state of the art): RELAXED
  passkeys + our OWN server-side anti-sharing layer. We do NOT rely on the passkey's device-binding.**
  Rationale (researched, L2): the clean cryptographic fix for counting physical devices behind a synced
  passkey — the WebAuthn `devicePubKey`/`supplementalPubKeys` extension — was DISCONTINUED in the W3C spec
  (Aug 2024); Apple never shipped it. And STRICT reject-synced would lock out iPhone/Mac + default-Android
  (their passkeys are always iCloud/Google-synced). So strict is a dead end for phone users. The 2026
  industry answer (streaming-service playbook) is to enforce on the IDENTITY + BEHAVIOUR server-side, not
  on the passkey. We own the server, so we do exactly that:
  1. **Accept synced passkeys** (backup-eligible OK) → iPhone/Android/desktop all enroll and work. The
     passkey's job is only to kill PASSWORD sharing (uncopyable, un-textable). Its sync status is IRRELEVANT
     to our device lock.
  2. **Device identity = OUR server-side device record, NOT the WebAuthn credential and NOT the IP.** Each
     device is keyed by a stable DEVICE-SIDE id: the persistent `localStorage` UUID (`__ag_uid`) + the
     hardware fingerprint (canvas / WebGL / screen / UA) from apiguard. This is NETWORK-INDEPENDENT — it does
     NOT change when the user roams between mobile 5G and home WiFi (mobile/home IPs rotate constantly, so
     **IP is LOGGED for forensics/anomaly only, NEVER used as a guard** — an IP block would false-positive
     real users daily).
  3. **Device allowlist, N per user (default 2, admin-configurable).** The first N distinct device-ids an
     account uses become its bound devices; a login from device #(N+1) is refused (or needs admin approval).
     Sharing one Apple ID/Google account to 100 people → 100 distinct physical devices → 100 distinct
     device-ids → blocked at #3 and flagged. The synced passkey being on all 100 is irrelevant; we gate on
     OUR record.
  4. **Concurrent-session cap, N (default 2).** Max N active server-side sessions per account at once; the
     next is denied or bumps the oldest. This is the DIRECT answer to "100 devices logged in at the same
     time" and is fully IP-independent (counts session tokens).
  5. **Anomaly signals (soft):** impossible-travel / IP-velocity / a sudden brand-new fingerprint → flag to
     admin or pop an apiguard challenge. Never an auto-block (too noisy with VPN/mobile).
- **Admin (`venobbuk`) = RELAXED with a generous/large device limit** so the operator can manage from any of
  their own devices. Regular users **default to 1 device/key (no sharing)**; the admin GRANTS additional keys
  per-user as needed (operator: "give them 2 keys if they want 2 devices — better control"). Device limit is
  per-user, admin-set — default 1, bump to 2+ case by case.
- **Each key/device carries an admin-editable REMARK field** (operator ask 2026-08-11), shown next to the key
  in the admin device list and editable anytime (e.g. "personal iPhone", "work laptop", "friend — approved
  8/11"). Stored on the device record; a `PATCH`/route sets it; the admin UI shows + edits it. So the operator
  can label every key and see at a glance who has what and why.
- **Each key/device has an admin-settable EXPIRATION date** (operator ask 2026-08-11), default none (never
  expires). When set, that key stops authenticating after the date — loginFinish must REJECT an assertion from
  an expired device (reason `device_expired`, bilingual message) and the admin UI shows the expiry + a date
  picker to set/clear/extend it. Use for trial users, time-boxed friend-keys, contractor access, etc. Independent
  of the device allowlist (an expired key still occupies its slot until removed, so the admin sees it and can
  revoke or extend). Enforced server-side on every login, so it can't be bypassed client-side.
- **Per-key RESET / REVOKE — regenerate + void the old one** (operator ask 2026-08-11): one admin action
  INSTANTLY invalidates a specific key's credential (the old passkey stops verifying immediately on the very
  next request — revocation is not deferred), frees its slot, and the user re-enrolls to REGENERATE a fresh
  key on their device. This is the leaked/compromised/handed-around-key remedy and the lost-phone recovery path.
  Distinct from "remove device" only in intent (reset = expect re-enroll); both void the old credential at once.
  Admin UI: a Reset/Revoke control per key (with confirm), plus the existing Reset-ALL-keys for a full restart.
- **Net admin key lifecycle (all per-user, in the admin dashboard):** grant/add keys (raise device limit) ·
  set/clear per-key remark · set/clear/extend per-key expiry · reset/revoke a key (void + re-enroll) ·
  reset all keys · view each key's remark/expiry/first-seen/last-seen/last-IP/active-sessions. Full control,
  full visibility, every action server-enforced and instant.
- **Honest ceiling (told operator, accepted):** the device-id is a strong SIGNAL, not an unforgeable hardware
  seal — it stops a reseller sharing to a crowd (100 real devices = we block #3) and false-positives no one on
  IP change; a determined attacker faking one identical device-id across many phones is the only gap, and the
  ONLY cryptographically absolute fix is a native app with hardware attestation (DeviceCheck / Play Integrity),
  out of scope for a website. Operator's verdict: "as good as we can get it" — build it.
- **Supersedes** the earlier "strict device-bound / reject synced" and "device identity = WebAuthn credential"
  lines above where they conflict: enrollment now ACCEPTS synced credentials, and the device LOCK is our
  device-id allowlist + concurrent cap, with the WebAuthn credential providing phishing-resistant login and
  admin-revocable recovery (server still stores each credential's public key + id for revoke/reset).