'use strict';
// Smoke test: proves the EXTRACTED package works standalone (no Pulse, no secrets).
// Exercises the stable surface: token mint/verify, PoW mint/solve/verify, and the VM sensor
// (self-computed baseline, O(1) verify, tamper reject). Exit non-zero on any failure.
const assert = require('assert');
let pass = 0;
const ok = (name, cond) => { assert(cond, name); console.log('  ok  ' + name); pass++; };

// ---- core: token + PoW ----
const apiguard = require('../core.js');
const guard = apiguard({ secret: 'x'.repeat(32), protect: '/api/' });

const tok = guard.mint.token({ path: '/api/x', fingerprint: 'fp1' });
ok('token mints', typeof tok === 'string' && tok.split('.').length === 3);
ok('token verifies (bound path+fp)', guard.verifyToken(tok, { path: '/api/x', fingerprint: 'fp1' }).status === 'ok');
ok('token rejects wrong path', guard.verifyToken(tok, { path: '/api/other', fingerprint: 'fp1' }).status === 'bad_sig');

const ch = guard.mint.challenge(12);
const counter = guard.solvePow(ch.salt, ch.bits);
const pv = guard.verifyPow({ salt: ch.salt, bits: ch.bits, expiry: ch.expiry, sig: ch.sig, counter });
ok('PoW solves + verifies', pv.ok === true);
ok('PoW rejects wrong counter', guard.verifyPow({ salt: ch.salt, bits: ch.bits, expiry: ch.expiry, sig: ch.sig, counter: counter + 1 }).ok === false);

// ---- vm sensor: baseline + verify + tamper ----
const S = require('../vmsensor.js');
const info = S.init('20260101', 16, 'deploy-secret');
ok('vmsensor inits a pool', info && info.N === 16);
const idx = S.indexFor('user@example');
ok('assigns a VM index', idx >= 0 && idx < 16 && !!S.asset(idx));
const inputs = S.inputsFor('nonceABC', 3);
const vt = S.expected(idx, inputs);
ok('VM token verifies (self-computed baseline)', S.verify(idx, inputs, vt) === true);
ok('tampered VM token REJECTED', S.verify(idx, inputs, (vt ^ 0x5a5a5a5a) >>> 0) === false);
ok('forged counter REJECTED', S.verify(idx, S.inputsFor('nonceABC', 9), vt) === false);

console.log('\nSMOKE PASS — ' + pass + ' assertions, extracted package runs standalone.');
