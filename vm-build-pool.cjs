#!/usr/bin/env node
'use strict';
// P4 coat + pool model: pre-build an OBFUSCATED VM pool to disk (apiguard/vmpool/<version>/) + manifest of
// integrity baselines. Obfuscate the WHOLE assignment program as ONE unit (concatenating onto an obf
// fragment produces invalid JS), and ASSERT each obf VM is CALLABLE + TRANSPARENT before writing (fail
// loudly — a broken coat must never ship silently). Server (vmsensor.init) just loads+serves+verifies.
// Run: node apiguard/vm-build-pool.cjs [version=YYYYMMDD] [N=256]
const O = require('javascript-obfuscator');
const { generate } = require('./vm-gen.cjs');
const S = require('./vmsensor.js');
const fs = require('fs'), path = require('path');

const OBF = {
  compact: true, controlFlowFlattening: true, controlFlowFlatteningThreshold: 0.75,
  stringArray: true, stringArrayEncoding: ['base64'], stringArrayThreshold: 1,
  numbersToExpressions: true, simplify: true, identifierNamesGenerator: 'mangled-shuffled',
  reservedStrings: ['__ag_vm', '__ag_bc', '__ag_vi'],   // keep the global hook names intact
};
const IN = [0x1234, 7, 0x55];   // probe inputs for the transparency assertion

const version = process.argv[2] || new Date().toISOString().slice(0, 10).replace(/-/g, '');
const N = parseInt(process.argv[3] || '256', 10);
const dir = path.join(__dirname, 'vmpool', version);
fs.mkdirSync(dir, { recursive: true });

const baselines = new Array(N);
const t = Date.now();
for (let i = 0; i < N; i++){
  const g = generate(S.seedOf(version, i), S.PROGRAM);
  const plain = 'window.__ag_vm=' + g.src + ';window.__ag_bc=[' + Array.from(g.bc).join(',') + '];window.__ag_vi=' + i + ';';
  const obf = O.obfuscate(plain, OBF).getObfuscatedCode();
  // eval under a window shim -> set the globals -> compute baseline + ASSERT the obf VM is callable & transparent
  global.window = {};
  (0, eval)(obf);
  const fn = global.window.__ag_vm;
  if (typeof fn !== 'function') throw new Error('vm ' + i + ': __ag_vm not a function after obfuscation');
  const base = S.fnv(String(fn) + S.NATIVE) >>> 0;
  const got = fn(global.window.__ag_bc, IN, function () { return base; }) >>> 0;
  const exp = g.expected(IN, base) >>> 0;
  if (got !== exp) throw new Error('vm ' + i + ': obf NOT transparent (' + got + ' != ' + exp + ')');
  baselines[i] = base;
  fs.writeFileSync(path.join(dir, 'vm-' + i + '.js'), obf);
  if (i % 50 === 0) process.stdout.write('.');
}
delete global.window;
fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify({ version, N, baselines, built: Date.now() }));
const sample = fs.readFileSync(path.join(dir, 'vm-0.js'), 'utf8');
console.log('\nbuilt OBFUSCATED pool v' + version + ' N=' + N + ' in ' + ((Date.now() - t) / 1000).toFixed(1) + 's (all ' + N + ' asserted callable+transparent)');
console.log('vm-0 size ' + sample.length + 'B; raw `case N:` visible? ' + /case [0-9]+:/.test(sample) + ' (false=opaque)');
