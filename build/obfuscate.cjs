// Build the blackbox: obfuscate client.js -> client.obf.js. Safe now that PoW is in WASM (no
// Function.toString() worker hack). debugProtection intentionally OFF (it freezes on devtools and
// would block headless verification / annoy legit users); enable per-site later if wanted.
const fs = require('fs'), path = require('path');
const O = require('javascript-obfuscator');
const src = fs.readFileSync(path.join(__dirname, '..', 'client.js'), 'utf8');
const res = O.obfuscate(src, {
  compact: true,
  controlFlowFlattening: true, controlFlowFlatteningThreshold: 0.75,
  deadCodeInjection: true, deadCodeInjectionThreshold: 0.4,
  identifierNamesGenerator: 'hexadecimal',
  numbersToExpressions: true, simplify: true,
  stringArray: true, stringArrayRotate: true, stringArrayShuffle: true,
  stringArrayThreshold: 0.9, stringArrayEncoding: ['base64'],
  stringArrayWrappersCount: 2, stringArrayWrappersType: 'function',
  selfDefending: true, transformObjectKeys: true,
  splitStrings: true, splitStringsChunkLength: 6,
});
const out = res.getObfuscatedCode();
fs.writeFileSync(path.join(__dirname, '..', 'client.obf.js'), out);
console.log('client.js -> client.obf.js  (' + src.length + ' -> ' + out.length + ' bytes)');
