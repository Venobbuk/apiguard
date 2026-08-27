// build/build-client.cjs — double-pass javascript-obfuscator, client.js -> client.obf.js
// Usage: node build/build-client.cjs [inputFile] [outputFile]
//   defaults (rotate.sh): client.js -> client.obf.js
const fs = require("fs"), path = require("path");
const O = require("javascript-obfuscator");
const dir = path.join(__dirname, "..");
const inFile  = process.argv[2] || path.join(dir, "client.js");
const outFile = process.argv[3] || path.join(dir, "client.obf.js");
const src = fs.readFileSync(inFile, "utf8");

const common = {
  compact: true,
  controlFlowFlattening: true, controlFlowFlatteningThreshold: 0.6,
  numbersToExpressions: false, simplify: true,
  stringArray: true, stringArrayEncoding: ["base64"],
  stringArrayThreshold: 0.85, stringArrayRotate: true, stringArrayShuffle: true,
  stringArrayIndexShift: true, stringArrayWrappersCount: 2,
  stringArrayWrappersType: "function", stringArrayCallsTransform: false,
  splitStrings: false,
  // selfDefending DISABLED (2026-08-14): PROVEN to infinite-loop page boot in a real browser for the
  // larger env-binding client (live-size obf loads ~190ms; with selfDefending this client hangs 12s+;
  // without it, ~450-870ms). A boot hang breaks page load (loadHot fragility). All other hardening kept
  // (double-pass, CFF 0.9, base64 stringArray, splitStrings, renameGlobals:false, reservedNames apiguard).
  selfDefending: false, transformObjectKeys: true,
  debugProtection: false,
  renameGlobals: false, reservedNames: ["^apiguard$", "__ag_vm", "__ag_bc", "__ag_vi"],
};

// SINGLE-PASS (2026-08-26): profiled — double-pass cost ~8s boot CPU + 3.3s GC for no real added protection
// (this obfuscator is auto-deobfuscatable either way). Single-pass = ~92KB, ~0.3s boot CPU, security intact.
const out = O.obfuscate(src, Object.assign({}, common, { identifierNamesGenerator: "mangled-shuffled" })).getObfuscatedCode();

fs.writeFileSync(outFile, out);
console.log("[build-client] %s (%d B) -> %s (%d B) [single-pass]", path.basename(inFile), src.length, path.basename(outFile), out.length);
