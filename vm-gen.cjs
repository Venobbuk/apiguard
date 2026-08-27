#!/usr/bin/env node
'use strict';
// PER-SESSION POLYMORPHIC VM GENERATOR — production copy for the Pulse VM sensor.
// P2 ADDED: the bytecode ships ENCRYPTED (per-VM keystream) and the dispatch DECRYPTS each byte ON DEMAND
// via _dec(q) — no full plaintext-opcode array ever exists in memory (read-once). expected() is UNCHANGED
// (it replays the PROGRAM, never the bytecode), so encryption is transparent to server verify. To recover
// the program an attacker must instrument _dec -> that shifts the dispatch source -> the P1 integrity fold
// mismatches -> wrong token. Encryption + fold compose.
const crypto = require('crypto');

function rng(seedHex) {
  let s = BigInt('0x' + seedHex.slice(0, 16));
  return () => { s = (s * 6364136223846793005n + 1442695040888963407n) & 0xffffffffffffffffn; return Number((s >> 17n) & 0xffffffffn) >>> 0; };
}
function shuffle(arr, rnd) { for (let i = arr.length - 1; i > 0; i--) { const j = rnd() % (i + 1); [arr[i], arr[j]] = [arr[j], arr[i]]; } return arr; }
// per-byte keystream — IDENTICAL on the generator (encrypt) and the emitted VM (_ks/_dec).
function ks(q, key) { return (Math.imul((q + 1) >>> 0, key >>> 0) >>> 11) & 255; }

const OPS = ['LOADIN', 'PUSHIMM', 'XOR', 'ADDMUL', 'ROTL', 'FOLD_INTEGRITY', 'OUT'];

function generate(sessionSeed, program) {
  const rnd = rng(sessionSeed);
  const idsPool = shuffle([...Array(256).keys()], rnd);
  let cur = 0; const opToIds = {}, idToOp = {};
  for (const op of OPS) { const n = op === 'OUT' ? 1 : 1 + (rnd() % 3); opToIds[op] = []; for (let k = 0; k < n; k++) { const id = idsPool[cur++]; opToIds[op].push(id); idToOp[id] = op; } }
  const decoys = []; for (let k = 0; k < 4; k++) { const id = idsPool[cur++]; decoys.push(id); }
  const REGN = 8; const regMap = shuffle([...Array(REGN).keys()], rnd);

  const pickId = op => opToIds[op][rnd() % opToIds[op].length];
  const bc = [];
  for (const ins of program) {
    bc.push(pickId(ins.op));
    if (ins.op === 'LOADIN') { bc.push(ins.in & 255, regMap[ins.r] & 255); }
    else if (ins.op === 'PUSHIMM') { bc.push(regMap[ins.r] & 255, ins.v & 255, (ins.v >> 8) & 255); }
    else if (ins.op === 'XOR' || ins.op === 'ADDMUL' || ins.op === 'ROTL') { bc.push(regMap[ins.a] & 255, regMap[ins.b] & 255); }
    else if (ins.op === 'FOLD_INTEGRITY') { bc.push(regMap[ins.r] & 255); }
    else if (ins.op === 'OUT') { bc.push(regMap[ins.r] & 255); }
  }
  // P2: encrypt the bytecode with a per-VM key; the VM decrypts each byte on demand.
  const KEY = rnd() >>> 0;
  const cipher = bc.map((b, i) => (b ^ ks(i, KEY)) & 255);

  // dispatch reads every byte through _dec(q) (read-once) instead of bc[q].
  const caseFor = op => {
    if (op === 'LOADIN')  return `R[_dec(p+2)]=IN[_dec(p+1)]|0;p+=3;`;
    if (op === 'PUSHIMM') return `R[_dec(p+1)]=(_dec(p+2)|(_dec(p+3)<<8))|0;p+=4;`;
    if (op === 'XOR')     return `R[_dec(p+1)]=(R[_dec(p+1)]^R[_dec(p+2)])|0;p+=3;`;
    if (op === 'ADDMUL')  return `R[_dec(p+1)]=Math.imul((R[_dec(p+1)]+R[_dec(p+2)])|0,2654435761)|0;p+=3;`;
    if (op === 'ROTL')    return `{var _x=R[_dec(p+1)]|0,_n=R[_dec(p+2)]&31;R[_dec(p+1)]=((_x<<_n)|(_x>>>(32-_n)))|0;}p+=3;`;
    if (op === 'FOLD_INTEGRITY') return `R[_dec(p+1)]=(R[_dec(p+1)]^SEED)|0;p+=2;`;
    if (op === 'OUT')     return `OUT=R[_dec(p+1)]|0;p+=2;`;
  };
  const cases = [];
  for (const op of OPS) for (const id of opToIds[op]) cases.push(`case ${id}:${caseFor(op)}break;`);
  for (const id of decoys) cases.push(`case ${id}:{var _q=(p*2654435761)|0;R[_q&7]=(R[_q&7]+_q)|0;}p+=2;break;`);
  shuffle(cases, rnd);

  const src =
`(function(bc,IN,integrityOf){
  var R=new Int32Array(${REGN});
  var SELF=integrityOf();
  var SEED=SELF|0;
  var KEY=${KEY};
  var _ks=function(q){return (Math.imul((q+1)>>>0,KEY>>>0)>>>11)&255;};
  var _dec=function(q){return (bc[q]^_ks(q))&255;};   // decrypt ONE byte on demand (read-once)
  var p=0,OUT=0,GUARD=0;
  while(p<bc.length){
    if(++GUARD>100000)break;
    switch(_dec(p)){
${cases.join('\n')}
      default:p++;
    }
  }
  return OUT>>>0;
})`;

  // server reference: replays the PROGRAM (never the bytecode) -> unaffected by encryption.
  function expected(IN, integritySeed) {
    const R = new Int32Array(REGN); let OUT = 0;
    for (const ins of program) {
      if (ins.op === 'LOADIN') R[regMap[ins.r]] = IN[ins.in] | 0;
      else if (ins.op === 'PUSHIMM') R[regMap[ins.r]] = ins.v | 0;
      else if (ins.op === 'XOR') R[regMap[ins.a]] = (R[regMap[ins.a]] ^ R[regMap[ins.b]]) | 0;
      else if (ins.op === 'ADDMUL') R[regMap[ins.a]] = Math.imul((R[regMap[ins.a]] + R[regMap[ins.b]]) | 0, 2654435761) | 0;
      else if (ins.op === 'ROTL') { const x = R[regMap[ins.a]] | 0, n = R[regMap[ins.b]] & 31; R[regMap[ins.a]] = ((x << n) | (x >>> (32 - n))) | 0; }
      else if (ins.op === 'FOLD_INTEGRITY') R[regMap[ins.r]] = (R[regMap[ins.r]] ^ integritySeed) | 0;
      else if (ins.op === 'OUT') OUT = R[regMap[ins.r]] | 0;
    }
    return OUT >>> 0;
  }
  return { src, bc: Uint8Array.from(cipher), expected, meta: { opAliases: Object.fromEntries(OPS.map(o => [o, opToIds[o].length])), decoys: decoys.length, regs: REGN, enc: true } };
}

function makeIntegrityOf(vmFn) {
  return function () { const h = crypto.createHash('sha256').update(vmFn.toString()).digest(); return h.readInt32BE(0); };
}
module.exports = { generate, makeIntegrityOf };
