// apiguard v2 — PoW VM (AssemblyScript -> WASM).
// SHA-256 + hashcash solver, compiled to WebAssembly so the token/PoW core is far harder to reverse than
// JS and needs no fragile Function.toString() worker hack. Byte-identical to Node/browser SHA-256.
//
// Memory layout (linear memory, exported): JS writes the salt ASCII at offset 0 (saltLen bytes).
// solve() appends the counter's decimal digits, hashes salt||counter, returns the first counter whose
// digest has >= `bits` leading zero bits, or -1 if none within maxCounter.

// round constants
const K: StaticArray<u32> = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
];

// Fixed scratch offsets placed HIGH (16 KB+) so they never collide with AssemblyScript's own static
// data (the K array, etc.) which lives low and grows up. One 64 KB page holds all of this.
const SALT: usize  = 16384;  // JS writes salt ASCII here
const MSG: usize   = 16448;  // salt||counter assembled here (< 64 bytes for our inputs)
const HASH: usize  = 16512;  // 32-byte digest
const W: usize     = 16576;  // 64 * u32 schedule (256 bytes)

// @inline
function rotr(x: u32, n: u32): u32 { return (x >> n) | (x << (32 - n)); }

// SHA-256 over `len` bytes at `inPtr`; writes 32 big-endian bytes to HASH.
function sha256(inPtr: usize, len: i32): void {
  let h0: u32 = 0x6a09e667, h1: u32 = 0xbb67ae85, h2: u32 = 0x3c6ef372, h3: u32 = 0xa54ff53a;
  let h4: u32 = 0x510e527f, h5: u32 = 0x9b05688c, h6: u32 = 0x1f83d9ab, h7: u32 = 0x5be0cd19;

  // padded length
  const bitLen: u64 = (<u64>len) * 8;
  let total = len + 1;
  while ((total & 63) != 56) total++;
  total += 8;

  // our inputs are short (<56 bytes) so exactly ONE 64-byte block. Assemble it at a pad buffer.
  const PAD: usize = 16960;
  for (let i = 0; i < total; i++) store<u8>(PAD + i, 0);
  memory.copy(PAD, inPtr, len);
  store<u8>(PAD + len, 0x80);
  // 64-bit big-endian bit length in the last 8 bytes
  for (let i = 0; i < 8; i++) {
    store<u8>(PAD + total - 1 - i, <u8>((bitLen >> (<u64>(8 * i))) & 0xff));
  }

  for (let off = 0; off < total; off += 64) {
    for (let t = 0; t < 16; t++) {
      const b = PAD + off + 4 * t;
      store<u32>(W + 4 * t,
        (<u32>load<u8>(b) << 24) | (<u32>load<u8>(b + 1) << 16) | (<u32>load<u8>(b + 2) << 8) | (<u32>load<u8>(b + 3)));
    }
    for (let t = 16; t < 64; t++) {
      const w15 = load<u32>(W + 4 * (t - 15));
      const w2 = load<u32>(W + 4 * (t - 2));
      const s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >> 3);
      const s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >> 10);
      store<u32>(W + 4 * t, load<u32>(W + 4 * (t - 16)) + s0 + load<u32>(W + 4 * (t - 7)) + s1);
    }
    let a = h0, b2 = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ ((~e) & g);
      const t1 = h + S1 + ch + K[t] + load<u32>(W + 4 * t);
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b2) ^ (a & c) ^ (b2 & c);
      const t2 = S0 + maj;
      h = g; g = f; f = e; e = d + t1; d = c; c = b2; b2 = a; a = t1 + t2;
    }
    h0 += a; h1 += b2; h2 += c; h3 += d; h4 += e; h5 += f; h6 += g; h7 += h;
  }

  // write digest big-endian, directly from the eight working words (no runtime allocation)
  storeBE(HASH + 0, h0); storeBE(HASH + 4, h1); storeBE(HASH + 8, h2); storeBE(HASH + 12, h3);
  storeBE(HASH + 16, h4); storeBE(HASH + 20, h5); storeBE(HASH + 24, h6); storeBE(HASH + 28, h7);
}
// @inline
function storeBE(p: usize, v: u32): void {
  store<u8>(p, <u8>(v >> 24)); store<u8>(p + 1, <u8>(v >> 16)); store<u8>(p + 2, <u8>(v >> 8)); store<u8>(p + 3, <u8>v);
}

function leadingZeroBits(): i32 {
  let bits = 0;
  for (let i = 0; i < 32; i++) {
    const byte = load<u8>(HASH + i);
    if (byte == 0) { bits += 8; continue; }
    let m: u8 = 0x80, add = 0;
    while (m != 0 && (byte & m) == 0) { add++; m = m >> 1; }
    bits += add; break;
  }
  return bits;
}

// write decimal ASCII of c at ptr, return number of digits
function itoa(c: i32, ptr: usize): i32 {
  if (c == 0) { store<u8>(ptr, 48); return 1; }
  let n = c, len = 0, t = c;
  while (t > 0) { len++; t = t / 10; }
  let i = len - 1;
  while (n > 0) { store<u8>(ptr + i, <u8>(48 + (n % 10))); n = n / 10; i--; }
  return len;
}

// exported: JS writes salt ASCII to SALT (via saltPtr()), passes its length + difficulty bits + a cap.
export function saltPtr(): usize { return SALT; }
export function solve(saltLen: i32, bits: i32, maxCounter: i32): i32 {
  for (let c = 0; c < maxCounter; c++) {
    memory.copy(MSG, SALT, saltLen);
    const dl = itoa(c, MSG + saltLen);
    sha256(MSG, saltLen + dl);
    if (leadingZeroBits() >= bits) return c;
  }
  return -1;
}
// verify a single (salt,counter) -> leading zero bits, for parity testing
export function hashBits(saltLen: i32, counter: i32): i32 {
  memory.copy(MSG, SALT, saltLen);
  const dl = itoa(counter, MSG + saltLen);
  sha256(MSG, saltLen + dl);
  return leadingZeroBits();
}
