// Unit test: HMAC-SHA256 thuần JS (cho n8n Code node - sandbox chặn require('crypto'))
// Chạy bằng: node sha256_hmac_test.js
'use strict';
const crypto = require('crypto');

// ===== Bộ cài đặt SHA-256 + HMAC thuần JavaScript =====
function utf8Bytes(str) {
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    else if (c >= 0xd800 && c <= 0xdbff) {
      const c2 = str.charCodeAt(++i);
      c = 0x10000 + ((c & 0x3ff) << 10) + (c2 & 0x3ff);
      out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 0x3f), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    } else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
  }
  return Uint8Array.from(out);
}

const K = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
];
function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
function sha256Bytes(msgBytes) {
  const len = msgBytes.length;
  const bitLen = len * 8;
  const data = new Uint8Array((((len + 8) >> 6) + 1) * 64);
  data.set(msgBytes);
  data[len] = 0x80;
  const dv = new DataView(data.buffer);
  dv.setUint32(data.length - 4, bitLen >>> 0, false);
  dv.setUint32(data.length - 8, Math.floor(bitLen / 0x100000000), false);
  const H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  const w = new Uint32Array(64);
  const dv2 = new DataView(data.buffer);
  for (let off = 0; off < data.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv2.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >>> 3);
      const s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
    }
    let [a,b,c,d,e,f,g,h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  H.forEach((v, i) => odv.setUint32(i * 4, v, false));
  return out;
}
function bytesToHex(b) { return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join(''); }
function hmacSha256Hex(keyStr, msgStr) {
  let key = utf8Bytes(keyStr);
  if (key.length > 64) key = sha256Bytes(key);
  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    const kb = i < key.length ? key[i] : 0;
    ipad[i] = kb ^ 0x36;
    opad[i] = kb ^ 0x5c;
  }
  const innerHash = sha256Bytes(Uint8Array.from([...ipad, ...utf8Bytes(msgStr)]));
  return bytesToHex(sha256Bytes(Uint8Array.from([...opad, ...innerHash])));
}

// ===== Tests =====
let pass = 0, fail = 0;
function check(name, got, want) {
  const ok = got === want;
  if (ok) pass++; else fail++;
  console.log((ok ? 'PASS' : 'FAIL') + '  ' + name + (ok ? '' : `\n  got:  ${got}\n  want: ${want}`));
}

check('sha256("")', bytesToHex(sha256Bytes(utf8Bytes(''))),
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
check('sha256("abc")', bytesToHex(sha256Bytes(utf8Bytes('abc'))),
  'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
check('sha256 utf8 vietnamese', bytesToHex(sha256Bytes(utf8Bytes('Đánh giá tốt'))),
  bytesToHex(crypto.createHash('sha256').update('Đánh giá tốt', 'utf8').digest()));

check('hmac rfc4231#2 (Jefe)', hmacSha256Hex('Jefe', 'what do ya want for nothing?'),
  '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');

check('hmac normal key', hmacSha256Hex('key', 'The quick brown fox jumps over the lazy dog'),
  crypto.createHmac('sha256', 'key').update('The quick brown fox jumps over the lazy dog').digest('hex'));

const partnerId = '80001', path = '/api/v2/product/get_comment', ts = '1700000000', token = 'abc123token', shopId = '130860061';
const baseStr = partnerId + path + ts + token + shopId;
check('hmac shopee base string', hmacSha256Hex('partnerkey_secret', baseStr),
  crypto.createHmac('sha256', 'partnerkey_secret').update(baseStr).digest('hex'));

const longKey = 'k'.repeat(100);
check('hmac long key (>64B)', hmacSha256Hex(longKey, 'msg'),
  crypto.createHmac('sha256', longKey).update('msg').digest('hex'));

check('TextEncoder available', typeof TextEncoder, 'function');

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

