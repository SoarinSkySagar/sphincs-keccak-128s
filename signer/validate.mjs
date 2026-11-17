// Cross-checks slh.mjs (backend "shake") against @noble/post-quantum's
// SLH-DSA-SHAKE-128s internal interface, byte for byte.
import { slh_dsa_shake_128s as ref } from "@noble/post-quantum/slh-dsa.js";
import { slh } from "./slh.mjs";

const mine = slh("shake");
const hex = (b) => Buffer.from(b).toString("hex");
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
let fail = 0;
const check = (name, ok) => { console.log(`${ok ? "PASS" : "FAIL"}  ${name}`); if (!ok) fail++; };

for (let t = 0; t < 2; t++) {
  const seed = new Uint8Array(48).map((_, i) => (i * 7 + t * 31 + 1) & 0xff);
  const M = new Uint8Array(32).map((_, i) => (i * 13 + t) & 0xff);

  const r = ref.internal.keygen(seed);
  let t0 = Date.now();
  const k = mine.keygen(seed);
  check(`[${t}] keygen public key matches (${Date.now() - t0} ms)`, eq(k.publicKey, r.publicKey));
  check(`[${t}] keygen secret key matches`, eq(k.secretKey, r.secretKey));

  const rs = ref.internal.sign(M, r.secretKey, { extraEntropy: false });
  mine.hash.reset(); t0 = Date.now();
  const s = mine.sign(M, k.secretKey);
  console.log(`      sign: ${mine.hash.calls} hash calls, ${Date.now() - t0} ms`);
  check(`[${t}] deterministic signature matches (${s.length} bytes)`, eq(s, rs));

  mine.hash.reset();
  check(`[${t}] my verify accepts reference signature`, mine.verify(M, rs, r.publicKey));
  console.log(`      verify: ${mine.hash.calls} hash calls`);
  check(`[${t}] reference verify accepts my signature`, ref.internal.verify(s, M, k.publicKey));

  const rnd = new Uint8Array(16).fill(0xab);
  const s2 = mine.sign(M, k.secretKey, rnd);
  check(`[${t}] randomized signature verifies in reference`, ref.internal.verify(s2, M, k.publicKey));

  const bad = s.slice(); bad[5000] ^= 1;
  check(`[${t}] tampered signature rejected`, !mine.verify(M, bad, k.publicKey));
  const M2 = M.slice(); M2[0] ^= 1;
  check(`[${t}] wrong message rejected`, !mine.verify(M2, s, k.publicKey));
}
console.log(fail ? `\n${fail} FAILED` : "\nall checks passed");
process.exit(fail ? 1 : 0);
