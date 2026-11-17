// Writes SPHINCS+-128s-keccak256 test vectors for the Solidity verifier.
//   node signer/gen-vectors.mjs <out.json> [count]
import { writeFileSync } from "node:fs";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { slh } from "./slh.mjs";

const out = process.argv[2] ?? "vectors.json";
const count = Number(process.argv[3] ?? 2);
const s = slh("keccak256");
const hex = (b) => "0x" + Buffer.from(b).toString("hex");
const vectors = [];
for (let t = 0; t < count; t++) {
  const seed = keccak_256(new TextEncoder().encode(`pq-wallet test key ${t}`)).slice(0, 32);
  const seed48 = new Uint8Array(48); seed48.set(seed); seed48.set(keccak_256(seed).slice(0, 16), 32);
  const { publicKey, secretKey } = s.keygen(seed48);
  const msg = keccak_256(new TextEncoder().encode(`pq-wallet test message ${t}`));
  s.hash.reset();
  const sig = s.sign(msg, secretKey, keccak_256(msg).slice(0, 16));
  const signCalls = s.hash.calls;
  if (!s.verify(msg, sig, publicKey)) throw new Error("self-verify failed");
  s.hash.reset(); s.verify(msg, sig, publicKey);
  vectors.push({ pk: hex(publicKey), msg: hex(msg), sig: hex(sig), signHashCalls: signCalls, verifyHashCalls: s.hash.calls });
  console.log(`vector ${t}: pk ${hex(publicKey)} sig ${sig.length} bytes, verify ${s.hash.calls} hashes`);
}
writeFileSync(out, JSON.stringify({ scheme: "SPHINCS+-128s-keccak256 (FIPS 205 simple, SHAKE256 -> keccak256 truncated)", vectors }, null, 2));
