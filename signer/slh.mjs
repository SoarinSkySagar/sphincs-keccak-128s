// SLH-DSA / SPHINCS+ "simple" construction (FIPS 205 algorithms, uncompressed ADRS),
// parameter set 128s, with a pluggable hash backend.
//
//   backend "shake"     = FIPS 205 SLH-DSA-SHAKE-128s (validated against @noble/post-quantum)
//   backend "keccak256" = the EVM-friendly variant: every SHAKE256(x, 8*len) call is
//                         replaced by keccak256(x)[0:len] (len <= 32), so on-chain
//                         verification uses the KECCAK256 opcode and the Baochip-1x
//                         SHA-3 engine can compute it with software padding.
//
// Internal interface only (FIPS 205 slh_*_internal): the message is signed as-is.
// For the wallet, M = the 32-byte EIP-8141 sig hash.
import { shake256, keccak_256 } from "@noble/hashes/sha3.js";

export const P128S = { n: 16, h: 63, d: 7, hp: 9, a: 12, k: 14, lgw: 4, m: 30 };
const W = 1 << P128S.lgw; // 16
const LEN1 = (8 * P128S.n) / P128S.lgw; // 32
const LEN2 = 3; // floor(log2(LEN1 * (W-1)) / lgw) + 1
const LEN = LEN1 + LEN2; // 35

// ADRS types
const WOTS_HASH = 0, WOTS_PK = 1, TREE = 2, FORS_TREE = 3, FORS_ROOTS = 4, WOTS_PRF = 5, FORS_PRF = 6;

const concat = (...a) => {
  const out = new Uint8Array(a.reduce((s, x) => s + x.length, 0));
  let o = 0;
  for (const x of a) { out.set(x, o); o += x.length; }
  return out;
};

export function makeHash(backend) {
  const raw =
    backend === "shake" ? (x, len) => shake256(x, { dkLen: len })
    : backend === "keccak256" ? (x, len) => { if (len > 32) throw new Error("len>32"); return keccak_256(x).slice(0, len); }
    : null;
  if (!raw) throw new Error(`unknown backend ${backend}`);
  const { n, m } = P128S;
  let calls = 0;
  return {
    get calls() { return calls; },
    reset() { calls = 0; },
    T: (pkSeed, adrs, msg) => { calls++; return raw(concat(pkSeed, adrs.bytes(), msg), n); }, // F, H, T_l
    PRF: (pkSeed, skSeed, adrs) => { calls++; return raw(concat(pkSeed, adrs.bytes(), skSeed), n); },
    PRFmsg: (skPrf, optRand, M) => { calls++; return raw(concat(skPrf, optRand, M), n); },
    Hmsg: (R, pkSeed, pkRoot, M) => { calls++; return raw(concat(R, pkSeed, pkRoot, M), m); },
  };
}

class Adrs {
  constructor() { this.b = new Uint8Array(32); }
  copy() { const a = new Adrs(); a.b.set(this.b); return a; }
  bytes() { return this.b; }
  #set32(off, v) { new DataView(this.b.buffer).setUint32(off, v >>> 0); }
  #get32(off) { return new DataView(this.b.buffer).getUint32(off); }
  setLayer(l) { this.#set32(0, l); }
  setTree(t) { // 12 bytes, big-endian; t is a BigInt < 2^64
    this.b.fill(0, 4, 16);
    new DataView(this.b.buffer).setBigUint64(8, BigInt.asUintN(64, t));
  }
  setTypeAndClear(t) { this.#set32(16, t); this.b.fill(0, 20, 32); }
  setKeyPair(i) { this.#set32(20, i); }
  getKeyPair() { return this.#get32(20); }
  setChain(i) { this.#set32(24, i); }
  setTreeHeight(z) { this.#set32(24, z); }
  setHash(i) { this.#set32(28, i); }
  setTreeIndex(i) { this.#set32(28, i); }
  getTreeIndex() { return this.#get32(28); }
}

// base_2b(X, b, out_len): big-endian bit stream split into b-bit integers
function base2b(X, b, outLen) {
  const out = []; let inp = 0, bits = 0, total = 0;
  for (let o = 0; o < outLen; o++) {
    while (bits < b) { total = (total << 8) | X[inp++]; bits += 8; }
    bits -= b;
    out.push((total >>> bits) & ((1 << b) - 1));
    total &= (1 << bits) - 1; // keep only unconsumed bits (b <= 12, so this stays small)
  }
  return out;
}
const toInt = (X) => X.reduce((acc, x) => (acc << 8n) | BigInt(x), 0n);

export function slh(backend, p = P128S) {
  const H = makeHash(backend);
  const { n, d, hp, a, k, lgw } = p;
  const mdLen = Math.ceil((k * a) / 8);           // 21
  const treeLen = Math.ceil((p.h - hp) / 8);      // 7
  const leafLen = Math.ceil(hp / 8);              // 2

  const chain = (X, i, s, pkSeed, adrs) => {
    let tmp = X;
    for (let j = i; j < i + s; j++) { adrs.setHash(j); tmp = H.T(pkSeed, adrs, tmp); }
    return tmp;
  };
  const wotsMsg = (M) => {
    const msg = base2b(M, lgw, LEN1);
    let csum = 0; for (const x of msg) csum += W - 1 - x;
    csum <<= (8 - ((LEN2 * lgw) % 8)) % 8;
    const cb = new Uint8Array(Math.ceil((LEN2 * lgw) / 8));
    for (let i = cb.length - 1, c = csum; i >= 0; i--, c >>>= 8) cb[i] = c & 0xff;
    return msg.concat(base2b(cb, lgw, LEN2));
  };
  const wotsPkGen = (skSeed, pkSeed, adrs) => {
    const skA = adrs.copy(); skA.setTypeAndClear(WOTS_PRF); skA.setKeyPair(adrs.getKeyPair());
    const tmp = [];
    for (let i = 0; i < LEN; i++) {
      skA.setChain(i); const sk = H.PRF(pkSeed, skSeed, skA);
      adrs.setChain(i); tmp.push(chain(sk, 0, W - 1, pkSeed, adrs));
    }
    const pkA = adrs.copy(); pkA.setTypeAndClear(WOTS_PK); pkA.setKeyPair(adrs.getKeyPair());
    return H.T(pkSeed, pkA, concat(...tmp));
  };
  const wotsSign = (M, skSeed, pkSeed, adrs) => {
    const msg = wotsMsg(M);
    const skA = adrs.copy(); skA.setTypeAndClear(WOTS_PRF); skA.setKeyPair(adrs.getKeyPair());
    const sig = [];
    for (let i = 0; i < LEN; i++) {
      skA.setChain(i); const sk = H.PRF(pkSeed, skSeed, skA);
      adrs.setChain(i); sig.push(chain(sk, 0, msg[i], pkSeed, adrs));
    }
    return concat(...sig);
  };
  const wotsPkFromSig = (sig, M, pkSeed, adrs) => {
    const msg = wotsMsg(M); const tmp = [];
    for (let i = 0; i < LEN; i++) {
      adrs.setChain(i);
      tmp.push(chain(sig.subarray(i * n, (i + 1) * n), msg[i], W - 1 - msg[i], pkSeed, adrs));
    }
    const pkA = adrs.copy(); pkA.setTypeAndClear(WOTS_PK); pkA.setKeyPair(adrs.getKeyPair());
    return H.T(pkSeed, pkA, concat(...tmp));
  };
  const xmssNode = (skSeed, i, z, pkSeed, adrs) => {
    if (z === 0) {
      adrs.setTypeAndClear(WOTS_HASH); adrs.setKeyPair(i);
      return wotsPkGen(skSeed, pkSeed, adrs);
    }
    const l = xmssNode(skSeed, 2 * i, z - 1, pkSeed, adrs);
    const r = xmssNode(skSeed, 2 * i + 1, z - 1, pkSeed, adrs);
    adrs.setTypeAndClear(TREE); adrs.setTreeHeight(z); adrs.setTreeIndex(i);
    return H.T(pkSeed, adrs, concat(l, r));
  };
  const xmssSign = (M, skSeed, idx, pkSeed, adrs) => {
    const auth = [];
    for (let j = 0; j < hp; j++) auth.push(xmssNode(skSeed, (idx >>> j) ^ 1, j, pkSeed, adrs));
    adrs.setTypeAndClear(WOTS_HASH); adrs.setKeyPair(idx);
    return concat(wotsSign(M, skSeed, pkSeed, adrs), ...auth);
  };
  const xmssPkFromSig = (idx, sig, M, pkSeed, adrs) => {
    adrs.setTypeAndClear(WOTS_HASH); adrs.setKeyPair(idx);
    let node = wotsPkFromSig(sig.subarray(0, LEN * n), M, pkSeed, adrs);
    const auth = sig.subarray(LEN * n);
    adrs.setTypeAndClear(TREE); adrs.setTreeIndex(idx);
    for (let kk = 0; kk < hp; kk++) {
      adrs.setTreeHeight(kk + 1);
      const ak = auth.subarray(kk * n, (kk + 1) * n);
      if (((idx >>> kk) & 1) === 0) { adrs.setTreeIndex(adrs.getTreeIndex() >>> 1); node = H.T(pkSeed, adrs, concat(node, ak)); }
      else { adrs.setTreeIndex((adrs.getTreeIndex() - 1) >>> 1); node = H.T(pkSeed, adrs, concat(ak, node)); }
    }
    return node;
  };
  const XMSS_SIG = (LEN + hp) * n;
  const htSign = (M, skSeed, pkSeed, idxTree, idxLeaf) => {
    const adrs = new Adrs(); adrs.setTree(idxTree);
    let sigTmp = xmssSign(M, skSeed, idxLeaf, pkSeed, adrs);
    const parts = [sigTmp];
    let root = xmssPkFromSig(idxLeaf, sigTmp, M, pkSeed, adrs);
    for (let j = 1; j < d; j++) {
      idxLeaf = Number(idxTree & BigInt((1 << hp) - 1)); idxTree >>= BigInt(hp);
      adrs.setLayer(j); adrs.setTree(idxTree);
      sigTmp = xmssSign(root, skSeed, idxLeaf, pkSeed, adrs); parts.push(sigTmp);
      if (j < d - 1) root = xmssPkFromSig(idxLeaf, sigTmp, root, pkSeed, adrs);
    }
    return concat(...parts);
  };
  const htVerify = (M, sig, pkSeed, idxTree, idxLeaf, pkRoot) => {
    const adrs = new Adrs(); adrs.setTree(idxTree);
    let node = xmssPkFromSig(idxLeaf, sig.subarray(0, XMSS_SIG), M, pkSeed, adrs);
    for (let j = 1; j < d; j++) {
      idxLeaf = Number(idxTree & BigInt((1 << hp) - 1)); idxTree >>= BigInt(hp);
      adrs.setLayer(j); adrs.setTree(idxTree);
      node = xmssPkFromSig(idxLeaf, sig.subarray(j * XMSS_SIG, (j + 1) * XMSS_SIG), node, pkSeed, adrs);
    }
    return node.every((x, i) => x === pkRoot[i]);
  };
  const forsSkGen = (skSeed, pkSeed, adrs, idx) => {
    const skA = adrs.copy(); skA.setTypeAndClear(FORS_PRF); skA.setKeyPair(adrs.getKeyPair()); skA.setTreeIndex(idx);
    return H.PRF(pkSeed, skSeed, skA);
  };
  const forsNode = (skSeed, i, z, pkSeed, adrs) => {
    if (z === 0) {
      const sk = forsSkGen(skSeed, pkSeed, adrs, i);
      adrs.setTreeHeight(0); adrs.setTreeIndex(i);
      return H.T(pkSeed, adrs, sk);
    }
    const l = forsNode(skSeed, 2 * i, z - 1, pkSeed, adrs);
    const r = forsNode(skSeed, 2 * i + 1, z - 1, pkSeed, adrs);
    adrs.setTreeHeight(z); adrs.setTreeIndex(i);
    return H.T(pkSeed, adrs, concat(l, r));
  };
  const forsSign = (md, skSeed, pkSeed, adrs) => {
    const idx = base2b(md, a, k); const parts = [];
    for (let i = 0; i < k; i++) {
      parts.push(forsSkGen(skSeed, pkSeed, adrs, i * (1 << a) + idx[i]));
      for (let j = 0; j < a; j++) {
        const s = (idx[i] >>> j) ^ 1;
        parts.push(forsNode(skSeed, i * (1 << (a - j)) + s, j, pkSeed, adrs));
      }
    }
    return concat(...parts);
  };
  const forsPkFromSig = (sig, md, pkSeed, adrs) => {
    const idx = base2b(md, a, k); const roots = [];
    for (let i = 0; i < k; i++) {
      const off = i * (a + 1) * n;
      adrs.setTreeHeight(0); adrs.setTreeIndex(i * (1 << a) + idx[i]);
      let node = H.T(pkSeed, adrs, sig.subarray(off, off + n));
      for (let j = 0; j < a; j++) {
        const aj = sig.subarray(off + (j + 1) * n, off + (j + 2) * n);
        adrs.setTreeHeight(j + 1);
        if (((idx[i] >>> j) & 1) === 0) { adrs.setTreeIndex(adrs.getTreeIndex() >>> 1); node = H.T(pkSeed, adrs, concat(node, aj)); }
        else { adrs.setTreeIndex((adrs.getTreeIndex() - 1) >>> 1); node = H.T(pkSeed, adrs, concat(aj, node)); }
      }
      roots.push(node);
    }
    const pkA = adrs.copy(); pkA.setTypeAndClear(FORS_ROOTS); pkA.setKeyPair(adrs.getKeyPair());
    return H.T(pkSeed, pkA, concat(...roots));
  };
  const splitDigest = (digest) => {
    const md = digest.subarray(0, mdLen);
    const idxTree = toInt(digest.subarray(mdLen, mdLen + treeLen)) & ((1n << BigInt(p.h - hp)) - 1n);
    const idxLeaf = Number(toInt(digest.subarray(mdLen + treeLen, mdLen + treeLen + leafLen)) & BigInt((1 << hp) - 1));
    return { md, idxTree, idxLeaf };
  };
  const FORS_SIG = k * (a + 1) * n;

  return {
    hash: H,
    sigLen: n + FORS_SIG + d * XMSS_SIG,
    // seed = SK.seed || SK.prf || PK.seed (3n bytes), like FIPS 205 / noble
    keygen(seed) {
      const skSeed = seed.subarray(0, n), skPrf = seed.subarray(n, 2 * n), pkSeed = seed.subarray(2 * n, 3 * n);
      const adrs = new Adrs(); adrs.setLayer(d - 1);
      const pkRoot = xmssNode(skSeed, 0, hp, pkSeed, adrs);
      return { publicKey: concat(pkSeed, pkRoot), secretKey: concat(skSeed, skPrf, pkSeed, pkRoot) };
    },
    // optRand: n bytes; omit for deterministic (opt_rand = PK.seed)
    sign(M, sk, optRand) {
      const skSeed = sk.subarray(0, n), skPrf = sk.subarray(n, 2 * n), pkSeed = sk.subarray(2 * n, 3 * n), pkRoot = sk.subarray(3 * n, 4 * n);
      const R = H.PRFmsg(skPrf, optRand ?? pkSeed, M);
      const { md, idxTree, idxLeaf } = splitDigest(H.Hmsg(R, pkSeed, pkRoot, M));
      const adrs = new Adrs(); adrs.setTree(idxTree); adrs.setTypeAndClear(FORS_TREE); adrs.setKeyPair(idxLeaf);
      const sigFors = forsSign(md, skSeed, pkSeed, adrs);
      const pkFors = forsPkFromSig(sigFors, md, pkSeed, adrs);
      return concat(R, sigFors, htSign(pkFors, skSeed, pkSeed, idxTree, idxLeaf));
    },
    verify(M, sig, pk) {
      if (sig.length !== n + FORS_SIG + d * XMSS_SIG) return false;
      const pkSeed = pk.subarray(0, n), pkRoot = pk.subarray(n, 2 * n);
      const R = sig.subarray(0, n), sigFors = sig.subarray(n, n + FORS_SIG), sigHt = sig.subarray(n + FORS_SIG);
      const { md, idxTree, idxLeaf } = splitDigest(H.Hmsg(R, pkSeed, pkRoot, M));
      const adrs = new Adrs(); adrs.setTree(idxTree); adrs.setTypeAndClear(FORS_TREE); adrs.setKeyPair(idxLeaf);
      const pkFors = forsPkFromSig(sigFors, md, pkSeed, adrs);
      return htVerify(pkFors, sigHt, pkSeed, idxTree, idxLeaf, pkRoot);
    },
  };
}
