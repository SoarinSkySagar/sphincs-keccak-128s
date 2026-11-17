# SPHINCS+-128s-keccak256 verifier

An on-chain verifier (Solidity, inline assembly) for FIPS 205 SLH-DSA, simple construction,
parameter set **128s**, with every SHAKE256 call replaced by **keccak256 truncated** to the
output length, plus a JavaScript reference signer.

| | |
|---|---|
| Parameters | n=16, h=63, d=7, h'=9, a=12, k=14, w=16 |
| Hash | keccak256, truncated (SHAKE256 → keccak256) |
| Interface | internal (`slh_verify_internal`): the 32-byte message is verified as-is |
| Public key | 32 bytes: PK.seed (16) ‖ PK.root (16) |
| Signature | 7,856 bytes |
| Gas | 359k–393k (Foundry external call, solc 0.8.28 via_ir, 1,000,000 optimizer runs; 3 vectors) |

- `src/SphincsKeccak128s.sol`: `library SphincsKeccak128s` (`verify(bytes32 pk, bytes32 message, bytes calldata sig)`)
  and a `SphincsKeccak128sVerifier` contract wrapping it.
- `signer/slh.mjs`: reference SLH-DSA with a SHAKE256 or keccak256 backend. The SHAKE backend is
  checked byte for byte against noble's SLH-DSA-SHAKE-128s (`signer/validate.mjs`).
- `signer/gen-vectors.mjs`: writes test vectors for the Foundry tests.

```bash
forge install foundry-rs/forge-std   # if lib/forge-std is empty
forge test -vv                        # prints verify gas per vector
npm install
npm run validate                      # reference signer == noble SLH-DSA-SHAKE-128s
npm run vectors                       # regenerate test/fixtures/sphincs-keccak-128s.json
```

Not audited. MIT licensed.
