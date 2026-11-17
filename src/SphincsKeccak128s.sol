// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SPHINCS+-128s-keccak256 verifier
/// @notice FIPS 205 SLH-DSA "simple" construction, parameter set 128s
///         (n=16, h=63, d=7, h'=9, a=12, k=14, w=16), with every SHAKE256 call
///         replaced by keccak256 truncated to the output length. Matches
///         signer/slh.mjs (backend "keccak256"), whose SHAKE backend is
///         validated byte-for-byte against the noble post-quantum SLH-DSA-SHAKE-128s.
/// @dev    Internal interface (slh_verify_internal): the 32-byte message is
///         verified as-is. pk = PK.seed (16 bytes) || PK.root (16 bytes).
///
/// Hash inputs are laid out in memory as  PK.seed(16) | ADRS(32) | data,
/// so every tweakable hash is one KECCAK256 over a contiguous buffer.
/// ADRS word (big-endian): layer(4) tree(12) type(4) keypair(4) chain|height(4) hash|index(4)
library SphincsKeccak128s {
    uint256 internal constant SIG_LEN = 7856;
    /// high 16 bytes of a word (an n = 16 byte node, left-aligned)
    uint256 internal constant HI = 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000;

    function verify(bytes32 pk, bytes32 message, bytes calldata sig) internal pure returns (bool ok) {
        if (sig.length != SIG_LEN) return false;
        assembly ("memory-safe") {
            let pkRoot := shl(128, pk)

            // Scratch buffers (beyond the free memory pointer; never returned).
            //   bufF: PK.seed | ADRS | up to 2 nodes          (F, H)
            //   bufT: PK.seed | ADRS | up to 35 nodes         (T_k, T_len)
            let bufF := mload(0x40)
            let bufT := add(bufF, 0x80)
            mstore(bufF, and(pk, HI))                      // PK.seed

            // ---- H_msg(R, PK.seed, PK.root, M) -> 30-byte digest ----
            mstore(bufT, and(calldataload(sig.offset), HI)) // R
            mstore(add(bufT, 16), pk)                       // PK.seed | PK.root
            mstore(add(bufT, 48), message)
            let dg := keccak256(bufT, 80)
            mstore(bufT, and(pk, HI))                       // PK.seed prefix for T_k / T_len

            // md = bytes 0..20 (14 x 12-bit FORS indices), idx_tree = bytes 21..27, idx_leaf = 28..29
            let idxTree := and(shr(32, dg), 0x3fffffffffffff)          // 54 bits
            let idxLeaf := and(shr(16, dg), 0x1ff)                      // 9 bits

            // ---- FORS: 14 trees of height 12 ----
            // ADRS base: layer 0 | tree idxTree | type FORS_TREE(3) | keypair idxLeaf
            let forsBase := or(or(shl(128, idxTree), shl(96, 3)), shl(64, idxLeaf))
            let p := add(sig.offset, 16)
            for { let i := 0 } lt(i, 14) { i := add(i, 1) } {
                let idx := and(shr(sub(244, mul(12, i)), dg), 0xfff)
                let ti := add(shl(12, i), idx)
                // leaf: F(sk), height 0
                mstore(add(bufF, 16), or(forsBase, ti))
                mstore(add(bufF, 48), and(calldataload(p), HI))
                let node := and(keccak256(bufF, 64), HI)
                p := add(p, 16)
                for { let j := 0 } lt(j, 12) { j := add(j, 1) } {
                    let auth := and(calldataload(p), HI)
                    p := add(p, 16)
                    switch and(shr(j, idx), 1)
                    case 0 { mstore(add(bufF, 48), node) mstore(add(bufF, 64), auth) }
                    default { mstore(add(bufF, 48), auth) mstore(add(bufF, 64), node) ti := sub(ti, 1) }
                    ti := shr(1, ti)
                    mstore(add(bufF, 16), or(or(forsBase, shl(32, add(j, 1))), ti))
                    node := and(keccak256(bufF, 80), HI)
                }
                mstore(add(bufT, add(48, shl(4, i))), node)
            }
            // T_k over the 14 roots: type FORS_ROOTS(4), keypair idxLeaf
            mstore(add(bufT, 16), or(or(shl(128, idxTree), shl(96, 4)), shl(64, idxLeaf)))
            let root := and(keccak256(bufT, 272), HI)        // 48 + 14*16

            // ---- Hypertree: 7 XMSS layers of height 9 ----
            for { let layer := 0 } lt(layer, 7) { layer := add(layer, 1) } {
                if layer {
                    idxLeaf := and(idxTree, 0x1ff)
                    idxTree := shr(9, idxTree)
                }
                let lt_ := or(shl(224, layer), shl(128, idxTree))   // layer | tree

                // WOTS+: message = root (32 nibbles) + 3-nibble checksum
                let csum := 0
                let wbase := or(lt_, shl(64, idxLeaf))               // type WOTS_HASH(0) | keypair
                for { let i := 0 } lt(i, 35) { i := add(i, 1) } {
                    let m_
                    switch lt(i, 32)
                    case 1 {
                        m_ := and(shr(sub(252, shl(2, i)), root), 0xf)
                        csum := add(csum, sub(15, m_))
                    }
                    default {
                        // checksum (max 480) << 4, as 2 bytes -> 3 nibbles
                        m_ := and(shr(sub(12, shl(2, sub(i, 32))), shl(4, csum)), 0xf)
                    }
                    let x := and(calldataload(p), HI)
                    p := add(p, 16)
                    let cbase := or(wbase, shl(32, i))
                    for { let j := m_ } lt(j, 15) { j := add(j, 1) } {
                        mstore(add(bufF, 16), or(cbase, j))
                        mstore(add(bufF, 48), x)
                        x := and(keccak256(bufF, 64), HI)
                    }
                    mstore(add(bufT, add(48, shl(4, i))), x)
                }
                // T_len: type WOTS_PK(1), keypair
                mstore(add(bufT, 16), or(or(lt_, shl(96, 1)), shl(64, idxLeaf)))
                let node := and(keccak256(bufT, 608), HI)    // 48 + 35*16

                // XMSS auth path: type TREE(2)
                let tbase := or(lt_, shl(96, 2))
                let ti := idxLeaf
                for { let k := 0 } lt(k, 9) { k := add(k, 1) } {
                    let auth := and(calldataload(p), HI)
                    p := add(p, 16)
                    switch and(shr(k, idxLeaf), 1)
                    case 0 { mstore(add(bufF, 48), node) mstore(add(bufF, 64), auth) }
                    default { mstore(add(bufF, 48), auth) mstore(add(bufF, 64), node) ti := sub(ti, 1) }
                    ti := shr(1, ti)
                    mstore(add(bufF, 16), or(or(tbase, shl(32, add(k, 1))), ti))
                    node := and(keccak256(bufF, 80), HI)
                }
                root := node
            }
            ok := eq(root, pkRoot)
        }
    }
}

/// @notice Standalone verifier, used to measure gas.
contract SphincsKeccak128sVerifier {
    function verify(bytes32 pk, bytes32 message, bytes calldata sig) external pure returns (bool) {
        return SphincsKeccak128s.verify(pk, message, sig);
    }
}
