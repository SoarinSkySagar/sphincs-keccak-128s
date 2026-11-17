// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {SphincsKeccak128sVerifier} from "../src/SphincsKeccak128s.sol";

contract SphincsKeccak128sTest is Test {
    SphincsKeccak128sVerifier v;
    string json;

    function setUp() public {
        v = new SphincsKeccak128sVerifier();
        json = vm.readFile("test/fixtures/sphincs-keccak-128s.json");
    }

    function vec(uint256 i) internal view returns (bytes32 pk, bytes32 msg_, bytes memory sig) {
        string memory b = string.concat(".vectors[", vm.toString(i), "]");
        pk = vm.parseJsonBytes32(json, string.concat(b, ".pk"));
        msg_ = vm.parseJsonBytes32(json, string.concat(b, ".msg"));
        sig = vm.parseJsonBytes(json, string.concat(b, ".sig"));
    }

    function test_validSignatures() public view {
        for (uint256 i = 0; i < 3; i++) {
            (bytes32 pk, bytes32 m, bytes memory sig) = vec(i);
            uint256 g = gasleft();
            bool ok = v.verify(pk, m, sig);
            console.log("vector", i, "verify gas (incl. call)", g - gasleft());
            assertTrue(ok, "valid signature rejected");
        }
    }

    function test_rejectsWrongMessage() public view {
        (bytes32 pk, bytes32 m, bytes memory sig) = vec(0);
        assertFalse(v.verify(pk, m ^ bytes32(uint256(1)), sig));
    }

    function test_rejectsWrongKey() public view {
        (, bytes32 m, bytes memory sig) = vec(0);
        (bytes32 pk1,,) = vec(1);
        assertFalse(v.verify(pk1, m, sig));
    }

    function test_rejectsTamperedSignature() public view {
        (bytes32 pk, bytes32 m, bytes memory sig) = vec(0);
        // flip one bit in R, in FORS, in each hypertree layer, and in the last auth node
        uint256[9] memory spots = [uint256(3), 1000, 2930, 3700, 4400, 5100, 5800, 6500, 7855];
        for (uint256 i = 0; i < spots.length; i++) {
            bytes memory bad = bytes.concat(sig);
            bad[spots[i]] ^= 0x01;
            assertFalse(v.verify(pk, m, bad), "tampered signature accepted");
        }
    }

    function test_rejectsWrongLength() public view {
        (bytes32 pk, bytes32 m, bytes memory sig) = vec(0);
        bytes memory shortSig = new bytes(sig.length - 1);
        assertFalse(v.verify(pk, m, shortSig));
    }
}
