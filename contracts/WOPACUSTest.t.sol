// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./wOPACUS.sol";

/// e2e tests for WOPACUS (no forge-std dependency).
interface VmI {
    function addr(uint256 pk) external returns (address);
    function sign(uint256 pk, bytes32 digest)
        external returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address) external;
    function expectRevert(bytes memory) external;
    function chainId(uint256) external;
}

contract WOPACUSTest {
    VmI constant vm = VmI(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    WOPACUS token;
    address holder;
    uint256 constant VALUE = 1000 ether;

    // Bridge quorum 2-of-5. Deterministic key map: the member addresses
    // sort ascending in label order (pk1 < pk2 < pk3 < pk4 < pk5), so
    // signature lists can be built member-by-member without sorting.
    uint256 constant PK1 = 0x1; // 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
    uint256 constant PK2 = 0x5; // 0xE1AB8145F7E55DC933D51A18C793F901A3A0B276
    uint256 constant PK3 = 0x6; // 0xE57bFE9F44B819898F47BF37E5AF72A0783E1141
    uint256 constant PK4 = 0x8; // 0xF1F6619B38A98d6De0800F1DEFC0A6399Eb6d30c
    uint256 constant PK5 = 0x9; // 0xF7eDc8FA1ECC32967F827C9043FCAE6bA73AFA5C
    // non-member receiver/signer, address above every member address
    uint256 constant PK_HOLDER = 0x10; // 0xFAE394561E33E242C551D15D4625309EA4C0B97F
    uint256 constant CHAIN_B = 11155111; // Sepolia, the deployment chain
    uint256 constant CHAIN_A = 1; // the replay source chain

    // secp256k1 group order n (EIP-2 high-s malleation test).
    uint256 constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function setUp() public {
        vm.chainId(CHAIN_B);
        holder = vm.addr(PK_HOLDER);
        address[] memory members = new address[](5);
        members[0] = vm.addr(PK1);
        members[1] = vm.addr(PK2);
        members[2] = vm.addr(PK3);
        members[3] = vm.addr(PK4);
        members[4] = vm.addr(PK5);
        token = new WOPACUS(members, 2);
    }

    function _sig(uint256 pk, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        // normalize to the EIP-2 low-s range (the contract rejects high s)
        if (uint256(s) > SECP256K1_N / 2) {
            s = bytes32(SECP256K1_N - uint256(s));
            v = v == 27 ? 28 : 27;
        }
        return abi.encodePacked(r, s, bytes1(uint8(v - 27)));
    }

    function _sigs2(uint256 pka, uint256 pkb, bytes32 digest)
        internal returns (bytes[] memory out)
    {
        out = new bytes[](2);
        out[0] = _sig(pka, digest);
        out[1] = _sig(pkb, digest);
    }

    function _digest(address to, uint256 value, bytes32 h)
        internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked("opacus-lock-v1", to, value, block.chainid, h)
        );
    }

    function testTokenIdentity() public {
        assertEqStr(token.name(), "Wrapped Opacus", "name");
        assertEqStr(token.symbol(), "wOPACUS", "symbol");
        assertTrue(token.decimals() == 18, "decimals");
        assertTrue(token.totalSupply() == 0, "fresh supply");
        assertTrue(token.quorumThreshold() == 2, "threshold");
        assertTrue(token.quorum(0) == vm.addr(PK1), "member 0");
    }

    function testMintBurnFlow() public {
        bytes32 h = keccak256("opacus-lock-tx-1");
        bytes[] memory sigs = _sigs2(PK1, PK2, _digest(holder, VALUE, h));
        token.mint(holder, VALUE, h, sigs);
        assertEq(token.balanceOf(holder), VALUE, "mint balance");
        assertEq(token.totalSupply(), VALUE, "mint supply");

        vm.prank(holder);
        token.burn(VALUE, "opacus-recipient");
        assertEq(token.balanceOf(holder), 0, "burn balance");
        assertEq(token.totalSupply(), 0, "burn supply");
    }

    function testTransferApprove() public {
        bytes32 h = keccak256("opacus-lock-tx-2");
        token.mint(holder, VALUE, h, _sigs2(PK1, PK2, _digest(holder, VALUE, h)));

        vm.prank(holder);
        token.transfer(address(0xBEEF), 100);
        assertEq(token.balanceOf(address(0xBEEF)), 100, "transfer");

        vm.prank(holder);
        token.approve(address(0xCEEF), 50);
        vm.prank(address(0xCEEF));
        token.transferFrom(holder, address(0xCEEF), 50);
        assertEq(token.balanceOf(address(0xCEEF)), 50, "transferFrom");
        assertEq(token.balanceOf(holder), VALUE - 150, "residual");
    }

    function testRevertNotEnoughSigs() public {
        bytes32 h = keccak256("opacus-lock-tx-4");
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sig(PK1, _digest(holder, VALUE, h));
        // threshold is 2-of-5: a single member sig is not enough
        vm.expectRevert(bytes("wOPACUS: not enough sigs"));
        token.mint(holder, VALUE, h, sigs);
    }

    function testRevertNonMemberSig() public {
        bytes32 h = keccak256("opacus-lock-tx-5");
        // holder is not a quorum member: only one distinct member sig
        bytes[] memory sigs = _sigs2(PK1, PK_HOLDER, _digest(holder, VALUE, h));
        vm.expectRevert(bytes("wOPACUS: quorum"));
        token.mint(holder, VALUE, h, sigs);
    }

    function testRevertWrongDigestSig() public {
        bytes32 h = keccak256("opacus-lock-tx-6");
        // different digest -> recovered signers are not members; the
        // recovered pair is pre-ordered ascending (PK2 recovers lower)
        bytes[] memory sigs = _sigs2(PK2, PK1, keccak256("wrong-digest"));
        vm.expectRevert(bytes("wOPACUS: quorum"));
        token.mint(holder, VALUE, h, sigs);
    }

    function testRevertDuplicateSigOrder() public {
        bytes32 h = keccak256("opacus-lock-tx-7");
        bytes memory one = _sig(PK1, _digest(holder, VALUE, h));
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = one;
        sigs[1] = one;
        // duplicate signer violates the strictly-sorted requirement
        vm.expectRevert(bytes("wOPACUS: sig order"));
        token.mint(holder, VALUE, h, sigs);
    }

    function testRevertOvermintDoubleUse() public {
        bytes32 h = keccak256("opacus-lock-tx-8");
        bytes[] memory sigs = _sigs2(PK1, PK2, _digest(holder, VALUE, h));
        token.mint(holder, VALUE, h, sigs);
        // same lock tx hash minted twice -> supply inflation guard
        vm.expectRevert(bytes("wOPACUS: used"));
        token.mint(holder, VALUE, h, sigs);
    }

    function testRevertCrossChainReplay() public {
        bytes32 h = keccak256("opacus-lock-tx-9");
        // signed on CHAIN_B (pinned by setUp); replay the same member
        // sigs on CHAIN_A with a fresh lock hash: the chainId-bound
        // digest makes the recovered signers non-members there.
        bytes[] memory sigs = _sigs2(PK1, PK2, _digest(holder, VALUE, h));
        token.mint(holder, VALUE, h, sigs);
        vm.chainId(CHAIN_A);
        bytes32 h2 = keccak256("opacus-lock-tx-9-replay");
        vm.expectRevert(bytes("wOPACUS: quorum"));
        token.mint(holder, VALUE, h2, sigs);
    }

    function testRevertHighS() public {
        bytes32 h = keccak256("opacus-lock-tx-10");
        bytes32 digest = _digest(holder, VALUE, h);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK1, digest);
        if (uint256(s) > SECP256K1_N / 2) {
            // normalize to low s first, then malleate to the high-s form
            s = bytes32(SECP256K1_N - uint256(s));
            v = v == 27 ? 28 : 27;
        }
        s = bytes32(SECP256K1_N - uint256(s));
        v = v == 27 ? 28 : 27;
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = abi.encodePacked(r, s, bytes1(uint8(v - 27)));
        sigs[1] = _sig(PK2, digest);
        vm.expectRevert(bytes("wOPACUS: high s"));
        token.mint(holder, VALUE, h, sigs);
    }

    function assertEq(uint256 a, uint256 b, string memory what) internal pure {
        require(a == b, what);
    }

    function assertEqStr(string memory a, string memory b, string memory what)
        internal pure {
        require(keccak256(bytes(a)) == keccak256(bytes(b)), what);
    }

    function assertTrue(bool c, string memory what) internal pure {
        require(c, what);
    }
}
