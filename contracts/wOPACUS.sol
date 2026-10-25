// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title wOPACUS - ERC20 wrapper of native Opacus on Ethereum.
/// @notice Minted by the bridge quorum when native Opacus is locked on
///         the Opacus chain; burned to release native Opacus back.
///         Tradeable on Uniswap V2/V3 like any ERC20.
/// @dev AUDIT REQUIRED before any mainnet deployment.
///      Redeploy hardening (audit WG-16): quorum is fixed N-of-M at
///      deployment, the mint digest binds block.chainid (no cross-chain
///      replay), and verification enforces the EIP-2 low-s range.
contract WOPACUS {
    string public constant name = "Wrapped Opacus";
    string public constant symbol = "wOPACUS";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /// Bridge quorum signers (validator-set style). The set and the
    /// threshold are fixed at deployment: there is NO updateQuorum;
    /// rotating the quorum requires a new contract.
    address[] public quorum;
    uint256 public quorumThreshold;

    /// secp256k1 group order n; signatures must satisfy s <= n/2 (EIP-2).
    uint256 constant SECP256K1_N_HALF =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// Opacus lock tx hashes already minted (replay guard: 1 lock = 1 mint).
    mapping(bytes32 => bool) private usedLock;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Minted(address indexed to, uint256 value, bytes32 opacusTxHash);
    event Burned(address indexed from, uint256 value, string opacusRecipient);
    event QuorumConfigured(address[] members, uint256 threshold);

    constructor(address[] memory members_, uint256 threshold_) {
        require(members_.length >= 1, "wOPACUS: quorum cfg");
        require(threshold_ >= 1 && threshold_ <= members_.length, "wOPACUS: quorum cfg");
        quorum = members_;
        quorumThreshold = threshold_;
        emit QuorumConfigured(members_, threshold_);
    }

    // ------------------------------------------------------------------
    // ERC20
    // ------------------------------------------------------------------

    function transfer(address to, uint256 value) external returns (bool) {
        _move(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= value, "wOPACUS: allowance");
        if (a != type(uint256).max) {
            allowance[from][msg.sender] = a - value;
        }
        _move(from, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function _move(address from, address to, uint256 value) internal {
        require(balanceOf[from] >= value, "wOPACUS: balance");
        unchecked {
            balanceOf[from] -= value;
            balanceOf[to] += value;
        }
        emit Transfer(from, to, value);
    }

    // ------------------------------------------------------------------
    // Bridge side
    // ------------------------------------------------------------------

    /// @notice Mint wOPACUS after a quorum attests an Opacus lock tx.
    /// @param to      EVM address receiving wOPACUS
    /// @param value   wei-amount (18 decimals after bridge scaling)
    /// @param opacusTxHash blake3 hash of the native Opacus lock tx
    /// @param sigs    65-byte (r,s,v) signatures over
    ///                keccak256(abi.encodePacked("opacus-lock-v1", to, value,
    ///                block.chainid, opacusTxHash)), sorted by signer
    ///                address ascending, no duplicates, s in the EIP-2
    ///                low-s range.
    function mint(
        address to,
        uint256 value,
        bytes32 opacusTxHash,
        bytes[] calldata sigs
    ) external {
        require(!usedLock[opacusTxHash], "wOPACUS: used");
        usedLock[opacusTxHash] = true;
        bytes32 digest = keccak256(
            abi.encodePacked("opacus-lock-v1", to, value, block.chainid, opacusTxHash)
        );
        _checkQuorum(digest, sigs);
        totalSupply += value;
        balanceOf[to] += value;
        emit Transfer(address(0), to, value);
        emit Minted(to, value, opacusTxHash);
    }

    /// @notice Burn wOPACUS to request native Opacus release.
    ///         Bridge relayers watch the Burned event.
    function burn(uint256 value, string calldata opacusRecipient) external {
        require(balanceOf[msg.sender] >= value, "wOPACUS: balance");
        unchecked {
            balanceOf[msg.sender] -= value;
            totalSupply -= value;
        }
        emit Transfer(msg.sender, address(0), value);
        emit Burned(msg.sender, value, opacusRecipient);
    }

    function _checkQuorum(bytes32 digest, bytes[] calldata sigs) internal view {
        require(sigs.length >= quorumThreshold, "wOPACUS: not enough sigs");
        uint256 distinct;
        address prev = address(0);
        for (uint256 i = 0; i < sigs.length; i++) {
            require(sigs[i].length == 65, "wOPACUS: sig len");
            bytes calldata sig = sigs[i];
            bytes32 r;
            bytes32 s;
            uint8 v;
            require(uint8(sig[64]) < 2, "wOPACUS: v");
            r = bytes32(sig[0:32]);
            s = bytes32(sig[32:64]);
            require(uint256(s) <= SECP256K1_N_HALF, "wOPACUS: high s");
            v = uint8(sig[64]) + 27;
            address signer = ecrecover(digest, v, r, s);
            require(signer > prev, "wOPACUS: sig order"); // dup + sorted check
            prev = signer;
            if (_isMember(signer)) {
                distinct += 1;
            }
        }
        require(distinct >= quorumThreshold, "wOPACUS: quorum");
    }

    function _isMember(address a) internal view returns (bool) {
        for (uint256 i = 0; i < quorum.length; i++) {
            if (quorum[i] == a) return true;
        }
        return false;
    }
}
