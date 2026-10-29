# Opacus

> **Website:** <https://opacus.io> &middot; **Repo:** <https://github.com/opacusio/opacus>

Opacus is a privacy payment network that fuses the proven transaction model of
Monero (ring-CT semantics, stealth addresses, Pedersen commitments) with
zk-SNARK spend anonymity in the spirit of Zcash Halo2 / FCMP++: every spend
carries a succinct proof that its key material belongs to the global set of
all wallet keys. Around the shielded core, Opacus ships an Ethereum-side
wrapped token (wOPACUS), a DEX/bridge toolchain, and an atomic-swap stack for
Monero <-> Opacus exchange, together with a zero-typing Windows (PowerShell)
tooling chain.

> **Status: v0.8.0: the P2P networking layer is live - authenticated peer
> identity (DLEq-bound handshake, secret zeroized in memory), persistent
> peer discovery with disco gossip, encrypted note transmission between
> wallets, and an Upgrade frame that hands an authenticated connection
> to the swap plane. Balance remains enforced in-circuit end to end
> (circuit, tx format, wallet, consensus). Test networks only. An
> independent security audit is REQUIRED before any mainnet use.**

## Quick Start

Requirements: git and Rust (install via rustup, https://rustup.rs). Verified with stable Rust 1.99.0 on Windows.

```
git clone https://github.com/opacusio/opacus.git
cd opacus
cargo build --release
cargo test --workspace
```

Typical timings on a modern machine (as of v0.8.0): clone ~20 s, release build ~2 min, full test run ~15-16 min - the consensus and wallet suites dominate it. 258 tests pass by default (0 failures); 3 slow full-depth (2^32 leaves) proof tests are ignored by default and can be run with:

```
cargo test --workspace -- --ignored
```

The workspace builds warning-free; CI enforces clippy with -D warnings. License: Apache-2.0.

## How the privacy works

- **Monero-style transaction layer.** Payments follow ring-CT semantics:
  Pedersen commitments hide amounts, stealth addresses hide recipients.
- **FCMP++-style membership proofs.** A Halo2 circuit (FcmpCircuit) proves in
  zero knowledge that the spend key is a member of the global
  note-commitment tree at mainnet depth 2^32, and reveals only a nullifier.
- **In-circuit value conservation (v4).** Every v4 spend proves its balance
  in zero knowledge: value commitments RC = v*V + r*R are built in-circuit
  from range-checked limbs over hashgen constants, inputs must equal
  outputs, and a binding signature over the 15-slot public instance vector
  makes any tampering fail verification.
- **Transparent proving system.** Proofs are built and verified with
  halo2_proofs 0.3.5 (zcash lineage) and its IPA commitment scheme over the
  Pasta (Vesta) scalar field - no trusted setup.
- **Commutative tree hashing.** The tree hash is h_tree = P(D, a+b, a*b) with
  Poseidon (t=3, x^5 S-box, 64 uniform full rounds, circ(2,1,1) MDS matrix,
  blake3-derived round constants), which removes direction bits from the
  witness path.
- **Constant-memory tree.** A sparse Merkle frontier with empty-subtree-root
  padding computes the 2^32-leaf root and authentication paths in
  O(leaves + depth) without ever materializing the tree (the naive approach
  would need about 137 GB of RAM).

## Workspace layout

| Path | Contents |
|------|----------|
| `crates/opacus-zk` | Halo2 FCMP++ zero-knowledge layer: Poseidon, sparse frontier, FcmpCircuit, v4 spend circuit, real IPA prover, prover bench |
| `crates/opacus-wallet` | Shielded wallet: zk spend build/prove/self-verify, zk-native light wallet, tx v4 serialization |
| `crates/opacus-consensus` | Consensus v4: validation order [S4 9], activation-height gate, nullifier seen-set, fee floor |
| `crates/opacus-node` | Daemon: transaction submission gated by consensus `accept_transaction` |
| `crates/opacus-bridge` | Monero bridge: cross-group DLEq, atomic-swap state machine, Monero RPC, swap P2P protocol |
| `crates/opacus-dex` | Ethereum side: RLP, ABI, EIP-155 signer, Uniswap Router02 calldata, JSON-RPC client, wOPACUS helpers |
| `crates/opacus-network` | Networking: node identity + DLEq handshake, persistent peers + disco gossip, encrypted note feed, TCP swap node, swap-plane handover |
| `contracts/` | wOPACUS.sol (quorum-mint ERC-20 wrapper) + Foundry deployment script and tests |
| repo root | Zero-typing PowerShell tooling: Sepolia deploy chain, key rotation, GitHub publish, release |

## Components

### opacus-zk (Halo2 FCMP++ zero-knowledge layer)

- Poseidon permutation over the Pasta (Vesta) scalar field (t=3, x^5 S-box,
  64 uniform full rounds, circ(2,1,1) MDS matrix, blake3-derived round
  constants).
- Sparse Merkle frontier at mainnet tree depth 2^32; empty-subtree-root
  padding gives O(leaves + depth) root and authentication-path computation.
- FcmpCircuit: single-region circuit (65 rows per permutation) with gates
  poseidon-round (degree 5 + absorb masking), init-zero, tree-add, tree-mul;
  public instances expose the note-commitment-tree root and the nullifier.
- v4 spend layer (v0.4): fixed-base scalar-mul chip (RC = v*V + r*R and the
  H_leaf*G3 term computed in-circuit as public instances), leaf-v2 note
  commitments, nullifier_v4 linking, and the full V4SpendCircuit - 1-in /
  2-out topology (MAX_IN = 2, MAX_OUT = 4), balance padding, 21-slot
  normative instance vector (15 base + 6-slot WG-26 swap tail), binding
  signature, k = 11 at tree depth 2^32 - with a mock-prover self-check and
  a real IPA prover path.
- In-circuit swap hashlock (WG-26): a spend can lock a note to a Poseidon
  hashlock H = Poseidon_3(dom_swap, s0, s1) over two 16-byte lanes of the
  swap preimage - lock derives the swap output leaf, claim reveals the
  preimage in-circuit and publishes the spent entry, refund skips the
  preimage check (timeout enforcement is WG-27); plain spends publish a
  zero swap tail.
- Real (non-mock) prover/verifier behind the `real-prover` feature: batch
  create_proof and plonk::SingleVerifier verification on
  halo2_proofs 0.3.5 (IPA, zcash lineage).
- `benches/prover.rs`: deterministic full-pipeline benchmark of the v4
  spend (prove_v4 / verify_v4) at 2^32 leaves, zero new dependencies.

### opacus-wallet (shielded wallet layer)

- `zk_spend.rs`: canonical Fp <-> 32-byte serialization, persistable
  WalletNote, in-memory TreeState with a `mainnet()` constructor, witness
  builder, and ZkSpendTx build/verify helpers that prove and self-verify
  BEFORE any wallet state mutation.
- `light_wallet.rs` is zk-native while preserving the public API: shielded
  balance (total/spendable/pending), incoming-note confirmation,
  `build_zk_spend` with single-note selection and change handling,
  `confirm_zk_tx` mirroring consensus, a nullifier seen-set registry, and
  tree introspection helpers.
- v0.4 / WG-26: `tx_v4.rs` - canonical v4/v5 transaction serialization
  feeding the exact 21-slot instance vector, `build_zk_spend_v5` and
  `confirm_zk_tx_v5` with `SwapIntent` (Lock / Claim / Refund) mirroring
  the consensus confirmation order; the wallet end-to-end cycle (including
  lock-then-claim and lock-then-refund) is green at mainnet tree depth
  2^32.

### opacus-consensus (v4 consensus layer)

- `accept_transaction` validates a v4 spend in the normative order [S4 9]:
  parse, proof verify, balance and binding signature, nullifier seen-set,
  tree root, fee floor, commit - with zero state mutation before ALL
  checks pass.
- Activation-height gate: after `CONSENSUS_V4_ACTIVATION_HEIGHT` only v4
  transactions are accepted (v3 rejected; a v4 transaction earlier than
  the height is rejected as EarlyV4; legacy structure remains valid only
  before activation).
- `ConsensusParams` / `ConsensusState` (commitment tree + nullifier
  seen-set), Accept/Reject taxonomy, and the `confirm_v4_consensus` state
  transition.

### opacus-node (daemon)

- `submit_transaction` routes every incoming transaction through consensus
  `accept_transaction`; invalid transactions are rejected before any state
  effect (rejections surface as `TxRejected`), and the daemon exposes its
  `ConsensusParams` / `ConsensusState` for introspection.

### opacus-bridge (Monero bridge)

- `xmr_dleq.rs`: cross-group Schnorr DLEq proving that one scalar controls
  both the Monero/Edwards key and the Ristretto key (blake3 challenge, wide
  mod-l reduction, 96-byte serialization).
- `xmr_swap.rs`: atomic-swap state machine Offered -> Accepted -> XmrLocked
  -> GhostLocked -> Claimed/Refunded with fund/claim timeouts, Maker/Taker
  roles, blake3 hashlock.
- `xmr_rpc.rs`: monero-wallet-rpc client (transfer with unlock_time and
  payment_id = hashlock, get_transfers filtered by payment_id, balance and
  address queries) plus monerod get_info, behind a Transport trait.
- `swap_p2p.rs`: SwapNetMessage protocol with u32-LE length-prefixed JSON
  framing, tamper-evident blake3 offer ids, and a session registry that
  reuses the swap state machine as the single source of truth (replay,
  duplicate, forged-claim and timeout validation).

### opacus-dex (Ethereum side)

- Minimal RLP encoder/decoder verified against known vectors.
- ABI encoding with keccak selectors (Uniswap V2 well-known selectors
  verified), including head/tail encoding with dynamic offsets.
- Legacy EIP-155 transaction signer (k256): keccak256 prehash,
  v = parity + 35 + 2*chainId, with a roundtrip test that recovers the
  sender address.
- Uniswap Router02 (0x7a25...) calldata builders: getAmountsOut,
  swapTokensForTokens / swapTokensForETH, WETH wrap, ERC-20
  approve/transfer/balanceOf.
- Ethereum JSON-RPC client (eth_call, gasPrice, nonce, estimateGas,
  sendRawTransaction) with fake-transport tests.
- wOPACUS helpers: set_wopacus/burn calldata and Minted/Burned event topics.

### opacus-network (networking + swap node)

- Node identity and handshake (N1): persistent ristretto node identity
  (atomic 0600 save, zero-scalar rejection, secret scalar zeroized on
  drop via a non-Copy wrapper) and a DLEq-authenticated
  transcript handshake over the length-prefixed opacus-net-v1 wire, with
  a replay cache, strict frame-size/peer-id caps, and disconnects on any
  protocol violation (including a notes frame during the handshake).
- Peer store and discovery (N2): persistent peers file (bounded cap with
  oldest eviction, dedupe with monotonic last_seen, corrupt-file
  quarantine) and disco batch gossip propagated through common peers.
- Authenticated node (N2-b): every post-handshake frame is bound to the
  authenticated peer and limited to Disco | Notes | Upgrade; bounded
  event ring; opacusd wiring (identity, disco, notes behind the daemon).
- Encrypted note feed (N3): blake3-only ECIES to the recipient ristretto
  identity key, encrypt-then-MAC verified BEFORE any decryption, an
  OPAQUE payload owned by the wallet layer, a public blake3 id any relay
  can verify and dedupe on, and a hop budget a relay can decrement
  WITHOUT keys (the MAC does not cover hops; the relaying node recomputes
  the public id); zero-hop blobs are stored but never relayed.
- Swap-plane handover (N3b): an authenticated peer can send an Upgrade
  frame; the net node hands the raw connection to the attached TCP swap
  node at a clean frame boundary (unknown or unattached planes are
  rejected and the connection closed; the swap protocol never crosses
  the authenticated control plane).
- TCP swap node: automatic protocol replies (Offer -> Accept,
  GhostLocked -> Claim) with protocol-violation disconnects; adopted
  (upgraded) connections speak the swap protocol directly.

### contracts (wOPACUS token)

- `wOPACUS.sol`: ERC-20 wrapper with quorum-gated mint (sorted-signature
  ecrecover check) and burn-for-release; deployed to the Sepolia testnet
  (address tracked in `contracts/wghost.address`), quorum threshold 1/1 for
  testnet. Marked AUDIT REQUIRED before any mainnet use.
- `foundry.toml` + `WOPACUSTest.t.sol`: forge suite for the wrapper - the
  WG-16 hardening pins the quorum N-of-M at deployment, binds the mint
  digest to block.chainid and enforces the EIP-2 low-s range.
- Legacy wGHOST (quorum 1/1) is DEPRECATED: the contract name compiles
  into the deployed bytecode and cannot be renamed in place, so the
  rebrand ships as a fresh wOPACUS deployment (audit WG-16).

## Build and test

Prerequisites: a recent stable Rust toolchain (rustup), Git; Foundry (forge)
for the contracts.

```
git clone https://github.com/opacusio/opacus.git
cd opacus

cargo build --release
cargo test --workspace

# real (non-mock) IPA prover tests:
cargo test -p opacus-zk --features real-prover

# prover benchmark - full v4 spend at 2^32 leaves (real IPA):
cargo bench -p opacus-zk --features real-prover --bench prover

# contracts (Foundry):
forge build --root contracts
forge test --root contracts
```

Test status (zero warnings in all crates):

| Crate | Tests |
|-------|-------|
| opacus-zk | 44 default + 2 real-prover (+1 ignored mainnet-depth mock, k = 12) |
| opacus-wallet | 14 fast + 2 mainnet-depth end-to-end (ignored by default; run with `cargo test -p opacus-wallet -- --ignored`) |
| opacus-consensus | 10 (real IPA proofs, depth 8) |
| opacus-crypto | 10 |
| opacus-node | 15 |
| opacus-bridge | 67 |
| opacus-dex | 16 |
| opacus-network | 80 |

Performance: a membership-only spend proof at mainnet tree depth (2^32
leaves) proves and verifies in about 2.1 s. The full v4 spend pipeline
(real IPA, k = 11) runs on a process-wide keyset cache (WG-17): since
PROVER-10S fuses 4 Poseidon rounds into every gate row, the WHOLE
pipeline (keygen included) runs in 4,81 s cold, 2,26 s at
steady-state prove with 0,03 s verify - inside the 10 s budget
[S4 8] end to end. The bench gates BOTH numbers: `cargo bench -p
opacus-zk --features real-prover --bench prover`.

## Sepolia deployment (zero-typing PowerShell chain)

1. `run_sepolia_deploy.ps1` - funds gate, in-process deployer key.
2. `deploy_wghost.ps1` - deploys the wrapped-token contract to Sepolia
   (legacy wGHOST run; the WG-16 redeploy round ships wOPACUS).
3. `finalize_wghost.ps1` - bytecode gate, soft token calls, hard quorum
   cross-checks, persists the address to `contracts/wghost.address`.

Also at the repo root: `fix_deployer_key.ps1` (zero-input deployer key
rotation with cross-verification), `publish_ghost.ps1` (safe one-command
GitHub publish with secret gates and no force-push).

## Security notes

- `deployer.key*` is never committed; the globally known public Foundry
  anvil #0 test key was detected as the deployer and rotated to a freshly
  generated random key (the old key survives only in a local git-ignored
  .bak file).
- Publishing excludes secrets by construction: a `.gitignore` guard set
  (`deployer.key*`, `*.key`, `*.pem`, `.env*`, `*.bak*`, `tools/`, build
  artifacts) plus an index-level secret gate that untracks offenders while
  keeping the files on disk.
- Commits use the noreply GitHub identity.
- Consensus v4 mutates state only after every validation step passes; the
  nullifier seen-set prevents replay; the activation-height gate prevents
  mixed v3/v4 replay across the fork boundary.
- The stored node identity secret lives in a zeroizing non-Copy
  wrapper: the scalar is scrubbed from memory when the identity is
  dropped, and the identity Debug output never includes secret
  material.
- The wOPACUS mint is quorum-gated; the threshold is fixed N-of-M at
  deployment (no in-place quorum updates). The legacy wGHOST Sepolia
  deployment (quorum 1/1) is deprecated. An external audit is REQUIRED
  before any mainnet use; testnet keys are throwaway.

## Roadmap

Shipped in v0.6 (networking): persistent node identity, DLEq-bound
authenticated handshake, peer discovery with disco gossip, and encrypted
note transmission between wallets (crates/opacus-network, phases N1-N3).
Shipped in v0.7 (protocol + hardening): the N3b swap-plane upgrade frame
and the F4 zeroized identity secret (non-Copy SecretScalar wrapper).

- Delivered (PROVER-10S): 4 Poseidon rounds fused per gate row - the
  mainnet MAX topology dropped 5103 -> 1551 rows (k = 13 -> 11) and the
  whole cold pipeline (keygen included) runs in 4,81 s with
  steady-state prove at 2,26 s - inside the 10 s budget [S4 8].
- Delivered (WG-26): the swap hashlock tail adds 54 rows
  (1551 -> 1605, k stays 11) - lock / claim / refund in-circuit [S4 12].
- Delivered (WG-26): hashlock-in-circuit - swap lock / claim / refund
  proven inside the v4 spend circuit, public swap tail, v5 wire
  [S4 12]; chain-level swap enforcement follows in WG-27. CLSAG adaptor
  signatures for on-chain swap enforcement remain planned (Refund frames
  are notices in v0.1).
- External security audit before any mainnet use - MANDATORY gate, see
  SECURITY.md ("Mainnet gate"); testnet keys are strictly one-time.

## Versioning and changelog

`CHANGELOG.md` follows the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format and
[Semantic Versioning](https://semver.org/). The current release is
**v0.8.0** (BIP-39 wallet keys + fused Poseidon spend circuit, k = 11).

## License

Apache-2.0 - see the `LICENSE` file at the repository root.
