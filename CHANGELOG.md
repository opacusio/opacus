# Changelog

All notable changes to the **Opacus** monorepo are documented in this file.
The initial public release consolidates the full pre-history of the private
development phase; every further change will be added here following the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format and
[Semantic Versioning](https://semver.org/).

Opacus is a privacy payment network that fuses Monero-style ring-CT semantics
with Zcash-style Halo2 FCMP++ spend proofs, plus an Ethereum-side wrapped
token (wGHOST) and tooling for bridging, DEX swaps and atomic swaps.

## [Unreleased]

### Added

- `bip39` 3.0 dependency (rust-bitcoin org, `zeroize` feature) via
  `[workspace.dependencies]`.
- Official BIP-39 English test vectors in opacus-crypto: seed round-trips,
  12/15/18/24-word acceptance, checksum/wordlist rejection, passphrase
  separation, v1 rejection, deterministic-RNG generate test.

### Changed

- **BREAKING (wallet keys)**: `SpendingKey` now uses standard BIP-39 English
  mnemonics (ADR r5-bip39-mnemonics, WG-25). `generate()` draws 256-bit entropy
  from the injected CSPRNG and yields a 24-word phrase; the restore path
  (`from_mnemonic`) enforces wordlist membership AND checksum, deriving the seed
  via PBKDF2-HMAC-SHA512 (2048 iterations, 64 bytes). Spend/view derivation is
  re-tagged to `ghost_spend_derive_v2` / `ghost_view_derive_v2` over the BIP-39
  seed. v1 pseudo-mnemonics ("ghost <hex chunks>") are rejected - testnet-only
  keys, no migration path.

- opacus-zk (WG-17): process-wide keyset cache for the v4 spend prover -
  `Params` keyed by k, vk/pk keyed by (DEPTH, n_in, n_out). Keygen is a
  pure function of the circuit structure (never of witness values), so
  cached keysets are bit-for-bit identical to freshly built ones. The
  first prove of a process pays the one-time keygen (~16 s cold at
  mainnet depth); every later call runs at steady-state 7.3-8.0 s prove
  and ~0.1 s verify, inside the 10 s budget [S4 8]. The bench now
  enforces the budget on the steady-state number and records the
  cold-start figure for the future EC-chain column count /
  membership-path count work. Also fixes the stale row-budget doc
  (rows_needed(32) = 5103, not 5006).
- Docs (mainnet gate): SECURITY.md gains a "Mainnet gate (mandatory)"
  section - an independent external security audit of the current main
  MUST be completed and triaged before any mainnet use; testnet burner
  keys are strictly one-time, never reused across rounds and never
  promoted to a network carrying real value. README roadmap marks the
  WG-17 prover budget as delivered.

- Contracts (WG-16 stage 1): the wrapped native token is rebranded to
  wOPACUS ("Wrapped Opacus", contracts/wOPACUS.sol). Redeploy hardening
  (audit WG-16): quorum fixed N-of-M at deployment (constructor range
  checks, QuorumConfigured event, no updateQuorum), the mint digest
  binds block.chainid under the "opacus-lock-v1" domain, the EIP-2
  low-s range is enforced, and the forge suite grew to 10 tests. The
  legacy wGHOST Sepolia deployment cannot be renamed in place (the name
  compiles into the deployed bytecode); its address record stays in
  contracts/wghost.address until the redeploy round.
- opacus-dex: wghost module renamed to wopacus (WOPACUS_ADDRESS env,
  legacy WGHOST_ADDRESS fallback); ABI encoder gained dynamic string
  support (two-pass head/tail); burn() and topics match the contract.

### Fixed

- Security (C-01): the Schnorr nonce of the cross-group DLEq proof
  (`opacus-bridge::xmr_dleq`) was derived from blake3(nano-time + pid),
  making it predictable. A predictable nonce lets an observer recover
  the node secret scalar from the public handshake Auth proof via
  s = r + c*x. The nonce source now draws 32 bytes from the OS CSPRNG
  (rand::rngs::OsRng, already a workspace dependency) and a regression
  test pins nonce non-determinism.
- Security (H-01): the per-node replay cache was locked for the whole
  handshake phase, so one stalled inbound connection could freeze every
  handshake on the node for the socket timeout (a rolling pool of
  stalled dials meant a permanent handshake blackout). The replay-cache
  critical section is now narrowed to the check-and-insert only, the
  handshake phase runs under a dedicated 10 s read budget, and inbound
  handshakes are bounded by a half-open cap (MAX_HALF_OPEN = 64), with
  a regression test per fix.
- Chore (M-09): a merged .gitignore line ("*.log*.bak-tx") left neither
  pattern effective, so debug.log (and any other *.log build artifact)
  was not ignored. The line is split into "*.log" and "*.bak-tx"; both
  rules now work as intended.
- Chore (M-04, M-05, CI): the contracts job no longer swallows failures
  (continue-on-error removed). Foundry is installed from the pinned
  v1.8.5 release and verified against its published SHA-256 before
  unpacking (previously foundry-toolchain@v1 fetched mutable builds
  unchecked). The Rust job gained a cargo fmt --check gate, and a new
  audit job runs cargo audit (RustSec) against Cargo.lock.
- Audit (L-12): tokio bumped 1.54.0 -> 1.54.1 in Cargo.lock (RUSTSEC-2026-0384) and
  a documented audit ignore for RUSTSEC-2026-0387 (crypto-bigint) was added in
  .cargo/audit.toml (transitive dependency, re-evaluate before the next
  release). cargo audit now exits clean.
- Docs (Infra-1): SECURITY.md added - private vulnerability reporting
  procedure (GitHub private advisory channel, supported versions,
  response targets, scope, safe harbor); deny.toml added - cargo-deny
  supply-chain policy (advisories mirror the RUSTSEC-2026-0387
  documented exception, licenses allowlist derived from the locked
  dependency tree, bans/sources at warn). Wiring cargo-deny into CI is
  a tracked follow-up.
- Chore (Infra-2, CI): all workflow actions pinned to full commit SHAs
  (actions/checkout v4.4.0, dtolnay/rust-toolchain stable,
  Swatinem/rust-cache v2.9.3) - mutable tag/branch refs eliminated.
- Chore (Infra-3, CI): cargo-deny wired as a dedicated job (advisories /
  licenses / bans) reading the repository deny.toml policy;
  EmbarkStudios/cargo-deny-action pinned to a full commit SHA (v2.1.1) -
  supply-chain policy now enforced on every push and PR.
- Security (Net-3): the authenticated-connection pool is bounded -
  NetNodeConfig.max_conns (default 128) caps ESTABLISHED connections
  (the H-01 half-open cap bounded only the handshake phase), and a
  duplicate connection from an already-connected peer is rejected
  instead of replacing the live entry (two handler threads for one
  node_id would race the idle-timeout cleanup against the fresh
  entry). The admission decision (try_clone + check-and-insert) runs
  under a single lock acquisition; regression tests cover both guards.
- Chore (Infra-4): the cargo-deny CI job failed on its first run - the
  licenses check reported every workspace member crate as "unlicensed".
  deny.toml assumed the members inherit Apache-2.0 from
  [workspace.package], but no member manifest actually declared
  license.workspace = true (opacus-dex and opacus-zk pin their fields
  directly). All eleven member manifests now declare the license
  (workspace inheritance or an explicit Apache-2.0 field); cargo-deny
  0.20.2 (the exact CI version) verifies clean locally: advisories ok,
  bans ok, licenses ok, sources ok.
- Security (Net-2): the swap plane's session registry grew without
  bound - every inbound Offer (including one arriving through the
  authenticated Upgrade plane) inserted a new tracked session, so a
  single flooding peer could balloon node memory without limit.
  SwapNodeConfig.max_sessions (default 64) now caps the registry: a
  NEW offer arriving at cap is dropped before the state machine (no
  reply, connection kept open, Rejected event), already-tracked offers
  keep their exact DuplicateOffer semantics, and non-Offer frames keep
  flowing on the same connection. v0.1 never evicts sessions, so the
  cap also bounds the registry's lifetime; restart or raise the cap to
  admit new offers again. Regression tests cover the flood drop and
  the preserved duplicate semantics.
- Security (Node-1): the daemon silently ignored DaemonConfig.network -
  whatever the operator configured (or typo'd), the node always ran the
  same hardcoded mix of a mainnet-shaped state over testnet parameters.
  The configured network is now validated strictly ("mainnet" |
  "testnet", case/whitespace normalized) BEFORE any side effect - an
  unknown value refuses startup (InitFailed) and leaves no data dir
  behind - and the consensus bundle flows through one documented
  selection point (pre-mainnet there is exactly one defined parameter
  set - the testnet set, v4 active from genesis - and one normative
  sparse accumulator shape, so both networks resolve to the same
  construction today; that match is the single place to extend when
  mainnet parameters land). The effective consensus parameters are
  logged at startup and opacusd gained a --network flag wired into
  DaemonConfig. Regression tests cover the strict validation, the
  normalization and the testnet selection.
- Security (Net-1): post-auth control-plane frames (Disco, Notes,
  Upgrade) crossed the wire as cleartext JSON - a passive observer saw
  the full peer graph and note metadata, and any in-path attacker could
  read or tamper with every frame after the (authenticated) handshake.
  The handshake now derives transport keys from a static-static ECDH
  over the DLEq-bound identity keys (sk_local * pr_peer - a shared
  secret only the two proven key holders can compute), bound to the
  verified transcript, with separate initiator->responder and
  responder->initiator directions. Every post-auth frame is sealed as
  mac(32) || ciphertext under the per-direction keys (keyed blake3 MAC
  verified BEFORE any decryption, blake3-keystream encryption - the
  same construction family as the note ECIES, no new dependencies),
  and the per-direction frame counters are strictly sequential, so
  replay, reordering and drops all close the connection. The Upgrade
  handover stays the boundary: the net plane's last frame (Upgrade) is
  sealed, the adopted raw socket then speaks the swap protocol as
  before (swap-plane transport is a separate tracked item). The
  handshake version bumps to 2, so a v1 peer is rejected at Hello with
  a clean BadVersion instead of failing on the first post-auth frame.
  Regression tests cover the cross-side key agreement, the
  seq/content binding of the seal/open construction and the cleartext
  rejection at the node level; the existing node-to-node tests now run
  entirely over the encrypted path.

## [0.7.0] - 2026-10-23

Protocol and hardening release: an authenticated connection can now be
explicitly upgraded into the swap plane (NetMsg::Upgrade + attach_swap
handover, opacusd wires both services), and the node identity secret is
zeroized in memory behind a non-Copy SecretScalar wrapper - with the
workspace gate (fmt, tests, clippy -D warnings) fully green.

### Added

#### crates/opacus-network - swap upgrade frame (N3b)
- handshake.rs: post-auth NetMsg::Upgrade{plane} frame - the wire-level
  request to hand an authenticated connection to a named plane; the plane
  is validated structurally (1..=16 chars, no whitespace) and must name
  the one plane served today ("swap"), reusing the Malformed error for
  precise reasons (no new HandshakeError variant).
- net_node.rs: NetNode::attach_swap + NetEvent::Upgraded - after the
  handshake the node serves Upgrade by handing the RAW socket to the
  attached swap node (adopt_stream) at a clean frame boundary; the
  control plane never sees swap frames and the swap plane never sees
  net frames. Without an attached swap plane every Upgrade is rejected
  and the connection closed; strict single-shot is preserved for
  everything else.
- opacusd: when both the net service and the swap service are running,
  the daemon attaches the swap node to the net node, so peers upgrade
  straight into the swap choreography.
- Tests: opacus-network 61 -> 65 (wire roundtrip and bad-plane
  rejection, Upgrade during the handshake, missing swap plane, and an
  end-to-end Offer -> Accept over an upgraded connection).

#### crates/opacus-network - zeroizing node identity secret (F4)
- identity.rs: the secret scalar now lives in a SecretScalar wrapper
  (Zeroize + ZeroizeOnDrop, mirroring the opacus-crypto SpendingKey
  pattern): the scalar is overwritten with zeros when the identity is
  dropped. NodeIdentity is no longer Copy, so an identity cannot be
  silently duplicated; the Debug output still skips the secret, and
  the from_secret/generate/secret/load_or_generate API plus the
  on-disk file format are unchanged.

### Changed

- Workspace version bump 0.6.0 -> 0.7.0 (workspace.package plus the
  explicit crate versions in opacus-dex and opacus-zk; Cargo.lock
  regenerated).
- README: status block and versioning line retargeted to v0.7.0; the
  roadmap Shipped paragraph covers both rounds (v0.6 networking,
  v0.7 protocol + hardening).
- v0.7.0 annotated tag and GitHub release notes.

## [0.6.0] - 2026-10-23

Networking release: the P2P layer grows a persistent node identity, a
DLEq-authenticated handshake, persistent peer discovery with disco gossip,
and encrypted wallet note transmission - all inside crates/opacus-network
with the workspace gate (fmt, tests, clippy -D warnings) fully green.

### Added

#### crates/opacus-network - networking phases N1-N3
- identity.rs (N1): persistent node identity - ristretto scalar plus
  compressed public key, deterministic from a 32-byte secret, atomic save
  with 0600 permissions and backup-collision guard, zero-scalar rejection.
- handshake.rs (N1): DLEq-authenticated handshake over the length-prefixed
  opacus-net-v1 wire: transcript hashing, forged-transcript and tampered
  DLEq rejection, wrong-key and replay rejection, replay cache with cap
  eviction, strict frame-size and peer-id caps, and a notes frame during
  the handshake disconnects (HandshakeError::NotesTooLarge).
- peers.rs (N2): persistent peer store - bounded cap with oldest eviction,
  insert dedupe with monotonic last_seen, remote-batch merge with
  self/conflict skips, corrupt-file quarantine, disco batch roundtrip.
- net_node.rs (N2-b): authenticated network node - every post-auth frame
  is Disco | Notes bound to the authenticated peer, disco gossip
  propagates through common peers, a bounded NoteInbox dedupes by the
  public note id, the bounded flood relay decrements the hop budget and
  recomputes the public id, send_notes targets one authenticated peer,
  NotesObserved event, opacusd wiring.
- notes.rs (N3): encrypted note feed - blake3-only ECIES to the recipient
  ristretto identity key (shared = e * pr; session keys via blake3
  derive_key over epk/pr/shared/nonce; keyed-blake3 keystream),
  encrypt-then-MAC verified BEFORE any decryption, an OPAQUE payload
  owned by the wallet layer, a public blake3 id digest any relay can
  verify and dedupe on, and a hop budget a relay can decrement WITHOUT
  keys (the MAC does not cover hops; the relaying node recomputes the
  public id); zero-hop blobs are stored but never relayed.
- Tests: opacus-network 10 -> 61, opacus-node 7 -> 8.

### Changed
- Workspace version bump 0.5.0 -> 0.6.0 (workspace.package plus the
  explicit crate versions in opacus-dex and opacus-zk).
- README: status line retargeted to v0.6.0; networking sections in the
  workspace layout, components, and the test matrix; roadmap updated
  (networking items shipped).
- CI: the rust job now enforces clippy with -D warnings on the whole
  workspace (the README warning-free claim is CI-checked).
- v0.6.0 annotated tag and GitHub release notes.

### Fixed
- CHANGELOG: stray literal backtick-r artifacts in the 0.5.0 entry.

## [0.5.0] - 2026-10-21

- daemon binary renamed to opacusd; daemon struct renamed to OpacusDaemon (crate opacus-node)
- workspace version bump 0.4.0 -> 0.5.0
### Changed
- Rebrand: the workspace moved to the opacusio GitHub org and every crate
  was renamed `ghost-*` -> `opacus-*` (packages, libraries, the
  `cli/ghost` -> `cli/opacus` binary `ghost` -> `opacus`, workspace
  members, cross-crate dependencies, imports, benches, CI and docs).
  Deliberately unchanged: wire-protocol strings (`ghost-swap-p2p-v1`,
  `ghost-swap-offer-id-v1`), circuit domain labels (`GHOST/v4/*`), the
  Poseidon label (`ghost-zk-poseidon-v1`) and the wGHOST token.

- Deferred: v4 prover optimization (EC-chain column count, membership-path count) retargeted to the next minor release.
## [0.4.0] - 2026-10-20

Value conservation release: the full FCMP++-style v4 spend pipeline now
enforces in-circuit balance end to end - zk circuit, transaction
serialization, wallet, and consensus - with an activation-height gate, a
prover benchmark, and a documentation refresh
(docs/specs/v0.4-value-conservation.md, sections [S4 1-13]).

### Added

#### crates/ghost-zk - v4 gates and the full spend circuit (phases 1a, 1b, 2)
- v4 foundations: rc-limb range-check gates, v4-hash gates, generator test
  vectors.
- Fixed-base scalar-mul chip: RC = v*V + r*R and the H_leaf*G3 term are
  computed in-circuit as public instances over hashgen constants - no
  in-curve arithmetic needed, the bit columns are shared with the
  range-checked limbs.
- Nullifier-v4 linking, leaf-v2 note commitments, and the value
  commitment primitives (value_commit / value_gen / blind_gen).
- V4SpendCircuit: 1-in / 2-out spend topology (MAX_IN = 2, MAX_OUT = 4)
  with balance padding; 15-slot normative public instance vector
  [root, N_0..N_1, RC_in_0..RC_in_1, RC_out_0..RC_out_3]; k = 13 at
  mainnet tree depth 2^32; binding signature over the instance vector
  (unbalanced or tampered spends fail verification).
- v4_prover: normative instance reconstruction (spend_instances), a
  mock-prover self-check available WITHOUT the real-prover feature, and
  real IPA prove_v4 / verify_v4 (params + keygen + create_proof /
  params + vk rebuild + verify_proof).
- acc_root_point bridge between the Fp accumulator root and the
  curve-point form consumed by sighash_v4.

#### crates/ghost-wallet - tx v4 serialization and zk-native flow (phase 3)
- tx_v4.rs: canonical v4 transaction serialization feeding the exact
  15-slot instance vector; build_zk_spend_v4 and confirm_zk_tx mirroring
  the consensus confirmation order.
- The wallet end-to-end cycle (build / prove / verify / confirm) is green
  at mainnet tree depth 2^32.

#### crates/ghost-consensus - consensus v4 validation (phase 4)
- accept_transaction: v4 validation order [S4 9] - parse, proof verify,
  balance and binding signature, nullifier seen-set, tree root, fee
  floor, commit - with zero state mutation before ALL checks pass.
- Activation-height gate: after CONSENSUS_V4_ACTIVATION_HEIGHT only v4
  transactions are accepted (v3 rejected; a v4 transaction earlier than
  the height is rejected as EarlyV4; legacy structure remains valid only
  before activation).
- ConsensusParams (with testnet()) and ConsensusState (mainnet(), tree +
  seen-set), the Accept/Reject taxonomy, and confirm_v4_consensus.

#### crates/ghost-node - daemon submit gate (phase 4)
- submit_transaction routes every incoming transaction through consensus
  accept_transaction; rejections surface as TxRejected before any pool or
  state effect; the daemon exposes params() and consensus().

#### repository - bench, docs, release (phase 5)
- crates/ghost-zk/benches/prover.rs: deterministic full-pipeline v4 spend
  benchmark (prove_v4 / verify_v4 stage timing) at 2^32 leaves; zero new
  dependencies; run with
  `cargo bench -p ghost-zk --features real-prover --bench prover`.
- README.md refreshed for v0.4.0 (v4 sections, bench, updated test
  matrix, Apache-2.0 license note); workspace version bumped to 0.4.0;
  CHANGELOG updated; v0.4.0 tag and GitHub release published via the
  release_ghost.ps1 path.

### Performance

- Full v4 spend at 2^32 leaves (real IPA, k = 13): the new bench measures
  the prove pipeline at about 16 s on the reference machine against the
  10 s budget [S4 8]; the optimization work (EC-chain column count,
  membership-path count) is queued for v0.5. The membership-only v0.3.0
  baseline (2.1 s prove + verify) is unchanged.

### Security

- Consensus v4 mutates state only after every validation step passes;
  nullifier replay is rejected via the seen-set; the fee floor is
  enforced at consensus level; the activation-height gate prevents mixed
  v3/v4 replay across the fork boundary.

## [0.3.0] - 2026-10-18

Initial public release.

### Added

#### crates/ghost-zk - Halo2 FCMP++ zero-knowledge layer
- Poseidon permutation (t=3, x^5 S-box, 64 uniform full rounds, circ(2,1,1)
  MDS matrix, blake3-derived round constants) over the Pasta (Vesta) scalar
  field, with a commutative tree hash h_tree = P(D, a+b, a*b) that removes
  direction bits from the witness path.
- Sparse Merkle frontier at mainnet tree depth 2^32: empty-subtree-root
  padding gives O(leaves + depth) root and authentication-path computation,
  so the mainnet-size tree is never materialized in memory.
- FcmpCircuit: single-region Halo2 circuit (65 rows per permutation), gates:
  poseidon-round (degree 5 + absorb masking), init-zero, tree-add, tree-mul;
  public instances expose the note-commitment-tree root and the nullifier.
- Real (non-mock) prover/verifier over Vesta behind the `real-prover`
  feature, using the halo2_proofs 0.3.5 IPA commitment scheme (zcash
  lineage): batch create_proof, plonk::SingleVerifier verification.
- Tests: 10 default + 11 with `real-prover` (real IPA prove/verify plus
  tamper rejection) + a mainnet-depth MockProver check (k=12, 2342 rows);
  a real spend proof at mainnet tree depth 2^32 proves and verifies in
  about 2.1 s.

#### crates/ghost-wallet - shielded wallet layer
- zk_spend.rs: canonical Fp <-> 32-byte serialization, persistable
  WalletNote, in-memory TreeState with a mainnet() constructor, witness
  builder, and ZkSpendTx build/verify helpers that prove and self-verify
  BEFORE any wallet state mutation.
- light_wallet.rs rewritten zk-native while preserving the public API:
  shielded balance (total/spendable/pending), incoming-note confirmation,
  build_zk_spend with single-note selection and change handling,
  confirm_zk_tx mirroring consensus (all output commitments appended to
  the tree in transaction order), a nullifier seen-set registry, and tree
  introspection helpers.
- End-to-end mainnet-depth test: full build/prove/verify/confirm cycle of
  a shielded payment at tree depth 2^32.

#### crates/ghost-bridge - Monero bridge
- xmr_dleq.rs: cross-group Schnorr DLEq proving that one scalar controls
  both the Monero/Edwards key and the Ristretto key (blake3 challenge,
  wide mod-l reduction, 96-byte serialization).
- xmr_swap.rs: atomic-swap state machine Offered -> Accepted -> XmrLocked
  -> GhostLocked -> Claimed/Refunded with fund/claim timeouts, Maker/Taker
  roles, blake3 hashlock, and observable lock transitions.
- xmr_rpc.rs: monero-wallet-rpc client (transfer with unlock_time and
  payment_id = hashlock, get_transfers filtered by payment_id, balance and
  address queries) plus monerod get_info, behind a Transport trait with
  fake-transport tests.
- swap_p2p.rs: swap P2P protocol core - SwapNetMessage enum (Offer, Accept,
  XmrLocked, GhostLocked carrying the preimage, Claim, Refund), u32-LE
  length-prefixed JSON framing, tamper-evident blake3 offer ids, and a
  session registry that reuses the xmr_swap state machine as the single
  source of truth (replay, duplicate, forged-claim and timeout validation).

#### crates/ghost-dex - Ethereum side (new crate)
- Minimal RLP encoder/decoder verified against known vectors.
- ABI encoding with keccak selectors (Uniswap V2 well-known selectors
  verified), including head/tail encoding with dynamic offsets.
- Legacy EIP-155 transaction signer (k256 ecdsa): keccak256 prehash, v =
  parity + 35 + 2*chainId, with a raw-transaction roundtrip test that
  recovers the sender address.
- Uniswap Router02 (0x7a25...) calldata builders: getAmountsOut,
  swapTokensForTokens / swapTokensForETH, WETH wrap, ERC-20
  approve/transfer/balanceOf.
- Ethereum JSON-RPC client (eth_call, gasPrice, transaction nonce,
  estimateGas, sendRawTransaction) over blocking HTTP with fake-transport
  tests.
- wGHOST helpers: set_wghost/burn calldata and Mint/Burn event topics.

#### crates/ghost-network - swap node
- swap_node.rs: TCP swap node reusing ghost-bridge::swap_p2p - framed
  socket I/O with declared-length caps, SwapNodeConfig, listener plus
  bootstrap dialing, a full-duplex connection loop with automatic protocol
  replies (Offer->Accept, GhostLocked->Claim) on the same socket,
  protocol-violation disconnects, and a bounded node-event ring log.
- End-to-end test: complete swap choreography Offer -> Accept -> XmrLocked
  -> GhostLocked (preimage) -> Claim across two live TCP nodes on
  127.0.0.1:0.

#### contracts/ - wGHOST token
- wGHOST.sol: ERC-20 wrapper with quorum-gated mint (sorted-signature
  ecrecover check) and burn-for-release; deployed to the Sepolia testnet
  (address tracked in contracts/wghost.address), quorum threshold 1/1 for
  testnet. Marked AUDIT REQUIRED.
- wGHOST.s.sol + foundry.toml: reproducible forge deployment script with
  environment-configured quorum signers (kept minimal pending forge-std
  restore).

#### Repository root - zero-typing Windows tooling (PowerShell)
- Sepolia deploy chain: run_sepolia_deploy.ps1 (funds gate, in-process
  deployer key) -> deploy_wghost.ps1 -> finalize_wghost.ps1 (bytecode gate,
  soft token calls, hard quorum cross-checks, WGHOST_ADDRESS persistence).
- fix_deployer_key.ps1: zero-input deployer key rotation with
  cross-verification.
- publish_ghost.ps1: safe one-command GitHub publish (secret gates, no
  force-push).

### Fixed
- ghost-zk did not compile (16 errors: E0061/E0382/E0425/E0599): the crate
  was adapted to the actual halo2_proofs 0.3.5 (zcash lineage) API -
  closure-based assign_advice/assign_fixed, query_fixed without rotation,
  Selector::enable instead of Region::enable_selector, AssignedCell::
  copy_advice instead of assign_advice_from, constrain_instance taking
  Cell by value, batch create_proof with triple-nested instances, and
  plonk::SingleVerifier; ff 0.13 has no Fp::from_u64.
- Out-of-memory in tree root computation: materializing 2^32 leaves
  (about 137 GB) replaced by empty-subtree-root padding.
- EIP-155 signing originally used SHA-256 as the prehash - replaced with
  keccak256 and the correct v = parity + 35 + 2*chainId.
- ghost-bridge Cargo.toml crashed cargo ("cannot extend value of type
  inline table with a dotted key") when dependency insertion met
  workspace-inheritance manifests (serde.workspace = true): the manifest
  was repaired to a self-contained form; non-conflicting workspace
  inheritance is preserved.
- u128_to_be32 wrote 16 bytes into an 8-byte slot; approve test word
  offset; RLP long-form list header (0xF8) offset; RPC fake envelope
  shape.

### Security
- Deployer key hygiene: the globally known public Foundry anvil #0 key
  (0xf39F...92266) was detected as the Sepolia deployer and sole quorum
  member (anyone could mint wGHOST) and rotated to a freshly generated
  random key. deployer.key is never committed; the old key is kept only in
  a local git-ignored .bak file.
- Repository publishing excludes secrets by construction: a .gitignore
  guard set (deployer.key*, *.key, *.pem, .env*, *.bak*, tools/, build
  artifacts) plus an index-level secret gate that untracks offenders while
  keeping the files on disk; commits use the noreply GitHub identity.

### Test status (zero warnings in all crates)
- ghost-zk: 10 + 11 (real-prover) + 1 mainnet-depth mock
- ghost-wallet: 7 fast + 2 mainnet-depth end-to-end
- ghost-bridge: 27 | ghost-dex: 13 | ghost-network: 8

### Known limitations / roadmap
- Value conservation is not yet enforced in-circuit (v0.4 accumulator per
  the complete FCMP++ design); nullifier-reuse prevention is currently
  consensus-side.
- Swap enforcement is off-chain in v0.1: hashlock-in-circuit and CLSAG
  adaptor signatures are planned for v0.4; Refund frames are notices;
  swap heights are taken from configuration.
- ghost-network has direct dials only; peer discovery/gossip and peer
  authentication (DLEq-bound identities) are planned next.
- Encrypted note transmission between wallets (out-of-band note-secret
  transfer today) is a networking-phase item.
- An external audit is REQUIRED before any mainnet use; testnet keys are
  throwaway and never committed.
