# Changelog

All notable changes to the **Opacus** monorepo are documented in this file.
The initial public release consolidates the full pre-history of the private
development phase; every further change will be added here following the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format and
[Semantic Versioning](https://semver.org/).

Opacus is a privacy payment network that fuses Monero-style ring-CT semantics
with Zcash-style Halo2 FCMP++ spend proofs, plus an Ethereum-side wrapped
token (wOPACUS) and tooling for bridging, DEX swaps and atomic swaps.

## [Unreleased]

### Changed

- Project rebrand completed: the legacy internal codename is scrubbed
  from the entire tree. The consensus and wire domain tags are renamed
  (`OPACUS/v4/...`, `OPACUS/v5/...`, `opacus_final_v1` PoW tag,
  `opacus-ballot-archive-v1`, `opacus-swap-p2p-v1`), the swap wire
  states and fields follow (`OpacusLocked`, `opacus_atoms`,
  `maker_opacus_address`), the miner core is `opacushash`, the node
  data dir is `~/.opacus`, the env surface is `OPACUS_NET*` /
  `OPACUS_SWAP*`, the key-derivation domain tags follow
  (`opacus_spend_derive_v2` / `opacus_view_derive_v2`, the pinned
  official-vector spend/view rows recomputed over the published BIP-39
  phrases and seeds), and the ticker reads OPACUS. The CLI ships the single
  canonical binary name `opacus` (the duplicate second bin target is
  gone); the daemon stays `opacusd`. Renamed with the code:
  `opacus-miner/src/opacushash.rs`, `contracts/wopacus.address`. The
  one-off migration scripts of the early deployment rounds are removed
  from the repo root; `deploy_wopacus.ps1` and `publish_opacus.ps1`
  remain as the deploy/publish entry points. Pre-mainnet window: the
  parameter-set rename is consensus-visible, so the R0 golden vectors
  and the R1 drop-dir artifacts are regenerated deterministically (same
  seed, same shape, new tags) and the R2 smoke is re-validated on the
  renamed surface.

### Added

- WG-CLSAG-adaptor monerod-compatible CLSAG adaptor signatures
  (opacus-bridge, `clsag_adaptor.rs`): a Monero one-time spend is
  pre-signed as a STANDARD CLSAG bound to the hidden swap secret t -
  pre-signature s'_di = a - t - c_di*(mu_P*x + mu_C*z) with the
  monerod-compatible aggregation hashes (CLSAG_agg_0 / CLSAG_agg_1),
  round skeleton (CLSAG_round) and real elligator Hp from
  `clsag_verify.rs`, and the auxiliary image D = [z/8]Hp(P) (the
  verifier consumes D8 = [8]D, so only z/8 closes the R-leg). The
  bilateral adaptor block {T = [t]G, T_h = [t]Hp(P), R_G = [a]G,
  R_H = [a]Hp(P), di} never enters any challenge input: the initial
  challenge is the standard monerod one over the nonce points
  H(round_skeleton || R_G || R_H), so completing with t (s_di = s'_di +
  t) yields a signature that passes the UNMODIFIED monerod-compatible
  verify_clsag - the acceptance gate - and the completed on-chain
  signature hands the adaptor holder the secret t = s_di - s'_di
  (fail-closed [t]G == T and [t]Hp(P_di) == T_h consistency checks).
  verify_adaptor reuses the monerod challenge chain verbatim and adds
  only the two binding equations L'_di + T == R_G and
  R'_di + T_h == R_H; the signer index di is bilateral off-chain data
  and stays hidden on-chain (the completed signature is an ordinary
  CLSAG). Deterministic domain-separated nonce
  (opacus-bridge/clsag-adaptor/nonce-v1 / .../decoy-v1); fail-closed
  discipline: canonical scalars < l, decompressible and non-degenerate
  T / T_h / R_G / R_H / I / D / ring points, degenerate secrets (x, t,
  z = 0) rejected at signing, non-canonical t rejected at completion.
  24-test matrix P1-P6 / N1-N18 (honest loop through the unmodified
  verifier, determinism, D = [z/8]Hp algebra, di edges, ring size 2,
  tamper matrix over every adaptor field, ring substitution,
  non-canonical encodings, degenerate points, wrong-secret completion
  and recovery). The v0.3 single-signer primitive `clsag.rs` stays
  untouched; scope doc docs/WG-CLSAG-adaptor-scope.md. opacus-bridge:
  86 -> 110 lib tests (+ 6 fixture).

- WG-CLSAG-adaptor-int swap protocol integration (opacus-bridge,
  `xmr_swap.rs` + `swap_p2p.rs`): the CLSAG adaptor becomes a
  fail-closed part of the XMR <-> OPACUS swap coordination protocol,
  closing the deferred section-6 item of the adaptor scope doc. The
  taker pre-signs the Monero-side claim spend of the locked XMR via
  `XmrClaimAdaptor::build` (over `sign_adaptor`) bound to the swap
  secret t = hash_to_scalar("opacus-bridge/swap-secret-v1" || preimage)
  - reduced mod l by the monerod hash_to_scalar, domain-separated from
  the hashlock and the WG-21 offer OTK - and the bilateral claim
  message blake3("opacus-swap/xmr-claim-msg-v1" || offer_id ||
  hashlock). The adaptor rides the existing Claim frame as an OPTIONAL
  Frame-level sidecar `xmr_claim` (hex `XmrClaimSidecar`, serde
  default: v1 frames decodable, old binaries ignore the field, offer
  ids untouched); the taker attaches it in OpacusLocked via
  `attach_xmr_claim` and sends it with `publish_claim` (driving the
  local state machine to Claimed). The maker's Claim handler verifies
  the adaptor against THIS swap (`verify_for`: message binding + the
  monerod challenge chain and L'/R' binding equations) and completes
  it with his OWN preimage (`complete_xmr_claim`: `complete` enforces
  [t]G == T) BEFORE accepting the claim - the result must pass the
  UNMODIFIED monerod-compatible verify_clsag, the completed signature
  is stored on the session (`xmr_completed`) and `recover_secret`
  hands the holder t from the on-chain signature. Fail-closed
  (WG-22 pattern): an invalid sidecar rejects the whole frame before
  any state transition (no peer_claimed, the refund window keeps
  running); a Claim WITHOUT the sidecar follows the v1 path unchanged;
  the sidecar is rejected on any non-Claim frame.
  SwapError::{MissingPreimage, XmrClaimInvalid};
  SwapNetError::XmrClaimSidecar. 17 new tests (P1 honest loop over the
  wire through the unmodified verifier + recover_secret round trip,
  P2 deterministic lossless sidecar roundtrip, P4 legacy path
  unchanged, N1-N13 tamper / substitution / binding / structural
  matrix). Network and node layers untouched (they consume
  SwapNet::receive_frame). Scope doc
  docs/WG-CLSAG-adaptor-int-scope.md. opacus-bridge: 110 -> 127 lib
  tests.
- GIP-0, the Opacus Improvement Proposal process (docs-only,
  `docs/gips/GIP-0-gip-process.md`, ZIP 0 analog): GIP types
  (Standards Track / Process / Informational), lifecycle
  Draft -> RFC (>= 7 days) -> Accepted -> Activated (+ Rejected /
  Withdrawn / Superseded), monotonic numbering never reused, the
  normative section template, and the WG/WP linkage rule - every work
  package touching consensus, wire, bridge, wallet or economics cites
  the GIP it implements; WG-16..WG-29 / WG-CLSAG* / PROVER-10S are
  grandfathered. Release discipline pinned: consecutive minor tags,
  tag <-> CHANGELOG section 1:1, release notes composed from the
  CHANGELOG (tag chain v0.3.0..v0.9.0 verified consecutive; v0.8.0 =
  da222bf, 2026-10-28). Future governance items (Opacus Grants funding
  model, decentralized OG/OC voting) will land as GIP documents before
  code.
- GIP-1, the Opacus Grants (OG) ecosystem funding model (docs-only,
  `docs/gips/GIP-1-og-funding-model.md`, Status: Draft - RFC window
  opens on merge): two-stage policy. Stage 0 (now) - CCS-style
  transparent public accounting, 0% of emission, no on-chain fund.
  Stage 1 (on-chain grants fund from block_reward) only after explicit
  conditions (block_reward wired into consensus validation - today it
  is defined but unused, per the v0.4 "consensus issuance policy" trust
  boundary; mainnet; audit cycle) and only within hard caps: fixed % of
  block subsidy only, mandatory sunset height, transparent fund
  addresses reconstructable from chain data, extension exclusively via
  coinholder vote (GIP-2); perpetual funds, opaque recipients and
  retroactive reallocation are MUST NOT. Prior art: ZIP 1014/1015/1016
  (Founders' Reward -> Canopy -> lockbox -> coinholder voting), Monero
  CCS, Dash masternode treasury, Decred Politeia. Open questions for
  the RFC window: Stage 1 percentage, payout cadence, interim
  custodian, wOPACUS treasury interaction.
- GIP-2, decentralized OG/OC voting (docs-only,
  `docs/gips/GIP-2-og-oc-voting.md`, Status: Draft - RFC window opens
  on merge; supersedes GIP-1 section 3.1(4) on activation): voting
  weight from PRIVATE balances via ZK proof-of-balance built on
  existing primitives - FcmpCircuit-style membership proof against a
  snapshot anchor (sparse frontier root at H_snap), in-range value-sum
  proof, and a domain-separated vote serial VS =
  Poseidon_3(vs_key, vote_rho, DOM_VS) for one-time use per proposal
  WITHOUT spending the voted notes (nullifier pattern, vote domain).
  Stage A: off-chain tally of ZK ballots, no consensus changes, outcome
  recorded as GIP minutes. Stage B (separate Standards Track GIP):
  on-chain coinholder voting, ZIP 1016 analog - chain-enforced VS
  seen-set, WG-27-style deterministic verdicts. Burn-to-vote and
  N-of-M quorum / Key-Holder veto are REJECTED; an N-of-M multisig
  remains only GIP-1's interim custodian. Normative requirements
  R1-R7 (private weight, snapshot anchor, double-vote resistance, GIP
  proposal registry, fixed windows, quorum, no silent chain changes).
  Open questions for the RFC window: snapshot cadence and pinning,
  quorum thresholds, ballot transport (raw vs WG-29 sealed enotes),
  post-snapshot note movement, dedicated vote circuit vs reuse of v4
  mechanics, delegation.
- GIP-1/GIP-2 RFC parameter positions (docs-only, section 9 of GIP-1
  and sections 9-10 of GIP-2; PROPOSED for the RFC window - not
  activated). GIP-1 section 9 pins the declining allocation schedule:
  10% / 10% / 5% of each epoch's own block subsidy with automatic 0%
  from block 630,000 (341,250,000,000,000 atomic units over three
  ~292-day epochs, ~2.4 years at 120 s blocks; 9.29% of the epochs'
  emission and 8.125% of total emission; flat 10% over the same window
  would be 367,500,000,000,000, so the decisive anti-capture mechanism
  is the auto-sunset, which removes manual renewal as a decision class
  and makes GIP-2 Stage B voting a deadline). GIP-2 section 9 pins the
  Stage A organization: exact weighted split-safe ballots (threshold
  models rejected - a T*N balance splits into N votes without identity
  to stop it), K <= 8 notes per ballot (k = 10..13 on existing
  v4/FcmpCircuit mechanics, ~10 s proving envelope), T_min = 10^6
  atomic units, H_snap = H_open with a 14-day window declared in
  advance, WG-29 sealed-enote transport with a mandatory public ballot
  archive, deterministic off-chain tally over the consensus-derived
  supply denominator with a 720-block challenge window, quorum 5%
  (fund decisions) / 2% (process) and 60% YES+NO approval for fund
  decisions, fail-closed status-quo defaults, Stage B trigger tied to
  GIP-1 Stage 1 with the block-630,000 deadline, and recorded known
  limitations (no private per-owner caps, vote-buying not fully
  solvable, custodial abstention). GIP-2 section 10 adds a
  non-normative plain-language summary (what is voted on, who votes,
  what does not need a vote).
- GIP-2 WP-3, the WG-29 ballot transport profile plus the raw fallback
  (third CODE deliverable of the GIP-2 RFC window; P-4;
  `crates/opacus-wallet/src/gov_transport.rs` +
  `crates/opacus-crypto/src/ecies.rs`, additive - no existing wallet,
  circuit, wire, network or consensus file changes semantics). The
  crypto side completes the WG-29 ECIES tag-parameterization:
  `BALLOT_TAGS` (a third domain-separated instantiation next to the N3
  note feed and the in-transaction enote), `BALLOT_DERIVE_TAG` +
  `keypair_from_seed_tagged` (the ballot collector key is a derivation
  of the collector's BIP-39 seed - no new trust root, GIP-2 section 7),
  and variable-length `seal_with_tags` / `open_with_tags` (the
  fixed-size enote paths delegate to the same core byte-identically;
  the existing enote test suite is the regression gate). The primary
  transport is the `GBE1` ballot envelope: magic + version + the
  proposal tag `(gip, transition, h_open)` in CLEARTEXT (public by
  construction, P-3 - enables bucket routing without opening) + the
  WG-29 sealed blob `epk 32 || nonce 16 || ct || mac 32` over the
  canonical ballot wire, with a 256 KiB profile cap on the parse path.
  Envelope semantics: the cleartext tag MUST match the ballot header
  after opening (relabelled envelopes fail closed,
  `HeaderMismatch`); the envelope id is the WG-29 id digest under the
  ballot tags - the v5 gossip relay dedupe key (randomized per seal,
  stable per byte-string); wiring the gossip channel is
  node-integration work outside the profile. The fallback transport
  is raw publication of the canonical ballot bytes - documented
  WEAKER (choice, weight and serials are public before close; copying
  stays useless for double-voting because serials are one-time
  tokens, R-3). The collector-side `BallotArchive` is the auditable
  minutes of P-4: per-proposal scope, ingests BOTH transports, checks
  parse + scope only, dedupes ONLY byte-equal retransmissions, and
  deliberately performs NO cryptographic verification - every verdict
  (shape, dust, anchor, proposal, ZK proof, binding signature,
  duplicate serials) belongs to the tally engine's published trace
  (`crate::tally::tally`), so rejected and duplicate-vote attempts
  stay visible in the minutes instead of being silently filtered.
  Close artifacts: `publish()` emits the entries (canonical ballot
  wires in arrival order, directly consumable by the WP-2 tally) plus
  `archive_id` - blake3 over the per-entry digests in ARRIVAL order;
  the minutes fingerprint their submission history while the tally
  `result_hash` stays order-invariant (different arrival orders =>
  different `archive_id`, SAME `result_hash`). Tests: opacus-wallet 9
  new (ballot-key tag separation, seal/open roundtrip with randomized
  envelope ids, wrong-key + tamper + magic/version/truncation/oversize
  matrix, relabelled-envelope and cross-tag fail-closed, raw fallback
  roundtrip, sealed-vs-raw transport neutrality - same result hash and
  weight totals from differently ordered archives, retransmission
  dedupe with a double-vote attempt kept in the minutes and rejected
  as DuplicateSerial by the tally, archive-scope and proposal
  mismatch, blind-archive + tally-Dust replay) and opacus-crypto 4 new
  (variable-length roundtrip incl. the empty plaintext, ballot/enote
  cross-instantiation isolation, tagged-derivation equivalence with
  `note_keypair_from_seed`, short + tampered rejection matrix).
- GIP-2 WP-2, the deterministic Stage A tally engine (second CODE
  deliverable of the GIP-2 RFC window; `crates/opacus-wallet/src/tally.rs`,
  additive - no existing wallet, circuit, wire or consensus file changes
  semantics; the only touch elsewhere is a `Clone` derive on `GovError`):
  processes the published ballot archive (GIP-2 3.2 step 4 / P-5) in
  CANONICAL ORDER - entries sorted by ballot bytes, byte-equal copies
  keeping submission order - so the accepted set, the weight totals and
  the result hash are independent of the archive arrival order: the P-5
  replay guarantee. Per ballot: strict canonical parse, the DECLARED
  anchor gate FIRST (P-3 fail-closed: the archived H_snap frontier root
  stands; a stale or foreign snapshot is reported as such), the declared
  proposal identity (gip / transition / h_open / derived proposal), full
  standalone verification (shape, T_min = 10^6 dust floor, the ZK
  proof-of-balance over instances reconstructed from the fields alone,
  the binding signature - the milliseconds-per-ballot budget of P-5) and
  one-vote-per-serial over a SeenSet (R-3; the same-note-same-proposal
  VS determinism of WP-1 makes a plain seen-set sufficient).
  Per-ballot rejection is TRACEABILITY, not a fatal error: every archive
  entry gets a verdict line - accepted / Malformed(GovError) /
  ProposalMismatch / AnchorMismatch / DuplicateSerial - with the sighash
  when the bytes parse. The decision rule is P-6 verbatim (u128
  internals, no overflow paths): quorum 5% of the emission denominator
  for fund decisions and 2% for process transitions with ABSTAIN
  counting toward participation only, approval 60% of YES+NO weight for
  fund decisions and simple majority for process votes (an exact tie
  rejects, fail-closed); quorum not met = NoQuorum = status quo
  persists; a zero denominator (H_open = 0) and an all-ABSTAIN quorum
  approve nothing. The public quorum denominator `emission_upto(h) =
  sum(block_reward(0..h))` (P-5) is the closed form over the halving
  eras mirroring `opacus_consensus::block::block_reward` - the wallet
  cannot depend on consensus without a dependency cycle (consensus
  already depends on the wallet), so the consensus-side sync test
  `crates/opacus-consensus/tests/gov_emission_sync.rs` pins the two
  implementations together at 17 heights (an emission-schedule change is
  a Standards Track GIP (R-7) and MUST touch both). The published
  `TallyRecord` (canonical wire, strict parse, exact length) commits via
  blake3 `result_hash` to the declared parameters, the weight totals and
  the sorted sighashes of the ACCEPTED ballots ONLY: halo2 blinding
  never enters the hash, so two independent runs over the same archive
  produce the SAME result hash (the golden-vector property), and
  rejected entries are trace metadata, not hash inputs.
  Tests: opacus-wallet 8 new (emission golden values incl. era
  boundaries and the 34-era convergence, the hand-computed P-6 decision
  matrix with exact-boundary cases incl. the all-ABSTAIN quorum and the
  degenerate denominator, record wire roundtrip with strict framing, a
  fund vote end-to-end with the full 7-entry rejection trace plus
  reverse-order replay equality, fund rejection below 60% despite
  quorum, all-ABSTAIN NoQuorum, process majority in both directions
  plus class-as-hash-input, and blinding/order independence of the
  result hash) and opacus-consensus 1 (the denominator sync guard).
- GIP-2 WP-1, the Stage A governance ballot builder (first CODE
  deliverable of the GIP-2 RFC window; `crates/opacus-zk/src/vote.rs` +
  `crates/opacus-wallet/src/gov.rs`, additive - no existing circuit,
  wire, consensus or wallet file changes semantics; only visibility
  `pub(crate)` upgrades in spend.rs so the ballot circuit can reuse the
  gadget suite): the vote chain `vs_key = Poseidon_3(a, b, DOM_VSK)`,
  `vote_rho = Poseidon_3(rho, proposal, DOM_VRHO)`,
  `VS = Poseidon_3(vs_key, vote_rho, DOM_VS)` with NEW domain constants
  DOM_VSK / DOM_VRHO / DOM_VS (`OPACUS/v4/dom/{vsk,vrho,vs}` labels) -
  domain-separated from the spend nullifier, so a vote never reveals or
  burns spending capability [GIP-2 7]. One `BallotCircuit<DEPTH, K>`
  proof per ballot (K in 1..=8, GIP-2 P-2) proves, from public
  instances `[root, proposal, V, VS_1..VS_K]`: membership of every
  note's tree entry at the snapshot anchor (v4 leaf chain
  `[s]G + [h]G3`, entry `P(L.x, L.y, DOM_ACC)`, commutative walk), the
  range-checked weight sum `V = v_1 + ... + v_K` (rc-limb gate per
  note; sound because membership pins each v_i to a REAL committed
  note, all < 2^64) and the in-circuit vote serials - the proposal
  identity feeds `vote_rho` IN-CIRCUIT from a public instance, so VS is
  a deterministic function of (note, proposal): a note revoting the
  same proposal derives the SAME VS and the tally seen-set rejects the
  duplicate (R-3), while different proposals derive fresh serials and
  nothing links them. Row budget lands on the GIP-2 P-2 estimate:
  K = 8 at mainnet depth 32 -> k = 13 (K = 1 test shape -> k = 9).
  Mock + real-prover paths with a (DEPTH, K)-keyed process keyset cache
  (the WG-17 pattern). Ballot binding signature (GIP-2 3.2) signs the
  ballot sighash `blake3("OPACUS/v4/gov/sighash", ...)` under a
  per-ballot keypair `bsk = H(owner shares, proposal)`,
  `bvk = [bsk] * R`: only the owner of both key shares can sign, the
  choice flip breaks verification, and the verification key does not
  link a voter's ballots across proposals. The wallet builder
  (`gov.rs`) enforces K <= 8, checked weight sum, T_min = 10^6 dust
  floor (P-2), recomputes every path to the anchor BEFORE proving
  (wallet-first-validator), self-verifies the fresh ballot, and ships
  the canonical wire format with strict parse (canonical encodings, no
  trailing bytes); `verify_ballot` reconstructs the proof instances
  from the ballot fields alone, `verify_ballot_against_tree` pins the
  anchor to a local frontier (foreign-anchor and stale-snapshot
  gates), `register` is the tally-side duplicate-VS primitive (WP-2
  formalizes the engine). Honest note: GIP-2 P-9 said "no new circuit
  for the first iteration" - implementation showed the value-sum
  REQUIRES the v4 leaf chain, which the spend circuit only exposes
  with DOM_NU nullifier reveals (a vote would burn its notes); WP-1
  therefore ships the additive BallotCircuit reusing the gadget suite
  unchanged, and GIP-2 sections 6/9 are amended by the same delivery.
  Tests: opacus-zk 9 (honest K = 1/K = 4 mock + in-circuit = host VS
  cross-check, tampered VS/root/weight instances, foreign note,
  duplicate-VS seen-set, domain separation, real-prover honest loop at
  k = 9) and opacus-wallet 7 (honest ballot loop, duplicate VS,
  foreign anchor, stale snapshot, dust + topology, wire roundtrip +
  choice-flip tamper, cross-proposal unlinkability).
- GIP-3, coinbase transactions and issuance enforcement (docs-only
  Standards Track (Consensus) spec,
  `docs/gips/GIP-3-coinbase-issuance.md`, Status: Draft - RFC window
  opens on merge; implements GIP-1 precondition E-1 and closes the
  v0.4 spec section 11 "consensus issuance policy" trust boundary):
  new transaction class v6 COINBASE - public output amounts, derived
  zero-blinding value commitments RC_j = v_j * V (never transmitted),
  no inputs / per-output RCs / fee field / proof / bind_sig, valid
  only as tx index 0 of a block with matching height, never
  mempool-valid; the fail-closed block issuance rule is
  sum(RC_out(coinbase)) == (block_reward(height) + sum(fees)) * V
  with u64 overflow rejected - any overclaim or underclaim fails the
  equation and the block is rejected; coinbase leaves enter the
  existing sparse frontier first (no accumulator reset); 100% of
  subsidy + fees goes to the miner (GIP-1 Stage 0 0% OG split
  preserved; any future split is a separate GIP after E-1/E-2/E-3
  within caps C-1..C-5); activation via
  CONSENSUS_COINBASE_ACTIVATION_HEIGHT ([S4 9] pattern); no coinbase
  maturity rule (enforcement would link spent nullifiers to leaf
  creation heights - a privacy break; reorg economics is the
  mitigation, ZK age proof is an open question); total finite emission
  4,199,999,997,690,000 atomic units, reward 0 from ~block 7,140,000.
  P1-P3 / N1-N8 test matrix pinned for the future WG-30 implementation,
  which is gated on GIP-3 Accepted status.

## [0.9.0] - 2026-11-01

### Added

- WG-26 swap hashlock, in-circuit (opacus-zk): a v4 spend can lock a note
  to a Poseidon hashlock H = Poseidon_3(dom_swap, s0, s1) over two
  canonical 16-byte lanes of the 32-byte swap preimage. Modes: lock (1)
  derives the swap_idx-th output leaf with H absorbed; claim (2) proves
  the preimage in-circuit and publishes the spent note tree entry;
  refund (3) mirrors claim without the preimage check (the timeout itself
  becomes a consensus check in WG-27). Plain spends publish a zero swap
  tail; a swap-locked note is unspendable as a plain note (membership
  fails).
- WG-26 swap tail, normative: the public instance vector grows from 15 to
  21 slots - flag (0 plain / 1 lock / 2 claim / 3 refund, range-
  constrained in-circuit), swap_idx, H, s0, s1, spent_swap_entry. The
  normative text now lives in the v0.4 spec as Section 12; the frozen v1
  definition stays docs/WG-26-swap-hashlock-scope.md 3.3.
- WG-26 wire (opacus-wallet): TX_VERSION_V5 = the complete v4 layout plus
  a mandatory 130-byte tail (flag u8, swap_idx u8, H 32B, s0 32B, s1 32B,
  entry 32B) with strict per-mode canonical rules; sighash_v5 covers
  every tail field; v4 parsers reject v5 bytes (no trailing-byte
  ambiguity). Wallet surface: SwapIntent (Lock / Claim / Refund),
  build_zk_spend_v5, confirm_zk_tx_v5.
- WG-27 chain-level swap enforcement (opacus-consensus): CLAIM/REFUND
  validity becomes a deterministic function of chain state and height,
  checked in confirm_v5_consensus (the normative v5 accept path:
  TxV5 parse + per-frame checks). ConsensusState gains the open-swap
  registry swaps: BTreeMap<[u8; 32], u64> keyed by the tail hashlock H
  (swap id = H, value = H_lock). Rules: R1 CLAIM only while h < T with
  T = H_lock + W_claim (ConsensusParams.claim_timeout_blocks, testnet
  default 200 = the bridge service convention; a per-swap window would
  need a wire change and is rejected with it - the tail stays frozen at
  130 bytes), R2 REFUND only while h >= T with no preimage, R3
  exactly-once terminalization (the registry entry is removed on
  CLAIM/REFUND; no terminated-set - the nullifier seen-set already
  blocks the spent entry and an honest re-LOCK of the same H stays
  possible), R4 unknown/not-yet-LOCKed H and duplicate LOCK rejected,
  R5 consensus as the single source of truth (node/bridge admission may
  only be stricter). Test matrix wg27_* pins the boundaries: CLAIM at
  h == T rejects (N1), h > T rejects (N2); REFUND at h < T (N3) and
  h == T - 1 (N4) reject, h == T accepts (P2); post-terminalization
  CLAIM/REFUND reject (N5/N6); wrong preimage lanes (N7) and unknown
  swap id (N8) reject; valid CLAIM at h < T accepts (P1). No wire
  changes: TX_VERSION_V5, the 130-byte tail, the 21-slot layout and
  sighash coverage stay frozen (WG-26 design v1); normative reference
  docs/WG-27-swap-enforcement-scope.md.
- WG-18 WP-2 (bridge/network): swap deadlines aligned with the
  consensus verdicts [R5] - claim strict (h < T), refund inclusive
  (h >= T), saturating timeout arithmetic; the WG-18 sweep stays a
  fast-path convenience while the chain terminalizes (the pre-LOCK
  fund window remains bridge-side, pre-consensus by design).
- WG-29 enc_notes (S4 7): in-transaction note encryption, end to end.
  The v5 builder seals every output note to the recipient's note key
  (D3: note_sk = scalar(blake3("opacus_note_derive_v1" || seed)) with a
  zeroizing wrapper) using the ristretto ECIES extracted to
  crates/opacus-crypto/src/ecies.rs (D4/D5: ephemeral scalar,
  blake3 derive_key keystream + keyed MAC, MAC verified before any
  decryption, WG-29 domain tags). The plaintext ENoteV1 is a fixed
  137-byte struct (version u8 = 1 || d 32 || a 32 || b 32 || rho 32 ||
  v u64 LE); the wire blob is epk 32 || nonce 16 || ct 137 || mac 32 =
  217 B (ENC_NOTE_MAX 1024 / MAX_OUT 4 unchanged, D7). The v5 sighash
  stream extends over the sealed enotes, framed le64(len) || bytes per
  output (D6) - this closes the documented WG-26 R3 gap on the v5 wire;
  the v4 sighash is untouched.
- WG-29 recovery + consensus evidence: after a v5 transaction is FULLY
  confirmed, the wallet scan path opens every enc_note with the local
  note_sk, recomputes the leaf point and requires a tree-leaf match (D2)
  before the note is inserted; the e2e test recovers notes from raw tx
  bytes alone in a second wallet (N3 off). Consensus: a v5 tx with
  sealed enotes confirms on the covered sighash, and any enc_note
  tamper or cross-output substitution shifts the sighash and is
  rejected (Balance). Bench smoke: proof bytes (22400) and rows (1605)
  unchanged.
- WG-CLSAG monerod-facing CLSAG verification (opacus-bridge,
  `clsag_verify.rs`): a byte-compatible re-implementation of monerod's
  `verRctCLSAGSimple` + `get_pre_mlsag_hash` on the bridge's own fe25519
  layer, so the Opacus side cryptographically confirms the Monero legs of
  atomic swaps (lock / claim / refund). A binary v2 tx parser covers
  tagged key outputs (`txout_to_tagged_key`), `ecdhInfo`/`outPk` without
  counter prefixes, Bulletproof and BulletproofPlus range proofs, and the
  v2 tx hash = keccak(H(prefix) || H(base) || H(prunable)). Fail-closed
  structural checks run before any crypto: canonical scalars (< l),
  decompressible points, non-degenerate key/auxiliary images, ring size
  >= 2, the signature buffer consumed exactly, unknown tx types rejected
  instead of guessed. The hash-to-point is monero's elligator map
  (`ge_fromfe_frombytes_vartime`, known-answer tested), NOT the blake3
  try-and-increment of the v0.3 adaptor primitive; domain tags are
  `CLSAG_agg_0` / `CLSAG_agg_1` / `CLSAG_round`. Acceptance gate: a real
  mainnet fixture (`tests/fixtures/clsag_mainnet_v1.json`, tx
  43bd6f459b84f14162143e28c83a0fd1d58cb8e4c328070fa79ca198a0c79a23,
  height 3796485, 2 inputs, ring size 16, BulletproofPlus) captured
  unpruned from monerod `get_transactions` + `get_outs` (both newly
  exposed on xmr_rpc behind the existing Transport). The 6 fixture tests
  pin parse round-trip with byte-exact re-serialization, honest
  acceptance, a tamper matrix (s / c1 / D / key image / pseudoOut / ring
  member dest+mask / range-proof bits), ring substitution with real
  chain outs and cross-input swaps, non-canonical scalar rejection, and
  exact buffer consumption. opacus-bridge: 67 -> 92 tests.
- WG-CLSAG benchmark smoke (opacus-bridge, `benches/clsag_bench.rs`,
  harness = false, no new dependencies): loads the mainnet fixture,
  gates the run fail-closed (the honest tx must verify - full tx and
  every input; a tampered tx must be rejected) and reports parse,
  `pre_mlsag_hash`, per-input `verify_clsag` and full `verify_tx`
  timings: `cargo bench -p opacus-bridge --bench clsag_bench`.

### Changed

- **BREAKING (testnet proofs)**: the 21-slot instance layout invalidates
  existing halo2 proofs on testnet (the instance column length is bound
  by the protocol). Pre-mainnet only; no migration path.
- Row budget erratum: the WG-26 scope freeze projected +140..160 rows
  (output-side continuation perms included); the delivered circuit needs
  only +54 (per-input swap continuation + select rows, one public swap
  row, one claim-preimage perm) - 1551 -> 1605 rows at the full MAX
  topology, required_k() stays 11 (2048 rows) behind a unit-test gate.
  The spec cost-budget paragraph and the phase table now carry the
  delivered numbers (k = 11) instead of the stale pre-PROVER-10S
  estimates (k = 13).
- WP-4 erratum (opacus-zk): the deliberately kept but never read
  SpendCells.e_cells field is removed - the synthesize-local entry
  handles were always the live ones. No behavior change.
- WP-4 erratum (opacus-wallet): the tx_v4 module doc now points at the
  21-slot layout (15 base + WG-26 swap tail) instead of the stale
  15-slot wording.

## [0.8.0] - 2026-10-28

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
  re-tagged to `opacus_spend_derive_v2` / `opacus_view_derive_v2` over the BIP-39
  seed. v1 pseudo-mnemonics ("opacus <hex chunks>") are rejected - testnet-only
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
  legacy wOPACUS Sepolia deployment cannot be renamed in place (the name
  compiles into the deployed bytecode); its address record stays in
  contracts/wopacus.address until the redeploy round.
- opacus-dex: wopacus module renamed to wopacus (WOPACUS_ADDRESS env,
  legacy WOPACUS_ADDRESS fallback); ABI encoder gained dynamic string
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
  new vk (v0.8).
  change; proofs/keysets from earlier builds do not verify against the
  now enforced, not just honestly assigned. BREAKING: circuit layout
  spend-poseidon-init gate: the zero start of every spend-hash chain is
  cold and the steady-state numbers. Also enables the previously-dead
  inside the 10 s budget [S4 8] end to end. The bench now gates BOTH the
  in 4,81 s with steady-state prove at 2,26 s and verify 0,03 s -
  circuit layout changed. The whole cold pipeline (keygen included) runs
  ROUNDS, MDS, round constants, domain tags) are unchanged; only the
  5103 -> 1551 rows (k = 13 -> 11). Protocol Poseidon constants (T,
  PERM_ROWS = 17 rows instead of 65 and the mainnet MAX topology drops
  every gate row of the v4 spend circuit - one permutation costs
- opacus-zk (PROVER-10S): PER_BLOCK = 4 Poseidon rounds are fused into

### Changed

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
  was renamed `opacus-*` -> `opacus-*` (packages, libraries, the
  `cli/opacus` -> `cli/opacus` binary `opacus` -> `opacus`, workspace
  members, cross-crate dependencies, imports, benches, CI and docs).
  Deliberately unchanged: wire-protocol strings (`opacus-swap-p2p-v1`,
  `opacus-swap-offer-id-v1`), circuit domain labels (`OPACUS/v4/*`), the
  Poseidon label (`opacus-zk-poseidon-v1`) and the wOPACUS token.

- Deferred: v4 prover optimization (EC-chain column count, membership-path count) retargeted to the next minor release.
## [0.4.0] - 2026-10-20

Value conservation release: the full FCMP++-style v4 spend pipeline now
enforces in-circuit balance end to end - zk circuit, transaction
serialization, wallet, and consensus - with an activation-height gate, a
prover benchmark, and a documentation refresh
(docs/specs/v0.4-value-conservation.md, sections [S4 1-13]).

### Added

#### crates/opacus-zk - v4 gates and the full spend circuit (phases 1a, 1b, 2)
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

#### crates/opacus-wallet - tx v4 serialization and zk-native flow (phase 3)
- tx_v4.rs: canonical v4 transaction serialization feeding the exact
  15-slot instance vector; build_zk_spend_v4 and confirm_zk_tx mirroring
  the consensus confirmation order.
- The wallet end-to-end cycle (build / prove / verify / confirm) is green
  at mainnet tree depth 2^32.

#### crates/opacus-consensus - consensus v4 validation (phase 4)
- accept_transaction: v4 validation order [S4 9] - parse, proof verify,
  balance and binding signature, nullifier seen-set, tree root, fee
  floor, commit - with zero state mutation before ALL checks pass.
- Activation-height gate: after CONSENSUS_V4_ACTIVATION_HEIGHT only v4
  transactions are accepted (v3 rejected; a v4 transaction earlier than
  the height is rejected as EarlyV4; legacy structure remains valid only
  before activation).
- ConsensusParams (with testnet()) and ConsensusState (mainnet(), tree +
  seen-set), the Accept/Reject taxonomy, and confirm_v4_consensus.

#### crates/opacus-node - daemon submit gate (phase 4)
- submit_transaction routes every incoming transaction through consensus
  accept_transaction; rejections surface as TxRejected before any pool or
  state effect; the daemon exposes params() and consensus().

#### repository - bench, docs, release (phase 5)
- crates/opacus-zk/benches/prover.rs: deterministic full-pipeline v4 spend
  benchmark (prove_v4 / verify_v4 stage timing) at 2^32 leaves; zero new
  dependencies; run with
  `cargo bench -p opacus-zk --features real-prover --bench prover`.
- README.md refreshed for v0.4.0 (v4 sections, bench, updated test
  matrix, Apache-2.0 license note); workspace version bumped to 0.4.0;
  CHANGELOG updated; v0.4.0 tag and GitHub release published via the
  release_opacus.ps1 path.

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

#### crates/opacus-zk - Halo2 FCMP++ zero-knowledge layer
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

#### crates/opacus-wallet - shielded wallet layer
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

#### crates/opacus-bridge - Monero bridge
- xmr_dleq.rs: cross-group Schnorr DLEq proving that one scalar controls
  both the Monero/Edwards key and the Ristretto key (blake3 challenge,
  wide mod-l reduction, 96-byte serialization).
- xmr_swap.rs: atomic-swap state machine Offered -> Accepted -> XmrLocked
  -> OpacusLocked -> Claimed/Refunded with fund/claim timeouts, Maker/Taker
  roles, blake3 hashlock, and observable lock transitions.
- xmr_rpc.rs: monero-wallet-rpc client (transfer with unlock_time and
  payment_id = hashlock, get_transfers filtered by payment_id, balance and
  address queries) plus monerod get_info, behind a Transport trait with
  fake-transport tests.
- swap_p2p.rs: swap P2P protocol core - SwapNetMessage enum (Offer, Accept,
  XmrLocked, OpacusLocked carrying the preimage, Claim, Refund), u32-LE
  length-prefixed JSON framing, tamper-evident blake3 offer ids, and a
  session registry that reuses the xmr_swap state machine as the single
  source of truth (replay, duplicate, forged-claim and timeout validation).

#### crates/opacus-dex - Ethereum side (new crate)
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
- wOPACUS helpers: set_wopacus/burn calldata and Mint/Burn event topics.

#### crates/opacus-network - swap node
- swap_node.rs: TCP swap node reusing opacus-bridge::swap_p2p - framed
  socket I/O with declared-length caps, SwapNodeConfig, listener plus
  bootstrap dialing, a full-duplex connection loop with automatic protocol
  replies (Offer->Accept, OpacusLocked->Claim) on the same socket,
  protocol-violation disconnects, and a bounded node-event ring log.
- End-to-end test: complete swap choreography Offer -> Accept -> XmrLocked
  -> OpacusLocked (preimage) -> Claim across two live TCP nodes on
  127.0.0.1:0.

#### contracts/ - wOPACUS token
- wOPACUS.sol: ERC-20 wrapper with quorum-gated mint (sorted-signature
  ecrecover check) and burn-for-release; deployed to the Sepolia testnet
  (address tracked in contracts/wopacus.address), quorum threshold 1/1 for
  testnet. Marked AUDIT REQUIRED.
- wOPACUS.s.sol + foundry.toml: reproducible forge deployment script with
  environment-configured quorum signers (kept minimal pending forge-std
  restore).

#### Repository root - zero-typing Windows tooling (PowerShell)
- Sepolia deploy chain (historical): funds gate -> deploy_wopacus.ps1 ->
  bytecode gate with soft token calls, hard quorum cross-checks and
  WOPACUS_ADDRESS persistence. The one-off migration scripts of these
  early rounds were removed in the rebrand pass; the deploy and publish
  entry points remain.
- publish_opacus.ps1: safe one-command GitHub publish (secret gates, no
  force-push).

### Fixed
- opacus-zk did not compile (16 errors: E0061/E0382/E0425/E0599): the crate
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
- opacus-bridge Cargo.toml crashed cargo ("cannot extend value of type
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
  member (anyone could mint wOPACUS) and rotated to a freshly generated
  random key. deployer.key is never committed; the old key is kept only in
  a local git-ignored .bak file.
- Repository publishing excludes secrets by construction: a .gitignore
  guard set (deployer.key*, *.key, *.pem, .env*, *.bak*, tools/, build
  artifacts) plus an index-level secret gate that untracks offenders while
  keeping the files on disk; commits use the noreply GitHub identity.

### Test status (zero warnings in all crates)
- opacus-zk: 10 + 11 (real-prover) + 1 mainnet-depth mock
- opacus-wallet: 7 fast + 2 mainnet-depth end-to-end
- opacus-bridge: 27 | opacus-dex: 13 | opacus-network: 8

### Known limitations / roadmap
- Value conservation is not yet enforced in-circuit (v0.4 accumulator per
  the complete FCMP++ design); nullifier-reuse prevention is currently
  consensus-side.
- Swap enforcement is off-chain in v0.1: hashlock-in-circuit and CLSAG
  adaptor signatures are planned for v0.4; Refund frames are notices;
  swap heights are taken from configuration.
- opacus-network has direct dials only; peer discovery/gossip and peer
  authentication (DLEq-bound identities) are planned next.
- Encrypted note transmission between wallets (out-of-band note-secret
  transfer today) is a networking-phase item.
- An external audit is REQUIRED before any mainnet use; testnet keys are
  throwaway and never committed.
