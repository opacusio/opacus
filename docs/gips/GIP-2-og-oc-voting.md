# GIP-2: Decentralized OG/OC Voting

- GIP: 2
- Title: Decentralized OG/OC Voting (coinholder governance for grants and
  community decisions)
- Type: Process
- Status: Draft (RFC window opens on merge; activation is a separate
  maintainer decision per GIP-0 section 4)
- Created: 2026-11-01
- Base: 0c8761b (GIP-1 Draft, post-v0.9.0 [Unreleased])
- Requires: GIP-0, GIP-1
- Supersedes (on activation): GIP-1 section 3.1 item 4 ("OG governance is
  maintainer-driven until GIP-2 is Activated")
- Analog: ZIP 1016 (coinholder-controlled fund), Decred Politeia
- Changes: docs-only (no Rust, no circuit, no wire, no contract changes)

## 1. Abstract

This document defines how Opacus coinholders (OG/OC stakeholders) make
binding governance decisions - grant approvals, fund policy, process
changes - without revealing their balances. The central design problem is
unique to Opacus: note ownership is private, so voting weight cannot be
counted from public state. The solution is a zero-knowledge
proof-of-balance built from primitives the codebase already has: a
membership proof against a snapshot anchor (sparse frontier root at a fixed
height) plus a per-proposal vote serial that prevents double voting without
spending the voted notes. Two stages are specified: Stage A (off-chain
tally of ZK votes, no consensus changes) and Stage B (fully on-chain
coinholder voting, a future Standards Track GIP). Burn-to-vote and
N-of-M quorum designs are evaluated and rejected.

## 2. Motivation

GIP-1 leaves OG governance maintainer-driven until this GIP is Activated,
and pins that any Stage 1 fund extension requires a coinholder vote. A
voting mechanism must therefore exist BEFORE the on-chain fund of GIP-1
Stage 1 can ever be drafted. Predecessor experience:

- **ZIP 1016** (Zcash, Proposed 2025): quarterly coinholder votes with a
  participation threshold (~2% of supply) and a Key-Holder veto - the veto
  is rejected here as a centralization backdoor (the very lesson ZIP 1016
  teaches).
- **Decred Politeia / Monero CCS**: proposal registries with off-chain
  signalling work at zero protocol cost, but their weight systems are
  either public or non-financial - neither transfers to private balances.
- **Burn-to-vote** designs (used by some DAOs) destroy value and bias the
  electorate toward short-term holders.

The Opacus-specific fact base (verified 2026-11-01): the v4 spend circuit
derives nullifiers in-circuit (`N = Poseidon_3(nk, rho, DOM_NU)`, key
schema `(a, b, rho)`); `FcmpCircuit` provides FCMP++-style membership
proofs over a sparse frontier (Poseidon merkle); note values are
circuit-visible. Consequently, a vote can prove "I owned notes of total
value V in the snapshot tree at height H_snap" while revealing neither
which notes nor their identities - and a domain-separated vote serial
`VS = Poseidon_3(vs_key, vote_rho, DOM_VS)` gives one-time use per
proposal without spending the notes. This is the ZK proof-of-balance the
tasklist identifies as Opacus's structural advantage.

## 3. Specification

### 3.1 Requirements for any variant (normative)

- **R-1 Private weight**: voting weight is proven in zero knowledge
  (membership + value sum); no ballot may reveal note identities, owners
  or balances.
- **R-2 Snapshot anchor**: all weight is measured against a fixed snapshot
  height `H_snap` (the sparse frontier root committed at `H_snap`); votes
  reference that root explicitly.
- **R-3 Double-vote resistance**: one vote serial `VS` per (proposal,
  note-set); a `VS` is never reusable for the same proposal. In Stage B the
  chain enforces this with a seen-set (the existing nullifier pattern); in
  Stage A the tally engine enforces it publicly.
- **R-4 Proposal registry**: proposals are GIP documents (GIP-0 numbering);
  a vote is always FOR/AGAINST/ABSTAIN a specific GIP-N at a specific
  status transition (RFC -> Accepted, fund-extension per GIP-1 C-4, etc.).
- **R-5 Fixed windows**: snapshot height, vote open and close heights are
  declared in the proposal BEFORE voting starts.
- **R-6 Quorum**: a decision is valid only above a minimum weight
  threshold and a minimum participation threshold (values: open question
  section 8; ZIP 1016 uses ~2% of supply as reference point).
- **R-7 No silent chain changes**: a vote outcome that changes consensus,
  wire or circuit behavior still requires a Standards Track GIP with green
  CI (GIP-0 section 7 linkage) - a Process vote never mutates protocol
  rules by itself.

### 3.2 Stage A - snapshot + anchor, off-chain tally (recommended now)

1. A proposal fixes `H_snap`, the vote window, and the VS domain tag.
2. Each voter builds (reusing v4/FcmpCircuit mechanics, no new circuit
   REQUIRED for the first iteration):
   - a membership proof that owned note commitments are in the frontier
     root at `H_snap`;
   - an in-range value-sum proof giving the vote weight V;
   - the vote serial `VS = Poseidon_3(vs_key, vote_rho, DOM_VS)` and a
     binding signature over the ballot (GIP-N, choice, V, VS, anchor).
3. Ballots are published off-chain (public registry/repository, transport
   detail is an open question - raw publication or WG-29 sealed enotes).
4. The tally engine checks every ballot, rejects duplicate `VS`, publishes
   the aggregate result with per-ballot traceability.
5. The outcome is recorded as a Process GIP amendment (or a new GIP), which
   becomes the auditable "minutes" of the decision.

Stage A requires NO consensus changes and NO new trust root: the tally is
verifiable by anyone replaying the ballots against the anchor.

### 3.3 Stage B - on-chain coinholder voting (later, Standards Track)

Votes become transactions carrying the same proof bundle; the chain
enforces `VS` uniqueness via a seen-set (WG-18-style sweep, the nullifier
pattern), and the tally is a deterministic function of chain state (the
WG-27 "verdict as function of chain state" pattern). Result aggregation,
quorum checks and weight accounting live in consensus validation. Stage B
MUST be filed as a separate Standards Track GIP with its own test matrix
(P/N convention, GIP-0 section 6) and is out of scope here.

### 3.4 Rejected designs

- **Burn-to-vote** (Variant 3): destroys holder value, biases the
  electorate toward sellers, and interacts badly with GIP-1's fixed-subsidy
  caps. REJECTED.
- **N-of-M quorum / Key-Holder veto** (Variant 4): concentrates power
  exactly where ZIP 1016's Key-Holder veto showed the failure mode.
  REJECTED as a voting mechanism; retained ONLY as GIP-1's interim
  custodian (multisig with public members) between Stage 0 accounting and a
  live Stage A.

## 4. Rationale

Stage A first because it delivers binding-ish signalling and auditable
minutes with zero protocol risk, reusing circuit mechanics that already
exist (membership proofs, in-circuit nullifier derivation, binding
signatures) - the only new artifacts are domain tags and the tally engine,
which is ordinary software. Stage B is worth its consensus cost only once
GIP-1 Stage 1 (an on-chain fund) makes on-chain finality for grant
decisions economically relevant. The VS construction mirrors the nullifier
pattern deliberately: one-time use without revealing WHICH note is
committing the ballot, preserving anonymity set rather than shrinking it.

## 5. Backwards Compatibility

None in Stage A: no chain, wire, circuit or contract changes; ballots are
off-chain artifacts. Stage B will touch consensus validation and MUST carry
its own compatibility analysis (seen-set growth, block-space cost, v4/v5
transaction semantics).

## 6. Test Plan

The Process GIP itself ships no chain behavior, but the WP-1 ballot
builder (delivered in this RFC window, see section 9 P-9) carries the
Stage A P/N matrix in `opacus-zk::vote` and `opacus-wallet::gov`:
honest ballot loop (K = 1 and K = 4, mock prover plus a real-prover
round trip), in-circuit `VS` == host derivation cross-check, tampered
`VS` / root / weight instance rejection, a foreign (non-member) note
failing membership, duplicate-`VS` seen-set rejection, foreign-anchor
and stale-snapshot gates, the `T_min` dust floor and the K <= 8
topology bound, canonical wire roundtrip with choice-flip signature
binding and no-trailing-bytes parsing, cross-proposal serial/key
unlinkability, and the row budget (K = 8 at DEPTH = 32 -> k = 13). The
WP-2 tally engine carries the Stage A tally matrix in
`opacus-wallet::tally`: golden emission-denominator values (era
boundaries, the 34-era convergence), the hand-computed P-6 decision
matrix with exact quorum/approval boundaries (including the all-ABSTAIN
quorum and the degenerate zero denominator), the record wire roundtrip
with strict framing, an end-to-end fund vote with the full per-ballot
rejection trace (duplicate serial, wrong GIP, foreign anchor, dust) and
its reverse-order replay equality, sub-60% rejection despite quorum,
process-majority both directions with the class byte as a hash input,
and blinding/order independence of the result hash; the emission
denominator is pinned to the consensus schedule by a consensus-side
sync test. The future vote-circuit / Stage B work packages MUST still
include a P/N
test matrix covering: weight under-valuation attempts, cross-proposal
`VS` reuse at chain level, non-canonical encodings, and degenerate
keys (the WG-CLSAG tamper-matrix convention).

## 7. Security Considerations

- **Anonymity vs integrity**: R-1 and R-3 are in tension - stronger
  double-vote linkage can shrink the anonymity set; the VS construction is
  domain-separated from spend nullifiers (DOM_VS) precisely so a vote
  never reveals or burns spending capability.
- **Sybil resistance** is inherent: weight comes from provably owned notes
  at `H_snap`, not from identities.
- **Snapshot sale attacks**: notes moved after `H_snap` do not vote (R-2);
  the window between snapshot and tally is a known secondary-market risk
  (open question 8.4).
- **Tally integrity (Stage A)**: ballots are individually verifiable and
  publicly archived; a wrong tally is detectable by replay, but the result
  must be challenged before being recorded - a Stage A limitation vs Stage
  B's chain-enforced finality.
- **No new keys or trust roots** are introduced by this document.

## 8. Open questions (for the RFC window)

1. Snapshot cadence (per-proposal vs fixed periodic snapshots) and how
   `H_snap` is pinned publicly.
2. Quorum and participation thresholds (ZIP 1016 ~2% reference).
3. Ballot transport: public raw publication vs WG-29 sealed enotes
   (privacy of the ballot before close vs auditability).
4. Handling of notes moved between `H_snap` and vote close (excluded by
   R-2; whether to re-snapshot on dispute is open).
5. Fresh dedicated vote circuit vs reuse of v4/FcmpCircuit mechanics for
   the first Stage A iteration (cost/latency trade-off; a vote-circuit WG
   is the natural future work package).
6. Voting delegation (proxy weight) - currently out of scope.

## 9. Proposed answers in the RFC window (position of 2026-11-01)

The parameters below are PROPOSED for the RFC discussion; none of this
is activated and none of it modifies sections 3-7 normatively. The
items answer the open questions of section 8 in order.

- **P-1 Weight model (answers 8.1 / 8.5)**: exact weighted (W1) - the
  ballot weight V is the sum of the voter's owned note values at
  H_snap. W1 is split-safe: fragmenting notes conserves total weight,
  so splitting attacks are profitless. Threshold models ("one vote if
  V >= T") are REJECTED: a T*N balance splits into N threshold-sized
  notes and inflates N votes, and a private chain has no identity to
  enforce one-person-one-vote. Homomorphic aggregation (a Pedersen
  commitment to V per ballot, per-choice aggregates opened at close)
  is a Stage A.5 privacy upgrade, not the first iteration.
- **P-2 Ballot shape**: at most K = 8 notes per ballot - a linear stack
  of note-proofs on the v4/FcmpCircuit mechanics (rows =
  2 + (4+32)*17*K, an unoptimized upper bound): K=1 -> 614 rows, k=10;
  K=8 -> 4,898 rows, k=13; the ~10 s PROVER-10S proving envelope
  covers a ballot either way. T_min = 10^6 atomic units per ballot as
  a dust filter (the real spam barrier is the proving cost). Larger
  holders submit multiple ballots; weight conservation makes that
  neutral.
- **P-3 Snapshot and window (answers 8.1 / 8.4)**: H_snap = H_open -
  the anchor is the frontier root at the vote OPEN height; there is no
  separate pre-open snapshot window to game. Window length 10,080
  blocks (14 days at 120 s blocks); all voting parameters are declared
  in the voting proposal at least 14 days before H_open. Notes moved
  after H_open carry no weight (R-2); re-snapshotting on dispute is
  NOT planned (fail-closed: the declared anchor stands).
- **P-4 Transport (answer 8.3)**: primary - ballots are WG-29 sealed
  enote payloads over the v5 wire gossip (network-layer anonymity
  equal to transaction broadcast, zero consensus impact); fallback -
  raw publication, documented as weaker. The tally engine MUST publish
  the full ballot archive at close; the archive is the auditable
  minutes.
- **P-5 Tally and recording (Stage A)**: deterministic off-chain tally
  (per-ballot verification is milliseconds; anyone can replay). The
  public quorum denominator is sum of block_reward(0..H_snap) - a
  deterministic function of consensus, so no balance is revealed.
  Challenge window of 720 blocks (1 day) between tally publication and
  the GIP status recording; a recording inconsistent with a public
  replay is a process violation (fail-closed).
- **P-6 Quorum and approval (answer 8.2)**: quorum 5% of supply at
  H_snap for fund decisions (the GIP-1 C-4 class) and 2% for process
  transitions - above the ZIP 1016 ~2% reference for fund votes,
  deliberately, to compensate Stage A's off-chain finality. Approval
  threshold 60% of YES+NO weight for fund decisions, simple majority
  for process votes; ABSTAIN counts toward participation only. Quorum
  not met = status quo persists (fail-closed governance).
- **P-7 Stage B trigger**: the on-chain variant (section 3.3) is
  drafted when GIP-1 Stage 1 moves toward activation. The practical
  deadline is the end of GIP-1 epoch 3 (block 630,000 of the schedule
  proposed in GIP-1 section 9): past it the fund auto-sunsets, and
  only a coinholder vote can revive it.
- **P-8 Known limitations (recorded, not hidden)**: per-owner weight
  caps are impossible without identity (the same exposure exists in
  ZIP 1016, only publicly there); vote-buying/coercion is not fully
  solvable privately (MACI-style key-switching is a future work
  package); exchange-custodied notes vote only if the custodian votes;
  Stage A finality is process finality - replay-detectable,
  chain-enforced only in Stage B.
- **P-9 Work packages**: WP-1 ballot builder in opacus-wallet (reuses
  the v4/FcmpCircuit prove path with a DOM_VS domain tag; no new
  circuit for the first iteration); WP-2 deterministic tally engine
  with golden vectors and a replay mode; WP-3 WG-29 ballot transport
  profile plus the raw fallback; testnet dress rehearsal before the
  first real vote.

  WP-1 delivery note (RFC window, recorded transparently): the
  "no new circuit" assumption did not survive implementation. The
  weight sum must bind each `v_i` to a REAL committed note, and the
  only in-circuit path to that binding is the v4 leaf chain
  (`[s]G + [h]G3`, membership walk) - which the existing spend circuit
  exposes ONLY together with `DOM_NU` nullifier reveals, i.e. a vote
  built on the unmodified spend circuit would burn the voting notes'
  spending capability (rejected by section 7). WP-1 therefore ships an
  ADDITIVE `BallotCircuit` in opacus-zk that reuses the v4 gadget
  suite unchanged (Poseidon perms, rc-limb range gate, fixed-base
  leaf chain, commutative tree walk) and swaps the nullifier stage for
  the domain-separated vote chain of section 3.2; no existing circuit
  file changes semantics (visibility-only `pub(crate)` upgrades).
  Measured row budget: K = 8 at DEPTH = 32 -> k = 13, matching the
  P-2 estimate; the ~10 s proving envelope holds.

  WP-2 delivery note (RFC window): the deterministic tally engine is
  delivered as `crates/opacus-wallet/src/tally.rs` (ordinary software,
  as section 4 anticipated). The archive is processed in canonical
  order (sorted by ballot bytes), so the published result hash is
  independent of arrival order and any replay over the same archive
  reproduces it byte-for-byte; proof blinding is excluded from the
  hash. Rejections are per-ballot trace lines, never fatal (step 4 of
  section 3.2). The P-5 denominator `sum(block_reward(0..H_snap))` is
  implemented in the wallet and pinned to the consensus schedule by a
  consensus-side sync test (a wallet->consensus dependency is
  impossible without a cycle; an emission-schedule change is a
  Standards Track GIP (R-7) and touches both). The engine's decision
  rule is P-6 verbatim, fail-closed on quorum, ties and degenerate
  denominators.

  WP-3 delivery note (RFC window): the P-4 transport profile is
  delivered as `crates/opacus-wallet/src/gov_transport.rs` plus the
  additive tag-parameterization completion of the WG-29 ECIES
  (`crates/opacus-crypto/src/ecies.rs`: `BALLOT_TAGS`,
  `BALLOT_DERIVE_TAG`, `keypair_from_seed_tagged`, variable-length
  `seal_with_tags` / `open_with_tags` - one algebra, the fixed-size
  enote paths delegate byte-identically and their existing test suite
  is the regression gate). The primary transport is the `GBE1`
  envelope: the canonical ballot wire sealed to the per-proposal
  ballot collector key (a derivation of the collector's BIP-39 seed -
  no new trust root, section 7) with the proposal tag
  `(gip, transition, h_open)` in cleartext (public by P-3; enables
  bucket routing without opening; a relabelled envelope fails closed
  on the ballot-header match). The fallback is raw publication of the
  canonical ballot bytes - documented weaker: the choice, the weight
  and the serials are public before close, while copying stays
  useless for double-voting (one-time serials, R-3). The
  collector-side `BallotArchive` takes BOTH transports, dedupes only
  byte-equal retransmissions and deliberately performs NO
  cryptographic verification - every verdict belongs to the tally
  engine's published trace, so the minutes stay COMPLETE (rejected
  and duplicate-vote attempts are visible and auditable, not silently
  filtered). `archive_id` fingerprints the minutes in ARRIVAL order;
  the tally `result_hash` stays order-invariant - two published
  copies with different arrival order have different `archive_id`
  and the SAME `result_hash` (both are the close artifacts of step
  5). Envelope ids (the WG-29 id digest under the ballot tags) are
  defined for v5 gossip relay dedupe; wiring the gossip channel is
  node-integration work, not part of this profile.

  WP-D0 stage note (runbook stage R0 executed): the deterministic
  in-process rehearsal is delivered as
  `crates/opacus-wallet/examples/dress_rehearsal.rs` plus the golden
  replay test `crates/opacus-wallet/tests/dress_rehearsal_golden.rs`
  over the committed close artifacts
  `crates/opacus-wallet/tests/vectors/` (`declared.json`,
  `minutes.json`, `golden-vectors.json`; seed 42, 7 voters, a
  mainnet-depth frontier with one dust leaf). The whole protocol runs
  in one process with the real prover at DEPTH = 32 (K = 8 -> k = 13,
  the P-2 budget): the honest window (5 sealed ballots + 1 raw-only +
  1 byte-equal retransmission), the full adversarial matrix - a
  build-time dust rejection (the T_MIN gate before any proving work),
  a dust wire smuggled over the raw fallback -> `Malformed(Dust)` in
  the published trace, a double vote on the same notes ->
  `DuplicateSerial`, a foreign-scope envelope -> `ProposalMismatch`,
  a relabelled envelope -> `HeaderMismatch`, a corrupted MAC byte ->
  `MacMismatch`, a truncated blob -> `Truncated`, an oversized blob ->
  `Oversize` - and the P-5 replay (shuffled archive: same
  `result_hash`, different `archive_id`). The rehearsal shape lands
  quorum + 84.7% approval -> Accepted (yes 58.3e9 / no 10.5e9 /
  abstain 12.5e9 against the denominator `emission_upto(100) = 1e12`).
  Determinism contract: every decision artifact is a pure function of
  `--seed`; the halo2 proof blinding (OsRng) varies the entry bytes
  run-to-run, so the `result_hash` and the record wire are stable
  forever while the minutes fingerprint is stable per published
  minutes - the replay test pins both over the committed vectors,
  re-verifies every accepted proof at mainnet depth and re-derives the
  decision rule, all inside the ordinary debug test budget (~12 s).
  Artifact hashes (sha256, refreshed by the rebrand pass - the R0
  example is byte-frozen, only the domain tags under it moved):
  declared.json
  27761a7923a5681131c6884bc2dff3d7c81ebba504c9748324efe3beeedee0b7;
  golden-vectors.json
  ba1657f9dcfb00b4465700e4cdfa4df392b2d16aa3ee676da35ee925ac194107;
  minutes.json
  49ae9f5d976befb6d745d899e2603a86eb89fe1177e67c16725776e8c84b0f5f.

  WP-D1 stage note (runbook stage R1 executed): the two-process
  rehearsal over a drop directory is delivered as three small bins -
  `crates/opacus-wallet/src/bin/dress/{collector,voter,auditor}.rs`
  (shared derivation/label module `dress/common.rs`; the R0 example
  stays byte-frozen) - plus the test layer
  `crates/opacus-wallet/tests/dress_rehearsal_two_process.rs`. The
  declaration is published first (`declared.json`: proposal, collector
  key, and the rehearsal block seed 42 / 7 voters / depth 32 that lets
  every independent voter process rebuild the anchored frontier);
  seven independent `dress_voter` processes drop ballots as FILES -
  the envelope file name is the hex `envelope_id`, the transport
  dedupe key - covering 5 FOR / 1 AGAINST / 1 ABSTAIN, one raw-only
  fallback ballot and one byte-equal raw retransmission of voter 0's
  ballot (the collector dedupes it across transports), plus the fault
  matrix as deliberate drops: a double vote on the same notes ->
  `DuplicateSerial`, a dust wire smuggled over the raw fallback ->
  `Malformed(Dust)` at the tally, a foreign-scope envelope ->
  `ProposalMismatch`, a relabelled envelope -> `HeaderMismatch`, a
  corrupted MAC byte -> `MacMismatch`, a truncated blob ->
  `Truncated`, an oversized envelope -> `Oversize`, a mislabelled
  garbage blob -> a raw-path reject. The collector ingests EVERYTHING
  in the directory blind (arrival order = lexicographic file scan):
  16 drops, 9 accepted entries, 6 failed events logged in the minutes,
  nothing fatal, nothing silently dropped; the close statement is
  Accepted (yes 58.3e9 / no 10.5e9 / abstain 12.5e9, accepted 7 /
  rejected 2) with `result_hash`
  2e25d244a287d782bc90c5a1cc3ec80859e134da6968f4577bfb3b221cb76053 -
  BYTE-EQUAL to the R0 golden vector: moving the whole protocol across
  real serialization boundaries does not move the decision (P-5);
  `archive_id` differs, as it must - fresh blinding bytes, a different
  arrival history. The minutes are blake3-pinned
  (`{minutes_body, minutes_digest}` over the canonical body): the
  auditor replays entries -> `archive_id`, re-runs the tally (every
  accepted proof re-verifies at mainnet depth) and the decision rule,
  matches totals, outcome, `result_hash`, the record wire and the full
  trace, and REJECTS a tampered minutes file (one flipped byte) before
  any replay work. CI-budget test: the committed close artifacts
  `crates/opacus-wallet/tests/vectors/dress-r1/` (16 drops + the
  declaration + the minutes) replay clean and fail the two tamper
  cases with zero proving; the full two-process flow (9 real prover
  runs) ships as the ignored e2e test. Artifact hashes (sha256,
  refreshed by the rebrand pass - same seed, same 16-drop shape, new
  domain tags): dress-r1/declared.json
  4e938b0c4073563703e4c973fd51463f118178619d3c9da8b868fab748cffe1e;
  dress-r1/minutes.json
  4f2bc684d608b8cc6dd7504bf086679c417fde292b98e3bc884192abd5e7d0d2.

  WP-D2a stage note (runbook stage R2 executed): the single-node
  testnet smoke is delivered as the CLI launch surface
  `cli/opacus/src/main.rs`: `opacus start` grows the `--network` flag
  (default "mainnet" - the pre-flag behavior is preserved; the value
  flows verbatim into `DaemonConfig` and is validated by the daemon,
  Node-1, so a typo refuses startup BEFORE any socket is bound or any
  file is written), the `--data-dir` flag (the "fresh data_dir"
  definition of done becomes testable without touching the real home
  dir), and the p2p autostart wiring - `opacus start` now calls
  `opacus_node::net_service::autostart` exactly like opacusd, because
  the stage-log item "p2p listener bound" needs a real listener
  (OPACUS_NET=0 still disables it; the flag order is daemon-first, so
  an invalid network can never bind). The runbook commands and the
  built binary agree on one canonical name: the single bin target
  `opacus` (same main.rs as the former second alias target, which the
  rebrand pass removed). Six new bin-crate tests pin the surface: defaults
  (mainnet, no data-dir override, no tor), the R2 smoke command
  parses, flags land in `DaemonConfig` with the daemon port defaults,
  the home default, the typo refusal with zero side effects, and a
  testnet boot over a fresh dir. The smoke itself ran on rustc
  1.99.1 release: negative boot `--network mainet` -> exit 1, no data
  dir, no socket; `opacus start --network testnet --data-dir <fresh>`
  -> "consensus: net=testnet | v4_activation_height=0 | fee_floor=0",
  the net node listening on 0.0.0.0:18080, "Opacus node running",
  killed with SIGINT after 25 s (the heartbeat stub runs forever);
  `create-wallet` + `address` OK (throwaway wallet, seed redacted in
  the committed log); `mine --solo --duration-secs 300` -> a
  difficulty-1000 header solved in ~23 ms, the engine halts on block
  found so the session completed in 5 s, observed 8.2 H/s on one
  release thread (2-core container), reward address auto-derived from
  the smoke wallet. The gap list is re-confirmed, not shrunk:
  `daemon.run()` is still a heartbeat loop (no chain service - the
  mined block is counted, not submitted to any state machine), the
  RPC port is only echoed in the log line (no server), and the
  wallet-gov bridge, gossip envelope channel and collector service
  are exactly the remaining WP-D2b/D2c/D2d work items. Raw smoke log
  committed as `docs/gips/GIP-2-r2-stage-log.txt` (re-captured on the
  renamed surface by the rebrand pass). Artifact hash (sha256):
  GIP-2-r2-stage-log.txt
  54c292ffc1694fef7258ff79cdf145b8e9190cf1cf200c7944aad752c6e96094.

  WP-D2b stage note (runbook stage R3 work item, the wallet-gov
  bridge): `build_ballot` now consumes wallet-real inputs. The
  LightWallet grows a v4 note store beside the existing zk-native
  one: `confirm_v4_leaf(entry, height)` appends every GLOBAL
  confirmed commitment (own or foreign - the anchor root is the root
  of the whole tree, so the mirror must hold foreign leaves too),
  `add_v4_note(note, height)` additionally tracks the note as the
  wallet's own votable set (`V4TrackedNote`: note, leaf index,
  confirmed height, spent flag), `mark_v4_spent` flips the flag (the
  v4 spend pipeline wires it in later), and `v4_leaves` /
  `v4_balance` / `v4_note_counts` expose the store (the wallet's fiat
  balance stays the old ledger and is deliberately untouched). Every
  confirmation carries the chain height and heights are enforced
  non-decreasing (`WalletError::OutOfOrder` - the sync walks blocks
  in order; this is exactly what makes the snapshot a prefix). The
  bridge itself is `LightWallet::gov_inputs_at(h_open) ->
  GovInputs { frontier, notes }`: the frontier is the wallet's v4
  tree cut to the leaves confirmed by `h_open` (new
  `TreeState::snapshot(len)` prefix helper - its root is the anchor
  the proposal declares, so notes confirmed after H_open are cut off
  per R-2 while an `h_open` beyond the tip simply yields the full
  frontier), and `notes` are the own `WalletNoteV4` entries with
  `confirmed_height <= h_open` at their leaf positions - the exact
  `(indices, &[&WalletNoteV4])` pair `build_ballot` consumes. Two
  semantic decisions are pinned: a note SPENT after H_open still
  votes (the weight is the H_open holding; the double-vote gate is
  the R-3 serial seen-set, not the spend state - the balance excludes
  it, the votable set does not), and the dust gate stays where P-2
  put it (the bridge passes sub-T_min snapshots straight through;
  `build_ballot` rejects them). Evidence is the test layer (no run
  artifacts this item): five new tests in the wallet lib suite
  - the snapshot cut (frontier length and votable set at h_open =
  11/12/20/99 over a scripted sync with foreign leaves interleaved),
  the full end-to-end feed (wallet -> `gov_inputs_at(12)` ->
  `build_ballot::<4>` -> standalone verify -> fresh against the
  snapshot -> STALE against the wallet's grown live frontier,
  `RootMismatch` - the collector-side H_open gate), the
  spent-after-H_open semantics, the out-of-order refusal (the
  rejected leaf leaves no trace; equal heights allowed), and the
  dust passthrough (`Dust { v: 900_000, t_min: 1_000_000 }` raised by
  the builder, not the bridge). Wallet lib tests 48 -> 53, workspace
  green end to end. This closes the "scan produces wallet notes, not
  the WalletNoteV4 + frontier pair" gap of runbook section 0; the
  remaining R3 items are WP-D2c (gossip envelope channel) and WP-D2d
  (collector service).

  WP-D2c stage note (runbook stage R3, second item): the gossip
  envelope channel is delivered as `crates/opacus-network/src/gov_channel.rs`,
  closing the WP-3 delivery-note deferral verbatim ("Envelope ids ...
  are defined for v5 gossip relay dedupe; wiring the gossip channel is
  node-integration work"). The v5 note feed caps one sealed payload at
  512 bytes while one GBE1 envelope at the rehearsal depth is ~22.7 KB,
  so the channel is a deterministic chunk layout plus a bounded
  reassembler: the sender chunks the envelope wire (`chunk_stream` -
  every chunk except the last is exactly 441 bytes, the canonical split,
  so one envelope maps to ONE chunk set), seals every chunk to the
  collector NODE identity with the ordinary note ECIES (`seal_stream`)
  and ships them in `Notes` frames of at most 32 blobs (`frames_of` -
  the GBE1 size is exactly 2 frames); the network stores and relays the
  chunks as ordinary notes and never interprets them (the chunk header
  lives INSIDE the sealed payload: magic GOV1, version, total, index,
  the 32-byte `stream_id` and a blake3 digest of the WHOLE payload);
  the collector opens every inbox blob addressed to it (`feed_note` -
  anything that fails to open is third-party relay traffic by design,
  `Ok(None)`, never an error) and feeds `GovAssembler`, which
  reassembles keyed by the `stream_id` - the caller passes the ballot
  `envelope_id`, the WG-29 id digest under the ballot tags, so the
  envelope-level dedupe is EXACT: a byte-equal retransmission arriving
  over a different relay path carries different blob ids (fresh ECIES)
  that the relay-level dedupe cannot catch, re-opens to the same chunk
  bytes and is dropped by the assembler - each envelope emits exactly
  once inside the dedupe window. Fail-closed discipline: a payload that
  opens AND claims the channel magic but violates the protocol (bad
  version, index out of range, zero total, non-canonical chunk width,
  oversize data, conflicting (total, hash) for one stream, digest
  mismatch at completion) is a hard error, never silently dropped;
  completed streams are hash-checked before emission, so a chunk that
  belongs to no honest stream can never complete one. Memory is
  bounded on every axis: 441 bytes of data per chunk, 256 chunks per
  stream (112,640-byte envelope cap - the DEPTH=32 GBE1 uses 52), the
  live-stream count and the completed-stream window are capped (a
  failed stream is dropped, not parked). Layer separation preserved:
  the wallet's production dependency graph stays node-free (the
  opacus-network dev-dependency exists only for the cross-layer test).
  Tests: 11 in-module (canonical chunk layout incl. the 22,686-byte
  GBE1 shape, out-of-order byte-exact reassembly, the full tamper
  matrix, stream-conflict and hash-mismatch drops, live-stream and
  seen-window bounds, seal/feed loopback with foreign and non-gov
  blobs ignored, frame capping) plus the live-network e2e - voter ->
  relay -> collector over three real NetNodes, the GBE1-sized stream
  in 2 frames, and a fresh-seal retransmission that dedupes (3 chunks,
  0 second emissions) - and the cross-layer wallet test
  `tests/gov_gossip_channel.rs`: ONE real DEPTH=32 prove, the envelope
  rides the channel end to end, comes back byte-equal, re-parses,
  re-opens with the collector key, re-verifies and re-anchors against
  the frontier. Remaining R3 items: WP-D2d (collector service) and the
  scripted scenario.

  Rebrand stage note (pre-R3 tree-wide pass): the project name is
  Opacus everywhere and the legacy internal codename is scrubbed from
  the whole tree - code identifiers, wire states and fields,
  consensus/wire domain tags (`OPACUS/v4/...`, `OPACUS/v5/...`, the
  `opacus_final_v1` PoW tag, `opacus-ballot-archive-v1`,
  `opacus-swap-p2p-v1`), the key-derivation tags
  (`opacus_spend_derive_v2` / `opacus_view_derive_v2`, the pinned
  official-vector rows recomputed over the published BIP-39 phrases),
  the miner core module (`opacushash`), the
  node data dir (`~/.opacus`), the env surface (`OPACUS_NET*`,
  `OPACUS_SWAP*`), the wrapped-token contract files
  (`contracts/wopacus.address`) and every document. The one-off
  migration scripts of the early deployment rounds left the repo root;
  `deploy_wopacus.ps1` / `publish_opacus.ps1` remain. Pre-mainnet is
  the only window where a consensus-visible tag rename is free, so it
  was spent deliberately: the decision SEMANTICS are untouched (same
  totals, same trace shape, same P-5/P-6 behavior), while every
  tag-derived fingerprint moved - the R0 golden set and the R1 drop-dir
  artifacts were regenerated deterministically (seed 42, 7 voters, the
  identical 16-drop matrix; the R1 close re-reproduced the R0 golden
  `result_hash` byte-for-byte under the new tags), the R2 smoke was
  re-validated on the renamed surface (stage log re-captured), and the
  runbook acceptance checklist grows a standing brand scan
  (case-insensitive grep of HEAD for the legacy codename) next to the
  secret scan. 58 tracked files rewritten, zero residual occurrences.

  WP-D2d stage note (runbook stage R3, third item): the collector
  service is delivered as `crates/opacus-node/src/gov_service.rs` plus
  the operator bin `gov_collector` (`init` / `ingest` / `close` over a
  state directory and a spool directory). The service is the node-side
  counterpart of the R1 `dress_collector`: `BallotArchive` is reused
  VERBATIM (the runbook pins "no new crypto") and the ingest endpoint
  now speaks the WP-D2c channel - the sender chunks the envelope wire
  (`seal_stream`, stream id = the public `envelope_id`) and drops one
  sealed blob per `*.gchunk` file into the spool, the collector drains
  the spool in a sorted scan, opens every blob with the collector NODE
  identity (the routing trust root; the ballot key stays a separate
  trust root declared in `declared.json` and verified against the
  derived key before anything opens) and feeds `GovAssembler`: a
  completed stream emits the envelope wire byte-exactly, a re-sealed
  byte-equal retransmission is swallowed by the assembler (fresh blob
  ids, the same chunk plaintexts), a channel violation is a hard
  verdict - logged, never fatal. A completed wire routes blind (the
  R1 discipline): GBE1 magic -> `ingest_sealed` (scope check, open
  with the ballot key, byte-equal dedupe), anything else -> the raw
  fallback; every verdict lands in the event log, nothing is silently
  dropped. A raw copy of the SAME ballot correctly surfaces as the
  retransmission case, not a second archive entry. State is one JSON
  file (archive entries + event log + completed stream ids); reopen
  rebuilds the archive by the canonical raw parse (the auditor path,
  zero proving), so ingest and close run as separate processes.
  `close` tallies at the rehearsal depth, runs the pure P-6 rule and
  publishes the EXACT R1 minutes schema (`{minutes_body,
  minutes_digest}`), so the R1 `dress_auditor` replays a service close
  unchanged. The sender side is the wallet example
  `gov_gossip_vote.rs`: the ballot is built from WALLET-REAL inputs
  through the WP-D2b bridge (the wallet mirrors the declared frontier
  leaf by leaf with monotonic confirm heights, owns exactly its own
  note, `gov_inputs_at(h_open)` snapshot root must equal the declared
  anchor) and shipped over the channel - `--double` ships a second
  ballot on the same notes (DuplicateSerial at the tally), `--raw`
  ships the raw wire as its own stream (sid = blake3 over the wire),
  `--retransmit` re-seals the same envelope. Tests: the service e2e
  (52-blob GBE1 stream through the spool endpoint, the raw fallback
  accepted, the re-sealed retransmission fully deduped, garbage logged
  not fatal, persistence across reopen, the close statement and the
  minutes schema) with two real DEPTH=32 proves, and the collector key
  policy pinned against the R1 derivation. Layering: opacus-node gains
  the wallet dependency (a node validates ballots); the wallet's
  production graph stays node-free (the D2c property holds - the
  sender is a dev-target example).

  R3 scenario stage note (runbook stage R3 EXECUTED - the P-9 gate):
  the scripted rehearsal ran end to end on the renamed surface
  (rustc 1.99.1 release, raw log `docs/gips/GIP-2-r3-stage-log.txt`).
  N=3 nodes booted `opacus start --network testnet` with three
  separate data dirs and ports 18081-18083 (3/3 p2p listeners bound,
  the dialers bootstrapped to node 1, zero crashes), and the solo
  miner solved a difficulty-1000 header on the same surface
  (~296 H/s single-thread). The maintainer published `declared.json`
  (gip 2 / transition 0 / h_open 100 / seed 42 / 5 voters) and the
  collector published its node routing key (`gov_collector init`).
  M=5 wallet processes voted over the WP-D2c channel into the WP-D2d
  collector spool: 3 FOR, 1 AGAINST, 1 ABSTAIN - every ballot built
  from WALLET-REAL inputs (the D2b bridge mirror of the declared
  frontier, `gov_inputs_at(100)` snapshot root equal to the declared
  anchor), 52 channel blobs per envelope, 364 blobs in wave 1. The
  faults behaved exactly as designed: voter 0's re-sealed
  retransmission was swallowed chunk-by-chunk (6 streams completed of
  7 shipped - the D2c envelope-level dedupe), voter 3 published the
  raw fallback ONLY (sid = blake3 over the raw wire, routed blind into
  `ingest_raw`), and voter 4's deliberate second ballot on the same
  notes collided with the honest abstain's serial - the canonical-order
  replay rejected exactly one copy (`DuplicateSerial`, the counted
  shape is independent of which copy wins). Two `gov_collector ingest`
  runs (one per wave, separate processes over the persisted state)
  brought the archive to 6 entries; the close published the R1-schema
  minutes: outcome=accepted (participation 57.3e9 of the 1e12
  denominator clears the 5% Fund quorum; 33.5e9 YES vs 13e9 NO is
  72% > 60% approval), yes 33.5e9 / no 13e9 / abstain 10.8e9, accepted
  5 / rejected 1, `result_hash`
  92af734953fdd4b3a4550b5902e6314aa21a23608346cfbfd11816a8149d951a,
  `archive_id`
  2b11761007abbb14648007ff0768f02f2936d4e5023c9ecf8d7c4e05f23a28c9.
  Every participant replayed: the offline `dress_auditor` verdict was
  `replay ok` and a flipped minutes byte was rejected (digest
  mismatch) before any replay work. The close artifacts are committed
  under `crates/opacus-wallet/tests/vectors/dress-r3/` (declaration,
  minutes, collector node key, the collector state with the full
  370-event ingest log) and pinned in CI by the new replay test
  `tests/gov_scenario_r3.rs` (clean replay + the tamper rejection +
  the recorded scenario shape). Stage R4 (the standing audit gate)
  needs no further code: the auditor path is the permanent acceptance
  tool for every future real close. Artifact hashes (sha256):
  dress-r3/declared.json
  bf75a279743f60c85ebf420f3012a63d7eaed333f9218a7702c8a2c843887a8b;
  dress-r3/minutes.json
  f74b46338416164b5c4bbb5218a8316168171781ae1825cf467209069cfed589;
  dress-r3/collector-node.json
  4023c7f7dd3e5722ef80c2bda8d98c770ad3a4f936e86548ba4b51827146772e;
  dress-r3/state.json
  e9cd35ce11bdf7b3617b83647dc7f849a8ff47ccb51ec3fab840f3c3b57f4582;
  GIP-2-r3-stage-log.txt
  353be268d666c3a5b62adc37996d701c4929533113e209c0081e187bf86a0901.

## 10. Plain-language summary (non-normative)

- **What is voted on**: (1) accepting or rejecting a GIP (status
  transitions); (2) changes to an EXISTING fund policy - percentage,
  sunset, recipient rules - never individual payments, which follow
  the already-approved policy; (3) a vote never changes protocol rules
  by itself: consensus, wire or circuit changes still require a
  Standards Track GIP with green CI (R-7).
- **Who votes**: any holder of OPACUS notes at H_open. Weight = amount
  held, proven in zero knowledge - no addresses, no balances, no note
  identities are revealed. One note votes once per proposal (VS) and
  is not burned; coins bought after H_open carry no weight; custodied
  coins vote only if the custodian votes; maintainers hold no special
  weight - one atomic unit is one unit of weight.
- **What does NOT need a vote**: today (GIP-1 Stage 0) there is no
  on-chain fund at all - expenses come from voluntary sources under
  public accounting; later, routine payouts follow the approved
  policy; only policy CHANGES go to a vote; no quorum means status
  quo.
