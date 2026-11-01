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

Not applicable to this Process GIP (no reference implementation). The
future vote-circuit / Stage B work packages MUST include a P/N test matrix
covering: honest ballot loop, weight under-valuation attempts, duplicate
`VS` rejection, stale/wrong anchor rejection, cross-proposal `VS` reuse,
non-canonical encodings, and degenerate keys (the WG-CLSAG tamper-matrix
convention).

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
