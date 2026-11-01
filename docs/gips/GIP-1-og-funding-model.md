# GIP-1: Opacus Grants (OG) - Ecosystem Funding Model

- GIP: 1
- Title: Opacus Grants (OG) - Ecosystem Funding Model
- Type: Process
- Status: Draft (RFC window opens on merge; activation is a separate
  maintainer decision per GIP-0 section 4)
- Created: 2026-11-01
- Base: dc5e5ce (GIP-0, post-v0.9.0 [Unreleased])
- Requires: GIP-0
- Analog: ZIP 1014 / ZIP 1015 / ZIP 1016 (zips.z.cash), Monero CCS, Dash
  treasury, Decred Politeia
- Changes: docs-only (no Rust, no circuit, no wire, no contract changes)

## 1. Abstract

This document defines the funding policy for Opacus Grants (OG), the
ecosystem funding arm of the Opacus project. It fixes a two-stage model:
Stage 0 (now) funds development through off-chain, CCS-style transparency
with zero percent of emission; Stage 1 (an on-chain grants fund paid from
`block_reward`) is allowed ONLY after explicit activation conditions are met
and ONLY within hard caps - a fixed percentage of the block subsidy, a
mandatory sunset height, transparent fund addresses, and extension
exclusively by coinholder vote. The eventual on-chain implementation would
be a separate Standards Track GIP; this document only pins the policy.

## 2. Motivation

Sustained funding is a survival property of any protocol. The design space
is well-explored by predecessors, with hard lessons:

- **Zcash** iterated its model for 5+ years: Founders' Reward (ZIP 1014,
  20% to ECC/ZF/grants, carried a lasting reputational cost), then Canopy
  retirement of that scheme, ZIP 1015 (12% lockbox + 8% FPF from NU6), and
  ZIP 1016 (coinholder-controlled fund, quarterly votes, ~2% supply
  participation threshold).
- **Monero** takes 0% of emission and funds development through the
  Community Crowdfunding System (off-chain donations, public ledger of
  proposals).
- **Dash** runs a ~10% on-chain masternode treasury; **Decred** 10% +
  Politeia.

The decisive Opacus-specific fact (verified 2026-11-01): emission exists in
the codebase as `block_reward(height)` (opacus-consensus/src/block.rs:
INITIAL_REWARD = 10_000_000_000 atomic units, halving every 210,000 blocks)
but is NOT yet wired into consensus validation - there is no coinbase
transaction type and no subsidy enforcement; `docs/specs/
v0.4-value-conservation.md` explicitly names "consensus issuance policy" as
the remaining trust boundary. Unlike Zcash, which amended a live model
post-hoc, Opacus can choose the funding model BEFORE emission is activated.
That window is closed once mainnet starts paying rewards.

## 3. Specification

### 3.1 Stage 0 - effective immediately (no chain changes)

1. OG operates as an off-chain grants process with **public accounting**:
   every grant (source, amount, recipient handle, deliverables, outcome) is
   published in a public ledger document (CCS-style transparency).
2. **0% of emission** is allocated to OG in Stage 0. No treasury, dev fund
   or fee split exists on-chain.
3. Grant money, where present, comes from voluntary ecosystem sources
   (including wOPACUS-side community arrangements), never from consensual
   chain rules.
4. OG governance is maintainer-driven until GIP-2 (decentralized OG/OC
   voting) is Activated; GIP-2 supersedes this clause.

### 3.2 Stage 1 - on-chain grants fund (NOT now)

Stage 1 MAY be drafted as a Standards Track GIP only after ALL of:

- **E-1**: `block_reward` is wired into consensus validation (coinbase
  transactions, subsidy enforcement, value conservation extended to
  issuance) - i.e., the "consensus issuance policy" trust boundary named by
  the v0.4 spec is closed;
- **E-2**: mainnet is live and has sustained economic activity;
- **E-3**: the project has survived one external security audit cycle of
  the issuance path ("Mainnet gate" in SECURITY.md).

If and when drafted, the Stage 1 GIP MUST satisfy ALL caps:

- **C-1**: fixed percentage of the BLOCK SUBSIDY only (never fees, never
  minted beyond the subsidy split), value fixed in the GIP;
- **C-2**: mandatory sunset height; past it, allocation reverts to 0%
  automatically (no per-block renewal);
- **C-3**: transparent fund addresses: payouts land on non-private,
  on-ledger auditable outputs; the fund's accounting MUST be publicly
  reconstructable from chain data alone;
- **C-4**: any extension, percentage change or recipient-policy change
  requires a coinholder vote under GIP-2 - never a maintainer unilateral
  action;
- **C-5**: one payout transaction per fixed cadence (e.g., per N blocks),
  deterministic and consensus-validated.

### 3.3 Prohibited in any stage (MUST NOT)

- a perpetual fund (Founders'-Reward style, no sunset);
- opaque or unattributable recipients of chain-derived funds;
- changing the allocation percentage or sunset without a coinholder vote
  (after GIP-2 is Activated; before that, without an explicit Process GIP);
- retroactive reallocation of already-paid grants.

## 4. Rationale

An on-chain fund is nearly irreversible: changing it means a hard fork, and
it concentrates a governance-capture target plus a regulatory surface inside
the protocol itself. Zcash paid the reputational price for an uncapped,
sunset-less scheme and spent five years fixing it (ZIP 1014 -> 1015 -> 1016).
Monero's 0% + CCS model shows that early-stage legitimacy can be bought with
transparency instead of emission share. Opacus starts where Zcash ended:
public accounting first, on-chain fund later, and only with sunset + voting.
Stage separation also keeps the upcoming issuance activation (E-1)
mechanically simple - no fund split in the first coinbase code path.

## 5. Backwards Compatibility

None in Stage 0: no chain, wire, circuit or contract changes. A Stage 1
GIP would carry its own compatibility analysis (coinbase validation touches
value conservation and the v4/v5 transaction semantics).

## 6. Test Plan

Not applicable (Process GIP, no reference implementation). The future
Stage 1 Standards Track GIP MUST include a consensus test matrix for
coinbase/subsidy enforcement (P/N convention per GIP-0 section 6).

## 7. Security Considerations

- Transparent fund addresses are a deliberate privacy trade-off: fund flows
  MUST be auditable by third parties from chain data alone; ordinary user
  privacy (sealed enotes, FCMP++ spend proofs) is unaffected.
- Hard caps + sunset + voting are anti-capture mechanisms: a fund without a
  sunset is a standing target for governance capture.
- This document introduces no keys, no treasury and no trust assumptions
  beyond existing ones.

## 8. Open questions (for the RFC window)

1. Stage 1 percentage value (predecessors: Zcash 20% -> 12+8%, Dash ~10%,
   Decred 10%; Opacus candidate range intentionally NOT fixed here).
2. Payout cadence (N blocks) and minimum grant size.
3. Interim custodian model between Stage 0 accounting and GIP-2 coinholder
   voting (candidate: N-of-M multisig with public members).
4. Interaction with the wOPACUS bridge treasury, if any (currently none in
   the contracts: `wOPACUS.sol` has no mint/treasury hooks beyond the
   audited quorum mint).

## 9. Proposed answers in the RFC window (position of 2026-11-01)

The values below are PROPOSED for the RFC discussion; they are not
activated and do not modify section 3. A future Stage 1 Standards Track
GIP would carry them into normative text under the caps of section 3.2.

- **P-1 Allocation schedule (declining, auto-sunset)** - percentage of
  EACH epoch's own block subsidy: epoch 1 (blocks 0-210,000) 10% =
  210,000,000,000,000 atomic units; epoch 2 (210,000-420,000) 10% =
  105,000,000,000,000 atomic units; epoch 3 (420,000-630,000) 5% =
  26,250,000,000,000 atomic units; from block 630,000 onward 0% -
  automatic, no per-block renewal (strengthens C-2 to "sunset by
  default"). Total: 341,250,000,000,000 atomic units over the three
  epochs = 9.29% of their combined emission (3,675,000,000,000,000)
  and 8.125% of total emission (4,199,999,997,690,000).
- **P-2 Time-base fact**: one epoch is 210,000 blocks x 120 s
  (BLOCK_TIME_SECONDS, opacus-consensus) = ~292 days, so the whole
  schedule spans ~2.4 years - not the 4-year Bitcoin horizon. Every
  horizon argument in this schedule is recomputed in blocks, not years.
- **P-3 Rationale (compressed)**: 10% matches the Dash/Decred treasury
  precedent; 20% (ZIP 1014) is the documented anti-pattern and 12%
  (ZIP 1015) is a repair value, not a starting point; 0% (Monero CCS)
  does not cover the planned external audit cycles (Mainnet gate,
  SECURITY.md). Within the window, flat 10% would total
  367,500,000,000,000 - only 7.14% more - so the decisive anti-capture
  mechanism is the AUTO-SUNSET, not the declining profile itself: past
  block 630,000 the fund is dead unless a GIP-2 coinholder vote (C-4)
  revives it. That makes Stage B voting a deadline, not an option.
- **P-4 Explicitly rejected**: any continuation past epoch 3 without a
  coinholder vote (a standing capture target once the audit bills are
  paid); one-off top-ups outside the subsidy split (violates C-1);
  retroactive schedule changes (violates section 3.3).
