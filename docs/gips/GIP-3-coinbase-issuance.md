# GIP-3: Coinbase Transactions and Issuance Enforcement

- GIP: 3
- Title: Coinbase Transactions and Issuance Enforcement (closing the E-1
  trust boundary)
- Type: Standards Track (Consensus)
- Status: Draft (RFC window opens on merge; activation is a separate
  maintainer decision per GIP-0 section 4)
- Created: 2026-11-01
- Base: 4b8700e (GIP-1/GIP-2 RFC positions, post-v0.9.0 [Unreleased])
- Requires: GIP-0, GIP-1
- Implements: GIP-1 precondition E-1 (block_reward wired into consensus
  validation); closes the v0.4 specification section 11 trust boundary
  ("the remaining trust boundary is consensus issuance policy")
- Analog: Monero miner transaction + RingCT block balance; Zcash value
  pool accounting (rejected, see section 4)
- Changes: docs-only in this document (no Rust, no circuit, no wire
  changes); the implementation is a future work package (WG-30), gated
  on Accepted status per GIP-0 section 4

## 1. Abstract

This document specifies the first coinbase transaction class for Opacus
and the block-level issuance rule that makes `block_reward(height)` a
validated consensus fact instead of unused code. The design reuses the
v0.4 homomorphic balance machinery with zero new cryptography: coinbase
outputs carry PUBLIC values and zero-blinding value commitments derived
by validators (never transmitted), and every block must satisfy the
point equation `sum(RC_out(coinbase)) == (subsidy(height) + fees) * V`.
Any overclaim or underclaim fails the equation and the block is
rejected - fail-closed by construction. The coinbase pays 100% of
subsidy + fees to the miner (GIP-1 Stage 0 allocates 0% to OG); no
circuit changes are required; emission starts only at an explicit
activation height.

## 2. Motivation

The v0.4 value-conservation spec (docs/specs/v0.4-value-conservation.md)
proves per-transaction balance in zero knowledge but leaves issuance
open: its section 11 states that conservation is proven and "the
remaining trust boundary is consensus issuance policy". GIP-1 adopts
that boundary as precondition E-1 - no on-chain fund may even be drafted
until `block_reward` is wired into consensus validation. The fact base
(verified 2026-11-01):

- `block_reward(height)` exists (crates/opacus-consensus/src/block.rs:
  `INITIAL_REWARD = 10_000_000_000`, halving every 210,000 blocks,
  shift capped at 60) and is exported, but is called by nothing - there
  is no coinbase transaction type and no subsidy enforcement;
- per-tx balance is already homomorphic: `sum(RC_in) - sum(RC_out) -
  fee * V = O` with a binding signature (v0.4 spec sections 4, 6), and
  `fee` is a public u64 field on the wire;
- leaf insertion into the sparse frontier is canonical and ordered
  (v0.4 spec section 9 step 6), so coinbase leaves can enter the same
  accumulator instance without any new tree machinery;
- total emission is finite and computable: the reward reaches 0 after
  34 halvings (~block 7,140,000), total supply 4,199,999,997,690,000
  atomic units.

GIP-1 fixed the funding POLICY before emission exists; this GIP makes
emission exist, mechanically simple - no fund split in the first
coinbase code path (GIP-1 section 4). Doing this before mainnet keeps
the window Zcash never had: issuance parameters go through public RFC,
not post-hoc amendment.

## 3. Specification

The key words MUST, MUST NOT, SHOULD, MAY are read as in RFC 2119.
References `[S4 N]` point to docs/specs/v0.4-value-conservation.md.

### 3.1 Transaction class v6 (COINBASE)

    tx v6 (COINBASE):
      version            u32 = 6
      height             u64  (MUST equal the containing block header height)
      outputs[]          n_out in [1, MAX_OUT = 4]:
            v_j          u64  (PUBLIC amount, native units)
            L_j          accumulator leaf (point, [S4 3])
            enc_note_j   opaque wallet note payload ([S4 7] transport)

A v6 transaction MUST NOT carry inputs, nullifiers, per-output RC
fields, a fee field, a circuit proof or a binding signature: a coinbase
spends nothing and creates value from the subsidy by definition; the
issuance equation below is the proof. v6 is valid ONLY as transaction
index 0 of a block whose header height equals the `height` field. A v6
transaction outside a block context (mempool, P2P gossip payload) is
invalid. v4/v5 parsers MUST reject v6 bytes; the v6 parser MUST reject
v4/v5 bytes. All three versions share the same field canonicality rules
(non-canonical encodings rejected, [S4 11]).

### 3.2 Derived value commitments (zero blinding)

For each coinbase output the validator computes

    RC_j = v_j * V            (blinding forced to 0, never transmitted)

and uses these derived points in the issuance equation. Hiding is not
lost: the amount is public on the wire by design (the subsidy is a
deterministic public function of height, so nothing beyond the fee
split is revealed), and the OWNER remains hidden - `enc_note_j` and the
leaf `L_j = P(D, a+b, a*b) + H_leaf * G3` with
`H_leaf = Poseidon_3(v, rho, DOM_LEAF)` are exactly as for ordinary
outputs. When the miner later spends the note, the spend circuit
reconstructs a fresh `RC` with a fresh blinding in-circuit ([S4 4]);
no special case exists downstream.

### 3.3 Block issuance rule (normative)

For every block, in addition to per-tx validation ([S4 9] steps 1-7):

1. exactly one v6 transaction MUST exist, at index 0; its `height` MUST
   equal the block header height;
2. `sum(v_j)` MUST equal `block_reward(height) + sum(fee_t)` over all
   v4/v5 transactions of the block - computed in u64 with overflow
   rejected (an overflow is a rejection, not a wrap);
3. the point equation MUST hold:
   `sum(RC_out(coinbase)) == (block_reward(height) + sum(fee_t)) * V`
   with RC_out derived per 3.2 - this is the fail-closed inflation
   check: claiming one atomic unit more or less than the deterministic
   subsidy plus fees fails;
4. coinbase leaves `L_j` MUST be inserted into the sparse frontier
   FIRST (canonical order: tx[0] leaves before tx[1..] leaves), and the
   resulting root MUST be the next canonical frontier root ([S4 9]
   step 6 machinery, unchanged);
5. no other transaction MAY precede or duplicate the coinbase; a block
   with a v6 transaction that fails any of the above is rejected whole.

`block_reward(height)` is the existing consensus function, unchanged.
Because each ordinary transaction balances itself ([S4 6] + bind_sig),
rule 3 is sufficient at block level: the residual of all per-tx
equations is exactly the coinbase imbalance.

### 3.4 No fund split (GIP-1 Stage 0 preserved)

100% of `block_reward(height) + fees` is payable to the miner. No
treasury, dev fund or OG split exists in this specification - GIP-1
Stage 0 fixes the OG allocation at 0%. Any future split is a separate
Standards Track GIP, allowed only after GIP-1 E-1 (this document), E-2
and E-3, and only within the caps C-1..C-5.

### 3.5 Activation

- `CONSENSUS_COINBASE_ACTIVATION_HEIGHT` (ConsensusParams, testnet
  parameter; the [S4 9] activation pattern). At and after the height,
  the rules of 3.3 apply and v6 is accepted; strictly before it, v6
  transactions are rejected and blocks MUST NOT contain one.
- The activation height defines where emission accounting starts. The
  accumulator instance is NOT reset: coinbase leaves are ordinary
  leaves of the running sparse frontier.

### 3.6 Emission bounds (informational, derived from existing code)

- Epoch length: 210,000 blocks x 120 s = ~292 days. Rewards:
  10,000,000,000 atomic units per block in epoch 1, halving per epoch;
  reward reaches 0 at 34 halvings (~block 7,140,000); total emission
  4,199,999,997,690,000 atomic units.
- After the subsidy reaches 0, the coinbase carries fees only. A
  coinbase MUST be present in a block if and only if
  `block_reward(height) + sum(fee_t) > 0`; a block with zero subsidy
  and zero fees MUST NOT contain one (the sum rule of 3.3(2)
  degenerates consistently in both directions).

## 4. Rationale

- **Zero-blinding derived commitments** (Monero RingCT style) instead of
  transmitted coinbase RCs: the subsidy is public by definition, so
  wire-banding a blinding factor buys nothing, and deriving `RC_j =
  v_j * V` lets the block-level equation close with NO new generators,
  NO circuit change and NO proof for the coinbase. Zcash-style chain
  value-pool accounting was rejected: it adds pool bookkeeping state
  for a property the per-tx balancing already delivers.
- **Public amounts on the coinbase wire**: revealed information equals
  `block_reward(height)` (already public) plus the miner's fee-split
  choice; owner secrecy is unaffected (sealed note, hidden leaf
  ownership). Privacy of ordinary transactions is untouched.
- **No coinbase maturity**: enforcing "spendable after N blocks" would
  require consensus to link a spent nullifier to the leaf's creation
  height - in a private chain that link is exactly what the anonymity
  set must NOT reveal. Deep-reorg fee sniping is the generic PoW reorg
  risk, covered by reorg economics, not by a maturity rule. A
  zero-knowledge age proof (leaf-insertion-height map + in-circuit
  height comparison) is a possible future extension (open question 8.1).
- **Mechanical simplicity first**: GIP-1 section 4 explicitly wants the
  first coinbase code path free of fund splits. This GIP closes E-1
  with the smallest consensus delta that makes issuance enforceable.

## 5. Backwards Compatibility

- New transaction version: pre-activation nodes reject v6 (version
  gate), post-activation nodes reject v4/v5-formatted coinbase
  attempts. Ordinary v4/v5 validation ([S4 9]) is unchanged.
- The sparse frontier accumulator is NOT reset; coinbase leaves are
  ordinary leaves, so wallet/tree logic needs no new instance.
- Wallet impact (WG-30 scope): recognize incoming coinbase `enc_note`
  payloads, persist `(v, rho, D, a, b)` as usual, spend them through
  the EXISTING v4 path (fresh RC blinding in-circuit). Block space
  grows by the coinbase transaction (~small, bounded by MAX_OUT = 4).
- ConsensusParams gain the activation height (testnet parameter;
  documented in release notes per the [S4 9] convention).

## 6. Test Plan (WG-30 must implement; P/N convention per GIP-0 section 6)

Positives:
- P1: honest block with coinbase `v = block_reward(height)`, leaf
  insertion order coinbase-first, canonical root advance - accepted.
- P2: coinbase collecting `subsidy + sum(fees)` across multiple fee-
  paying transactions - accepted.
- P3: reward-0 epoch (height >= ~7,140,000): fee-only coinbase -
  accepted.

Negatives:
- N1: overclaim by one atomic unit (`sum(v_j) = subsidy + fees + 1`)
  - rejected at the point equation.
- N2: underclaim (burning value) - rejected at the sum rule.
- N3: two coinbase transactions / coinbase not at index 0 - rejected.
- N4: `height` field != block header height - rejected.
- N5: v6 carrying inputs/nullifiers/proof fields - rejected at parse.
- N6: v6 broadcast outside a block (mempool) - rejected.
- N7: u64 overflow in `sum(v_j)` or `subsidy + fees` - rejected.
- N8: coinbase before the activation height - rejected.
- Wallet e2e: mine -> receive -> spend a coinbase note through the v4
  path (fresh RC blinding), all existing suites remain green.

## 7. Security Considerations

- **Inflation is fail-closed**: the only value-creation path is the
  deterministic equation of 3.3(3); any deviation fails. The bind_sig
  soundness argument ([S4 6]) is untouched - the coinbase adds no new
  signature or trust assumption.
- **Fee accounting**: fees are public u64 fields; overflow is a
  rejection (N7), not a wrap. The sum rule closes the classic
  "collect fees twice" hole.
- **No-maturity trade-off** (documented, not hidden): without a
  maturity rule, a deep reorg can re-target recent coinbase notes -
  the same attack class as any recent spend; reorg economics (PoW) is
  the mitigation. A ZK age proof remains a future option (8.1).
- **Coinbase privacy**: amounts public (deterministic subsidy), owners
  sealed. Mining pools concentrate payouts in clear - a known,
  accepted trade-off for the first implementation.
- **External audit**: the Mainnet gate (SECURITY.md) applies to the
  issuance path exactly as GIP-1 E-3 requires; activation on mainnet
  MUST NOT precede a passed audit cycle.

## 8. Open questions (for the RFC window)

1. ZK coinbase age proof (enables a maturity-like rule without linking
   spent leaves to creation heights) - needed at all, or reorg
   economics sufficient?
2. Miner payout conventions: single-output vs split outputs for pool
   payouts; is MAX_OUT = 4 enough for pool batching?
3. Tail-emission policy after epoch 34 (0% forever vs a future GIP-2
   vote to introduce one) - GIP-1/GIP-2 silent by design; RFC decides
   whether to pin "0% forever" now.
4. Wallet discovery for mining pools: direct payout construction vs
   WG-29 sealed enote transport for miner rewards.
5. Activation height coordination for testnet (parameter default) and
   whether genesis should embed the parameter for mainnet.
6. Whether the sighash/merkle coverage rules need a normative appendix
   for v6 (block merkle root already binds the coinbase; a redundant
   sighash is deliberately absent).
