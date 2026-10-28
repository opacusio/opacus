# WG-26 Scope Freeze: Swap Hashlock in the v4 zk Circuit

- Marker: WG-26-SCOPE-FREEZE-V1
- Status: FROZEN v1 (2026-10-28), repo HEAD 958da74 (v0.8.0)
- Queue: item (a) hashlock-in-circuit. Chain-level enforcement follows as WG-27 (item b). Audit stays last (item g).
- Evidence base: HASHLOCK-SCOUT-V2 dump at HEAD 958da74 (12 sections, 36 windows, 8 censuses).

## 1. Problem

The GHOST leg of an atomic swap is currently a p2p honor system:

- xmr_swap.rs tracks Phase Offered..Refunded, but GhostLocked only records a
  ghost_tx_ref string pointing at "the bridge pool". Nothing on-chain binds
  that pool lock to the offer hashlock.
- The preimage travels in swap_p2p messages (GhostLocked, Claim) in cleartext
  JSON; a claim is unverifiable by consensus.
- Consensus [S4 9] checks topology, proof, balance, nullifiers and root; it
  has zero swap awareness. Scout v2 census: 0 hashlock/preimage hits in zk
  spend.rs, zk v4.rs and wallet tx_v4.rs; consensus mentions only TxV4
  imports.
- xmr_swap.rs module docs name the gap explicitly (line 23: "Enforcing the
  hashlock inside the Ghost zk circuit ...").

## 2. Goals and Non-goals

Goals (scope of item a):

- G1. A swap-locked note can be spent only through a claim that reveals a
  valid preimage (in-circuit Poseidon check) or through a timeout refund.
- G2. Lock and claim publish the hashlock material as public instances, so
  WG-27 can enforce swaps chain-level with no new cryptography.
- G3. Plain (non-swap) transactions keep their semantics: the instance
  layout extends by APPENDING slots; the v4 wire format stays valid.

Non-goals:

- Monero CLSAG legs (WG-20/21/22 already cover the adaptor work).
- p2p message changes and node/swap_service wiring (WG-27).
- Legacy swap.rs engine (58 lines, 0 tests; deprecation candidate, separate
  hygiene item).

## 3. Frozen Design

### 3.1 Primitive (crates/opacus-zk/src/v4.rs)

- New domain: dom_swap() = fp_from_label(b"GHOST/v4/dom/swap").
- A 32-byte preimage splits into two canonical 16-byte lanes s0 and s1
  (each 128 bits, no field-reduction ambiguity).
- H = Poseidon_3(dom_swap, s0, s1) via the existing poseidon_absorb
  convention (same shape as nk and tree entries).
- hashlock_swap(preimage: [u8; 32]) returns (H, s0, s1). Host-side helper in
  WG-26; the same algebra is replicated in-circuit in WP-2.
- The bridge blake3 hashlock_of (b"ghost-swap-hashlock-v1") is UNCHANGED and
  remains the XMR-leg lock (Monero payment_id). One 32-byte preimage feeds
  both legs: blake3 on the XMR side, Poseidon lanes on the GHOST side.
  Revealing the preimage once satisfies both chains.

### 3.2 Swap modes (public instance slot 15)

flag: 0 plain, 1 lock, 2 claim, 3 refund. In-circuit range constraint:
flag times (flag-1) times (flag-2) times (flag-3) = 0.

- mode 1 LOCK: output number swap_idx (1-based) derives its leaf with H
  absorbed; all inputs stay plain; s0, s1 and entry instances are zero.
- mode 2 CLAIM: input number swap_idx derives its leaf with H absorbed; the
  circuit proves Poseidon_3(dom_swap, s0, s1) = H; the spent note tree entry
  is published in slot 20.
- mode 3 REFUND: identical membership and derivation to claim, but NO
  preimage check (s0 and s1 zero on wire and in circuit). The timeout itself
  is consensus-side: WG-27 checks height against the lock registration.
- Any mode other than 0 requires H nonzero. H = 0 is reserved for "no swap".

Enforcement intuition: a swap-locked note leaf exists in the tree ONLY in
its swap-derived form, so a plain (flag 0) spend of that note fails
membership. The owner cannot quietly re-spend it as a normal note.

### 3.3 Instance layout (normative [S4 12]; extends [S4 8])

Slots 0..14 unchanged (root, N_1..N_MAX_IN, RC_in pairs, RC_out pairs).
Appended tail; SPEND_INSTANCE_SLOTS goes from 15 to 21:

  slot 15: flag (0..3)
  slot 16: swap_idx (0; or 1..=MAX_OUT in lock, 1..=MAX_IN in claim/refund)
  slot 17: H
  slot 18: s0
  slot 19: s1
  slot 20: spent_swap_entry (tree entry of the swapped input, modes 2 and 3;
           zero otherwise)

spend_instances() gains the 6-slot tail with zero pads; tx.instances_of()
passes the swap fields; verify_v4 and mock_verify_v4 consume the 21-slot
vector.

### 3.4 Circuit mechanics (crates/opacus-zk/src/spend.rs)

- Witness: SpendWitness unchanged; V4SpendCircuit gains swap intent fields
  (mode, idx, h, s0, s1) on the circuit struct, same pattern as r_in/r_out.
- Leaf derivation: keep the plain H_leaf perm per note; add a swap
  continuation perm per note (one extra Poseidon block absorbing (H, 0));
  select plain vs swap scalars feeding the leaf chain with arithmetic select
  on indicator polynomials built from flag and swap_idx (public instances,
  so no witness branching).
- Claim preimage check: one extra Poseidon block in fixed domain proving
  Poseidon_3(dom_swap, s0, s1) - H = 0 under the mode 2 indicator.
- Spent entry: constrain_instance of the already-computed tree-entry cell of
  the selected input (no new perm).
- Negative-test hooks follow the corrupt_limb/corrupt_leaf convention:
  corrupt_preimage (flip a lane bit) and corrupt_swap_flag.

### 3.5 Row budget (k stays 11; gated by test)

Current: rows_needed() = 1551 rows at the full MAX topology; required_k()
adds margin 64; k = 11 gives 2048 rows; free = 2048 - (1551 + 64) = 433.
Additions: swap continuation perms MAX_IN x PERM_ROWS (2 x 17) for inputs
plus MAX_OUT x PERM_ROWS (4 x 17) for outputs = 102 rows; claim preimage
perm 17 rows; select plumbing and swap witness cells approx 20 to 40 rows.
Total approx +140 to +160. Projected: about 1711 + 64 = 1775 < 2048.
required_k() stays 11; a unit test asserts it so any regression fails
loudly.

### 3.6 Wire (crates/opacus-wallet/src/tx_v4.rs)

- TX_VERSION_V5: u32 LE version 5. Layout: the complete v4 byte layout,
  then a mandatory swap tail: flag u8, swap_idx u8, H 32B (Fp LE), s0 32B,
  s1 32B, entry 32B. Tail is 130 bytes.
- from_bytes: version 4 parses exactly as today and rejects any trailing
  bytes, so v4 parsers reject v5 bytes (no ambiguity). Version 5 parses the
  v4 fields then the tail with canonical rules: flag 0 forces all five swap
  fields zero; flag 1 requires H nonzero, s lanes zero, entry zero; flag 2
  requires H nonzero, (s0, s1) nonzero, entry nonzero; flag 3 requires H
  nonzero, s lanes zero, entry nonzero; swap_idx bounds per mode; any
  violation is TxV4Error::Canonical or Topology.
- to_bytes: v4 fields then the tail.
- sighash: sighash_v5 = blake3(b"GHOST/v4/sighash", le64(5), root, ns,
  leaves, rc_in, rc_out, fee, le64(flag), le64(swap_idx), H, s0, s1, entry).
  All verification-relevant swap material is covered (enc_notes stay
  deliberately uncovered, as documented today).
- TxV4 struct gains: swap_flag u8, swap_idx u8, swap_h Fp, swap_s0 Fp,
  swap_s1 Fp, swap_entry Fp. check_topology extends with the same mode
  rules.

### 3.7 Wallet surface

- pub enum SwapIntent { Lock { out_index, preimage }, Claim { in_index,
  preimage }, Refund { in_index } } (usize index, [u8; 32] preimage).
- SpendPlanV4 gains pub swap: Option<SwapIntent>; build_zk_spend_v4 derives
  (H, s0, s1) via hashlock_swap, computes the swap-variant leaf and emits a
  v5 TxV4; confirm_zk_tx accepts v4 and v5 (the wallet is the first
  validator, [S4 10]).
- The lock note must be created with the counterparty key shares; the wallet
  API docs state that the maker loses unilateral spend authority over that
  output (by design).

### 3.8 Consensus and p2p (preview of WG-27, item b)

- ConsensusParams.swap_activation_height; accept_transaction admits version
  5 only at/after it (v4 stays accepted; both accepted post-activation).
- ConsensusState gains the swap registry: H maps to (entry, lock_height,
  claim_timeout). Lock (flag 1) inserts (H, tree_rep of leaves[swap_idx-1]);
  claim and refund (flags 2, 3) require registry[H].entry equal to the
  published spent_swap_entry; refund additionally requires height at/after
  lock_height + claim_timeout.
- swap_node.rs and swap_service.rs wire registry events into the existing
  p2p swap plane; GhostLocked and Claim messages keep flowing (ops
  convenience) while the chain becomes the arbiter.

## 4. Work Packages

- WP-1 (zk primitive): v4.rs dom_swap + lane split + hashlock_swap + unit
  vectors. Small, no circuit changes.
- WP-2 (circuit): instance tail, swap continuation and select, claim check,
  entry instance, negative tests, required_k assert.
- WP-3 (wire and wallet): TX_VERSION_V5, tail codec, sighash_v5, SwapIntent
  plumbing, round-trip and rejection tests.
- WP-4 (docs and close): [S4 12] normative text, README protocol line,
  CHANGELOG unreleased entry, commit split zk / wallet / docs.
Order: WP-1, WP-2, WP-3, WP-4 strictly; each keeps the tree compiling and
tests green.

## 5. Test Plan (minimum gate)

- T1 hashlock_swap vectors: a known preimage gives stable (H, s0, s1); lane
  split round-trips.
- T2 mock-prover positives: plain tx green (regression); lock honest green;
  claim honest green; refund honest green.
- T3 negatives: wrong preimage (claim); H mismatch (claim against a lock of
  a different H); plain spend of a locked note; flag or idx out of range;
  lock with s lanes nonzero; claim with zero lanes.
- T4 required_k() still 11.
- T5 wire: v5 round-trip; v4 parser rejects v5 bytes; canonical rejections
  per 3.6; sighash_v5 differs from the v4 digest.
- T6 wallet: lock-then-claim end-to-end on one tree (build both, confirm
  both); refund path builds.
- T7 consensus: existing v4 fixtures stay green (no behavior change before
  WG-27).

## 6. Anchors at HEAD 958da74 (scout v2)

- zk spend.rs (2562 lines): MAX_IN 108, MAX_OUT 110, PERM_ROWS 119,
  SPEND_INSTANCE_SLOTS 126, SpendHashConfig 429, V4SpendCircuit 1667,
  rows_needed 1688, required_k 1705, instance order 1913, sighash_v4 195.
- zk v4.rs: dom_leaf_v2 72, dom_nk 77, dom_nu 82, hashgen 112, value_commit
  143, nullifier_key 148.
- zk v4_prover.rs (463 lines): spend_instances 38, prove_v4 241,
  acc_root_point 345.
- wallet tx_v4.rs (967 lines): WalletNoteV4 63, TxV4Error 127, TxV4 194,
  check_topology 220, instances_of 276, sighash 284, to_bytes 298,
  from_bytes 328, SpendPlanV4 451, build_zk_spend_v4 461, confirm_zk_tx 594.
- consensus v4.rs (595 lines): ConsensusParams 53, ConsensusState 83,
  accept_transaction 271, confirm_v4_consensus 315.
- bridge: xmr_swap.rs 357 lines (Offer 58, hashlock_of 104), swap_p2p.rs
  1281 lines (SwapOfferPayload 58, Frame 104, OfferAdaptor 292), swap.rs
  58 lines (legacy engine).

## 7. Risks and Notes

- R1. The instance layout bump invalidates existing proofs on testnet
  (halo2 binds the instance column length). Testnet-only BREAKING; document
  in CHANGELOG; no mainnet exposure (pre-mainnet).
- R2. The v5 tail sits after bind_sig, keeping the v4 byte prefix stable;
  the sighash domain string stays b"GHOST/v4/sighash" with the le64(5)
  version tag (no new domain label).
- R3. enc_notes remain outside the sighash (pre-existing documented gap;
  unchanged by WG-26).
- R4. H = 0 is reserved; a Poseidon output colliding with 0 is negligible,
  and mode 0 forces the zero lanes anyway.
- R5. The spent-entry instance (slot 20) publishes the link between a claim
  and its lock; this link is inherent to atomic swaps and leaks nothing
  beyond what the lock already published.
