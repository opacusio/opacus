# WG-CLSAG: Monerod-facing CLSAG verification - scope doc (design freeze)

- Status: DESIGN FROZEN (WP-A)
- Date: 2026-10-31
- Base: fd1e2c89ffff6dfbd9bcb5e471cd125b0b239bac (WG-29 WP-E)
- Target release: v0.4
- Owner: opacus-bridge

## 1. Goal

Add real, byte-compatible VERIFICATION of Monero CLSAG ring signatures to
opacus-bridge, so the Ghost side can cryptographically confirm the Monero
legs of atomic swaps (lock, claim, refund) directly from monerod data.

This closes the gap left open in v0.3: crates/opacus-bridge/src/clsag.rs is
a bridge-internal, single-signer CLSAG-style adaptor primitive. Its
hash-to-point (domain-separated blake3 try-and-increment) and its challenge
tags (ghost-bridge/clsag/*-v1) are deliberately NOT monerod-compatible;
clsag.rs L26-L31 states that byte-compatibility lands with on-chain CLSAG
verification in v0.4. That v0.4 layer is this work package.

Verification only. This package does not add signing of real monerod CLSAGs
and does not change the existing adaptor primitive in any way.

## 2. Background - current state (recon v2, 2026-10-31)

- crates/opacus-bridge/src/clsag.rs (615 lines, sha b5b349d7d459):
  one-time keys P = [x] B and I = [x] H(P), validate_one_time_binding,
  adaptor sign / verify / complete / recover, 14 tests.
- crates/opacus-bridge/src/adaptor.rs (477 lines, sha bca89fed5fb6):
  Schnorr adaptor over the swap secret t (SwapSecret, AdaptorSignature).
- crates/opacus-bridge/src/xmr_swap.rs (393 lines, sha 9562252db727):
  swap session state machine: lock_xmr, mark_xmr_locked, claim, refund,
  WG-18 deadline rules.
- crates/opacus-bridge/src/swap_p2p.rs (1281 lines, sha 78e93b70971c):
  WG-21/22 offer sidecar OfferAdaptor {p, image} with fail-closed
  structural validation (validate_one_time_binding at receive time).
- crates/opacus-bridge/src/xmr_dleq.rs: DLEQ proofs for Monero legs.
- crates/opacus-bridge/src/xmr_rpc.rs: monerod RPC transport behind the
  Transport trait (get_info and friends).
- curve25519-dalek 4.1.3 in Cargo.lock; bridge and opacus-crypto both
  depend on it (edwards + scalar features available).

## 3. In scope

1. New module crates/opacus-bridge/src/clsag_verify.rs:
   - parse the CLSAG section of a Monero ringCT transaction
     (rctSigPrunable, RCTTypeCLSAG): per input n scalars s[0..n-1], c1,
     key image I, pseudo-out commitment D (32 bytes each); n is parsed
     from the tx, not hardcoded (16 for current mainnet txs);
   - pseudoOuts for CLSAG txs live in the prunable section;
   - message m per monero get_pre_mlsag_hash (tx prefix hash + rct base).
2. Verify each input against its ring:
   - one-time pubkeys P_i and amount commitments C_i of the decoys are
     resolved from the txin_to_key key_offsets (absolute offsets into the
     chain output index space) via get_outs;
   - the real input commitment comes from the tx itself.
3. Fixture-driven acceptance tests with REAL monerod data (section 6).
4. Transport extension in xmr_rpc.rs: get_transactions / get_outs behind
   the existing Transport trait.
5. lib.rs: pub mod clsag_verify; plus the re-exports needed by tests.

## 4. Out of scope (this work package)

- Signing monerod-compatible CLSAGs (maker XMR lock spend). Separate
  package: needs wallet-side ring selection. The current clsag.rs
  adaptor primitive stays byte-for-byte unchanged.
- MLSAG and pre-HF12 ring sizes (Monero txs older than October 2020):
  not verified.
- Bulletproofs / range proofs: monerod stays the source of truth for
  overall tx validity; we verify the CLSAG layer only.
- Ghost consensus changes: chain-level swap enforcement with CLSAG
  evidence is WP-C over the WG-27 lanes (refund/claim) in v4.rs.

## 5. Verification algorithm - normative references

The normative algorithm is the Monero implementation, not a paper text:

- monero/src/ringct/rctSigs.cpp: genClsag, verClsag
- monero/src/ringct/rctTypes.h: clsag struct (s, c1, I, D); pin the
  numeric value of RCTTypeCLSAG against rctTypes.h during WP-B
- monero/src/ringct/rctOps.cpp: hash_to_point via ge_fromfe_frombytes_
  vartime on the key image (NOT the blake3 try-and-increment of the
  v0.3 bridge primitive), scalar ops
- domain tag literals to pin against monero source during WP-B:
  CLSAG_agg_0 (challenge modifier over ring P and the key image),
  CLSAG_agg_1 (over ring C and the pseudo-out D), CLSAG_round (round
  challenge hash)
- CLSAG paper: Concise Linkable Spontaneous Anonymous Group signatures
  (2020), deployed in Monero at network upgrade 12 (October 2020, ring
  size 11 -> 16)

The structure to reproduce: challenge modifiers mu_P and mu_C scale the
key ring and the commitment ring respectively; the round challenge chains
over (L_i, R_i) pairs computed from the scaled ring, the key image and
the pseudo-out. Exact equations and tag literals are pinned from monero
source during WP-B; ground truth is real monerod data, so any drift is
caught by the fixture tests below, which are the acceptance gate.

Fail-closed structural checks before any cryptographic work: scalars
must be canonical (< curve order l), points must decompress, key image
must not be the identity, ring size must be >= 2, parsed lengths must
consume the signature buffer exactly. Reject-early discipline mirrors
the verify_rejects_* test family of clsag.rs.

## 6. Fixtures and acceptance tests

1. Fixture source: a real mainnet Monero transaction with CLSAG
   signatures, captured as unpruned raw tx hex plus the ring member
   data (one-time keys, commitments) pulled via get_outs.
2. Storage: tests/fixtures/clsag_mainnet_v1.json (tx hex, height, ring
   offsets, expected verdicts). ASCII JSON only, no secrets.
3. Tests (all must pass):
   - parse_fixture_roundtrip: parse the tx; per-input s/c1/I/D and
     pseudoOuts counts match the ring size and the input count;
   - verify_fixture_accepts: the verClsag-equivalent accepts every
     input of the honest tx;
   - tamper_rejected: flipping one bit in s, c1, I, D or in one ring
     member breaks verification (matrix over all inputs);
   - ring_substitution_rejected: swapping one decoy for another real
     chain output breaks verification;
   - non_canonical_scalar_rejected: any s_i >= l rejected pre-crypto;
   - buffer_exactly_consumed: trailing or missing signature bytes are
     a parse error.
4. Byte-compat pin: re-serializing the parsed signature must reproduce
   the exact byte slice of the fixture tx.

## 7. Risks

- key_offsets decoding (varint absolute offsets) mistakes: mitigated by
  the re-serialize byte-compat pin (section 6, item 4).
- commitment leg handling: full C_i ring verification needs get_outs
  commitments; it lands in WP-B behind its own test and never merges
  untested. The key-image leg is verified first.
- degenerate points (small order, torsion) in I or D: fail-closed
  rejects, reusing the degenerate-point discipline of clsag.rs.
- monero hard forking again (new ring size or new tx type): the parser
  is versioned and rejects unknown tx types instead of guessing.

## 8. Work packages

- WP-A (this commit): design freeze, scope doc only, no code.
- WP-B: clsag_verify.rs + parser + verClsag-equivalent + fixture tests
  + xmr_rpc Transport extension. Gates: cargo check --workspace
  --all-targets, cargo test -p opacus-bridge --release, CI green.
  Bench: SKIPPED-BY-CONSTRUCTION (opacus-zk circuit untouched).
- WP-C: chain-level swap enforcement: CLSAG evidence wired into the
  WG-27 claim/refund lanes in consensus v4.rs (Refund frames, README
  roadmap L323-324). Separate scope pin + impl; consensus tests
  required.
- WP-D: README + CHANGELOG updates, bench smoke at the new HEAD
  (22400 proof bytes baseline must hold), push + CI watch.

## 9. Acceptance for WP-A (this commit)

- Exactly one new file docs/WG-CLSAG-verify-scope.md; zero production
  code touched; numstat = 1 added file, 0 deletions.
- cargo check --workspace --all-targets: pass (tree otherwise intact).
- cargo test -p opacus-bridge --release: pass (all 14 clsag tests and
  the rest of the bridge suite intact).
- Bench: SKIPPED-BY-CONSTRUCTION - no crate in the zk path is modified,
  so the 22400 proof bytes baseline cannot change.
