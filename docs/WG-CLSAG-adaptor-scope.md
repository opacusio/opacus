# WG-CLSAG-adaptor: Monerod-compatible CLSAG adaptor signatures - scope doc (design freeze)

- Status: DESIGN FROZEN (WP-A)
- Date: 2026-11-01
- Base: c0800ae4b8b1041e80b8c71c39445203fa0ea6cc (v0.9.0, CI 4/4)
- Target release: post-v0.9.0 ([Unreleased])
- Owner: opacus-bridge

## 1. Goal

Add real, monerod-compatible CLSAG ADAPTOR signatures to opacus-bridge: a
Monero one-time spend can be pre-signed as a standard CLSAG bound to a
hidden swap secret t; the counterparty completes it with t and the result
is a CLSAG that passes monerod's verRctCLSAGSimple unmodified; the
completed signature, once visible on the Monero chain, hands the adaptor
holder the secret t.

This is the Monero-side half of on-chain swap enforcement (the Ghost-side
half is WG-27 chain-level CLAIM/REFUND rules). The README roadmap item
"CLSAG adaptor signatures for on-chain swap enforcement" is delivered by
this package.

Verification-only predecessor: crates/opacus-bridge/src/clsag_verify.rs
(WG-CLSAG, v0.9.0) - byte-compatible monerod verifier with real elligator
hash-to-point and real CLSAG domain tags. The v0.3 primitive
crates/opacus-bridge/src/clsag.rs (single-signer, blake3 hp) stays
untouched; this package supersedes it on the Monero side.

## 2. The construction (normative)

Monerod-compatible pieces, reused from clsag_verify.rs (no new
implementations):

- mu_P = H(CLSAG_agg_0 || dests || masks || I || D || C_offset),
  mu_C = H(CLSAG_agg_1 || ...) (rctSigs.cpp aggregation hashes);
- round skeleton H(CLSAG_round || dests || masks || C_offset || message);
- Hp(P) = hash_to_p3 (monero hash_to_ec over ge_fromfe_frombytes_vartime);
- canonical scalars (< l), decompress + non-degenerate discipline.

Signer side (index di, one-time key x, blinding difference z where
[mask_di] - [C_offset] = [z]G):

- P = [x]G, I = [x]Hp(P), D = [z]Hp(P);
- nonce a (deterministic, domain-separated, section 4);
- R_G = [a]G, R_H = [a]Hp(P);
- initial challenge c = H(round_skeleton || R_G || R_H) - the STANDARD
  monerod initial challenge; the adaptor never touches the challenge
  inputs of any other position;
- walk all other positions with fresh random s_i (standard);
- pre-signature s'_di = a - t - c_di*(mu_P*x + mu_C*z), where
  T = [t]G and T_h = [t]Hp(P).

Adaptor public block (bridge-internal, off-chain - NOT part of any wire
format): { T, T_h, R_G, R_H, di } attached to the standard
ClsagSig { s (with s'_di at di), c1, d }.

Adaptor verification (verifies without x or t, reusing the monerod walk):

1. standard structural checks: n >= 2, |s| = n, all s' canonical, c1
   canonical, I / D / ring points decompress, I / D8 non-degenerate;
2. walk from c1 over positions 0..n-1 (standard challenge chain, s'
   values) - the walk is c1-seeded and closes exactly like monerod's;
3. initial-challenge binding: c_{di+1} == H(round_skeleton || R_G ||
   R_H), with c_{di+1} taken from the walk;
4. adaptor binding at di:
   L'_di + T == R_G and R'_di + T_h == R_H, where
   L' = s'_di*G + [c_di*mu_P]P_di + [c_di*mu_C](mask_di - C_offset),
   R' = s'_di*Hp(P_di) + [c_di*mu_P]I + [c_di*mu_C]*D8.

Because T enters NO challenge, the completed signature s_di = s'_di + t
is structurally indistinguishable from an honest CLSAG: it closes under
the unmodified monerod walk and is monerod-valid. t is recovered from the
on-chain signature: t = s_di - s'_di, accepted only if canonical and
[t]G == T and [t]Hp(P) == T_h.

Degeneracy policy (WG-19 discipline): T, T_h, R_G, R_H must decompress,
must not be identity and must not be small-order; di < n; s'_di canonical
before any crypto; recovered t canonical before use.

## 3. In scope

1. New module crates/opacus-bridge/src/clsag_adaptor.rs:
   - ClsagAdaptorSig struct { sig: ClsagSig, t_point, t_h_point, r_g,
     r_h, di } (named ...Sig to avoid the root re-export collision with
     the v0.3 clsag::ClsagAdaptor);
   - sign_adaptor(...) -> ClsagAdaptorSig (deterministic nonce);
   - verify_adaptor(&adaptor, message, key_image, ring, c_offset) -> bool;
   - complete(&adaptor, t) -> ClsagSig (canonical check on t AND
     [t]G == T before any completion);
   - recover_secret(full: &ClsagSig, adaptor, ring) -> Option<[u8; 32]>
     with the [t]G and [t]Hp(P_di) consistency checks;
   - synthetic ring builder for tests (decoys = deterministic prime-order
     points, zero-amount commitments; the CLSAG algebra only consumes
     ring points and C_offset, amounts are out of scope).
2. Visibility only in clsag_verify.rs: hash_to_scalar, tag_slot,
   canonical_scalar, decompress_point and the three domain tags
   HASH_KEY_CLSAG_AGG_0 / AGG_1 / ROUND become pub(crate). NO logic
   changes.
3. Test suite pinned to the matrix in section 5, fail-closed.

## 4. Nonce policy

a = hash_to_scalar("ghost-bridge/clsag-adaptor/nonce-v1" || x_bytes ||
T || message || le64(di)). Deterministic: signing never depends on system
randomness and never reuses a nonce across distinct (message, T) pairs.
The domain tag is fresh - no collision with the v0.3 tags
(ghost-bridge/clsag/*-v1) or WG-18 (sha3 over key + point + message).

## 5. Test matrix

- P1 honest loop: sign -> verify_adaptor ok -> complete -> the completed
  ClsagSig passes the UNMODIFIED monerod-compatible verify_clsag ->
  recover_secret returns t (acceptance gate).
- P2 determinism: two signs over the same input are byte-identical.
- P3 recovery consistency: t*G == T and t*Hp(P) == T_h.
- P4 challenge-sequence identity: the completed signature and the adaptor
  walk share the same c sequence (P1 implies it; pinned by an explicit
  test that recomputes both chains).
- N1 wrong T; N2 wrong T_h; N3 wrong R_G; N4 wrong R_H; N5 wrong di
  (shifted and out of range); N6 tampered s'_di; N7 tampered s'_decoy;
  N8 degenerate T (identity / small order); N9 non-canonical s'_di
  (+l encoding); N10 ring substitution (decoy dest/mask swapped);
  N11 completion with wrong t -> verify_clsag rejects;
  N12 non-canonical t at completion rejected;
  N13 wrong message rejected; N14 wrong C_offset rejected;
  N15 key image / D mismatch rejected.

## 6. Out of scope

- Swap protocol integration (xmr_swap.rs state machine, swap_p2p sidecar
  fields, bridge service wiring) - a later WP on top of this primitive.
- Ghost-side (FCMP/Halo2) adaptor signatures.
- Range proofs / amounts: verify_clsag does not cover Bulletproofs.
- Wire formats: the adaptor block is bilateral off-chain data; the v5
  tail (130 B) and the 21-slot instance layout stay frozen (WG-26 v1).

## 7. Acceptance gate

Every test fail-closed; the honest completed signature must verify with
the unmodified verify_clsag (the monerod-compatible port) - that is the
"monerod-valid completion" criterion. Local gates: fmt, clippy -D
warnings (all-targets), build, test --workspace. CI: all checks green,
no bypass.
