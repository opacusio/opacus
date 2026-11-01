# WG-CLSAG-adaptor-int: Swap protocol integration of the CLSAG adaptor - scope doc (design freeze)

- Status: DESIGN FROZEN
- Date: 2026-11-01
- Base: aeaf76a8 (WG-CLSAG-adaptor WP-D, CI 4/4 on c0800ae base)
- Target release: post-v0.9.0 ([Unreleased])
- Owner: opacus-bridge

## 1. Goal

Close the deferred item of `docs/WG-CLSAG-adaptor-scope.md` section 6
("Swap protocol integration - xmr_swap.rs state machine, swap_p2p sidecar
fields, bridge service wiring - a later WP on top of this primitive"): the
monerod-compatible CLSAG adaptor primitive (`clsag_adaptor.rs`, WP-B) becomes
a first-class, fail-closed part of the XMR <-> GHOST swap coordination
protocol. The taker pre-signs the Monero-side claim spend of the locked XMR
as a CLSAG adaptor bound to the swap secret `t`; the maker completes it with
`t` derived from his own preimage and obtains a signature that passes the
UNMODIFIED monerod-compatible `verify_clsag` - the Monero-side counterpart of
the WG-26 in-circuit hashlock proof and the WG-27 chain-level CLAIM/REFUND
rules.

## 2. The binding (normative)

The swap secret and the claim message are deterministic functions of data
both sides already hold - no new secrets are introduced and no extra
secret-handover frame is needed:

- `t = hash_to_scalar("ghost-bridge/swap-secret-v1" || preimage)` - reduced
  mod l by the monerod `hash_to_scalar`, so `t` is always a canonical scalar
  (a raw blake3 output would be non-canonical for ~2.7% of preimages and
  `complete` would reject honest completions). Domain-separated from the
  hashlock (`ghost-swap-hashlock-v1`), the WG-21 offer OTK
  (`ghost-bridge/offer-otk-v1`) and the adaptor nonce tag.
- `message = blake3("ghost-swap/xmr-claim-msg-v1" || offer_id || hashlock)` -
  the bilateral claim-tx binding: the pre-signature is only valid for the
  claim of THIS swap (the offer id already binds the full offer payload).

`complete` enforces `[t]G == T` before completing, so the completed
signature exists if and only if the adaptor was honestly bound to
`t(preimage)`; the `verify_clsag` acceptance gate runs on every completion.
The completed on-chain signature hands the holder the secret
(`recover_secret`: `t = s_di - s'_di`, `[t]G == T`, `[t]Hp(P_di) == T_h`) -
on-chain, monerod-visible evidence of preimage knowledge.

## 3. Protocol placement

The adaptor rides the existing `Claim` frame (taker -> maker) as an OPTIONAL
Frame-level sidecar `xmr_claim` - the same pattern as the WG-21 offer OTK
sidecar: `serde(default)` + `skip_serializing_if` keep v1 frames decodable,
old binaries ignore the unknown JSON field, offer ids are untouched. The
sidecar is bilateral off-chain data (scope doc of WP-B, section 2); the v5
tail (130 B) and the 21-slot instance layout stay frozen (WG-26 v1).

Choreography (adaptor-enabled taker; heights are caller-provided as in v0.1):

```text
Offer -> Accept -> XmrLocked -> GhostLocked (preimage revealed)
  taker: build_xmr_claim(x, z, preimage, offer binding, ring, c_offset, di)
         attach_xmr_claim (Taker, GhostLocked)
  taker: publish_claim -> Claim frame CARRIES xmr_claim sidecar
  maker: Claim handler - structural parse, verify_adaptor + message binding,
         complete with t = swap_secret(session preimage), verify_clsag gate,
         completed signature stored on the session
  legacy: a Claim WITHOUT the sidecar follows the v1 path unchanged
```

Fail-closed discipline (WG-22 pattern): an invalid sidecar rejects the whole
frame BEFORE any state transition (`peer_claimed` stays unset, the maker's
refund window keeps running); the adaptor sidecar is only accepted on Claim
frames; a session without a stored preimage cannot complete.

## 4. In scope

1. `xmr_swap.rs` (state machine + protocol record):
   - `swap_secret`, `swap_claim_message` (section 2);
   - `XmrClaimAdaptor { adaptor: ClsagAdaptorSig, ring: Vec<RingMember>,
     key_image, c_offset }` with `build_xmr_claim` (taker-side builder over
     `sign_adaptor` + `hash_to_p3`, self-check `verify_adaptor`),
     `verify_for` (message binding + `verify_adaptor`) and `complete_for`
     (`complete` + `verify_clsag` acceptance gate);
   - session fields `xmr_claim` / `xmr_completed` and the state machine
     methods `attach_xmr_claim` (Taker, GhostLocked) and
     `complete_xmr_claim` (Maker, GhostLocked);
   - new `SwapError` variants: `MissingPreimage`, `XmrClaimInvalid`.
2. `swap_p2p.rs` (wire): hex sidecar `XmrClaimSidecar` with structural
   validation (`to_claim` / `from_claim`), `Frame.xmr_claim` field, threading
   into the Claim handler (fail-closed), `publish_claim` (taker; drives
   `SwapSession::claim` to Claimed and auto-attaches the sidecar), new
   `SwapNetError::XmrClaimSidecar(&'static str)`.
3. Test matrix pinned to section 6, fail-closed. Crate: opacus-bridge only -
   the network/node layers consume `SwapNet::receive_frame` and need no
   changes (optional sidecar, unchanged method signatures).

## 5. Out of scope

- opacus-network / opacus-node service wiring (the layers above the bridge;
  a later WP if the node API should expose the adaptor explicitly).
- Real Monero transaction construction (tx prefix, outputs, Bulletproofs):
  the claim `message` is the bilateral binding above; ring and `c_offset`
  are caller-provided exactly as in WP-B's synthetic model.
- Ghost-side (FCMP/Halo2) adaptor signatures; the v0.3 primitives
  (`adaptor.rs`, `clsag.rs`) stay untouched; wire formats stay frozen.

## 6. Test matrix

- P1 honest loop over the wire: offer -> accept -> xmr lock -> ghost lock ->
  attach -> publish_claim -> the maker session stores a completed signature
  that passes the UNMODIFIED monerod-compatible `verify_clsag` (acceptance
  gate) and `recover_secret` returns `t = swap_secret(preimage)`.
- P2 determinism: two `build_xmr_claim` calls over the same inputs produce
  byte-identical sidecars (deterministic nonce, WP-B).
- P3 `swap_secret` is always canonical (reduced mod l) and domain-separated
  from the hashlock / offer OTK derivations.
- P4 legacy path unchanged: a Claim without the sidecar is accepted on a
  session without adaptor bookkeeping; v1 frames decode.
- P5 message binding: adaptors built for a different offer / hashlock are
  rejected (`verify_for` message check).
- N1 tampered `s'` (decoy position) rejected; N2 tampered `s'_di` rejected;
  N3 adaptor bound to a wrong secret (T mismatch) fails completion; N4 wrong
  message binding rejected; N5 non-canonical `s'` encoding rejected;
  N6 ring substitution rejected; N7 `di >= n` rejected structurally;
  N8 `s.len() != n` rejected structurally; N9 non-hex sidecar fields
  rejected; N10 sidecar on a non-Claim frame rejected; N11 missing stored
  preimage rejected (`MissingPreimage`); N12 wrong-role claim rejected
  (state machine, unchanged); N13 sidecar length mismatches (`ring` /
  `dests` / `masks` / `s`) rejected.

## 7. Acceptance gate

Every test fail-closed; the maker-side completion must produce a signature
that verifies with the unmodified monerod-compatible `verify_clsag` - the
"monerod-valid completion" criterion of WP-B carries over to the protocol
layer. Local gates: fmt, clippy -D warnings (all-targets), build,
test --workspace. CI: all checks green, no bypass.
