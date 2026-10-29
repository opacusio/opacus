# WG-27 -- Chain-level swap enforcement (claim/refund as consensus checks)

Status : DRAFT v3 (frozen by the WP-1 commit; after that -- fix-forward only)
Drafted: 2026-10-29, at HEAD b9417acbb058d86a507fe14c39f0baa28a8eae13 (WG-26 WP-4)
         v3 = v2 + precision upgrades from the scope v2 probe audit; no rule
         changes (R1-R5 keep their meaning).
Parent : WG-26 (docs/WG-26-swap-hashlock-scope.md), hashlock frozen design v1,
         including its section 3.8 preview of WG-27 (item b)
Spec   : docs/specs/v0.4-value-conservation.md, section 12, cited repo-wide
         as [S4 12]

## 1. Problem

WG-26 shipped the swap hashlock machinery end to end: dom_swap domain lanes
s0/s1 (16 bytes each), the commitment H = Poseidon_3(dom_swap, s0, s1),
LOCK/CLAIM/REFUND frame semantics, the 21-slot layout, and TX_VERSION_V5
with a 130-byte swap tail fully covered by sighash. Wallets can build, sign
and broadcast v5 swap transactions (SwapIntent; build_zk_spend_v5 /
confirm_zk_tx_v5 in crates/opacus-wallet/src/tx_v4.rs).

What WG-26 intentionally left out is turning the claim/refund lifecycle
into a consensus-checked property. The repo says so explicitly: CHANGELOG
("becomes a consensus check in WG-27"), README ("timeout enforcement is
WG-27"), WG-26 section 3.8 (preview of WG-27, item b), and the spec note
at v0.4-value-conservation.md:309 ("itself is consensus-side (WG-27)").
Today timeout knowledge lives outside the chain state machine: bridge-side
offer timeouts (crates/opacus-bridge/src/swap_p2p.rs) and the WG-18
deadline sweep (SwapNode::enforce_deadlines) auto-refund expired bridge
sessions. But a node that accepts a CLAIM after expiry, or a REFUND before
expiry, still finalizes a transition the swap contract never allowed -- and
honest peers have no consensus rule with which to reject the offending
transaction or block.

## 2. Goal and non-goals

Goal: CLAIM/REFUND validity becomes a deterministic function of chain state
and height, enforced by consensus. Rules:

    R1  CLAIM is valid only while confirm height h < T, with
        T = H_lock + W_claim. H_lock is the height of the LOCK
        registration in consensus state (WG-26 section 3.8: "WG-27 checks
        height against the lock registration"). W_claim is the claim
        window of the swap record; the bridge already carries
        claim_timeout_blocks (service default 200). Whether W_claim rides
        the LOCK tail or becomes a ConsensusParams default is a WP-2
        decision (open point O1); if it rides the tail, sighash coverage
        applies as everywhere else in v5. The frame must prove knowledge
        of the preimage lanes (s0, s1) with Poseidon_3(dom_swap, s0, s1)
        == the commitment recorded at LOCK, directly or via the WG-26 ZK
        path.
    R2  REFUND is valid only while h >= T. No preimage is required. The
        frame must be authorized per the LOCK record (sighash over the v5
        tail). The pre-LOCK fund window (fund_timeout_blocks) never
        reaches consensus: before LOCK there is nothing on-chain to
        police, so it stays bridge-side (WG-18).
    R3  A swap terminalizes exactly once: after a valid CLAIM or REFUND,
        any further CLAIM/REFUND on the same swap id is rejected.
    R4  CLAIM/REFUND for an unknown or not-yet-LOCKed swap id is rejected.
    R5  Consensus (confirm_v4_consensus) is the single source of truth.
        The node level (swap_service, feed_height path) mirrors R1/R2 as
        admission filters that may only be stricter than consensus, never
        looser.

Boundary semantics: strict inequality for CLAIM (h < T), inclusive for
REFUND (h >= T). No dead zone: at every height exactly one of CLAIM/REFUND
is possible.

Non-goals:
- No wire format changes: TX_VERSION_V5, the 130-byte tail, the 21-slot
  layout and sighash coverage stay frozen (WG-26 design v1).
- No new hashlock primitives: dom_swap lanes and Poseidon_3 usage unchanged
  (WG-26: swaps enforced chain-level "with no new cryptography").
- No new p2p messages. WG-26 section 3.8 deferred "p2p message changes and
  node/swap_service wiring" to WG-27; the wiring half lands in WP-3 (R5),
  the p2p half closes as "not needed": terminalization is observed
  on-chain and WG-18 Refund notices already exist. If the WP-3 review
  finds a gap, it is a scope amendment in this file first.
- No bridge protocol rework: swap_p2p.rs, swap_node.rs and xmr_swap.rs are
  read-only prior art; the WG-18 sweep stays, subordinated to consensus
  (section 7).
- No cooperative/premature refund path: refund before T is out of scope.

## 3. Surfaces touched (anchors verified at b9417ac)

- crates/opacus-consensus/src/v4.rs (596 lines): ConsensusParams,
  ConsensusState, accept_transaction, confirm_v4_consensus; a swap slot
  already exists in the construction code (v4.rs:408 "swap: None").
  WP-2 implements R1-R4 here plus the negative test matrix.
- crates/opacus-node/src/swap_service.rs (521): feed_height chain-tip
  feed; already runs the WG-18 sweep passthrough. WP-3 adds the R5
  admission mirror.
- crates/opacus-network/src/swap_node.rs: SwapNode::enforce_deadlines
  (WG-18 deadline sweep). Stays; subordinated to consensus verdicts
  (section 7).
- Wallet: crates/opacus-wallet/src/tx_v4.rs (SwapIntent,
  build_zk_spend_v5, confirm_zk_tx_v5). WP-3 adds Refund frame building.
- crates/opacus-bridge/src/swap_p2p.rs (1281; offer timeouts,
  fund_timeout_blocks, SwapNet::expired_sessions),
  crates/opacus-bridge/src/xmr_swap.rs (357; refund states) and
  crates/opacus-bridge/src/adaptor.rs (WG-18 adaptor signatures): prior
  art; no planned changes.
- docs/specs/v0.4-value-conservation.md (391): WP-4 extends [S4 12] with
  the enforcement rules and adds a test-matrix section.

## 4. Work packages

    WP-1  docs-only: freeze this file in a standalone commit
          ("WG-27 WP-1: swap enforcement scope freeze"). No code changes.
    WP-2  consensus: R1-R4 in v4.rs plus the negative test matrix
          (section 5); pins open points O1/O2.
    WP-3  node/wallet: R5 admission mirror in swap_service; Refund frames
          in wallet tx_v4.rs; WG-18 sweep aligned with consensus
          verdicts; bridge touchpoints only if review requires.
    WP-4  docs: spec [S4 12] extension + test-matrix section, README,
          CHANGELOG.

Order is strict: WP-2 starts only after WP-1 lands; WP-3 only after WP-2
tests are green; WP-4 last. Every WP is a separate commit, audited via dump
before the manual push.

## 5. Test matrix (WP-2)

    N1  CLAIM at h == T                    -> reject (pins strict inequality)
    N2  CLAIM at h >  T                    -> reject
    N3  REFUND at h <  T                   -> reject
    N4  REFUND at h == T - 1               -> reject (boundary)
    N5  CLAIM after terminalization        -> reject
    N6  REFUND after terminalization       -> reject
    N7  CLAIM with wrong preimage lanes    -> reject
    N8  CLAIM/REFUND with unknown swap id  -> reject
    P1  CLAIM with valid preimage at h<T   -> accept
    P2  REFUND at h>=T per LOCK signature  -> accept

Every N-case must fail on pre-WP-2 code and pass after WP-2 (verified in
the dump audit), proving the checks are load-bearing rather than vacuous.

## 6. Acceptance criteria

- All N-cases reject and all P-cases pass at WP-2; full existing suite
  stays green.
- Zero changes to TX_VERSION_V5, tail length, slot layout, sighash domain,
  dom_swap lanes, Poseidon_3 usage.
- After WP-3, node admission and the WG-18 sweep never contradict the
  consensus verdict at the same height.
- ConsensusParams gains no new tunables unless the WP-2 review proves a
  boundary needs one (O1 is the expected candidate); any addition is a
  scope amendment in this file first.
- Spec [S4 12] text, this document, README and CHANGELOG agree after WP-4.

## 7. Risks

- Height source drift between admission and consensus: R5 makes consensus
  the single source; admission may only be stricter.
- Off-by-one at T: pinned by N1/N4.
- Reorg across T: verdicts are re-derived from the effective chain at
  confirm time; ConsensusState memoizes terminalization only, never
  height-verdict pairs.
- WG-18 sweep vs consensus divergence: the sweep acts on bridge session
  phases and protocol timeouts; consensus acts on H_lock + W_claim. If
  the clocks disagree at the boundary, a session could be refunded
  bridge-side while the chain would still accept a CLAIM. WP-3 makes the
  chain the source of truth for terminalization and keeps the sweep as a
  fast-path convenience only.
- Bridge xmr refund racing on-chain terminalization: WP-3 review item.

## 8. Rollback

The checks are additive guards with no storage migration; reverting WP-2
restores exact WG-26 behavior. Wire compatibility is unaffected by WP-2 and
WP-3 (Refund frames reuse the frozen v5 tail).

## 9. Anchors and open points (after the scope v2 probe audit)

Verified by probes at b9417ac:

    A1  WG-18 = adaptor signatures (adaptor.rs) + deadline sweep
        (SwapNode::enforce_deadlines, SwapNet::expired_sessions, service
        passthrough in swap_service.rs). Node/bridge level only; no
        consensus rule exists today. WG-27 adds the consensus arbiter.
    A2  Bridge timeout fields exist: fund_timeout_blocks (swap_p2p.rs:65)
        and claim_timeout_blocks (service default 200). Fund window is
        pre-LOCK and stays bridge-side; only the claim window reaches
        consensus (R1/R2).
    A3  The repo already queues WG-27 as the consensus check (CHANGELOG,
        README, WG-26 section 3.8, spec note); wording matches R1-R5.

Open points, pinned before WP-2 lands:

    O1  Carrier of W_claim: LOCK tail field vs ConsensusParams default.
    O2  Consensus-state representation of terminalization: per-swap-id
        set in ConsensusState and its memory bound.