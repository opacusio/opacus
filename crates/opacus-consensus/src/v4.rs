//! Consensus validation for tx v4 [S4 9] and the activation height gate.
//!
//! Phase 4 additive module: nothing in the existing consensus files
//! changes semantics; this module ADDS the normative v4 acceptance path.
//!
//! - [`ConsensusParams`] carries the two consensus parameters [S4 9]:
//!   `v4_activation_height` (CONSENSUS_V4_ACTIVATION_HEIGHT, testnet
//!   parameter) and `fee_floor` (FEE_FLOOR, testnet default 0).
//! - [`ConsensusState`] is the node's shielded-pool view: the sparse
//!   frontier ([`TreeState`], reused - ONE normative tree implementation)
//!   plus the nullifier seen-set [S4 9 step 5].
//! - [`accept_transaction`] is the single entry point a node calls with
//!   raw wire bytes and the current height. It enforces the activation
//!   gate FIRST (after `v4_activation_height` only version-4 wire is
//!   accepted; a v3 transaction after the height is REJECTED; a v4
//!   transaction before the height is REJECTED), then runs the normative
//!   seven-step order [S4 9] with NO state mutation until every check
//!   has passed ("first failure rejects").
//!
//! Dependency note: this crate reuses `opacus-wallet`'s `TxV4` (strict
//! canonical parser) and `TreeState` (frontier) instead of duplicating
//! them. Single-source-of-truth for the wire format and the tree beats
//! layering purity; both crates already share `opacus-zk` primitives and
//! there is no dependency cycle (wallet does not depend on consensus).
//! Promoting the shared types into a dedicated crate is a v0.5 refactor
//! item and does not change any rule implemented here.
//!
//! Balance enforcement [S4 6, S4 9 steps 3+4]: the binding signature is
//! verified under the recomputed `bvk = sum(RC_in) - sum(RC_out) -
//! fee * V`. With honest values `bvk = bsk * R` and the signer knows
//! `bsk`; an unbalanced transaction shifts `bvk` by `d * V`, and forging
//! the signature would require the discrete logarithm of `V` with
//! respect to `R` - unknown by construction [S4 2]. Conservation is
//! therefore enforced with zero trust in off-circuit accounting.

use std::collections::HashSet;

use borsh::BorshDeserialize;
use opacus_wallet::tx_v4::{TxV4, TxV4Error, FEE_FLOOR_TESTNET, TX_VERSION_V4};
use opacus_wallet::zk_spend::{fp_to_bytes, TreeState};
use opacus_zk::prelude::*;
use opacus_zk::spend::{binding_vk, tree_rep, verify_bind};
use opacus_zk::v4_prover::verify_v4;

use crate::transaction::Transaction;

// ---------------------------------------------------------------------------
// Consensus parameters [S4 9]
// ---------------------------------------------------------------------------

/// Consensus parameters for the v4 rules.
#[derive(Clone, Debug)]
pub struct ConsensusParams {
    /// CONSENSUS_V4_ACTIVATION_HEIGHT [S4 9]: at and after this height v4
    /// is the only accepted version and v <= 3 is rejected. Testnet
    /// default 0 (v4-only from genesis; the shielded pool is reset -
    /// acceptable pre-mainnet per [S4 9 activation]).
    pub v4_activation_height: u64,
    /// FEE_FLOOR [S4 9 step 7]: consensus parameter, testnet default 0.
    pub fee_floor: u64,
}

impl ConsensusParams {
    /// Testnet defaults: v4 active from genesis, zero fee floor.
    pub fn testnet() -> Self {
        Self {
            v4_activation_height: 0,
            fee_floor: FEE_FLOOR_TESTNET,
        }
    }
}

// ---------------------------------------------------------------------------
// Node state: frontier + seen-set [S4 9 steps 5+6]
// ---------------------------------------------------------------------------

/// The node's shielded-pool state: the sparse note-commitment frontier
/// and the nullifier seen-set.
///
/// Cost of `root()` is O(leaves + depth) - the 2^32-slot mainnet tree is
/// never materialized [v0.3 sparse frontier design, reused unchanged].
#[derive(Clone, Debug)]
pub struct ConsensusState {
    tree: TreeState,
    seen: HashSet<[u8; 32]>,
}

impl ConsensusState {
    /// Fresh state over a tree of `2^depth` leaf slots.
    pub fn new(depth: usize) -> Self {
        Self {
            tree: TreeState::new(depth),
            seen: HashSet::new(),
        }
    }

    /// Mainnet-shaped state (2^32 slots) [S4 9 activation: v4 activates a
    /// NEW accumulator instance - a fresh state of this shape is what a
    /// node constructs at the activation height].
    pub fn mainnet() -> Self {
        Self::new(TreeState::mainnet().depth())
    }

    /// Wrap an existing frontier (e.g. built by a wallet syncing the
    /// pool). The seen-set starts empty.
    pub fn from_tree(tree: TreeState) -> Self {
        Self {
            tree,
            seen: HashSet::new(),
        }
    }

    /// Current frontier root - what an honest tx must anchor at [S4 9
    /// step 6 precondition].
    pub fn root(&self) -> Fp {
        self.tree.root()
    }

    /// Number of real leaves in the frontier.
    pub fn leaf_count(&self) -> usize {
        self.tree.len()
    }

    /// Number of seen nullifiers.
    pub fn seen_count(&self) -> usize {
        self.seen.len()
    }

    /// Read-only frontier view (wallet builders anchor against it).
    pub fn tree(&self) -> &TreeState {
        &self.tree
    }
}

impl From<TreeState> for ConsensusState {
    fn from(tree: TreeState) -> Self {
        Self::from_tree(tree)
    }
}

// ---------------------------------------------------------------------------
// Accept / Reject [S4 9]
// ---------------------------------------------------------------------------

/// A transaction accepted by [`accept_transaction`].
#[derive(Clone, Debug)]
pub enum Accept {
    /// A fully validated v4 transaction: every check of [S4 9] passed and
    /// the state (frontier + seen-set) has ALREADY been updated.
    V4(TxV4),
    /// A pre-activation legacy (v <= 3) transaction, accepted
    /// structurally; v0.3 validation machinery is unchanged and remains
    /// outside this module.
    Legacy(Transaction),
}

/// Why a transaction was rejected. First failure rejects [S4 9].
#[derive(Debug)]
pub enum Reject {
    /// Activation gate [S4 9 activation]: at/after the height the wire
    /// version must be exactly 4. `got` is the first four wire bytes read
    /// as u32 LE (zero-padded when the payload is shorter).
    Version {
        got: u32,
        height: u64,
        activation: u64,
    },
    /// A v4 transaction before CONSENSUS_V4_ACTIVATION_HEIGHT.
    EarlyV4 { height: u64, activation: u64 },
    /// Pre-activation legacy transaction failed structural parse.
    Legacy(String),
    /// [S4 9 step 1] parse/structure failure (canonical encodings,
    /// topology bounds, enc_note caps, trailing bytes).
    Structure(String),
    /// [S4 9 step 2] halo2 proof verification failed against the
    /// instances reconstructed from the serialized tx.
    Proof(String),
    /// [S4 9 steps 3+4] homomorphic balance + bind_sig: the signature
    /// under the recomputed bvk is invalid (unbalanced values, tampered
    /// fee/RC/leaf/nullifier, or a forged signature).
    Balance,
    /// [S4 9 step 5] a published nullifier was already seen (replay).
    NullifierSeen,
    /// [S4 9 step 6 precondition] the tx does not anchor at the current
    /// frontier root.
    RootMismatch,
    /// [S4 9 step 7] fee below the consensus floor.
    Fee,
}

impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reject::Version {
                got,
                height,
                activation,
            } => write!(
                f,
                "tx version {got} rejected at height {height} (v4 activation height {activation}: only version 4 is accepted)"
            ),
            Reject::EarlyV4 { height, activation } => write!(
                f,
                "v4 transaction at height {height} rejected: v4 activates at height {activation}"
            ),
            Reject::Legacy(e) => write!(f, "legacy transaction rejected: {e}"),
            Reject::Structure(e) => write!(f, "tx v4 structure rejected [S4 9 step 1]: {e}"),
            Reject::Proof(e) => write!(f, "tx v4 proof rejected [S4 9 step 2]: {e}"),
            Reject::Balance => write!(
                f,
                "tx v4 balance/bind_sig rejected [S4 9 steps 3+4]: signature under recomputed bvk is invalid (unbalanced or tampered)"
            ),
            Reject::NullifierSeen => {
                write!(f, "tx v4 rejected [S4 9 step 5]: nullifier already seen")
            }
            Reject::RootMismatch => write!(
                f,
                "tx v4 rejected [S4 9 step 6]: does not anchor at the current frontier root"
            ),
            Reject::Fee => write!(f, "tx v4 rejected [S4 9 step 7]: fee below the floor"),
        }
    }
}

impl std::error::Error for Reject {}

impl From<TxV4Error> for Reject {
    fn from(e: TxV4Error) -> Self {
        match e {
            TxV4Error::Balance => Reject::Balance,
            TxV4Error::NullifierSeen => Reject::NullifierSeen,
            TxV4Error::RootMismatch => Reject::RootMismatch,
            TxV4Error::Fee => Reject::Fee,
            other => Reject::Structure(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point [S4 9]
// ---------------------------------------------------------------------------

/// Read the wire version: the first four bytes as u32 LE, zero-padded
/// when the payload is shorter than four bytes.
fn peek_version(raw: &[u8]) -> u32 {
    let mut b = [0u8; 4];
    for (i, byte) in raw.iter().take(4).enumerate() {
        b[i] = *byte;
    }
    u32::from_le_bytes(b)
}

/// Accept or reject a raw transaction at `height` [S4 9].
///
/// Activation gate FIRST [S4 9 activation]:
/// - `height >= params.v4_activation_height`: the wire version MUST be
///   exactly 4; anything else (including a v3 transaction) is rejected
///   with [`Reject::Version`].
/// - `height < params.v4_activation_height`: a v4 wire payload is
///   rejected with [`Reject::EarlyV4`]; a legacy (v <= 3) payload is
///   accepted structurally as [`Accept::Legacy`].
///
/// For v4 the normative seven-step order runs with NO state mutation
/// until every check has passed; only then are the output leaves
/// appended to the frontier and the nullifiers inserted into the
/// seen-set [S4 9 steps 5-7].
///
/// `DEPTH` is the circuit/tree depth the state was built for; the caller
/// MUST pass the depth matching `state` (mainnet: 32). A mismatch is a
/// programmer error and panics.
pub fn accept_transaction<const DEPTH: usize>(
    params: &ConsensusParams,
    height: u64,
    raw: &[u8],
    state: &mut ConsensusState,
) -> Result<Accept, Reject> {
    let active = height >= params.v4_activation_height;
    let version = peek_version(raw);

    if version == TX_VERSION_V4 {
        if !active {
            return Err(Reject::EarlyV4 {
                height,
                activation: params.v4_activation_height,
            });
        }
        // [S4 9 step 1] strict canonical parse (bounds, canonical
        // encodings, enc_note caps, no trailing bytes).
        let tx = TxV4::from_bytes(raw).map_err(Reject::from)?;
        confirm_v4_consensus::<DEPTH>(&tx, params, state)?;
        Ok(Accept::V4(tx))
    } else {
        if active {
            // [S4 9 activation] after the height v4 is the ONLY accepted
            // version; v <= 3 is rejected.
            return Err(Reject::Version {
                got: version,
                height,
                activation: params.v4_activation_height,
            });
        }
        // Pre-activation legacy path: structural parse only.
        let tx = Transaction::try_from_slice(raw)
            .map_err(|e| Reject::Legacy(format!("borsh parse failed: {e}")))?;
        Ok(Accept::Legacy(tx))
    }
}

/// The normative v4 validation order [S4 9], consensus-owned.
///
/// Mirrors the wallet-side `confirm_zk_tx` (the wallet is the first
/// validator of its own transactions [S4 10]) but lives here, owns the
/// consensus parameters and the node state, and adds nothing else.
/// NO state mutation happens before the last check passes.
pub fn confirm_v4_consensus<const DEPTH: usize>(
    tx: &TxV4,
    params: &ConsensusParams,
    state: &mut ConsensusState,
) -> Result<(), Reject> {
    assert_eq!(
        state.tree.depth(),
        DEPTH,
        "ConsensusState depth must match the DEPTH generic"
    );

    // [S4 9 step 1] structure/topology (parse already succeeded).
    tx.check_topology().map_err(Reject::from)?;

    // [S4 9 step 2] halo2 verify against instances reconstructed from the
    // serialized tx fields - they MUST equal the tx fields exactly, which
    // the shared `spend_instances` helper guarantees [S4 8].
    let n_in = tx.nullifiers.len();
    let n_out = tx.leaves.len();
    let instances = tx.instances_of();
    verify_v4::<DEPTH>(&tx.proof, &instances, n_in, n_out)
        .map_err(|e| Reject::Proof(e.to_string()))?;

    // [S4 9 steps 3+4] homomorphic balance + bind_sig, enforced JOINTLY
    // by the binding signature under the recomputed bvk [S4 6].
    let s = tx.sighash();
    let bvk = binding_vk(&tx.rc_in, &tx.rc_out, tx.fee);
    if !verify_bind(&s, &bvk, &tx.bind_sig) {
        return Err(Reject::Balance);
    }

    // [S4 9 step 5] nullifier seen-set (defense in depth [S4 5]).
    let keys: Vec<[u8; 32]> = tx.nullifiers.iter().map(|n| fp_to_bytes(*n)).collect();
    for k in &keys {
        if state.seen.contains(k) {
            return Err(Reject::NullifierSeen);
        }
    }

    // [S4 9 step 6 precondition] the tx must anchor at the CURRENT
    // frontier root; leaf insertion then advances it canonically.
    if state.tree.root() != tx.root {
        return Err(Reject::RootMismatch);
    }

    // [S4 9 step 7] fee floor.
    if tx.fee < params.fee_floor {
        return Err(Reject::Fee);
    }

    // All checks passed [S4 9 step 6]: commit leaf insertion + seen-set.
    for l in &tx.leaves {
        state.tree.append(tree_rep(l));
    }
    for k in keys {
        state.seen.insert(k);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests [S4 9, S4 13 phase 4 acceptance]
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use opacus_wallet::tx_v4::{build_zk_spend_v4, SpendPlanV4, WalletNoteV4};

    const ACT: u64 = 100;
    const DEPTH: usize = 8;

    /// Consensus params with a nonzero activation height so BOTH sides of
    /// the gate are testable, and a zero fee floor unless overridden.
    fn params() -> ConsensusParams {
        ConsensusParams {
            v4_activation_height: ACT,
            fee_floor: 0,
        }
    }

    /// One honest spend fixture: 3000 in -> 1500 + 1495 out + 5 fee,
    /// built and self-verified by the wallet against a depth-8 tree.
    fn fixture_tx() -> (TreeState, TxV4) {
        let in_note = WalletNoteV4::random(3_000);
        let out1 = WalletNoteV4::random(1_500);
        let out2 = WalletNoteV4::random(1_495);
        let mut tree = TreeState::new(DEPTH);
        tree.append(in_note.tree_entry().expect("note decodes"));
        let plan = SpendPlanV4 {
            inputs: vec![(in_note.clone(), 0)],
            outputs: vec![out1, out2],
            fee: 5,
            swap: None,
        };
        let tx = build_zk_spend_v4::<DEPTH>(&tree, &plan).expect("fixture spend builds");
        (tree, tx)
    }

    fn state_from(tree: &TreeState) -> ConsensusState {
        ConsensusState::from_tree(tree.clone())
    }

    fn legacy_tx_bytes() -> Vec<u8> {
        let tx = Transaction {
            version: 3,
            inputs: vec![[7u8; 32]],
            outputs: vec![],
            fee: 11,
        };
        borsh::to_vec(&tx).expect("legacy borsh serialize")
    }

    #[test]
    fn v4_accepts_honest_tx_at_and_after_activation() {
        let (tree, tx) = fixture_tx();
        let wire = tx.to_bytes();

        // Exactly at the activation height.
        let mut st = state_from(&tree);
        let before_root = st.root();
        let acc = accept_transaction::<DEPTH>(&params(), ACT, &wire, &mut st)
            .expect("honest tx accepted exactly at the activation height");
        assert!(matches!(acc, Accept::V4(_)));
        assert_eq!(st.leaf_count(), 1 + 2, "n_out leaves appended");
        assert_eq!(st.seen_count(), 1, "n_in nullifiers seen");
        assert_ne!(st.root(), before_root, "frontier advanced");

        // Strictly after it.
        let mut st2 = state_from(&tree);
        let acc2 = accept_transaction::<DEPTH>(&params(), ACT + 50, &wire, &mut st2)
            .expect("honest tx accepted after the activation height");
        assert!(matches!(acc2, Accept::V4(_)));
    }

    #[test]
    fn v4_rejected_before_activation_early_v4() {
        let (tree, tx) = fixture_tx();
        let mut st = state_from(&tree);
        let err = accept_transaction::<DEPTH>(&params(), ACT - 1, &tx.to_bytes(), &mut st)
            .expect_err("v4 before activation must be rejected");
        assert!(
            matches!(err, Reject::EarlyV4 { height, .. } if height == ACT - 1),
            "got: {err:?}"
        );
        assert_eq!(st.leaf_count(), 1, "state untouched on reject");
        assert_eq!(st.seen_count(), 0, "state untouched on reject");
    }

    #[test]
    fn v3_and_garbage_rejected_after_activation() {
        // Phase 4 acceptance [S4 13]: node rejects v3 txs after the height.
        let mut st = ConsensusState::new(DEPTH);
        let err = accept_transaction::<DEPTH>(&params(), ACT, &legacy_tx_bytes(), &mut st)
            .expect_err("v3 after activation must be rejected");
        assert!(
            matches!(err, Reject::Version { got: 3, .. }) || matches!(err, Reject::Version { .. }),
            "version gate reject, got: {err:?}"
        );

        // Short garbage is likewise not a v4 payload.
        let err2 = accept_transaction::<DEPTH>(&params(), ACT, &[9, 9, 9], &mut st)
            .expect_err("non-v4 payload after activation must be rejected");
        assert!(matches!(err2, Reject::Version { .. }));

        // Tampered v4 magic (version 5) is rejected, not parsed.
        let (tree, tx) = fixture_tx();
        let mut wire = tx.to_bytes();
        wire[0] = 5;
        let mut st2 = state_from(&tree);
        let err3 = accept_transaction::<DEPTH>(&params(), ACT, &wire, &mut st2)
            .expect_err("version 5 must be rejected");
        assert!(matches!(err3, Reject::Version { got: 5, .. }));
    }

    #[test]
    fn legacy_accepted_structurally_before_activation() {
        let mut st = ConsensusState::new(DEPTH);
        let acc = accept_transaction::<DEPTH>(&params(), ACT - 1, &legacy_tx_bytes(), &mut st)
            .expect("legacy tx before activation accepted structurally");
        assert!(matches!(acc, Accept::Legacy(_)));
    }

    #[test]
    fn unbalanced_v4_rejected_by_binding_signature() {
        // Phase 4 acceptance [S4 13]: node rejects unbalanced txs. The
        // circuit instances do not cover the fee, so a fee mutation keeps
        // the proof valid while shifting bvk by +-d * V [S4 6] - the
        // binding signature MUST fail.
        let (tree, tx) = fixture_tx();
        let wire = tx.to_bytes();
        let parsed = TxV4::from_bytes(&wire).expect("fixture wire parses");

        // Over-charge: outputs + fee now exceed inputs by 1 atom.
        let mut over = parsed.clone();
        over.fee += 1;
        let mut st = state_from(&tree);
        let err = accept_transaction::<DEPTH>(&params(), ACT, &over.to_bytes(), &mut st)
            .expect_err("fee +1 (unbalanced) must be rejected");
        assert!(matches!(err, Reject::Balance), "got: {err:?}");
        assert_eq!(st.seen_count(), 0, "state untouched on reject");

        // Under-charge: inputs now exceed outputs + fee by 1 atom.
        let mut under = parsed.clone();
        under.fee = under.fee.saturating_sub(1);
        let mut st2 = state_from(&tree);
        let err2 = accept_transaction::<DEPTH>(&params(), ACT, &under.to_bytes(), &mut st2)
            .expect_err("fee -1 (unbalanced) must be rejected");
        assert!(matches!(err2, Reject::Balance), "got: {err2:?}");
    }

    #[test]
    fn nullifier_replay_rejected() {
        let (tree, tx) = fixture_tx();
        let wire = tx.to_bytes();
        let mut st = state_from(&tree);
        accept_transaction::<DEPTH>(&params(), ACT, &wire, &mut st).expect("first acceptance ok");
        // Seen-set (step 5) fires before the root check (step 6): the
        // replayed tx anchors at the now-stale root, yet the seen nullifier
        // is reported first.
        let err = accept_transaction::<DEPTH>(&params(), ACT, &wire, &mut st)
            .expect_err("replay must be rejected");
        assert!(matches!(err, Reject::NullifierSeen), "got: {err:?}");
    }

    #[test]
    fn fee_below_floor_rejected() {
        let (tree, tx) = fixture_tx();
        let wire = tx.to_bytes();
        let p = ConsensusParams {
            v4_activation_height: ACT,
            fee_floor: 6, // fixture fee is 5
        };
        let mut st = state_from(&tree);
        let err = accept_transaction::<DEPTH>(&p, ACT, &wire, &mut st)
            .expect_err("fee 5 < floor 6 must be rejected");
        assert!(matches!(err, Reject::Fee), "got: {err:?}");
        // The same tx is fine under a zero floor: integrity checks are
        // orthogonal to the policy parameter [S4 9 step 7].
        let mut st2 = state_from(&tree);
        accept_transaction::<DEPTH>(&params(), ACT, &wire, &mut st2)
            .expect("fee 5 passes a zero floor");
    }

    #[test]
    fn stale_root_rejected() {
        let (mut tree, tx) = fixture_tx();
        let wire = tx.to_bytes();
        // The frontier advanced since the tx was built.
        tree.append(Fp::from(12345u64));
        let mut st = ConsensusState::from_tree(tree);
        let err = accept_transaction::<DEPTH>(&params(), ACT, &wire, &mut st)
            .expect_err("stale anchor must be rejected");
        assert!(matches!(err, Reject::RootMismatch), "got: {err:?}");
    }

    #[test]
    fn tampered_proof_rejected() {
        let (tree, tx) = fixture_tx();
        let mut wire = tx.to_bytes();
        let parsed = TxV4::from_bytes(&wire).expect("fixture wire parses");
        let mid = parsed.proof.len() / 2;
        let proof_start = wire.len() - parsed.bind_sig.len() - parsed.proof.len();
        wire[proof_start + mid] ^= 1;
        let mut st = state_from(&tree);
        let err = accept_transaction::<DEPTH>(&params(), ACT, &wire, &mut st)
            .expect_err("tampered proof must be rejected");
        assert!(matches!(err, Reject::Proof(_)), "got: {err:?}");
    }

    #[test]
    fn reject_display_covers_activation_gate() {
        let r = Reject::Version {
            got: 3,
            height: 900,
            activation: 100,
        };
        let msg = r.to_string();
        assert!(msg.contains("activation height 100"), "display: {msg}");
        assert!(msg.contains("only version 4"), "display: {msg}");
    }
}
