//! Consensus validation for tx v4 [S4 9] and the activation height gate.
//!
//! Phase 4 additive module: nothing in the existing consensus files
//! changes semantics; this module ADDS the normative v4 acceptance path.
//!
//! - [`ConsensusParams`] carries the consensus parameters [S4 9, WG-27]:
//!   `v4_activation_height` (CONSENSUS_V4_ACTIVATION_HEIGHT, testnet
//!   parameter), `fee_floor` (FEE_FLOOR, testnet default 0) and
//!   `claim_timeout_blocks` (W_CLAIM, the WG-27 claim window, testnet
//!   default 200 [O1]).
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

use std::collections::{BTreeMap, HashSet};

use borsh::BorshDeserialize;
use opacus_wallet::tx_v4::{
    TxV4, TxV4Error, TxV5, FEE_FLOOR_TESTNET, TX_VERSION_V4, TX_VERSION_V5,
};
use opacus_wallet::zk_spend::{fp_to_bytes, TreeState};
use opacus_zk::prelude::*;
use opacus_zk::spend::{binding_vk, tree_rep, verify_bind};
use opacus_zk::v4_prover::verify_v4;

use crate::transaction::Transaction;

// ---------------------------------------------------------------------------
// Consensus parameters [S4 9]
// ---------------------------------------------------------------------------

/// WG-27 [O1]: the consensus claim window W_claim in blocks. Every swap
/// deadline is T = H_lock + W_claim, where H_lock is the height the LOCK
/// was accepted at. W_claim is a network parameter, not a LOCK tail
/// field: the WG-26 tail is frozen (130 bytes; the lock tail carries
/// only H), and a per-swap window would need a wire change. Testnet
/// default 200 matches the bridge service claim_timeout_blocks
/// convention [WG-27 scope A2].
pub const W_CLAIM_TESTNET: u64 = 200;

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
    /// WG-27 R1/R2 [O1]: the claim window W_claim in blocks. CLAIM is
    /// valid only while h < H_lock + W_claim, REFUND only while
    /// h >= H_lock + W_claim. Testnet default 200.
    pub claim_timeout_blocks: u64,
}

impl ConsensusParams {
    /// Testnet defaults: v4 active from genesis, zero fee floor, a
    /// 200-block claim window.
    pub fn testnet() -> Self {
        Self {
            v4_activation_height: 0,
            fee_floor: FEE_FLOOR_TESTNET,
            claim_timeout_blocks: W_CLAIM_TESTNET,
        }
    }
}

// ---------------------------------------------------------------------------
// Node state: frontier + seen-set [S4 9 steps 5+6]
// ---------------------------------------------------------------------------

/// The node's shielded-pool state: the sparse note-commitment frontier,
/// the nullifier seen-set, and the WG-27 swap lock registry.
///
/// Cost of `root()` is O(leaves + depth) - the 2^32-slot mainnet tree is
/// never materialized [v0.3 sparse frontier design, reused unchanged].
#[derive(Clone, Debug)]
pub struct ConsensusState {
    tree: TreeState,
    seen: HashSet<[u8; 32]>,
    /// WG-27 [O2]: open swap locks keyed by the swap id - the 32-byte
    /// tail hashlock H encoded like nullifiers (`fp_to_bytes`) - mapped
    /// to H_lock, the height the LOCK was accepted at. A LOCK inserts;
    /// a CLAIM/REFUND terminalization REMOVES [R3]: no terminated-set
    /// is kept because the permanent nullifier seen-set already makes
    /// the terminalized swap entry unspendable, and re-LOCKing the same
    /// H must stay possible. Memory bound: one entry per OPEN swap -
    /// the same growth class as the nullifier seen-set.
    swaps: BTreeMap<[u8; 32], u64>,
}

impl ConsensusState {
    /// Fresh state over a tree of `2^depth` leaf slots.
    pub fn new(depth: usize) -> Self {
        Self {
            tree: TreeState::new(depth),
            seen: HashSet::new(),
            swaps: BTreeMap::new(),
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
            swaps: BTreeMap::new(),
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

    /// WG-27: number of open (not yet terminalized) swap locks.
    pub fn open_swaps(&self) -> usize {
        self.swaps.len()
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
    /// A fully validated v5 (WG-26 swap wire) transaction: every check
    /// of [S4 9] plus the WG-27 swap rules R1-R4 passed and the state
    /// (frontier + seen-set + swap registry) has ALREADY been updated.
    V5(TxV5),
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
    /// [WG-27 R4] claim/refund for a swap id with no open LOCK in the
    /// registry. `got` is the tail hashlock H (nullifier encoding).
    SwapUnknown { got: [u8; 32] },
    /// [WG-27 R4 family] a LOCK for this swap id is already open.
    SwapLockExists { got: [u8; 32] },
    /// [WG-27 R1] a CLAIM at/after the deadline T = H_lock + W_claim
    /// (strict inequality required: claim only while h < T).
    SwapClaimLate { height: u64, deadline: u64 },
    /// [WG-27 R2] a REFUND before the deadline T = H_lock + W_claim
    /// (inclusive: refund valid from h == T on).
    SwapRefundEarly { height: u64, deadline: u64 },
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
            Reject::SwapUnknown { got } => write!(
                f,
                "swap rejected [WG-27 R4]: no open LOCK for swap id {}",
                hex_encode_swap_id(got)
            ),
            Reject::SwapLockExists { got } => write!(
                f,
                "swap lock rejected [WG-27 R4]: swap id {} is already open",
                hex_encode_swap_id(got)
            ),
            Reject::SwapClaimLate { height, deadline } => write!(
                f,
                "claim rejected [WG-27 R1]: height {height} is at/after the claim deadline {deadline} (claim requires h < T)"
            ),
            Reject::SwapRefundEarly { height, deadline } => write!(
                f,
                "refund rejected [WG-27 R2]: height {height} is before the refund deadline {deadline} (refund requires h >= T)"
            ),
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

/// Hex-encode a swap id for rejection messages (consensus carries no
/// hex dependency; a tiny local encoder keeps the error path cheap).
fn hex_encode_swap_id(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in id {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Accept or reject a raw transaction at `height` [S4 9].
///
/// Activation gate FIRST [S4 9 activation, WG-27]:
/// - `height >= params.v4_activation_height`: the wire version MUST be
///   4 (v4) or 5 (the WG-26 swap wire); anything else (including a v3
///   transaction) is rejected with [`Reject::Version`].
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
    } else if version == TX_VERSION_V5 {
        if !active {
            // The WG-26 swap wire activates together with v4 [S4 9
            // activation]: a v5 payload before the height fails the
            // same v4-family gate.
            return Err(Reject::EarlyV4 {
                height,
                activation: params.v4_activation_height,
            });
        }
        // [S4 9 step 1, S4 12 3.6] strict canonical v5 parse: the v4
        // body under version 5 plus the fixed 130-byte swap tail, the
        // canonical tail rules and no trailing bytes.
        let tx = TxV5::from_bytes(raw).map_err(Reject::from)?;
        confirm_v5_consensus::<DEPTH>(&tx, params, height, state)?;
        Ok(Accept::V5(tx))
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
// WG-27: chain-level swap enforcement (R1-R4) on the v5 wire [S4 12]
// ---------------------------------------------------------------------------

/// The normative v5 validation order: the [S4 9] steps with the
/// swap-tail-aware 21-slot instances and the tail-covered sighash, plus
/// the WG-27 swap lifecycle rules. Consensus is the single source of
/// truth for claim/refund validity [WG-27 R5]. NO state mutation
/// happens before the last check passes.
///
/// Rules [WG-27 scope, frozen]:
/// - R1  CLAIM only while `height < T`, `T = H_lock + W_claim` (strict);
/// - R2  REFUND only while `height >= T` (inclusive; no preimage);
/// - R3  a swap terminalizes exactly once (registry removal + the
///   permanent nullifier seen-set);
/// - R4  unknown/not-LOCKed swap id rejected (registry + the circuit
///   swap-variant membership proof).
pub fn confirm_v5_consensus<const DEPTH: usize>(
    tx: &TxV5,
    params: &ConsensusParams,
    height: u64,
    state: &mut ConsensusState,
) -> Result<(), Reject> {
    assert_eq!(
        state.tree.depth(),
        DEPTH,
        "ConsensusState depth must match the DEPTH generic"
    );

    // [S4 9 step 1, S4 12 3.6] structure/topology + canonical swap tail
    // (the parse already enforced them; re-checked here to mirror the
    // wallet-side confirm order exactly).
    tx.check_swap_tail().map_err(Reject::from)?;

    // [S4 9 step 2] halo2 verify against the 21-slot instances
    // reconstructed from the serialized tx fields - tail included
    // [S4 8, S4 12].
    let n_in = tx.base.nullifiers.len();
    let n_out = tx.base.leaves.len();
    let instances = tx.instances_of();
    verify_v4::<DEPTH>(&tx.base.proof, &instances, n_in, n_out)
        .map_err(|e| Reject::Proof(e.to_string()))?;

    // [S4 9 steps 3+4] homomorphic balance + bind_sig under the v5
    // sighash (the tail is covered [S4 12 3.6]).
    let s = tx.sighash();
    let bvk = binding_vk(&tx.base.rc_in, &tx.base.rc_out, tx.base.fee);
    if !verify_bind(&s, &bvk, &tx.base.bind_sig) {
        return Err(Reject::Balance);
    }

    // [S4 9 step 5] nullifier seen-set (defense in depth [S4 5]).
    let keys: Vec<[u8; 32]> = tx.base.nullifiers.iter().map(|n| fp_to_bytes(*n)).collect();
    for k in &keys {
        if state.seen.contains(k) {
            return Err(Reject::NullifierSeen);
        }
    }

    // [S4 9 step 6 precondition] anchor at the CURRENT frontier root.
    if state.tree.root() != tx.base.root {
        return Err(Reject::RootMismatch);
    }

    // [S4 9 step 7] fee floor.
    if tx.base.fee < params.fee_floor {
        return Err(Reject::Fee);
    }

    // [WG-27 R1-R4] swap lifecycle checks. The swap id is the 32-byte
    // tail hashlock H encoded like nullifiers. For flag 2/3 the circuit
    // already proves that the spent input anchors at the swap-variant
    // entry absorbing THIS H, and a swap-variant entry can only be
    // published by an accepted LOCK - the registry is the
    // consensus-side belt over that cryptographic guarantee.
    let swap_id = fp_to_bytes(tx.swap.h);
    match tx.swap.flag {
        // LOCK: register the swap id at this height; duplicate ids are
        // rejected fail-closed while one is open.
        1 => {
            if state.swaps.contains_key(&swap_id) {
                return Err(Reject::SwapLockExists { got: swap_id });
            }
        }
        // CLAIM: valid only while height < T [R1, strict].
        2 => {
            let lock_height = *state
                .swaps
                .get(&swap_id)
                .ok_or(Reject::SwapUnknown { got: swap_id })?;
            let t = lock_height.saturating_add(params.claim_timeout_blocks);
            if height >= t {
                return Err(Reject::SwapClaimLate {
                    height,
                    deadline: t,
                });
            }
        }
        // REFUND: valid from height == T on [R2, inclusive].
        3 => {
            let lock_height = *state
                .swaps
                .get(&swap_id)
                .ok_or(Reject::SwapUnknown { got: swap_id })?;
            let t = lock_height.saturating_add(params.claim_timeout_blocks);
            if height < t {
                return Err(Reject::SwapRefundEarly {
                    height,
                    deadline: t,
                });
            }
        }
        // Plain (flag 0): the zero tail was enforced by the parse.
        _ => {}
    }

    // All checks passed - commit: leaf insertion, seen-set, swap
    // registry [S4 9 step 6; WG-27 R3 terminalization = removal].
    for l in &tx.base.leaves {
        state.tree.append(tree_rep(l));
    }
    for k in keys {
        state.seen.insert(k);
    }
    match tx.swap.flag {
        1 => {
            state.swaps.insert(swap_id, height);
        }
        2 | 3 => {
            state.swaps.remove(&swap_id);
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests [S4 9, S4 13 phase 4 acceptance]
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use opacus_wallet::tx_v4::{
        build_zk_spend_v4, build_zk_spend_v5, SpendPlanV4, SwapIntent, WalletNoteV4,
    };
    use opacus_zk::v4::hashlock_swap;

    const ACT: u64 = 100;
    const DEPTH: usize = 8;
    /// WG-27 test claim window: a LOCK at ACT deadlines at ACT + W_CLAIM.
    const W_CLAIM: u64 = 200;
    /// The canonical 32-byte preimage of the test swaps.
    const PRE: [u8; 32] = [0x5au8; 32];

    /// Consensus params with a nonzero activation height so BOTH sides of
    /// the gate are testable, and a zero fee floor unless overridden.
    fn params() -> ConsensusParams {
        ConsensusParams {
            v4_activation_height: ACT,
            fee_floor: 0,
            claim_timeout_blocks: W_CLAIM,
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

        // Since WG-27 a version-5 magic parses as the WG-26 swap wire:
        // a v4 body flipped to version 5 is a v5 payload MISSING the
        // 130-byte tail, so it is rejected as malformed structure, not
        // by the version gate.
        let (tree, tx) = fixture_tx();
        let mut wire = tx.to_bytes();
        wire[0] = 5;
        let mut st2 = state_from(&tree);
        let err3 = accept_transaction::<DEPTH>(&params(), ACT, &wire, &mut st2)
            .expect_err("v4 body under a v5 magic (truncated tail) must be rejected");
        assert!(matches!(err3, Reject::Structure(_)), "got: {err3:?}");
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
            claim_timeout_blocks: W_CLAIM,
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

    // ------------------------------------------------------------------
    // WG-27 chain-level swap enforcement [scope section 5]. Matrix:
    // N1 claim at h == T, N2 claim at h > T, N3 refund at h < T,
    // N4 refund at h == T - 1, N5 claim after terminalization,
    // N6 refund after terminalization, N7 wrong preimage lanes,
    // N8 unknown swap id; P1 valid claim at h < T, P2 refund at h >= T.
    // Every N-case asserts the SPECIFIC Reject variant so the checks
    // are provably load-bearing rather than vacuous.
    // A lock registered at ACT deadlines at T = ACT + W_CLAIM = 300.
    // ------------------------------------------------------------------

    /// A state whose frontier holds exactly the given funding notes
    /// (leaf i = notes[i].tree_entry()).
    fn funded_state(notes: &[WalletNoteV4]) -> ConsensusState {
        let mut tree = TreeState::new(DEPTH);
        for n in notes {
            tree.append(n.tree_entry().expect("note decodes"));
        }
        ConsensusState::from_tree(tree)
    }

    /// LOCK wire: 1-in (fund at fund_idx) / 2-out (locked swap output
    /// FIRST at output idx 1, change second), fee 50.
    fn lock_wire(
        tree: &TreeState,
        fund: &WalletNoteV4,
        fund_idx: usize,
        locked: &WalletNoteV4,
        change: &WalletNoteV4,
        h: Fp,
    ) -> Vec<u8> {
        let plan = SpendPlanV4 {
            inputs: vec![(fund.clone(), fund_idx)],
            outputs: vec![locked.clone(), change.clone()],
            fee: 50,
            swap: Some(SwapIntent::Lock { idx: 1, h }),
        };
        build_zk_spend_v5::<DEPTH>(tree, &plan)
            .expect("lock builds")
            .to_bytes()
    }

    /// CLAIM wire: spends the locked swap entry at locked_idx, reveals
    /// the preimage, 460 out + 40 fee.
    fn claim_wire(
        tree: &TreeState,
        locked: &WalletNoteV4,
        locked_idx: usize,
        preimage: &[u8; 32],
    ) -> Vec<u8> {
        let plan = SpendPlanV4 {
            inputs: vec![(locked.clone(), locked_idx)],
            outputs: vec![WalletNoteV4::random(460)],
            fee: 40,
            swap: Some(SwapIntent::Claim {
                idx: 1,
                preimage: *preimage,
            }),
        };
        build_zk_spend_v5::<DEPTH>(tree, &plan)
            .expect("claim builds")
            .to_bytes()
    }

    /// REFUND wire: spends the locked swap entry at locked_idx back
    /// under the lock hashlock h, empty lanes, 460 out + 40 fee.
    fn refund_wire(tree: &TreeState, locked: &WalletNoteV4, locked_idx: usize, h: Fp) -> Vec<u8> {
        let plan = SpendPlanV4 {
            inputs: vec![(locked.clone(), locked_idx)],
            outputs: vec![WalletNoteV4::random(460)],
            fee: 40,
            swap: Some(SwapIntent::Refund { idx: 1, h }),
        };
        build_zk_spend_v5::<DEPTH>(tree, &plan)
            .expect("refund builds")
            .to_bytes()
    }

    /// One open swap: a LOCK of 500 atoms under hashlock_swap(PRE)
    /// accepted at height ACT. Returns (state, locked note, h). The
    /// locked swap entry sits at tree leaf index 1 (fund at 0, change
    /// at 2); the deadline is T = ACT + W_CLAIM.
    fn locked_swap() -> (ConsensusState, WalletNoteV4, Fp) {
        let (h, _, _) = hashlock_swap(&PRE);
        let fund = WalletNoteV4::random(1_000);
        let locked = WalletNoteV4::random(500);
        let change = WalletNoteV4::random(450);
        let mut st = funded_state(std::slice::from_ref(&fund));
        let wire = lock_wire(st.tree(), &fund, 0, &locked, &change, h);
        let acc = accept_transaction::<DEPTH>(&params(), ACT, &wire, &mut st)
            .expect("lock accepted at the lock height");
        assert!(matches!(acc, Accept::V5(_)));
        assert_eq!(st.open_swaps(), 1, "lock registered in the swap set");
        (st, locked, h)
    }

    #[test]
    fn wg27_p1_claim_with_valid_preimage_before_t_accepts() {
        // [P1] CLAIM with a valid preimage at h < T -> accept.
        let (mut st, locked, _) = locked_swap();
        let wire = claim_wire(st.tree(), &locked, 1, &PRE);
        let acc = accept_transaction::<DEPTH>(&params(), ACT + W_CLAIM - 1, &wire, &mut st)
            .expect("claim inside the window accepted");
        assert!(matches!(acc, Accept::V5(_)));
        assert_eq!(st.open_swaps(), 0, "terminalized: registry entry removed");
        assert_eq!(st.seen_count(), 2, "lock + claim nullifiers");
    }

    #[test]
    fn wg27_n1_claim_at_t_rejected() {
        // [N1] CLAIM at h == T -> reject (pins the strict inequality).
        let (mut st, locked, _) = locked_swap();
        let wire = claim_wire(st.tree(), &locked, 1, &PRE);
        let err = accept_transaction::<DEPTH>(&params(), ACT + W_CLAIM, &wire, &mut st)
            .expect_err("claim exactly at T must be rejected");
        assert!(
            matches!(
                err,
                Reject::SwapClaimLate { height, deadline }
                    if height == ACT + W_CLAIM && deadline == ACT + W_CLAIM
            ),
            "got: {err:?}"
        );
        assert!(err.to_string().contains("WG-27 R1"), "display: {err}");
        assert_eq!(st.open_swaps(), 1, "state untouched on reject");
    }

    #[test]
    fn wg27_n2_claim_after_t_rejected() {
        // [N2] CLAIM at h > T -> reject.
        let (mut st, locked, _) = locked_swap();
        let wire = claim_wire(st.tree(), &locked, 1, &PRE);
        let err = accept_transaction::<DEPTH>(&params(), ACT + W_CLAIM + 1, &wire, &mut st)
            .expect_err("claim after T must be rejected");
        assert!(matches!(err, Reject::SwapClaimLate { .. }), "got: {err:?}");
    }

    #[test]
    fn wg27_p2_refund_at_t_accepts() {
        // [P2] REFUND at h >= T (exactly T) per the LOCK owner keys ->
        // accept.
        let (mut st, locked, h) = locked_swap();
        let wire = refund_wire(st.tree(), &locked, 1, h);
        let acc = accept_transaction::<DEPTH>(&params(), ACT + W_CLAIM, &wire, &mut st)
            .expect("refund exactly at T accepted");
        assert!(matches!(acc, Accept::V5(_)));
        assert_eq!(st.open_swaps(), 0, "terminalized");
    }

    #[test]
    fn wg27_n3_refund_before_t_rejected() {
        // [N3] REFUND at h < T -> reject.
        let (mut st, locked, h) = locked_swap();
        let wire = refund_wire(st.tree(), &locked, 1, h);
        let err = accept_transaction::<DEPTH>(&params(), ACT + W_CLAIM - 50, &wire, &mut st)
            .expect_err("refund before T must be rejected");
        assert!(
            matches!(err, Reject::SwapRefundEarly { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn wg27_n4_refund_at_t_minus_1_rejected() {
        // [N4] REFUND at h == T - 1 -> reject (boundary pin).
        let (mut st, locked, h) = locked_swap();
        let wire = refund_wire(st.tree(), &locked, 1, h);
        let err = accept_transaction::<DEPTH>(&params(), ACT + W_CLAIM - 1, &wire, &mut st)
            .expect_err("refund one block before T must be rejected");
        assert!(
            matches!(
                err,
                Reject::SwapRefundEarly { deadline, height: _ } if deadline == ACT + W_CLAIM
            ),
            "got: {err:?}"
        );
        assert_eq!(st.open_swaps(), 1, "state untouched on reject");
    }

    #[test]
    fn wg27_n5_claim_after_terminalization_rejected() {
        // [N5] CLAIM after terminalization -> reject. The first claim
        // consumes the swap entry (its nullifier enters the seen-set),
        // so the replayed claim fails at [S4 9 step 5] BEFORE the
        // registry: terminalization is enforced twice over.
        let (mut st, locked, _) = locked_swap();
        let wire = claim_wire(st.tree(), &locked, 1, &PRE);
        accept_transaction::<DEPTH>(&params(), ACT + 50, &wire, &mut st)
            .expect("first claim terminalizes the swap");
        let err = accept_transaction::<DEPTH>(&params(), ACT + 51, &wire, &mut st)
            .expect_err("second claim on the same swap id must be rejected");
        assert!(matches!(err, Reject::NullifierSeen), "got: {err:?}");
        assert_eq!(st.open_swaps(), 0);
    }

    #[test]
    fn wg27_n6_refund_after_terminalization_rejected() {
        // [N6] REFUND after terminalization -> reject: the refund spends
        // the same swap entry whose nullifier the claim already made
        // seen.
        let (mut st, locked, h) = locked_swap();
        let claim = claim_wire(st.tree(), &locked, 1, &PRE);
        accept_transaction::<DEPTH>(&params(), ACT + 50, &claim, &mut st)
            .expect("claim terminalizes the swap");
        let refund = refund_wire(st.tree(), &locked, 1, h);
        let err = accept_transaction::<DEPTH>(&params(), ACT + 51, &refund, &mut st)
            .expect_err("refund after terminalization must be rejected");
        assert!(matches!(err, Reject::NullifierSeen), "got: {err:?}");
    }

    #[test]
    fn wg27_n7_tampered_preimage_lane_rejected() {
        // [N7] CLAIM with wrong preimage lanes -> reject. The honest
        // builder cannot emit wrong lanes (the wallet derives them from
        // the preimage and the circuit checks P(dom_swap, s0, s1) = H,
        // covered by the opacus-zk wg26 tests); at the consensus intake
        // the tail is instance-covered, so a mutated lane breaks the
        // proof reconstruction first [S4 9 step 2].
        let (mut st, locked, _) = locked_swap();
        let wire = claim_wire(st.tree(), &locked, 1, &PRE);
        let mut parsed = TxV5::from_bytes(&wire).expect("claim wire parses");
        parsed.swap.s0 += Fp::ONE;
        let err = accept_transaction::<DEPTH>(&params(), ACT + 10, &parsed.to_bytes(), &mut st)
            .expect_err("tampered preimage lane must be rejected");
        assert!(matches!(err, Reject::Proof(_)), "got: {err:?}");
    }

    #[test]
    fn wg27_n8_unknown_swap_id_rejected() {
        // [N8] CLAIM with an unknown swap id -> reject. The tree is
        // intact but the registry is empty (a node restored the frontier
        // from a snapshot without the swap set, via
        // ConsensusState::from_tree): the proof still verifies, so the
        // REGISTRY check is what rejects - proving it load-bearing.
        let (st, locked, _) = locked_swap();
        let mut bare = ConsensusState::from_tree(st.tree().clone());
        assert_eq!(bare.open_swaps(), 0, "from_tree starts with no swaps");
        let wire = claim_wire(bare.tree(), &locked, 1, &PRE);
        let err = accept_transaction::<DEPTH>(&params(), ACT + 10, &wire, &mut bare)
            .expect_err("claim without an open LOCK must be rejected");
        assert!(matches!(err, Reject::SwapUnknown { .. }), "got: {err:?}");
        assert_eq!(bare.leaf_count(), 3, "state untouched on reject");
    }

    #[test]
    fn wg27_lock_duplicate_swap_id_rejected() {
        // [R4 family] a second LOCK with the same H while one is open is
        // rejected fail-closed: deadlines must stay unambiguous.
        let (h, _, _) = hashlock_swap(&PRE);
        let f1 = WalletNoteV4::random(1_000);
        let f2 = WalletNoteV4::random(1_000);
        let mut st = funded_state(&[f1.clone(), f2.clone()]);
        // f2 sits at leaf index 1 BEFORE the first lock is accepted.
        let w1 = lock_wire(
            st.tree(),
            &f1,
            0,
            &WalletNoteV4::random(500),
            &WalletNoteV4::random(450),
            h,
        );
        accept_transaction::<DEPTH>(&params(), ACT, &w1, &mut st).expect("first lock ok");
        // After the lock the frontier is [f1, f2, l1, c1]: f2 stays at 1.
        let w2 = lock_wire(
            st.tree(),
            &f2,
            1,
            &WalletNoteV4::random(500),
            &WalletNoteV4::random(450),
            h,
        );
        let err = accept_transaction::<DEPTH>(&params(), ACT + 1, &w2, &mut st)
            .expect_err("duplicate swap id lock must be rejected");
        assert!(matches!(err, Reject::SwapLockExists { .. }), "got: {err:?}");
        assert_eq!(st.open_swaps(), 1, "registry untouched by the reject");
    }

    #[test]
    fn wg27_relock_after_terminalization_accepted() {
        // Terminalization REMOVES the registry entry [R3/O2]: the same H
        // can be honestly re-locked afterwards, and the fresh deadline
        // derives from the NEW lock height. Tree bookkeeping:
        // [f1, f2] -> lock1 out (l1@2, c1@3) -> claim1 out (@4) ->
        // lock2 out (l2@5, c2@6).
        let (h, _, _) = hashlock_swap(&PRE);
        let f1 = WalletNoteV4::random(1_000);
        let f2 = WalletNoteV4::random(1_000);
        let mut st = funded_state(&[f1.clone(), f2.clone()]);
        let l1 = WalletNoteV4::random(500);
        let w1 = lock_wire(st.tree(), &f1, 0, &l1, &WalletNoteV4::random(450), h);
        accept_transaction::<DEPTH>(&params(), ACT, &w1, &mut st).expect("first lock ok");
        let claim = claim_wire(st.tree(), &l1, 2, &PRE);
        accept_transaction::<DEPTH>(&params(), ACT + 5, &claim, &mut st)
            .expect("claim terminalizes the first swap");
        assert_eq!(st.open_swaps(), 0);
        let l2 = WalletNoteV4::random(500);
        let w2 = lock_wire(st.tree(), &f2, 1, &l2, &WalletNoteV4::random(450), h);
        accept_transaction::<DEPTH>(&params(), ACT + 10, &w2, &mut st)
            .expect("re-lock of the same H accepted after terminalization");
        assert_eq!(st.open_swaps(), 1);
        // The fresh deadline derives from the NEW lock height (ACT + 10).
        let claim2 = claim_wire(st.tree(), &l2, 5, &PRE);
        accept_transaction::<DEPTH>(&params(), ACT + 10 + W_CLAIM - 1, &claim2, &mut st)
            .expect("claim of the re-locked swap inside its fresh window");
        assert_eq!(st.open_swaps(), 0);
    }

    #[test]
    fn wg27_plain_v5_accepted_without_swap_effects() {
        // The v5 accept path carries plain (zero-tail) transactions
        // too: accepted like v4, with no swap-registry effects.
        let fund = WalletNoteV4::random(1_000);
        let mut st = funded_state(std::slice::from_ref(&fund));
        let plan = SpendPlanV4 {
            inputs: vec![(fund, 0)],
            outputs: vec![WalletNoteV4::random(900)],
            fee: 100,
            swap: None,
        };
        let wire = build_zk_spend_v5::<DEPTH>(st.tree(), &plan)
            .expect("plain v5 builds")
            .to_bytes();
        let acc =
            accept_transaction::<DEPTH>(&params(), ACT, &wire, &mut st).expect("plain v5 accepted");
        assert!(matches!(acc, Accept::V5(_)));
        assert_eq!(st.open_swaps(), 0, "no swap effects");
    }
}
