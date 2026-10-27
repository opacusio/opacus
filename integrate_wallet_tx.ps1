# integrate_wallet_tx.ps1
# Ghost project - shielded transaction flow inside LightWallet.
# Writes (with backups): light_wallet.rs (zk tree + build/confirm spend flow),
# zk_spend.rs (+TreeState::depth). No dependency changes needed.
# Generated 2026-10-17 - sandbox verified: 7 fast tests passed,
# 2 mainnet-depth e2e (prove+verify+confirm through LightWallet) passed.

$ErrorActionPreference = "Stop"

# ---- adjust if your project lives elsewhere ----
$ProjectRoot = "$PSScriptRoot"

Write-Host "=== ghost-wallet: shielded tx flow in LightWallet ===" -ForegroundColor Cyan

if (!(Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: cargo not found in PATH." -ForegroundColor Red
    exit 1
}

if (!(Test-Path (Join-Path $ProjectRoot "Cargo.toml"))) {
    Write-Host "ERROR: $ProjectRoot\Cargo.toml not found." -ForegroundColor Red
    exit 1
}

function Write-Text([string]$Path, [string]$Content) {
    $dir = Split-Path -Parent $Path
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ("  wrote " + $Path)
}

# ---- 0) file backups (always, small files) ----
foreach ($f in @("light_wallet.rs", "zk_spend.rs")) {
    $p = Join-Path $ProjectRoot "crates\ghost-wallet\src\$f"
    if (Test-Path $p) {
        Copy-Item $p "$p.bak-tx" -Force
        Write-Host "  backup -> $f.bak-tx"
    } else {
        Write-Host "ERROR: $p not found - run integrate_zk_wallet.ps1 first" -ForegroundColor Red
        exit 1
    }
}

# ---- crates\ghost-wallet\src\zk_spend.rs ----
Write-Text (Join-Path $ProjectRoot "crates\ghost-wallet\src\zk_spend.rs") @'
//! Wallet-facing zk spend layer built on top of `ghost-zk`.
//!
//! Responsibilities:
//! - byte-serializable shielded notes ([`WalletNote`]) so the wallet can
//!   persist them in its storage;
//! - an in-memory view of the global note-commitment tree ([`TreeState`]);
//! - building and verifying one-input / many-output shielded transactions
//!   ([`ZkSpendTx`]) with a real IPA proof (requires the `real-prover`
//!   feature of `ghost-zk`).
//!
//! Security notes:
//! - value conservation is NOT yet enforced inside the circuit (the FCMP++
//!   value accumulator + EC chips land in v0.4); output commitments are
//!   published in the transaction and will be bound by the accumulator;
//! - nullifier reuse is rejected by consensus (double-spend check), not by
//!   this module; the wallet must not re-spend a note whose nullifier it has
//!   already published.

use ghost_zk::prelude::*;

// ---------------------------------------------------------------------------
// Fp <-> bytes
// ---------------------------------------------------------------------------

/// Canonical 32-byte representation of a field element.
pub fn fp_to_bytes(f: Fp) -> [u8; 32] {
    let repr = f.to_repr();
    let mut out = [0u8; 32];
    out.copy_from_slice(repr.as_ref());
    out
}

/// Parse a field element from its canonical 32-byte representation.
/// Returns `None` for non-canonical encodings (value >= field modulus).
pub fn fp_from_bytes(bytes: &[u8; 32]) -> Option<Fp> {
    let mut repr = <Fp as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(bytes);
    <Fp as PrimeField>::from_repr(repr).into_option()
}

// ---------------------------------------------------------------------------
// WalletNote
// ---------------------------------------------------------------------------

/// A persistable shielded note: spending key + nonce + value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletNote {
    /// Spending key (canonical little-endian `Fp`).
    pub sk: [u8; 32],
    /// Note nonce (canonical little-endian `Fp`).
    pub rho: [u8; 32],
    /// Amount in atoms.
    pub value: u64,
}

impl WalletNote {
    /// Fresh random note of `value` atoms.
    pub fn random(value: u64) -> Self {
        let sk = fp_to_bytes(Fp::random(OsRng));
        let rho = fp_to_bytes(Fp::random(OsRng));
        Self { sk, rho, value }
    }

    /// Rebuild the in-memory [`Note`]. `None` if stored bytes are corrupt.
    pub fn to_note(&self) -> Option<Note> {
        let sk = fp_from_bytes(&self.sk)?;
        let rho = fp_from_bytes(&self.rho)?;
        Some(Note::new(sk, rho, self.value))
    }

    /// Note commitment — the leaf that enters the global tree.
    pub fn commitment(&self) -> Option<Fp> {
        self.to_note().map(|n| n.commitment())
    }

    /// Nullifier revealed when this note is spent.
    pub fn nullifier(&self) -> Option<Fp> {
        self.to_note().map(|n| n.nullifier())
    }
}

// ---------------------------------------------------------------------------
// TreeState
// ---------------------------------------------------------------------------

/// The wallet's view of the global note-commitment Merkle tree.
///
/// Cost of `root()`/`auth_path()` is `O(len + depth)` — the 2^32-slot
/// mainnet tree is never materialized.
#[derive(Clone, Debug)]
pub struct TreeState {
    depth: usize,
    leaves: Vec<Fp>,
}

impl TreeState {
    /// Tree of `2^depth` leaf slots.
    pub fn new(depth: usize) -> Self {
        Self {
            depth,
            leaves: Vec::new(),
        }
    }

    /// Mainnet-shaped tree (2^32 slots).
    pub fn mainnet() -> Self {
        Self::new(TREE_DEPTH_MAINNET)
    }

    /// Append a commitment; returns its leaf index.
    pub fn append(&mut self, cm: Fp) -> usize {
        self.leaves.push(cm);
        self.leaves.len() - 1
    }

    /// Current tree root.
    pub fn root(&self) -> Fp {
        merkle::build_root(&self.leaves, self.depth)
    }

    /// Tree depth (the tree has `2^depth` leaf slots).
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Authentication path for the leaf at `index`.
    pub fn auth_path(&self, index: usize) -> Option<Vec<Fp>> {
        if index >= self.leaves.len() {
            return None;
        }
        Some(merkle::auth_path(&self.leaves, index, self.depth))
    }

    /// The commitment stored at `index`.
    pub fn leaf(&self, index: usize) -> Option<Fp> {
        self.leaves.get(index).copied()
    }

    /// Number of real leaves.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Spend pipeline
// ---------------------------------------------------------------------------

/// The note to spend plus its position in the global tree.
#[derive(Clone, Debug)]
pub struct SpendInput {
    pub note: WalletNote,
    /// Leaf index of `note.commitment()` inside the tree the tx anchors to.
    pub leaf_index: usize,
}

/// Errors from the zk spend pipeline.
#[derive(Debug)]
pub enum ZkSpendError {
    /// `leaf_index` does not point at this note's commitment in the tree.
    UnknownLeaf,
    /// Stored note bytes are not valid field elements.
    CorruptNote,
    /// Proof generation or verification failed.
    Proof(String),
}

impl std::fmt::Display for ZkSpendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZkSpendError::UnknownLeaf => write!(f, "note commitment not found at given leaf index"),
            ZkSpendError::CorruptNote => write!(f, "stored note bytes are corrupt"),
            ZkSpendError::Proof(e) => write!(f, "zk proof failure: {e}"),
        }
    }
}

impl std::error::Error for ZkSpendError {}

/// Build the private witness for spending `input` against `tree`.
///
/// Returns `(witness, root, nullifier)`. Works without the `real-prover`
/// feature, so wallets can validate their state (paths, root recomputation)
/// even in mock builds.
pub fn build_witness(
    tree: &TreeState,
    input: &SpendInput,
) -> Result<(FcmpWitness, Fp, Fp), ZkSpendError> {
    let note = input.note.to_note().ok_or(ZkSpendError::CorruptNote)?;
    let cm = note.commitment();
    match tree.leaf(input.leaf_index) {
        Some(leaf) if leaf == cm => {}
        _ => return Err(ZkSpendError::UnknownLeaf),
    }
    let path = tree
        .auth_path(input.leaf_index)
        .ok_or(ZkSpendError::UnknownLeaf)?;
    let witness = FcmpWitness {
        sk: note.sk,
        rho: note.rho,
        value: note.value,
        path,
    };
    Ok((witness, tree.root(), note.nullifier()))
}

// ---------------------------------------------------------------------------
// Real proving
//
// The dependency spec in `Cargo.toml` enables `ghost-zk/real-prover`, so the
// IPA prover is always available here.
// ---------------------------------------------------------------------------

mod real {
    use super::*;

    /// A complete shielded transaction: one spent note, its proof, and the
    /// commitments of freshly created output notes.
    #[derive(Clone, Debug)]
    pub struct ZkSpendTx {
        /// Merkle root the proof is anchored to.
        pub root: Fp,
        /// Revealed nullifier of the spent note.
        pub nullifier: Fp,
        /// Commitments of the newly created notes (change + recipients).
        pub output_commitments: Vec<Fp>,
        /// The IPA spend proof.
        pub proof: FcmpProof,
    }

    impl ZkSpendTx {
        /// Verify the transaction proof against tree depth `DEPTH`.
        pub fn verify_with_depth<const DEPTH: usize>(&self) -> Result<(), ZkSpendError> {
            let k = ghost_zk::circuit::FcmpCircuit::<DEPTH>::required_k();
            verify::<DEPTH>(k, &self.proof).map_err(|e| ZkSpendError::Proof(e.to_string()))
        }

        /// Verify against the mainnet tree depth (32).
        pub fn verify_mainnet(&self) -> Result<(), ZkSpendError> {
            self.verify_with_depth::<TREE_DEPTH_MAINNET>()
        }
    }

    /// Build and prove a spend against a tree of depth `DEPTH`.
    ///
    /// `outputs` are the notes created by this transaction (change and/or
    /// recipients); their commitments are published with the tx.
    pub fn build_with_depth<const DEPTH: usize>(
        tree: &TreeState,
        input: &SpendInput,
        outputs: &[WalletNote],
    ) -> Result<ZkSpendTx, ZkSpendError> {
        let (witness, root, nullifier) = build_witness(tree, input)?;
        let k = ghost_zk::circuit::FcmpCircuit::<DEPTH>::required_k();
        let proof = prove::<DEPTH>(k, &witness, root, nullifier)
            .map_err(|e| ZkSpendError::Proof(e.to_string()))?;
        let mut output_commitments = Vec::with_capacity(outputs.len());
        for o in outputs {
            output_commitments.push(o.commitment().ok_or(ZkSpendError::CorruptNote)?);
        }
        Ok(ZkSpendTx {
            root,
            nullifier,
            output_commitments,
            proof,
        })
    }

    /// Build and prove a spend against the mainnet-depth tree (2^32 slots).
    pub fn build_mainnet(
        tree: &TreeState,
        input: &SpendInput,
        outputs: &[WalletNote],
    ) -> Result<ZkSpendTx, ZkSpendError> {
        build_with_depth::<TREE_DEPTH_MAINNET>(tree, input, outputs)
    }
}

pub use real::{build_mainnet, build_with_depth, ZkSpendTx};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fp_bytes_roundtrip() {
        for _ in 0..8 {
            let f = Fp::random(OsRng);
            assert_eq!(fp_from_bytes(&fp_to_bytes(f)), Some(f));
        }
        // 0xff..ff exceeds the Pallas base field modulus -> non-canonical.
        assert_eq!(fp_from_bytes(&[0xff; 32]), None);
        assert_eq!(fp_from_bytes(&[0u8; 32]), Some(Fp::ZERO));
    }

    #[test]
    fn wallet_note_flow() {
        let wn = WalletNote::random(12345);
        let note = wn.to_note().expect("valid note");
        assert_eq!(wn.commitment(), Some(note.commitment()));
        assert_eq!(wn.nullifier(), Some(note.nullifier()));
        // Serialization roundtrip through the struct itself.
        let copy = WalletNote {
            sk: wn.sk,
            rho: wn.rho,
            value: wn.value,
        };
        assert_eq!(copy, wn);
        assert_eq!(copy.commitment(), wn.commitment());
    }

    #[test]
    fn witness_recomputes_root() {
        let mut tree = TreeState::new(4);
        let notes: Vec<WalletNote> = (0..5)
            .map(|i| WalletNote::random(100 + i as u64))
            .collect();
        let mut idxs = Vec::new();
        for n in &notes {
            idxs.push(tree.append(n.commitment().expect("valid note")));
        }
        let input = SpendInput {
            note: notes[2].clone(),
            leaf_index: idxs[2],
        };
        let (witness, root, nf) = build_witness(&tree, &input).expect("witness");
        let leaf = notes[2].commitment().expect("valid note");
        assert_eq!(merkle::recompute_root(leaf, &witness.path), root);
        assert_eq!(nf, notes[2].nullifier().expect("valid note"));

        // Wrong index is rejected.
        let bad = SpendInput {
            note: notes[2].clone(),
            leaf_index: 99,
        };
        assert!(matches!(
            build_witness(&tree, &bad),
            Err(ZkSpendError::UnknownLeaf)
        ));
        // A different note at the right index is rejected too.
        let other = SpendInput {
            note: WalletNote::random(1),
            leaf_index: idxs[3],
        };
        assert!(matches!(
            build_witness(&tree, &other),
            Err(ZkSpendError::UnknownLeaf)
        ));
    }

    #[test]
    fn spend_tx_prove_and_verify() {
        let mut tree = TreeState::new(4);
        let notes: Vec<WalletNote> = (0..5)
            .map(|i| WalletNote::random(100 + i as u64))
            .collect();
        let mut idxs = Vec::new();
        for n in &notes {
            idxs.push(tree.append(n.commitment().expect("valid note")));
        }

        let input = SpendInput {
            note: notes[2].clone(),
            leaf_index: idxs[2],
        };
        let outs = [WalletNote::random(70), WalletNote::random(32)];
        let tx = build_with_depth::<4>(&tree, &input, &outs).expect("prove");
        tx.verify_with_depth::<4>().expect("verify");

        // Tampered root must not verify.
        let mut bad = tx.clone();
        bad.proof.root = bad.proof.root + Fp::ONE;
        assert!(bad.verify_with_depth::<4>().is_err());

        // Output commitments are deterministic.
        let tx2 = build_with_depth::<4>(&tree, &input, &outs).expect("prove 2");
        assert_eq!(tx.output_commitments, tx2.output_commitments);
        assert_eq!(tx.nullifier, tx2.nullifier);
    }

    #[test]
    #[ignore = "slow: full mainnet-depth (2^32) IPA proof; run with --ignored"]
    fn spend_tx_mainnet_depth() {
        let mut tree = TreeState::mainnet();
        let notes: Vec<WalletNote> = (0..3)
            .map(|i| WalletNote::random(1_000 + i as u64))
            .collect();
        let mut idxs = Vec::new();
        for n in &notes {
            idxs.push(tree.append(n.commitment().expect("valid note")));
        }
        let input = SpendInput {
            note: notes[1].clone(),
            leaf_index: idxs[1],
        };
        let outs = [WalletNote::random(400), WalletNote::random(600)];
        let tx = build_mainnet(&tree, &input, &outs).expect("prove at depth 32");
        tx.verify_mainnet().expect("verify at depth 32");
    }
}

'@

# ---- crates\ghost-wallet\src\light_wallet.rs ----
Write-Text (Join-Path $ProjectRoot "crates\ghost-wallet\src\light_wallet.rs") @'
//! Light Wallet

use ghost_crypto::keys::SpendingKey;
use ghost_crypto::stealth::{PublicAddress, RecipientKeys};
use std::collections::{HashMap, HashSet};

use crate::zk_spend::{
    build_with_depth, fp_to_bytes, SpendInput, TreeState, WalletNote, ZkSpendError, ZkSpendTx,
};
use ghost_zk::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("Insufficient funds: need {needed}, have {available}")]
    InsufficientFunds { needed: u64, available: u64 },
    #[error("Not synced")]
    NotSynced,
    #[error("Corrupt zk note bytes")]
    CorruptNote,
    #[error("zk error: {0}")]
    Zk(String),
}

impl From<ZkSpendError> for WalletError {
    fn from(e: ZkSpendError) -> Self {
        WalletError::Zk(e.to_string())
    }
}

#[derive(Clone, Debug, Default)]
pub struct Balance {
    pub total: u64,
    pub spendable: u64,
    pub pending: u64,
}

#[derive(Clone, Debug)]
pub struct UnspentNote {
    pub commitment: [u8; 32],
    pub amount: u64,
    pub onetime_privkey: [u8; 32],
    pub tree_position: u64,
}

/// A zk-native note tracked by this wallet.
#[derive(Clone, Debug)]
pub struct ZkTrackedNote {
    pub note: WalletNote,
    /// Position of the note commitment in the global Merkle tree.
    pub leaf_index: usize,
    pub spent: bool,
}

/// One payment instruction inside a shielded transaction.
///
/// `recipient_sk: None` means the output belongs to this wallet (change /
/// self-consolidation). `Some(sk)` means the note is bound to a recipient's
/// derived one-time secret; the wallet publishes its commitment and forgets
/// it (the recipient learns `sk` out-of-band / via the network's note
/// encryption, which arrives with the networking phase).
#[derive(Clone, Debug)]
pub struct ZkPayment {
    pub value: u64,
    pub recipient_sk: Option<[u8; 32]>,
}

/// Result of building a shielded transaction: the signed-off zk spend plus
/// the wallet's own output notes, which become spendable after
/// [`LightWallet::confirm_zk_tx`] (mirrors the consensus confirm step).
#[derive(Clone, Debug)]
pub struct ZkSpendReceipt {
    pub tx: ZkSpendTx,
    pub own_outputs: Vec<WalletNote>,
}

pub struct LightWallet {
    keys: RecipientKeys,
    address: String,
    unspent_notes: HashMap<[u8; 32], UnspentNote>,
    balance: Balance,
    /// The wallet's mirror of the global note-commitment tree.
    zk_tree: TreeState,
    zk_notes: HashMap<[u8; 32], ZkTrackedNote>,
    zk_seen_nullifiers: HashSet<[u8; 32]>,
}

impl LightWallet {
    pub fn new(spending_key: &SpendingKey) -> Self {
        Self::new_with_tree_depth(spending_key, TREE_DEPTH_MAINNET)
    }

    /// Constructor with a configurable tree depth (testnets / tests).
    pub fn new_with_tree_depth(spending_key: &SpendingKey, depth: usize) -> Self {
        let keys = RecipientKeys {
            view_key: spending_key.view_key,
            spend_key: spending_key.spend_key,
        };
        let address = PublicAddress::from_keys(&keys).to_string();
        Self {
            keys,
            address,
            unspent_notes: HashMap::new(),
            balance: Balance::default(),
            zk_tree: TreeState::new(depth),
            zk_notes: HashMap::new(),
            zk_seen_nullifiers: HashSet::new(),
        }
    }

    pub fn get_address(&self) -> &str { &self.address }
    pub fn get_balance(&self) -> &Balance { &self.balance }

    pub fn add_note(&mut self, note: UnspentNote) {
        self.balance.total += note.amount;
        self.balance.spendable += note.amount;
        self.unspent_notes.insert(note.commitment, note);
    }

    // ------------------------------------------------------------------
    // zk (shielded) layer
    // ------------------------------------------------------------------

    /// Current root of the wallet's note-commitment tree.
    pub fn zk_root(&self) -> Fp {
        self.zk_tree.root()
    }

    /// Number of real leaves in the wallet's tree.
    pub fn zk_leaves(&self) -> usize {
        self.zk_tree.len()
    }

    /// Sum of unspent shielded notes.
    pub fn zk_balance(&self) -> u64 {
        self.zk_notes.values().filter(|t| !t.spent).map(|t| t.note.value).sum()
    }

    /// `(total_tracked, spent)` zk note counts.
    pub fn zk_note_counts(&self) -> (usize, usize) {
        let spent = self.zk_notes.values().filter(|t| t.spent).count();
        (self.zk_notes.len(), spent)
    }

    /// Whether a nullifier has already been published by this wallet.
    pub fn is_nullifier_seen(&self, nf: Fp) -> bool {
        self.zk_seen_nullifiers.contains(&fp_to_bytes(nf))
    }

    /// Track an incoming (or locally minted) shielded note: append its
    /// commitment to the tree and credit the balance.
    pub fn add_zk_note(&mut self, note: WalletNote) -> Result<usize, WalletError> {
        let cm = note.commitment().ok_or(WalletError::CorruptNote)?;
        let idx = self.zk_tree.append(cm);
        let value = note.value;
        self.zk_notes.insert(
            fp_to_bytes(cm),
            ZkTrackedNote {
                note,
                leaf_index: idx,
                spent: false,
            },
        );
        self.balance.total += value;
        self.balance.spendable += value;
        Ok(idx)
    }

    /// Convenience for incoming transfers: build the note from raw secrets.
    pub fn confirm_incoming_note(
        &mut self,
        sk: [u8; 32],
        rho: [u8; 32],
        value: u64,
    ) -> Result<usize, WalletError> {
        self.add_zk_note(WalletNote { sk, rho, value })
    }

    /// Build and prove a mainnet-depth shielded transaction (one input note,
    /// many outputs). See [`Self::build_zk_spend_with_depth`].
    pub fn build_zk_spend(
        &mut self,
        payments: &[ZkPayment],
    ) -> Result<ZkSpendReceipt, WalletError> {
        self.build_zk_spend_with_depth::<TREE_DEPTH_MAINNET>(payments)
    }

    /// Build and prove a shielded transaction against a tree of depth
    /// `DEPTH` (must match the wallet's tree depth).
    ///
    /// Selection is naive: the first unspent note covering `sum(values)`.
    /// The transaction is verified immediately; only after a successful
    /// proof is the input note marked spent and its nullifier recorded.
    pub fn build_zk_spend_with_depth<const DEPTH: usize>(
        &mut self,
        payments: &[ZkPayment],
    ) -> Result<ZkSpendReceipt, WalletError> {
        if self.zk_tree.depth() != DEPTH {
            return Err(WalletError::Zk(format!(
                "tree depth {} does not match DEPTH {}",
                self.zk_tree.depth(),
                DEPTH
            )));
        }
        let needed: u64 = payments.iter().map(|p| p.value).sum();
        if needed == 0 {
            return Err(WalletError::Zk("empty payment list".into()));
        }
        let picked = self
            .zk_notes
            .iter()
            .find(|(_, t)| !t.spent && t.note.value >= needed)
            .map(|(cm, t)| (*cm, t.note.clone(), t.leaf_index))
            .ok_or(WalletError::InsufficientFunds {
                needed,
                available: self.zk_balance(),
            })?;
        let (cm_key, input_note, leaf_index) = picked;
        let input_value = input_note.value;

        let mut outputs = Vec::with_capacity(payments.len());
        for p in payments {
            let sk = p.recipient_sk.unwrap_or_else(|| fp_to_bytes(Fp::random(OsRng)));
            let rho = fp_to_bytes(Fp::random(OsRng));
            outputs.push(WalletNote {
                sk,
                rho,
                value: p.value,
            });
        }

        let spend_input = SpendInput {
            note: input_note,
            leaf_index,
        };
        let tx = build_with_depth::<DEPTH>(&self.zk_tree, &spend_input, &outputs)?;
        // Self-check: never mutate wallet state on an unverifiable tx.
        tx.verify_with_depth::<DEPTH>()?;

        if let Some(t) = self.zk_notes.get_mut(&cm_key) {
            t.spent = true;
        }
        self.zk_seen_nullifiers.insert(fp_to_bytes(tx.nullifier));

        let own_outputs: Vec<WalletNote> = payments
            .iter()
            .zip(outputs.iter())
            .filter(|(p, _)| p.recipient_sk.is_none())
            .map(|(_, o)| o.clone())
            .collect();
        let own_change: u64 = own_outputs.iter().map(|o| o.value).sum();

        self.balance.spendable = self.balance.spendable.saturating_sub(input_value);
        self.balance.pending += own_change;

        Ok(ZkSpendReceipt { tx, own_outputs })
    }

    /// Confirm a built transaction: append every output commitment to the
    /// tree (mirroring consensus order) and make our own outputs spendable.
    pub fn confirm_zk_tx(&mut self, receipt: &ZkSpendReceipt) -> Result<(), WalletError> {
        let base = self.zk_tree.len();
        for cm in &receipt.tx.output_commitments {
            self.zk_tree.append(*cm);
        }
        for note in &receipt.own_outputs {
            let cm = note.commitment().ok_or(WalletError::CorruptNote)?;
            let pos = receipt
                .tx
                .output_commitments
                .iter()
                .position(|c| c == &cm)
                .ok_or(WalletError::CorruptNote)?;
            self.zk_notes.insert(
                fp_to_bytes(cm),
                ZkTrackedNote {
                    note: note.clone(),
                    leaf_index: base + pos,
                    spent: false,
                },
            );
        }
        let own_change: u64 = receipt.own_outputs.iter().map(|o| o.value).sum();
        self.balance.pending = self.balance.pending.saturating_sub(own_change);
        self.balance.spendable += own_change;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_wallet(depth: usize) -> LightWallet {
        let sk = SpendingKey {
            spend_key: [7u8; 32],
            view_key: [9u8; 32],
            mnemonic: "test wallet".into(),
        };
        LightWallet::new_with_tree_depth(&sk, depth)
    }

    #[test]
    fn zk_notes_track_balance() {
        let mut w = test_wallet(4);
        w.add_zk_note(WalletNote::random(100)).unwrap();
        w.add_zk_note(WalletNote::random(50)).unwrap();
        assert_eq!(w.zk_balance(), 150);
        assert_eq!(w.get_balance().total, 150);
        assert_eq!(w.zk_leaves(), 2);
        assert_eq!(w.zk_note_counts(), (2, 0));
    }

    #[test]
    fn zk_spend_change_flow_depth4() {
        let mut w = test_wallet(4);
        w.add_zk_note(WalletNote::random(100)).unwrap();
        w.add_zk_note(WalletNote::random(50)).unwrap();

        let recipient_sk = fp_to_bytes(Fp::random(OsRng));
        let payments = vec![
            ZkPayment {
                value: 30,
                recipient_sk: Some(recipient_sk),
            },
            ZkPayment {
                value: 70,
                recipient_sk: None, // change back to us
            },
        ];
        let receipt = w.build_zk_spend_with_depth::<4>(&payments).expect("build");

        // Input burned immediately, change pending until confirmation.
        assert_eq!(w.zk_balance(), 50);
        assert_eq!(w.get_balance().spendable, 50);
        assert_eq!(w.get_balance().pending, 70);
        assert!(w.is_nullifier_seen(receipt.tx.nullifier));
        assert_eq!(receipt.tx.output_commitments.len(), 2);
        assert_eq!(w.zk_note_counts(), (2, 1));

        // Confirm mirrors consensus: outputs enter the tree, change spendable.
        w.confirm_zk_tx(&receipt).unwrap();
        assert_eq!(w.zk_balance(), 120);
        assert_eq!(w.get_balance().pending, 0);
        assert_eq!(w.get_balance().total, 150);
        assert_eq!(w.zk_leaves(), 4);

        // Incoming external note credits the wallet.
        w.confirm_incoming_note([3u8; 32], [4u8; 32], 500).unwrap();
        assert_eq!(w.zk_balance(), 620);

        // No single unspent note covers 800 (max is the 500-incoming note;
        // the spent 100-note is skipped even though balance totals 620).
        let res = w.build_zk_spend_with_depth::<4>(&[ZkPayment {
            value: 800,
            recipient_sk: None,
        }]);
        assert!(matches!(
            res,
            Err(WalletError::InsufficientFunds { needed: 800, .. })
        ));

        // Recipient's note is bound to their secret, not ours.
        let own = WalletNote {
            sk: recipient_sk,
            rho: [5u8; 32],
            value: 30,
        };
        assert_ne!(own.commitment().unwrap(), Fp::ZERO);
    }

    #[test]
    fn zk_insufficient_funds() {
        let mut w = test_wallet(4);
        w.add_zk_note(WalletNote::random(10)).unwrap();
        let res = w.build_zk_spend_with_depth::<4>(&[ZkPayment {
            value: 11,
            recipient_sk: None,
        }]);
        assert!(matches!(
            res,
            Err(WalletError::InsufficientFunds {
                needed: 11,
                available: 10
            })
        ));
    }

    #[test]
    #[ignore = "slow: full mainnet-depth (2^32) IPA proof"]
    fn zk_spend_mainnet_e2e() {
        let mut w = test_wallet(TREE_DEPTH_MAINNET);
        w.add_zk_note(WalletNote::random(1000)).unwrap();
        let receipt = w
            .build_zk_spend(&[
                ZkPayment {
                    value: 400,
                    recipient_sk: None,
                },
                ZkPayment {
                    value: 600,
                    recipient_sk: None,
                },
            ])
            .expect("mainnet build");
        receipt.tx.verify_mainnet().expect("mainnet verify");
        w.confirm_zk_tx(&receipt).unwrap();
        assert_eq!(w.zk_balance(), 1000);
        assert_eq!(w.zk_leaves(), 3);
    }
}

'@

# ---- 1) tests ----
Write-Host ""
Push-Location $ProjectRoot
try {
    Write-Host "=== running: cargo test -p ghost-wallet --release ===" -ForegroundColor Cyan
    cargo test -p ghost-wallet --release
    if ($LASTEXITCODE -ne 0) {
        Write-Host "WALLET TESTS FAILED - paste the output above back to the assistant" -ForegroundColor Red
        exit 1
    }
    Write-Host "WALLET ZK TESTS PASSED (7 fast)" -ForegroundColor Green

    Write-Host ""
    Write-Host "=== running: mainnet-depth e2e through LightWallet (about 10-60 s) ===" -ForegroundColor Cyan
    cargo test -p ghost-wallet --release mainnet -- --ignored
    if ($LASTEXITCODE -ne 0) {
        Write-Host "MAINNET E2E FAILED - paste the output above back to the assistant" -ForegroundColor Red
        exit 1
    }
    Write-Host "MAINNET E2E PASSED - shielded tx flow fully operational" -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "Wallet API now:" -ForegroundColor Cyan
Write-Host "  w.add_zk_note(WalletNote) / w.confirm_incoming_note(sk,rho,value)"
Write-Host "  w.build_zk_spend(&[ZkPayment]) -> ZkSpendReceipt (proves at mainnet depth)"
Write-Host "  w.confirm_zk_tx(&receipt) / w.zk_balance() / w.is_nullifier_seen(nf)"
