//! Wallet-facing zk spend layer built on top of `opacus-zk`.
//!
//! Responsibilities:
//! - byte-serializable shielded notes ([`WalletNote`]) so the wallet can
//!   persist them in its storage;
//! - an in-memory view of the global note-commitment tree ([`TreeState`]);
//! - building and verifying one-input / many-output shielded transactions
//!   ([`ZkSpendTx`]) with a real IPA proof (requires the `real-prover`
//!   feature of `opacus-zk`).
//!
//! Security notes:
//! - value conservation is NOT yet enforced inside the circuit (the FCMP++
//!   value accumulator + EC chips land in v0.4); output commitments are
//!   published in the transaction and will be bound by the accumulator;
//! - nullifier reuse is rejected by consensus (double-spend check), not by
//!   this module; the wallet must not re-spend a note whose nullifier it has
//!   already published.

use opacus_zk::prelude::*;

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

    /// Prefix snapshot: the tree as it was at `len` leaves (WP-D2b: the
    /// frontier at the vote-open height - the root the proposal anchors
    /// to). `None` if `len` exceeds the current leaf count.
    pub fn snapshot(&self, len: usize) -> Option<TreeState> {
        if len > self.leaves.len() {
            return None;
        }
        Some(TreeState {
            depth: self.depth,
            leaves: self.leaves[..len].to_vec(),
        })
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
// The dependency spec in `Cargo.toml` enables `opacus-zk/real-prover`, so the
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
            let k = opacus_zk::circuit::FcmpCircuit::<DEPTH>::required_k();
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
        let k = opacus_zk::circuit::FcmpCircuit::<DEPTH>::required_k();
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
        let notes: Vec<WalletNote> = (0..5).map(|i| WalletNote::random(100 + i as u64)).collect();
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
        let notes: Vec<WalletNote> = (0..5).map(|i| WalletNote::random(100 + i as u64)).collect();
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
        bad.proof.root += Fp::ONE;
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
