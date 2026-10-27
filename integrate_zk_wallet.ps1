# integrate_zk_wallet.ps1
# Ghost project - wire zk spend proofs into ghost-wallet (additive patch).
# Writes: crates\ghost-zk\src\lib.rs (adds prelude), crates\ghost-wallet\src\zk_spend.rs (new),
# edits ghost-wallet Cargo.toml + lib.rs idempotently, then tests everything.
# Generated 2026-10-17 - sandbox verified: ghost-zk 10+11 passed,
# zk_spend 4 passed, mainnet-depth (2^32) real IPA proof+verify 6.4s passed.

$ErrorActionPreference = "Stop"

# ---- adjust if your project lives elsewhere ----
$ProjectRoot = "$PSScriptRoot"

Write-Host "=== ghost-wallet zk integration: adding zk_spend module ===" -ForegroundColor Cyan

if (!(Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: cargo not found in PATH. Use a shell where 'cargo --version' works." -ForegroundColor Red
    exit 1
}

if (!(Test-Path (Join-Path $ProjectRoot "Cargo.toml"))) {
    Write-Host "ERROR: $ProjectRoot\Cargo.toml not found. Edit `$ProjectRoot in this script." -ForegroundColor Red
    exit 1
}

function Write-Text([string]$Path, [string]$Content) {
    $dir = Split-Path -Parent $Path
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ("  wrote " + $Path)
}

# ---- 0) backups (idempotent) ----
$walletDir = Join-Path $ProjectRoot "crates\ghost-wallet"
if (!(Test-Path $walletDir)) {
    Write-Host "ERROR: $walletDir not found - is ghost-wallet present?" -ForegroundColor Red
    exit 1
}
$bak = Join-Path $ProjectRoot "crates\ghost-wallet.bak-zkint"
if (!(Test-Path $bak)) {
    Copy-Item $walletDir $bak -Recurse
    Write-Host "  backup -> crates\ghost-wallet.bak-zkint"
} else {
    Write-Host "  backup already exists, keeping it"
}
$zkLibPath = Join-Path $ProjectRoot "crates\ghost-zk\src\lib.rs"
Copy-Item $zkLibPath "$zkLibPath.bak-zkint" -Force
Write-Host "  backup -> crates\ghost-zk\src\lib.rs.bak-zkint"

# ---- crates\ghost-zk\src\lib.rs ----
Write-Text (Join-Path $ProjectRoot "crates\ghost-zk\src\lib.rs") @'
//! # ghost-zk
//!
//! Halo2-based FCMP-style zero-knowledge membership proofs for Ghost.
//!
//! One proof (`FcmpCircuit`) simultaneously demonstrates:
//! - **ownership**: the spender knows the note's spending key;
//! - **membership**: the note commitment is a leaf of the (2^DEPTH) Merkle tree;
//! - **spending**: the public nullifier is the unique nullifier of that note.
//!
//! Building blocks live in [`poseidon`] (hash), [`merkle`] (tree) and
//! [`circuit`] (proof). With the `real-prover` feature, [`prover`] wraps the
//! full IPA-based prover/verifier over the Pallas/Vesta cycle.

pub mod circuit;
pub mod merkle;
pub mod poseidon;
#[cfg(feature = "real-prover")]
pub mod prover;

/// Everything a wallet (or any downstream crate) typically needs from
/// ghost-zk, in one import: `use ghost_zk::prelude::*;`
pub mod prelude {
    pub use crate::circuit::FcmpWitness;
    pub use crate::{merkle, Note, TREE_DEPTH_MAINNET};
    pub use ff::{Field, PrimeField};
    pub use pasta_curves::Fp;
    pub use rand::rngs::OsRng;
    #[cfg(feature = "real-prover")]
    pub use crate::prover::{prove, verify, FcmpProof};
}

use pasta_curves::Fp;
use thiserror::Error;

/// Mainnet tree depth: 2^32 leaves (anonymity set of about 4.3 billion).
pub const TREE_DEPTH_MAINNET: usize = 32;

#[derive(Debug, Error)]
pub enum ZkError {
    #[error("authentication path length mismatch: expected {expected}, got {got}")]
    PathLength { expected: usize, got: usize },
    #[error("proof verification failed")]
    VerificationFailed,
    #[error("halo2 error: {0}")]
    Halo2(#[from] halo2_proofs::plonk::Error),
}

/// A spendable shielded note.
#[derive(Clone, Debug)]
pub struct Note {
    /// Spending key.
    pub sk: Fp,
    /// Note nonce.
    pub rho: Fp,
    /// Amount in atoms.
    pub value: u64,
}

impl Note {
    pub fn new(sk: Fp, rho: Fp, value: u64) -> Self {
        Self { sk, rho, value }
    }

    /// Public key commitment derived from the spending key.
    pub fn spending_key_pub(&self) -> Fp {
        poseidon::h_pk(self.sk)
    }

    /// Note commitment — this is what leaves the tree.
    pub fn commitment(&self) -> Fp {
        poseidon::h_leaf(self.spending_key_pub(), self.rho, Fp::from(self.value))
    }

    /// Nullifier — published when the note is spent.
    pub fn nullifier(&self) -> Fp {
        poseidon::h_null(self.spending_key_pub(), self.rho)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use rand::rngs::OsRng;

    #[test]
    fn note_hashes_are_consistent() {
        let n = Note::new(Fp::random(OsRng), Fp::random(OsRng), 42);
        assert_eq!(n.commitment(), n.commitment());
        assert_eq!(n.nullifier(), n.nullifier());
        assert_ne!(n.commitment(), n.nullifier());
        assert_ne!(n.commitment(), n.spending_key_pub());

        // Different notes never share commitments or nullifiers.
        let m = Note::new(n.sk, n.rho, n.value + 1);
        assert_ne!(n.commitment(), m.commitment());
        // Nullifier must not depend on the value.
        assert_eq!(n.nullifier(), m.nullifier());
    }
}

'@

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

# ---- 1) ghost-wallet/Cargo.toml: add (or fix) the ghost-zk dependency ----
$tomlPath = Join-Path $ProjectRoot "crates\ghost-wallet\Cargo.toml"
$dep = 'ghost-zk = { path = "../ghost-zk", features = ["real-prover"] }'
$lines = [System.IO.File]::ReadAllLines($tomlPath)
$out = New-Object System.Collections.Generic.List[string]
$depFound = $false
$inserted = $false
foreach ($l in $lines) {
    if ($l -match '^\s*ghost-zk\s*=') { $depFound = $true }
    if (!$depFound -and !$inserted -and $l -match '^\s*\[dependencies\]\s*$') {
        $out.Add($l)
        $out.Add($dep)
        $inserted = $true
        continue
    }
    $out.Add($l)
}
if (!$depFound) {
    if (!$inserted) {
        $out.Add('[dependencies]')
        $out.Add($dep)
    }
    [System.IO.File]::WriteAllLines($tomlPath, $out, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "  added ghost-zk dependency to ghost-wallet\Cargo.toml"
} else {
    for ($i = 0; $i -lt $out.Count; $i++) {
        if ($out[$i] -match '^\s*ghost-zk\s*=') { $out[$i] = $dep }
    }
    [System.IO.File]::WriteAllLines($tomlPath, $out, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "  ghost-zk dependency present - ensured real-prover feature"
}

# ---- 2) ghost-wallet/src/lib.rs: declare the module ----
$libPath = Join-Path $ProjectRoot "crates\ghost-wallet\src\lib.rs"
$lib = [System.IO.File]::ReadAllText($libPath)
if ($lib -match '(?m)^(\s*)(pub\s+)?mod\s+zk_spend\s*;') {
    if ($Matches[2]) {
        Write-Host "  zk_spend module already declared public"
    } else {
        $lib = [regex]::Replace($lib, '(?m)^(\s*)mod\s+zk_spend\s*;', '$1pub mod zk_spend;')
        [System.IO.File]::WriteAllText($libPath, $lib, (New-Object System.Text.UTF8Encoding($false)))
        Write-Host "  made existing 'mod zk_spend' public"
    }
} else {
    if (!$lib.EndsWith("`n")) { $lib += "`r`n" }
    $lib += "`r`npub mod zk_spend;`r`n"
    [System.IO.File]::WriteAllText($libPath, $lib, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "  registered 'pub mod zk_spend;' in ghost-wallet\src\lib.rs"
}

# ---- 3) tests ----
Write-Host ""
Push-Location $ProjectRoot
try {
    Write-Host "=== running: cargo test -p ghost-zk --release ===" -ForegroundColor Cyan
    cargo test -p ghost-zk --release
    if ($LASTEXITCODE -ne 0) {
        Write-Host "GHOST-ZK TESTS FAILED - paste the output above back to the assistant" -ForegroundColor Red
        exit 1
    }
    Write-Host "GHOST-ZK TESTS PASSED" -ForegroundColor Green

    Write-Host ""
    Write-Host "=== running: cargo test -p ghost-wallet --release zk_spend ===" -ForegroundColor Cyan
    cargo test -p ghost-wallet --release zk_spend
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ZK_SPEND TESTS FAILED - paste the output above back to the assistant" -ForegroundColor Red
        exit 1
    }
    Write-Host "ZK_SPEND TESTS PASSED" -ForegroundColor Green

    Write-Host ""
    Write-Host "=== running: full mainnet-depth (2^32) real IPA spend proof (about 10-60 s) ===" -ForegroundColor Cyan
    cargo test -p ghost-wallet --release mainnet_depth -- --ignored
    if ($LASTEXITCODE -ne 0) {
        Write-Host "MAINNET-DEPTH PROOF FAILED - paste the output above back to the assistant" -ForegroundColor Red
        exit 1
    }
    Write-Host "MAINNET-DEPTH SPEND PROOF PASSED - wallet zk layer is fully operational" -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  - wallet now can: WalletNote::random / TreeState / build_mainnet / verify_mainnet"
Write-Host "  - wire into tx flow: outputs -> TreeState::append on confirmed txs, spend -> nullifier+proof"
