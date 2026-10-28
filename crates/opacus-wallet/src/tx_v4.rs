//! Transaction format v4 and the wallet spend pipeline [S4 7, S4 9, S4 10].
//!
//! Additive module: nothing in the existing wallet files changes.
//!
//! - [`WalletNoteV4`] persists the normative v0.4 note (v, rho, D, a, b)
//!   [S4 10]; rho is a fresh random field element per note, which is what
//!   makes nullifiers unique [S4 3].
//! - [`TxV4`] is the wire form of tx v4 [S4 7] with a strict canonical
//!   parser (bounds, canonical encodings, no trailing bytes).
//! - [`build_zk_spend_v4`] is the v4 build pipeline: exact conservation is
//!   checked BEFORE any proving work, the proof is self-verified BEFORE any
//!   wallet state can be considered committed [S4 10], and the binding
//!   signature is produced over the sighash [S4 6].
//! - [`confirm_zk_tx`] mirrors the consensus validation order [S4 9]: the
//!   wallet is the first validator of its own transactions.
//!
//! Root convention (Phase 3): the accumulator root is an `Fp` merkle root
//! over tree entries; the delivered `sighash_v4` takes the root as a curve
//! point. The single bridge is `opacus_zk::v4_prover::acc_root_point`,
//! i.e. `[root] * G` over the system base point. Instance reconstruction
//! goes through `opacus_zk::v4_prover::spend_instances` - the ONE normative
//! 15-slot layout [S4 8], shared by builder and confirmer.
//!
//! Note transport: `enc_notes` are opaque per-output payloads [S4 7]; the
//! first cut ships them empty (length slots + caps only). Dedicated note
//! encryption is a separate roadmap item, and building plaintext payloads
//! here would leak amounts and keys - not done.

use opacus_zk::prelude::*;
use opacus_zk::spend::{
    balance_holds, binding_sk, binding_vk, leaf_entry_v2, sighash_v4, sighash_v5, sign_bind,
    swap_leaf_entry_v2, swap_leaf_point_v2, tree_rep, verify_bind, SpendNoteInput, SpendNoteOutput,
    SpendWitness, SwapPub, MAX_IN, MAX_OUT,
};
use opacus_zk::v4::{blind_gen, hashlock_swap, leaf_v2, nullifier_v4, value_commit, value_gen};
use opacus_zk::v4_prover::{
    acc_root_point, pallas, prove_v4, spend_instances, spend_instances_with_swap, verify_v4, Curve,
    Fq, Group, GroupEncoding,
};
use std::collections::HashSet;

use crate::zk_spend::{fp_from_bytes, fp_to_bytes, TreeState};

// ---------------------------------------------------------------------------
// Constants [S4 7, S4 9]
// ---------------------------------------------------------------------------

/// Cap on one output's opaque note payload [S4 9 step 1: enc_note length
/// caps; S4 11 griefing bound].
pub const ENC_NOTE_MAX: usize = 1024;

/// Testnet fee floor [S4 9 step 7: consensus parameter, testnet default 0].
pub const FEE_FLOOR_TESTNET: u64 = 0;

/// Wire version of this format [S4 7].
pub const TX_VERSION_V4: u32 = 4;

/// Wire version of the WG-26 swap format [S4 12 3.6]: the v4 field set
/// under version 5 plus the fixed-size swap tail. A zero tail is a plain
/// v5 transaction.
pub const TX_VERSION_V5: u32 = 5;

/// Wire size of the swap tail: flag u8 + idx u8 + four canonical field
/// encodings (h, s0, s1, entry).
pub const SWAP_TAIL_BYTES: usize = 2 + 4 * 32;

// ---------------------------------------------------------------------------
// WalletNoteV4 [S4 3, S4 10]
// ---------------------------------------------------------------------------

/// A persistable v0.4 note: `(v, rho, D, a, b)` [S4 10]. The spender, and
/// only the spender, knows both owner key shares `(a, b)` [S4 3].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletNoteV4 {
    /// Diversifier domain (in-circuit witness).
    pub d: [u8; 32],
    /// Owner key share 1.
    pub a: [u8; 32],
    /// Owner key share 2.
    pub b: [u8; 32],
    /// Per-note nullifier seed [S4 3].
    pub rho: [u8; 32],
    /// Amount in atoms, 0 <= v < 2^64.
    pub value: u64,
}

impl WalletNoteV4 {
    /// Fresh random note; rho is drawn from OsRng, so per-leaf rho
    /// uniqueness holds with overwhelming probability [S4 3, S4 10].
    pub fn random(value: u64) -> Self {
        Self {
            d: fp_to_bytes(Fp::random(OsRng)),
            a: fp_to_bytes(Fp::random(OsRng)),
            b: fp_to_bytes(Fp::random(OsRng)),
            rho: fp_to_bytes(Fp::random(OsRng)),
            value,
        }
    }

    /// Decode the four field elements; `None` if stored bytes are corrupt
    /// (non-canonical encodings rejected [S4 11]).
    pub fn parts(&self) -> Option<(Fp, Fp, Fp, Fp)> {
        Some((
            fp_from_bytes(&self.d)?,
            fp_from_bytes(&self.a)?,
            fp_from_bytes(&self.b)?,
            fp_from_bytes(&self.rho)?,
        ))
    }

    /// The accumulator leaf point `L = P(D, a+b, a*b) + H_leaf * G3` [S4 3].
    pub fn leaf_point(&self) -> Option<pallas::Point> {
        let (d, a, b, rho) = self.parts()?;
        Some(leaf_v2(d, a, b, self.value, rho))
    }

    /// The tree entry `tree_entry(L) = Poseidon_3(L.x, L.y, DOM_ACC)` -
    /// what the wallet's `Fp` frontier actually stores.
    pub fn tree_entry(&self) -> Option<Fp> {
        let (d, a, b, rho) = self.parts()?;
        Some(leaf_entry_v2(d, a, b, self.value, rho))
    }

    /// The nullifier `N = Poseidon_3(nk, rho, DOM_NU)` revealed at spend
    /// time [S4 5].
    pub fn nullifier(&self) -> Option<Fp> {
        let (_, a, b, rho) = self.parts()?;
        Some(nullifier_v4(a, b, rho))
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the v4 wallet pipeline.
#[derive(Debug)]
pub enum TxV4Error {
    /// Topology/structure violation (counts, enc_note caps).
    Topology(String),
    /// Wire version is not 4 (v4 path) or not 5 (WG-26 v5 path).
    Version(u32),
    /// A field encoding is not canonical [S4 11].
    Canonical,
    /// The byte stream ended mid-field.
    Truncated,
    /// Extra bytes after the complete transaction.
    TrailingBytes,
    /// The anchor tree does not hold the note's entry at the given index.
    UnknownLeaf,
    /// Stored note bytes are not valid field elements.
    CorruptNote,
    /// Exact conservation violated: inputs != outputs + fee [S4 10].
    Unbalanced { inputs: u64, outputs_plus_fee: u64 },
    /// u64 overflow while summing values.
    Overflow,
    /// Halo2 prove/verify failure.
    Proof(String),
    /// Binding signature failed under the recomputed bvk [S4 9 steps 3+4].
    Balance,
    /// A nullifier was already seen (replay) [S4 9 step 5].
    NullifierSeen,
    /// The tx does not anchor at the wallet's current frontier root.
    RootMismatch,
    /// Fee below the floor [S4 9 step 7].
    Fee,
}

impl std::fmt::Display for TxV4Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxV4Error::Topology(m) => write!(f, "tx v4 topology violation: {m}"),
            TxV4Error::Version(v) => write!(f, "unsupported tx version: {v}"),
            TxV4Error::Canonical => write!(f, "non-canonical field encoding"),
            TxV4Error::Truncated => write!(f, "tx bytes truncated mid-field"),
            TxV4Error::TrailingBytes => write!(f, "trailing bytes after tx"),
            TxV4Error::UnknownLeaf => write!(f, "note entry not found at the given leaf index"),
            TxV4Error::CorruptNote => write!(f, "stored note bytes are corrupt"),
            TxV4Error::Unbalanced {
                inputs,
                outputs_plus_fee,
            } => write!(
                f,
                "unbalanced spend: inputs {inputs}, outputs+fee {outputs_plus_fee}"
            ),
            TxV4Error::Overflow => write!(f, "value sum overflow"),
            TxV4Error::Proof(e) => write!(f, "zk proof failure: {e}"),
            TxV4Error::Balance => write!(f, "binding signature check failed (balance)"),
            TxV4Error::NullifierSeen => write!(f, "nullifier already seen"),
            TxV4Error::RootMismatch => write!(f, "tx root does not match the current frontier"),
            TxV4Error::Fee => write!(f, "fee below the floor"),
        }
    }
}

impl std::error::Error for TxV4Error {}

// ---------------------------------------------------------------------------
// TxV4 [S4 7]
// ---------------------------------------------------------------------------

/// A v4 shielded transaction. Published points are kept decoded; the wire
/// form carries compressed encodings ([`TxV4::to_bytes`]).
#[derive(Clone, Debug)]
pub struct TxV4 {
    /// Public accumulator root (Fp merkle root over tree entries).
    pub root: Fp,
    /// Revealed nullifiers, len = n_in in 1..=MAX_IN [S4 5].
    pub nullifiers: Vec<Fp>,
    /// New accumulator leaves, len = n_out in 1..=MAX_OUT [S4 3].
    pub leaves: Vec<pallas::Point>,
    /// Input value commitments [S4 4], len = n_in.
    pub rc_in: Vec<pallas::Point>,
    /// Output value commitments [S4 4], len = n_out.
    pub rc_out: Vec<pallas::Point>,
    /// Opaque per-output note payloads [S4 7]; empty in the first cut
    /// (dedicated encryption is a separate roadmap item).
    pub enc_notes: Vec<Vec<u8>>,
    /// Fee in native units.
    pub fee: u64,
    /// Halo2 IPA proof over the 15-slot instance column [S4 8].
    pub proof: Vec<u8>,
    /// 64-byte binding signature [S4 6].
    pub bind_sig: [u8; 64],
}

impl TxV4 {
    /// Structural check [S4 9 step 1]: topology bounds, payload caps,
    /// published points are non-identity (pads live in the instance
    /// column, never in the tx fields).
    pub fn check_topology(&self) -> Result<(), TxV4Error> {
        let n_in = self.nullifiers.len();
        let n_out = self.leaves.len();
        if n_in == 0 || n_in > MAX_IN {
            return Err(TxV4Error::Topology(format!(
                "n_in {n_in} not in 1..={MAX_IN}"
            )));
        }
        if n_out == 0 || n_out > MAX_OUT {
            return Err(TxV4Error::Topology(format!(
                "n_out {n_out} not in 1..={MAX_OUT}"
            )));
        }
        if self.rc_in.len() != n_in {
            return Err(TxV4Error::Topology(format!(
                "rc_in len {} != n_in {n_in}",
                self.rc_in.len()
            )));
        }
        if self.rc_out.len() != n_out {
            return Err(TxV4Error::Topology(format!(
                "rc_out len {} != n_out {n_out}",
                self.rc_out.len()
            )));
        }
        if self.enc_notes.len() != n_out {
            return Err(TxV4Error::Topology(format!(
                "enc_notes len {} != n_out {n_out}",
                self.enc_notes.len()
            )));
        }
        for (i, e) in self.enc_notes.iter().enumerate() {
            if e.len() > ENC_NOTE_MAX {
                return Err(TxV4Error::Topology(format!(
                    "enc_note[{i}] len {} > ENC_NOTE_MAX {ENC_NOTE_MAX}",
                    e.len()
                )));
            }
        }
        for p in self
            .leaves
            .iter()
            .chain(self.rc_in.iter())
            .chain(self.rc_out.iter())
        {
            if bool::from(p.is_identity()) {
                return Err(TxV4Error::Canonical);
            }
        }
        Ok(())
    }

    /// The normative public instance vector [S4 8], reconstructed from the
    /// tx fields through the ONE shared helper - builder and confirmer
    /// cannot disagree [S4 9 step 2: instances MUST equal tx fields
    /// exactly].
    pub fn instances_of(&self) -> Vec<Fp> {
        spend_instances(self.root, &self.nullifiers, &self.rc_in, &self.rc_out)
    }

    /// Sighash [S4 7]: covers every serialized field consumed by
    /// verification (root, nullifiers, leaves, RCs, fee; version enters
    /// as the constant le64(4)). enc_notes are opaque to verification and
    /// deliberately not covered.
    pub fn sighash(&self) -> [u8; 32] {
        sighash_v4(
            &acc_root_point(self.root),
            &self.nullifiers,
            &self.leaves,
            &self.rc_in,
            &self.rc_out,
            self.fee,
        )
    }

    /// Canonical wire form [S4 7]: version u32 LE, counts, root, nullifiers,
    /// leaves, RC_in, RC_out, enc_notes (u32 length-prefixed), fee u64 LE,
    /// proof (u32 length-prefixed), bind_sig (64 B).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&TX_VERSION_V4.to_le_bytes());
        b.push(self.nullifiers.len() as u8);
        b.push(self.leaves.len() as u8);
        b.extend_from_slice(fp_to_bytes(self.root).as_slice());
        for n in &self.nullifiers {
            b.extend_from_slice(fp_to_bytes(*n).as_slice());
        }
        for p in self
            .leaves
            .iter()
            .chain(self.rc_in.iter())
            .chain(self.rc_out.iter())
        {
            b.extend_from_slice(p.to_affine().to_bytes().as_ref());
        }
        for e in &self.enc_notes {
            b.extend_from_slice(&(e.len() as u32).to_le_bytes());
            b.extend_from_slice(e);
        }
        b.extend_from_slice(&self.fee.to_le_bytes());
        b.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.proof);
        b.extend_from_slice(&self.bind_sig);
        b
    }

    /// Strict parser: version, topology bounds, canonical encodings
    /// [S4 11], enc_note caps, and NO trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<TxV4, TxV4Error> {
        let mut c = Cursor { b: bytes, off: 0 };
        let version = c.take_u32_le()?;
        if version != TX_VERSION_V4 {
            return Err(TxV4Error::Version(version));
        }
        let tx = parse_tx_body(&mut c)?;
        if c.off != c.b.len() {
            return Err(TxV4Error::TrailingBytes);
        }
        Ok(tx)
    }
}

/// Parse the v4 field body after the wire version has been consumed and
/// checked by the caller - the ONE normative body parser, shared by the
/// v4 and WG-26 v5 strict parsers [S4 12 3.6]. Trailing-byte policy
/// belongs to the caller (v4: nothing may remain; v5: the swap tail).
fn parse_tx_body(c: &mut Cursor) -> Result<TxV4, TxV4Error> {
    let n_in = c.take_u8()? as usize;
    let n_out = c.take_u8()? as usize;
    if n_in == 0 || n_in > MAX_IN {
        return Err(TxV4Error::Topology(format!(
            "n_in {n_in} not in 1..={MAX_IN}"
        )));
    }
    if n_out == 0 || n_out > MAX_OUT {
        return Err(TxV4Error::Topology(format!(
            "n_out {n_out} not in 1..={MAX_OUT}"
        )));
    }
    let root = fp_from_bytes(&c.take_32()?).ok_or(TxV4Error::Canonical)?;
    let mut nullifiers = Vec::with_capacity(n_in);
    for _ in 0..n_in {
        nullifiers.push(fp_from_bytes(&c.take_32()?).ok_or(TxV4Error::Canonical)?);
    }
    let mut leaves = Vec::with_capacity(n_out);
    for _ in 0..n_out {
        leaves.push(take_point(&mut *c)?);
    }
    let mut rc_in = Vec::with_capacity(n_in);
    for _ in 0..n_in {
        rc_in.push(take_point(&mut *c)?);
    }
    let mut rc_out = Vec::with_capacity(n_out);
    for _ in 0..n_out {
        rc_out.push(take_point(&mut *c)?);
    }
    let mut enc_notes = Vec::with_capacity(n_out);
    for _ in 0..n_out {
        let len = c.take_u32_le()? as usize;
        if len > ENC_NOTE_MAX {
            return Err(TxV4Error::Topology(format!(
                "enc_note len {len} > ENC_NOTE_MAX {ENC_NOTE_MAX}"
            )));
        }
        enc_notes.push(c.take(len)?.to_vec());
    }
    let fee = c.take_u64_le()?;
    let plen = c.take_u32_le()? as usize;
    let proof = c.take(plen)?.to_vec();
    let mut bind_sig = [0u8; 64];
    bind_sig.copy_from_slice(c.take(64)?);
    Ok(TxV4 {
        root,
        nullifiers,
        leaves,
        rc_in,
        rc_out,
        enc_notes,
        fee,
        proof,
        bind_sig,
    })
}

fn take_point(c: &mut Cursor) -> Result<pallas::Point, TxV4Error> {
    let arr = c.take_32()?;
    let p = <pallas::Point as GroupEncoding>::from_bytes(&arr)
        .into_option()
        .ok_or(TxV4Error::Canonical)?;
    if bool::from(p.is_identity()) {
        return Err(TxV4Error::Canonical);
    }
    Ok(p)
}

/// Minimal byte-cursor over a tx wire form.
struct Cursor<'a> {
    b: &'a [u8],
    off: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TxV4Error> {
        if self.b.len() - self.off < n {
            return Err(TxV4Error::Truncated);
        }
        let s = &self.b[self.off..self.off + n];
        self.off += n;
        Ok(s)
    }
    fn take_u8(&mut self) -> Result<u8, TxV4Error> {
        Ok(self.take(1)?[0])
    }
    fn take_32(&mut self) -> Result<[u8; 32], TxV4Error> {
        let s = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        Ok(a)
    }
    fn take_u32_le(&mut self) -> Result<u32, TxV4Error> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn take_u64_le(&mut self) -> Result<u64, TxV4Error> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }
}

// ---------------------------------------------------------------------------
// TxV5: the WG-26 swap wire [S4 12 3.6]
// ---------------------------------------------------------------------------

/// A v5 shielded transaction: the v4 field set plus the normative swap
/// tail (flag, idx, H, s0, s1, spent_swap_entry) [S4 12 3.6].
///
/// Wire form: the v4 body under version 5, then the fixed-size tail
/// ([`SWAP_TAIL_BYTES`]). A zero tail is a plain transaction; the tail is
/// covered by the v5 sighash and rides the normative instance slots
/// 15..20 through [`spend_instances_with_swap`].
#[derive(Clone, Debug)]
pub struct TxV5 {
    /// The v4 base fields (root, nullifiers, leaves, RCs, enc_notes, fee,
    /// proof, bind_sig).
    pub base: TxV4,
    /// Public swap material; the zero tail for a plain v5 transaction.
    pub swap: SwapPub,
}

impl TxV5 {
    /// The zero swap tail (plain v5 transaction).
    pub fn swap_none() -> SwapPub {
        SwapPub {
            flag: 0,
            idx: 0,
            h: Fp::ZERO,
            s0: Fp::ZERO,
            s1: Fp::ZERO,
            entry: Fp::ZERO,
        }
    }

    /// Structural check [S4 9 step 1, S4 12 3.6]: the base topology must
    /// be well-formed and the tail must match its mode exactly.
    pub fn check_swap_tail(&self) -> Result<(), TxV4Error> {
        self.base.check_topology()?;
        let s = &self.swap;
        let nz = |f: &Fp| *f != Fp::ZERO;
        match s.flag {
            0 => {
                // Plain: the whole tail is zero.
                if s.idx != 0 || nz(&s.h) || nz(&s.s0) || nz(&s.s1) || nz(&s.entry) {
                    return Err(TxV4Error::Topology("plain v5 tail must be all-zero".into()));
                }
            }
            1 => {
                // Lock: a real output index, a real hashlock, empty lanes,
                // no spent-swap entry.
                if s.idx == 0 || s.idx as usize > self.base.leaves.len() {
                    return Err(TxV4Error::Topology(format!(
                        "lock idx {} not in 1..={}",
                        s.idx,
                        self.base.leaves.len()
                    )));
                }
                if !nz(&s.h) || nz(&s.s0) || nz(&s.s1) || nz(&s.entry) {
                    return Err(TxV4Error::Topology("lock tail must carry only H".into()));
                }
            }
            2 | 3 => {
                // Claim/refund: a real input index, a real hashlock and the
                // spent swap entry; only the claim carries preimage lanes.
                if s.idx == 0 || s.idx as usize > self.base.nullifiers.len() {
                    return Err(TxV4Error::Topology(format!(
                        "claim/refund idx {} not in 1..={}",
                        s.idx,
                        self.base.nullifiers.len()
                    )));
                }
                if !nz(&s.h) || !nz(&s.entry) {
                    return Err(TxV4Error::Topology(
                        "claim/refund must carry H and the swap entry".into(),
                    ));
                }
                if s.flag == 3 && (nz(&s.s0) || nz(&s.s1)) {
                    return Err(TxV4Error::Topology(
                        "refund must not carry preimage lanes".into(),
                    ));
                }
            }
            other => {
                return Err(TxV4Error::Topology(format!("unknown swap flag {other}")));
            }
        }
        Ok(())
    }

    /// The normative public instance vector [S4 8, S4 12]: the 21-slot
    /// layout with the swap tail published.
    pub fn instances_of(&self) -> Vec<Fp> {
        spend_instances_with_swap(
            self.base.root,
            &self.base.nullifiers,
            &self.base.rc_in,
            &self.base.rc_out,
            &self.swap,
        )
    }

    /// Sighash [S4 7, S4 12 3.6]: the v5 stream covers every serialized
    /// field consumed by verification INCLUDING the swap tail; version
    /// enters as the constant le64(5). enc_notes stay opaque and
    /// deliberately uncovered, as in v4.
    pub fn sighash(&self) -> [u8; 32] {
        sighash_v5(
            &acc_root_point(self.base.root),
            &self.base.nullifiers,
            &self.base.leaves,
            &self.base.rc_in,
            &self.base.rc_out,
            self.base.fee,
            &self.swap,
        )
    }

    /// Canonical wire form [S4 12 3.6]: the v4 body under version 5,
    /// followed by the fixed-size swap tail (flag u8, idx u8, then h, s0,
    /// s1, entry as canonical 32-byte field encodings).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = self.base.to_bytes();
        b[0..4].copy_from_slice(&TX_VERSION_V5.to_le_bytes());
        b.push(self.swap.flag);
        b.push(self.swap.idx);
        b.extend_from_slice(fp_to_bytes(self.swap.h).as_slice());
        b.extend_from_slice(fp_to_bytes(self.swap.s0).as_slice());
        b.extend_from_slice(fp_to_bytes(self.swap.s1).as_slice());
        b.extend_from_slice(fp_to_bytes(self.swap.entry).as_slice());
        b
    }

    /// Strict parser [S4 11, S4 12 3.6]: version 5, the v4 body rules,
    /// exactly `SWAP_TAIL_BYTES` tail bytes with canonical field
    /// encodings, the canonical tail rules, and NO trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<TxV5, TxV4Error> {
        let mut c = Cursor { b: bytes, off: 0 };
        let version = c.take_u32_le()?;
        if version != TX_VERSION_V5 {
            return Err(TxV4Error::Version(version));
        }
        let base = parse_tx_body(&mut c)?;
        let flag = c.take_u8()?;
        let idx = c.take_u8()?;
        let h = fp_from_bytes(&c.take_32()?).ok_or(TxV4Error::Canonical)?;
        let s0 = fp_from_bytes(&c.take_32()?).ok_or(TxV4Error::Canonical)?;
        let s1 = fp_from_bytes(&c.take_32()?).ok_or(TxV4Error::Canonical)?;
        let entry = fp_from_bytes(&c.take_32()?).ok_or(TxV4Error::Canonical)?;
        if c.off != c.b.len() {
            return Err(TxV4Error::TrailingBytes);
        }
        let tx = TxV5 {
            base,
            swap: SwapPub {
                flag,
                idx,
                h,
                s0,
                s1,
                entry,
            },
        };
        tx.check_swap_tail()?;
        Ok(tx)
    }
}

// ---------------------------------------------------------------------------
// Build pipeline [S4 10]
// ---------------------------------------------------------------------------

/// WG-26 [S4 12 3.7]: a swap instruction inside a spend plan. The builder
/// derives the published [`SwapPub`] tail from the intent:
/// - `Lock` publishes `h` and creates output `idx` (1-based) with the
///   swap-variant leaf absorbing `h` [S4 12 3.1];
/// - `Claim` derives `(H, s0, s1)` from the preimage and spends input
///   `idx` (1-based) through its swap-variant leaf, publishing its entry;
/// - `Refund` spends input `idx` back under the lock's `h` with empty
///   lanes (no preimage).
#[derive(Clone, Debug)]
pub enum SwapIntent {
    /// Lock output `idx` (1-based) under the hashlock `h`.
    Lock { idx: u8, h: Fp },
    /// Claim input `idx` (1-based) by revealing the 32-byte preimage.
    Claim { idx: u8, preimage: [u8; 32] },
    /// Refund input `idx` (1-based) under the lock's hashlock `h`.
    Refund { idx: u8, h: Fp },
}

/// The spend plan handed to [`build_zk_spend_v4`]: which notes to spend
/// (with their leaf indices in the anchor tree), which notes to create,
/// and the configured fee. Single-note selection is retained for the first
/// cut [S4 10], but the builder accepts the full 1..=MAX_IN topology.
#[derive(Clone, Debug)]
pub struct SpendPlanV4 {
    pub inputs: Vec<(WalletNoteV4, usize)>,
    pub outputs: Vec<WalletNoteV4>,
    pub fee: u64,
    /// WG-26 [S4 12 3.7]: optional swap instruction; `None` is plain.
    pub swap: Option<SwapIntent>,
}

/// Build the v4 spend [S4 10]: note selection checks, exact conservation
/// BEFORE any proving work, RC computation [S4 4], proof, self-verify, and
/// the binding signature [S4 6]. The prove/self-verify-before-mutation
/// invariant of v0.3 is preserved.
pub fn build_zk_spend_v4<const DEPTH: usize>(
    tree: &TreeState,
    plan: &SpendPlanV4,
) -> Result<TxV4, TxV4Error> {
    let n_in = plan.inputs.len();
    let n_out = plan.outputs.len();
    if n_in == 0 || n_in > MAX_IN || n_out == 0 || n_out > MAX_OUT {
        return Err(TxV4Error::Topology(format!(
            "inputs {n_in} in 1..={MAX_IN}, outputs {n_out} in 1..={MAX_OUT}"
        )));
    }

    // Decode inputs and prove membership against the anchor tree.
    let mut notes_in: Vec<(Fp, Fp, Fp, Fp, u64, Vec<Fp>)> = Vec::with_capacity(n_in);
    for (note, idx) in &plan.inputs {
        let (d, a, b, rho) = note.parts().ok_or(TxV4Error::CorruptNote)?;
        let entry = note.tree_entry().ok_or(TxV4Error::CorruptNote)?;
        match tree.leaf(*idx) {
            Some(l) if l == entry => {}
            _ => return Err(TxV4Error::UnknownLeaf),
        }
        let path = tree.auth_path(*idx).ok_or(TxV4Error::UnknownLeaf)?;
        notes_in.push((d, a, b, rho, note.value, path));
    }

    // EXACT conservation before any proving work [S4 10]: inputs must equal
    // outputs + fee; an under- OR over-spend is rejected here so the wallet
    // never broadcasts an unbalanced tx (and never burns proving time on a
    // tx that cannot sign).
    let sum_in: u64 = notes_in.iter().map(|n| n.4).sum();
    let sum_out: u64 = plan.outputs.iter().map(|n| n.value).sum();
    let fee = plan.fee;
    let needed = sum_out.checked_add(fee).ok_or(TxV4Error::Overflow)?;
    if sum_in != needed {
        return Err(TxV4Error::Unbalanced {
            inputs: sum_in,
            outputs_plus_fee: needed,
        });
    }

    // Validate outputs up front so later expects are total.
    for n in &plan.outputs {
        n.parts().ok_or(TxV4Error::CorruptNote)?;
    }

    // Blinding scalars and host-side RCs [S4 4]; the circuit derives the
    // same RCs from the witnessed (v, r) - pinned by the Phase 1b/2 tests.
    let r_in: Vec<Fq> = (0..n_in).map(|_| Fq::random(OsRng)).collect();
    let r_out: Vec<Fq> = (0..n_out).map(|_| Fq::random(OsRng)).collect();
    let vg = value_gen();
    let rg = blind_gen();
    let rc_in: Vec<pallas::Point> = (0..n_in)
        .map(|i| value_commit(notes_in[i].4, r_in[i], &vg, &rg))
        .collect();
    let rc_out: Vec<pallas::Point> = (0..n_out)
        .map(|j| value_commit(plan.outputs[j].value, r_out[j], &vg, &rg))
        .collect();

    let ns: Vec<Fp> = notes_in
        .iter()
        .map(|n| nullifier_v4(n.1, n.2, n.3))
        .collect();
    let leaves: Vec<pallas::Point> = plan
        .outputs
        .iter()
        .map(|n| n.leaf_point().expect("validated above"))
        .collect();
    let root = tree.root();

    // Normative 15-slot instances [S4 8] through the shared helper.
    let instances = spend_instances(root, &ns, &rc_in, &rc_out);

    // Witness [S4 8] and prove.
    let witness = SpendWitness {
        inputs: notes_in
            .iter()
            .map(|n| SpendNoteInput {
                d: n.0,
                a: n.1,
                b: n.2,
                rho: n.3,
                v: n.4,
                path: n.5.clone(),
            })
            .collect(),
        outputs: plan
            .outputs
            .iter()
            .map(|n| SpendNoteOutput { v: n.value })
            .collect(),
    };
    let proof = prove_v4::<DEPTH>(&witness, &r_in, &r_out, n_in, n_out, &instances)
        .map_err(|e| TxV4Error::Proof(format!("prove: {e}")))?;

    // Self-verify BEFORE any wallet state mutation [S4 10].
    verify_v4::<DEPTH>(&proof.proof, &instances, n_in, n_out)
        .map_err(|e| TxV4Error::Proof(format!("self-verify: {e}")))?;

    // Sighash and the binding signature [S4 6, S4 7]. With honest values
    // bvk = bsk * R; the signer-side balance_holds is an internal sanity
    // assert (the verifier-side guarantee is verify_bind alone).
    let s = sighash_v4(&acc_root_point(root), &ns, &leaves, &rc_in, &rc_out, fee);
    let bsk = binding_sk(&r_in, &r_out);
    let bvk = binding_vk(&rc_in, &rc_out, fee);
    debug_assert!(balance_holds(&rc_in, &rc_out, fee, bsk));
    let bind_sig = sign_bind(&s, bsk, &bvk);

    Ok(TxV4 {
        root,
        nullifiers: ns,
        leaves,
        rc_in,
        rc_out,
        enc_notes: vec![Vec::new(); n_out],
        fee,
        proof: proof.proof,
        bind_sig,
    })
}

// ---------------------------------------------------------------------------
// WG-26 build pipeline [S4 12 3.6, 3.7]
// ---------------------------------------------------------------------------

/// Build the v5 spend [S4 10, S4 12]: the v4 build pipeline with the swap
/// tail wired end to end.
///
/// - `plan.swap = None` builds a plain v5 transaction (zero tail).
/// - `Lock { idx, h }` publishes output `idx` with its swap-variant leaf
///   absorbing `h` [S4 12 3.1]; the other outputs stay plain.
/// - `Claim { idx, preimage }` spends input `idx` through its
///   swap-variant leaf: the tree anchor at the plan's leaf index must be
///   the swap-variant entry, the published entry slot carries it, and
///   `(H, s0, s1)` derive from the preimage.
/// - `Refund { idx, h }` spends input `idx` back under the lock's `h`
///   with empty lanes.
///
/// Conservation, RCs, proving, self-verification and the binding
/// signature are the v4 pipeline unchanged; the instances and the
/// sighash are the v5 (21-slot, tail-covered) forms.
pub fn build_zk_spend_v5<const DEPTH: usize>(
    tree: &TreeState,
    plan: &SpendPlanV4,
) -> Result<TxV5, TxV4Error> {
    let n_in = plan.inputs.len();
    let n_out = plan.outputs.len();
    if n_in == 0 || n_in > MAX_IN || n_out == 0 || n_out > MAX_OUT {
        return Err(TxV4Error::Topology(format!(
            "inputs {n_in} in 1..={MAX_IN}, outputs {n_out} in 1..={MAX_OUT}"
        )));
    }

    // Resolve the swap intent into the published tail [S4 12] with
    // mode-specific index bounds; a claim derives (H, s0, s1) from the
    // preimage, a lock/refund carries H directly.
    let mut swap = match &plan.swap {
        None => TxV5::swap_none(),
        Some(SwapIntent::Lock { idx, h }) => {
            if *idx == 0 || *idx as usize > n_out {
                return Err(TxV4Error::Topology(format!(
                    "lock idx {idx} not in 1..={n_out}"
                )));
            }
            if *h == Fp::ZERO {
                return Err(TxV4Error::Topology("lock hashlock must be nonzero".into()));
            }
            SwapPub {
                flag: 1,
                idx: *idx,
                h: *h,
                s0: Fp::ZERO,
                s1: Fp::ZERO,
                entry: Fp::ZERO,
            }
        }
        Some(SwapIntent::Claim { idx, preimage }) => {
            if *idx == 0 || *idx as usize > n_in {
                return Err(TxV4Error::Topology(format!(
                    "claim idx {idx} not in 1..={n_in}"
                )));
            }
            let (h, s0, s1) = hashlock_swap(preimage);
            SwapPub {
                flag: 2,
                idx: *idx,
                h,
                s0,
                s1,
                entry: Fp::ZERO,
            }
        }
        Some(SwapIntent::Refund { idx, h }) => {
            if *idx == 0 || *idx as usize > n_in {
                return Err(TxV4Error::Topology(format!(
                    "refund idx {idx} not in 1..={n_in}"
                )));
            }
            if *h == Fp::ZERO {
                return Err(TxV4Error::Topology(
                    "refund hashlock must be nonzero".into(),
                ));
            }
            SwapPub {
                flag: 3,
                idx: *idx,
                h: *h,
                s0: Fp::ZERO,
                s1: Fp::ZERO,
                entry: Fp::ZERO,
            }
        }
    };
    let swap_in = matches!(swap.flag, 2 | 3).then_some(swap.idx as usize);
    let lock_out = (swap.flag == 1).then_some(swap.idx as usize);

    // Decode inputs and prove membership against the anchor tree. A
    // claim/refund input anchors at its SWAP-VARIANT entry [S4 12 3.1]:
    // the tree holds the locked entry, so the plain-entry check would
    // reject the very note the lock published.
    let mut notes_in: Vec<(Fp, Fp, Fp, Fp, u64, Vec<Fp>)> = Vec::with_capacity(n_in);
    let mut swap_entry = Fp::ZERO;
    for (i, (note, idx)) in plan.inputs.iter().enumerate() {
        let (d, a, b, rho) = note.parts().ok_or(TxV4Error::CorruptNote)?;
        let want = if swap_in == Some(i + 1) {
            let e = swap_leaf_entry_v2(d, a, b, note.value, rho, swap.h);
            swap_entry = e;
            e
        } else {
            note.tree_entry().ok_or(TxV4Error::CorruptNote)?
        };
        match tree.leaf(*idx) {
            Some(l) if l == want => {}
            _ => return Err(TxV4Error::UnknownLeaf),
        }
        let path = tree.auth_path(*idx).ok_or(TxV4Error::UnknownLeaf)?;
        notes_in.push((d, a, b, rho, note.value, path));
    }
    if matches!(swap.flag, 2 | 3) {
        swap.entry = swap_entry;
    }

    // EXACT conservation before any proving work [S4 10], unchanged.
    let sum_in: u64 = notes_in.iter().map(|n| n.4).sum();
    let sum_out: u64 = plan.outputs.iter().map(|n| n.value).sum();
    let fee = plan.fee;
    let needed = sum_out.checked_add(fee).ok_or(TxV4Error::Overflow)?;
    if sum_in != needed {
        return Err(TxV4Error::Unbalanced {
            inputs: sum_in,
            outputs_plus_fee: needed,
        });
    }

    // Validate outputs up front so later expects are total.
    for n in &plan.outputs {
        n.parts().ok_or(TxV4Error::CorruptNote)?;
    }

    // Blinding scalars and host-side RCs [S4 4], unchanged.
    let r_in: Vec<Fq> = (0..n_in).map(|_| Fq::random(OsRng)).collect();
    let r_out: Vec<Fq> = (0..n_out).map(|_| Fq::random(OsRng)).collect();
    let vg = value_gen();
    let rg = blind_gen();
    let rc_in: Vec<pallas::Point> = (0..n_in)
        .map(|i| value_commit(notes_in[i].4, r_in[i], &vg, &rg))
        .collect();
    let rc_out: Vec<pallas::Point> = (0..n_out)
        .map(|j| value_commit(plan.outputs[j].value, r_out[j], &vg, &rg))
        .collect();

    let ns: Vec<Fp> = notes_in
        .iter()
        .map(|n| nullifier_v4(n.1, n.2, n.3))
        .collect();
    // Published leaves [S4 3, S4 12 3.1]: the locked output is published
    // with its swap-variant leaf absorbing H; every other output stays
    // plain.
    let leaves: Vec<pallas::Point> = plan
        .outputs
        .iter()
        .enumerate()
        .map(|(j, n)| {
            if lock_out == Some(j + 1) {
                let (d, a, b, rho) = n.parts().expect("validated above");
                swap_leaf_point_v2(d, a, b, n.value, rho, swap.h)
            } else {
                n.leaf_point().expect("validated above")
            }
        })
        .collect();
    let root = tree.root();

    // Normative 21-slot instances [S4 8, S4 12] through the shared helper.
    let instances = spend_instances_with_swap(root, &ns, &rc_in, &rc_out, &swap);

    // Witness [S4 8] and prove (the swap tail rides the instances).
    let witness = SpendWitness {
        inputs: notes_in
            .iter()
            .map(|n| SpendNoteInput {
                d: n.0,
                a: n.1,
                b: n.2,
                rho: n.3,
                v: n.4,
                path: n.5.clone(),
            })
            .collect(),
        outputs: plan
            .outputs
            .iter()
            .map(|n| SpendNoteOutput { v: n.value })
            .collect(),
    };
    let proof = prove_v4::<DEPTH>(&witness, &r_in, &r_out, n_in, n_out, &instances)
        .map_err(|e| TxV4Error::Proof(format!("prove: {e}")))?;

    // Self-verify BEFORE any wallet state mutation [S4 10].
    verify_v4::<DEPTH>(&proof.proof, &instances, n_in, n_out)
        .map_err(|e| TxV4Error::Proof(format!("self-verify: {e}")))?;

    // Sighash and the binding signature [S4 6, S4 12 3.6]: the v5 stream
    // covers the tail.
    let s = sighash_v5(
        &acc_root_point(root),
        &ns,
        &leaves,
        &rc_in,
        &rc_out,
        fee,
        &swap,
    );
    let bsk = binding_sk(&r_in, &r_out);
    let bvk = binding_vk(&rc_in, &rc_out, fee);
    debug_assert!(balance_holds(&rc_in, &rc_out, fee, bsk));
    let bind_sig = sign_bind(&s, bsk, &bvk);

    Ok(TxV5 {
        base: TxV4 {
            root,
            nullifiers: ns,
            leaves,
            rc_in,
            rc_out,
            enc_notes: vec![Vec::new(); n_out],
            fee,
            proof: proof.proof,
            bind_sig,
        },
        swap,
    })
}

// ---------------------------------------------------------------------------
// Confirm pipeline [S4 9]
// ---------------------------------------------------------------------------

/// Confirm a v4 transaction exactly as consensus would [S4 9]: the wallet
/// is the first validator of its own transactions [S4 10].
///
/// Validation runs in the normative order with NO state mutation until
/// every check has passed; only then are the seen-set and the frontier
/// updated (all seven checks execute first - "first failure rejects").
///
/// `fee_floor` is the caller's consensus parameter [S4 9 step 7] (testnet
/// default 0, [`FEE_FLOOR_TESTNET`]).
pub fn confirm_zk_tx<const DEPTH: usize>(
    tx: &TxV4,
    tree: &mut TreeState,
    seen: &mut HashSet<[u8; 32]>,
    fee_floor: u64,
) -> Result<(), TxV4Error> {
    // [S4 9] step 1: parse/structure.
    tx.check_topology()?;

    // step 2: halo2 verify against instances reconstructed from the
    // serialized tx fields - MUST equal tx fields exactly.
    let n_in = tx.nullifiers.len();
    let n_out = tx.leaves.len();
    let instances = tx.instances_of();
    verify_v4::<DEPTH>(&tx.proof, &instances, n_in, n_out)
        .map_err(|e| TxV4Error::Proof(format!("verify: {e}")))?;

    // steps 3+4: balance and bind_sig are enforced JOINTLY by the binding
    // signature under the recomputed bvk [S4 6]: a valid signature proves
    // the signer knows dlog_R(bvk), impossible when a nonzero value delta
    // shifts bvk by d * V (dlog_R(V) unknown) - see spend::balance_holds.
    let s = tx.sighash();
    let bvk = binding_vk(&tx.rc_in, &tx.rc_out, tx.fee);
    if !verify_bind(&s, &bvk, &tx.bind_sig) {
        return Err(TxV4Error::Balance);
    }

    // step 5: nullifier seen-set (defense in depth [S4 5, S4 9]).
    let keys: Vec<[u8; 32]> = tx.nullifiers.iter().map(|n| fp_to_bytes(*n)).collect();
    for k in &keys {
        if seen.contains(k) {
            return Err(TxV4Error::NullifierSeen);
        }
    }

    // step 6 (precondition): the tx must anchor at the CURRENT frontier
    // root; leaf insertion then advances it canonically.
    if tree.root() != tx.root {
        return Err(TxV4Error::RootMismatch);
    }

    // step 7: fee floor [S4 9].
    if tx.fee < fee_floor {
        return Err(TxV4Error::Fee);
    }

    // All checks passed: commit leaf insertion + seen-set [S4 9 step 6].
    for l in &tx.leaves {
        tree.append(tree_rep(l));
    }
    for k in keys {
        seen.insert(k);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// WG-26 confirm pipeline [S4 9, S4 12 3.6]
// ---------------------------------------------------------------------------

/// Confirm a v5 transaction exactly as consensus would [S4 9, S4 12]: the
/// v4 validation order with the swap-tail-aware instances and the
/// tail-covered sighash. NO state mutation until every check has passed.
pub fn confirm_zk_tx_v5<const DEPTH: usize>(
    tx: &TxV5,
    tree: &mut TreeState,
    seen: &mut HashSet<[u8; 32]>,
    fee_floor: u64,
) -> Result<(), TxV4Error> {
    // [S4 9 step 1] structure/topology + canonical swap tail.
    tx.check_swap_tail()?;

    // step 2: halo2 verify against the 21-slot instances reconstructed
    // from the serialized tx fields (tail included) [S4 8, S4 12].
    let n_in = tx.base.nullifiers.len();
    let n_out = tx.base.leaves.len();
    let instances = tx.instances_of();
    verify_v4::<DEPTH>(&tx.base.proof, &instances, n_in, n_out)
        .map_err(|e| TxV4Error::Proof(format!("verify: {e}")))?;

    // steps 3+4: balance and bind_sig jointly under the recomputed bvk
    // [S4 6]; the sighash is the v5 stream (tail covered).
    let s = tx.sighash();
    let bvk = binding_vk(&tx.base.rc_in, &tx.base.rc_out, tx.base.fee);
    if !verify_bind(&s, &bvk, &tx.base.bind_sig) {
        return Err(TxV4Error::Balance);
    }

    // step 5: nullifier seen-set (defense in depth [S4 5, S4 9]).
    let keys: Vec<[u8; 32]> = tx.base.nullifiers.iter().map(|n| fp_to_bytes(*n)).collect();
    for k in &keys {
        if seen.contains(k) {
            return Err(TxV4Error::NullifierSeen);
        }
    }

    // step 6: anchor at the CURRENT frontier root [S4 9 step 6].
    if tree.root() != tx.base.root {
        return Err(TxV4Error::RootMismatch);
    }

    // step 7: fee floor [S4 9 step 7].
    if tx.base.fee < fee_floor {
        return Err(TxV4Error::Fee);
    }

    // All checks passed: commit leaf insertion + seen-set [S4 9 step 6].
    for l in &tx.base.leaves {
        tree.append(tree_rep(l));
    }
    for k in keys {
        seen.insert(k);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opacus_zk::spend::SPEND_INSTANCE_SLOTS;

    fn fixture_tree(depth: usize, n: usize) -> (TreeState, Vec<WalletNoteV4>, Vec<usize>) {
        let mut tree = TreeState::new(depth);
        let notes: Vec<WalletNoteV4> = (0..n)
            .map(|i| WalletNoteV4::random(1_000 + i as u64))
            .collect();
        let mut idxs = Vec::new();
        for note in &notes {
            idxs.push(tree.append(note.tree_entry().expect("valid note")));
        }
        (tree, notes, idxs)
    }

    /// A hand-assembled, well-formed tx (no proving) for wire/sighash tests.
    fn hand_tx() -> TxV4 {
        let g = pallas::Point::generator();
        TxV4 {
            root: Fp::from(99u64),
            nullifiers: vec![Fp::from(11u64)],
            leaves: vec![g * Fq::from(2), g * Fq::from(21)],
            rc_in: vec![g * Fq::from(3)],
            rc_out: vec![g * Fq::from(4), g * Fq::from(5)],
            enc_notes: vec![b"demo".to_vec(), Vec::new()],
            fee: 5,
            proof: vec![1u8, 2, 3],
            bind_sig: [7u8; 64],
        }
    }

    #[test]
    fn wallet_note_v4_flow() {
        let wn = WalletNoteV4::random(12345);
        // Deterministic derivations.
        let l1 = wn.leaf_point().expect("valid note");
        assert_eq!(Some(l1), wn.leaf_point());
        let e1 = wn.tree_entry().expect("valid note");
        assert_eq!(Some(e1), wn.tree_entry());
        // The entry is a function of the leaf point alone.
        assert_eq!(e1, tree_rep(&l1));
        // The key part is symmetric in (a, b) [S4 3].
        let swapped = WalletNoteV4 {
            d: wn.d,
            a: wn.b,
            b: wn.a,
            rho: wn.rho,
            value: wn.value,
        };
        assert_eq!(swapped.tree_entry(), Some(e1));
        // The G3 term matters: changing the value moves the entry.
        let richer = WalletNoteV4 {
            d: wn.d,
            a: wn.a,
            b: wn.b,
            rho: wn.rho,
            value: wn.value + 1,
        };
        assert_ne!(richer.tree_entry(), Some(e1));
        // Nullifier is deterministic and independent of the value.
        assert_eq!(wn.nullifier(), wn.nullifier());
        assert_eq!(richer.nullifier(), wn.nullifier());
        // Corrupt bytes are rejected.
        let mut bad = wn.clone();
        bad.a = [0xff; 32];
        assert!(bad.parts().is_none());
        assert!(bad.leaf_point().is_none());
    }

    #[test]
    fn acc_root_point_is_deterministic() {
        // [root] * G over the system base; deterministic and binding.
        assert_eq!(acc_root_point(Fp::ZERO), pallas::Point::identity());
        assert_eq!(
            acc_root_point(Fp::from(5u64)),
            pallas::Point::generator() * Fq::from(5)
        );
        let a = acc_root_point(Fp::from(77u64));
        assert_eq!(a, acc_root_point(Fp::from(77u64)));
        assert_ne!(a, acc_root_point(Fp::from(78u64)));
    }

    #[test]
    fn tx_v4_bytes_roundtrip_strict() {
        let tx = hand_tx();
        // Full roundtrip preserves every field.
        let parsed = TxV4::from_bytes(&tx.to_bytes()).expect("parse own wire form");
        assert_eq!(parsed.root, tx.root);
        assert_eq!(parsed.nullifiers, tx.nullifiers);
        let pb = |ps: &[pallas::Point]| {
            ps.iter()
                .map(|p| p.to_affine().to_bytes())
                .collect::<Vec<_>>()
        };
        assert_eq!(pb(&parsed.leaves), pb(&tx.leaves));
        assert_eq!(pb(&parsed.rc_in), pb(&tx.rc_in));
        assert_eq!(pb(&parsed.rc_out), pb(&tx.rc_out));
        assert_eq!(parsed.enc_notes, tx.enc_notes);
        assert_eq!(parsed.fee, tx.fee);
        assert_eq!(parsed.proof, tx.proof);
        assert_eq!(parsed.bind_sig, tx.bind_sig);
        parsed.check_topology().expect("hand tx is well-formed");

        // Trailing byte rejected.
        let mut b = tx.to_bytes();
        b.push(0);
        assert!(matches!(
            TxV4::from_bytes(&b),
            Err(TxV4Error::TrailingBytes)
        ));
        // Truncation rejected.
        let b = tx.to_bytes();
        assert!(matches!(
            TxV4::from_bytes(&b[..b.len() - 1]),
            Err(TxV4Error::Truncated)
        ));
        // Wrong version rejected.
        let mut b = tx.to_bytes();
        b[0] = 3;
        assert!(matches!(TxV4::from_bytes(&b), Err(TxV4Error::Version(3))));
        // n_in = 0 rejected.
        let mut b = tx.to_bytes();
        b[4] = 0;
        assert!(matches!(TxV4::from_bytes(&b), Err(TxV4Error::Topology(_))));
        // Non-canonical root (0xff..ff >= modulus) rejected [S4 11].
        let mut b = tx.to_bytes();
        for slot in b.iter_mut().skip(6).take(32) {
            *slot = 0xff;
        }
        assert!(matches!(TxV4::from_bytes(&b), Err(TxV4Error::Canonical)));
        // Identity leaf point rejected [S4 11].
        let mut b = tx.to_bytes();
        let id = pallas::Point::identity().to_affine().to_bytes();
        let leaf_off = 6 + 32 + 32; // version(4)+counts(2) + root + N_0
        b[leaf_off..leaf_off + 32].copy_from_slice(id.as_ref());
        assert!(matches!(TxV4::from_bytes(&b), Err(TxV4Error::Canonical)));
        // Oversized enc_note rejected [S4 9 step 1].
        let mut tx2 = hand_tx();
        tx2.enc_notes[0] = vec![0u8; ENC_NOTE_MAX + 1];
        assert!(matches!(
            TxV4::from_bytes(&tx2.to_bytes()),
            Err(TxV4Error::Topology(_))
        ));
        // Topology inconsistency between leaves and rc_out rejected.
        let mut t3 = hand_tx();
        t3.leaves.pop();
        assert!(t3.check_topology().is_err());
    }

    #[test]
    fn tx_v4_sighash_covers_all_tx_fields() {
        let tx = hand_tx();
        let base = tx.sighash();
        let g = pallas::Point::generator();
        // Root.
        let mut t = tx.clone();
        t.root += Fp::ONE;
        assert_ne!(t.sighash(), base);
        // Nullifier.
        let mut t = tx.clone();
        t.nullifiers[0] += Fp::ONE;
        assert_ne!(t.sighash(), base);
        // Leaf.
        let mut t = tx.clone();
        t.leaves[0] += g;
        assert_ne!(t.sighash(), base);
        // RC_in / RC_out.
        let mut t = tx.clone();
        t.rc_in[0] += g;
        assert_ne!(t.sighash(), base);
        let mut t = tx.clone();
        t.rc_out[1] += g;
        assert_ne!(t.sighash(), base);
        // Fee.
        let mut t = tx.clone();
        t.fee += 1;
        assert_ne!(t.sighash(), base);
        // Topology change (second input) also shifts S.
        let mut t = tx.clone();
        t.nullifiers.push(Fp::from(12u64));
        t.rc_in.push(t.rc_in[0]);
        assert_ne!(t.sighash(), base);
    }

    #[test]
    fn build_zk_spend_rejects_unbalanced_before_proving() {
        let (tree, notes, idxs) = fixture_tree(4, 3);
        // Over-spend: outputs + fee exceed inputs.
        let plan = SpendPlanV4 {
            inputs: vec![(notes[0].clone(), idxs[0])],
            outputs: vec![WalletNoteV4::random(900), WalletNoteV4::random(150)],
            fee: 100,
            swap: None,
        };
        assert!(matches!(
            build_zk_spend_v4::<4>(&tree, &plan),
            Err(TxV4Error::Unbalanced { .. })
        ));
        // Under-spend (silent burn) is equally rejected: exact conservation.
        let plan = SpendPlanV4 {
            inputs: vec![(notes[0].clone(), idxs[0])],
            outputs: vec![WalletNoteV4::random(800), WalletNoteV4::random(100)],
            fee: 50,
            swap: None,
        };
        assert!(matches!(
            build_zk_spend_v4::<4>(&tree, &plan),
            Err(TxV4Error::Unbalanced { .. })
        ));
        // Unknown leaf index rejected before any proving.
        let plan = SpendPlanV4 {
            inputs: vec![(notes[1].clone(), 99)],
            outputs: vec![WalletNoteV4::random(900), WalletNoteV4::random(100)],
            fee: 0,
            swap: None,
        };
        assert!(matches!(
            build_zk_spend_v4::<4>(&tree, &plan),
            Err(TxV4Error::UnknownLeaf)
        ));
    }

    #[test]
    fn build_zk_spend_confirm_depth8() {
        const DEPTH: usize = 8;
        let (mut tree, notes, idxs) = fixture_tree(DEPTH, 5);
        // Wallet topology [S4 10]: 1-in / 2-out, change + recipient + fee.
        // notes[2] carries 1002 atoms.
        let change = WalletNoteV4::random(702);
        let recipient = WalletNoteV4::random(250);
        let plan = SpendPlanV4 {
            inputs: vec![(notes[2].clone(), idxs[2])],
            outputs: vec![change.clone(), recipient.clone()],
            fee: 50,
            swap: None,
        };
        let tx = build_zk_spend_v4::<DEPTH>(&tree, &plan).expect("prove at depth 8");
        // Change correctness [S4 14]: the first published leaf is exactly
        // the change note's leaf; the 15-slot instances are normative.
        assert_eq!(Some(tx.leaves[0]), change.leaf_point());
        assert_eq!(Some(tx.leaves[1]), recipient.leaf_point());
        assert_eq!(tx.instances_of().len(), SPEND_INSTANCE_SLOTS);

        // Snapshot the PRE-confirmation frontier for the fee-floor case.
        let mut tree_fee = tree.clone();

        // Confirm accepts; the seen-set gains exactly one nullifier.
        let mut seen = HashSet::new();
        confirm_zk_tx::<DEPTH>(&tx, &mut tree, &mut seen, FEE_FLOOR_TESTNET)
            .expect("honest tx confirms");
        assert_eq!(seen.len(), 1);

        // Replay: rejected at step 5 (seen-set), BEFORE the root check.
        assert!(matches!(
            confirm_zk_tx::<DEPTH>(&tx, &mut tree, &mut seen, FEE_FLOOR_TESTNET),
            Err(TxV4Error::NullifierSeen)
        ));

        // A tampered bind_sig fails the balance step [S4 9 steps 3+4] -
        // the halo2 proof still verifies (it binds instances, not the
        // signature), so this isolates the bind_sig check.
        let mut bad = tx.clone();
        bad.bind_sig[40] ^= 1;
        let mut tree2 = fixture_tree(DEPTH, 5).0;
        assert!(matches!(
            confirm_zk_tx::<DEPTH>(&bad, &mut tree2, &mut HashSet::new(), FEE_FLOOR_TESTNET),
            Err(TxV4Error::Balance)
        ));

        // A tampered fee shifts S and shifts bvk: bind_sig fails.
        let mut bad = tx.clone();
        bad.fee += 1;
        let mut tree3 = fixture_tree(DEPTH, 5).0;
        assert!(matches!(
            confirm_zk_tx::<DEPTH>(&bad, &mut tree3, &mut HashSet::new(), FEE_FLOOR_TESTNET),
            Err(TxV4Error::Balance)
        ));

        // Fee floor [S4 9 step 7]: a floor above the tx fee is rejected
        // even though everything else is honest (same anchored frontier).
        assert!(matches!(
            confirm_zk_tx::<DEPTH>(&tx, &mut tree_fee, &mut HashSet::new(), tx.fee + 1),
            Err(TxV4Error::Fee)
        ));

        // A tx anchored at a different frontier is rejected [S4 9 step 6].
        let mut tree5 = fixture_tree(DEPTH, 7).0;
        assert!(matches!(
            confirm_zk_tx::<DEPTH>(&tx, &mut tree5, &mut HashSet::new(), FEE_FLOOR_TESTNET),
            Err(TxV4Error::RootMismatch)
        ));
    }

    #[test]
    fn v4_wallet_end_to_end_mainnet_depth() {
        // Phase 3 acceptance [S4 13]: wallet e2e green at 2^32 depth.
        // Runs un-ignored so CI enforces it (the Phase 2 precedent: the
        // mainnet-depth prove test is part of the default suite).
        const DEPTH: usize = TREE_DEPTH_MAINNET;
        let (mut tree, notes, idxs) = fixture_tree(DEPTH, 4);
        // notes[1] carries 1001 atoms.
        let change = WalletNoteV4::random(601);
        let recipient = WalletNoteV4::random(350);
        let plan = SpendPlanV4 {
            inputs: vec![(notes[1].clone(), idxs[1])],
            outputs: vec![change.clone(), recipient.clone()],
            fee: 50,
            swap: None,
        };
        let tx = build_zk_spend_v4::<DEPTH>(&tree, &plan).expect("prove at mainnet depth");
        let mut seen = HashSet::new();
        confirm_zk_tx::<DEPTH>(&tx, &mut tree, &mut seen, FEE_FLOOR_TESTNET)
            .expect("confirm at mainnet depth");
        assert_eq!(seen.len(), 1);
        // Change correctness [S4 14].
        assert_eq!(Some(tx.leaves[0]), change.leaf_point());
        // The frontier absorbed both output leaves canonically [S4 9 step 6].
        assert_eq!(tree.leaf(tree.len() - 2), Some(tree_rep(&tx.leaves[0])));
        assert_eq!(tree.leaf(tree.len() - 1), Some(tree_rep(&tx.leaves[1])));
    }

    // -------------------------------------------------------------------
    // WG-26 WP-3 [S4 12 3.6/3.7]: T5 v5 wire, T6 lock-then-claim
    // -------------------------------------------------------------------

    /// A hand-assembled, well-formed PLAIN v5 tx (no proving).
    fn hand_v5() -> TxV5 {
        TxV5 {
            base: hand_tx(),
            swap: TxV5::swap_none(),
        }
    }

    #[test]
    fn tx_v5_plain_wire_roundtrip_strict() {
        let tx = hand_v5();
        let parsed = TxV5::from_bytes(&tx.to_bytes()).expect("parse own v5 wire");
        assert_eq!(parsed.base.root, tx.base.root);
        assert_eq!(parsed.base.fee, tx.base.fee);
        assert_eq!(parsed.swap.flag, 0);
        parsed.check_swap_tail().expect("hand v5 is well-formed");

        // The v5 body is the v4 body under version 5 plus a zero tail.
        let v5 = tx.to_bytes();
        let mut v4 = tx.base.to_bytes();
        assert_eq!(v5.len(), v4.len() + SWAP_TAIL_BYTES);
        assert_eq!(
            u32::from_le_bytes(v5[0..4].try_into().expect("4 bytes")),
            TX_VERSION_V5
        );
        v4[0] = 5;
        assert_eq!(&v5[..v4.len()], &v4[..], "v5 body = v4 body @ version 5");
        assert!(v5[v4.len()..].iter().all(|&b| b == 0), "zero tail");

        // Trailing byte / truncation / wrong version rejected.
        let mut b = v5.clone();
        b.push(0);
        assert!(matches!(
            TxV5::from_bytes(&b),
            Err(TxV4Error::TrailingBytes)
        ));
        assert!(matches!(
            TxV5::from_bytes(&v5[..v5.len() - 1]),
            Err(TxV4Error::Truncated)
        ));
        let mut b = v5.clone();
        b[0] = 4;
        assert!(matches!(TxV5::from_bytes(&b), Err(TxV4Error::Version(4))));
    }

    #[test]
    fn tx_v5_tail_canonical_rules() {
        // Unknown flag.
        let mut t = hand_v5();
        t.swap.flag = 9;
        assert!(matches!(
            TxV5::from_bytes(&t.to_bytes()),
            Err(TxV4Error::Topology(_))
        ));
        // Plain (flag 0) with a nonzero tail slot.
        let mut t = hand_v5();
        t.swap.idx = 1;
        assert!(matches!(
            TxV5::from_bytes(&t.to_bytes()),
            Err(TxV4Error::Topology(_))
        ));
        // Lock without H.
        let mut t = hand_v5();
        t.swap.flag = 1;
        t.swap.idx = 1;
        assert!(matches!(
            TxV5::from_bytes(&t.to_bytes()),
            Err(TxV4Error::Topology(_))
        ));
        // Lock with a junk spent-swap entry.
        let mut t = hand_v5();
        t.swap.flag = 1;
        t.swap.idx = 1;
        t.swap.h = Fp::from(7u64);
        t.swap.entry = Fp::from(9u64);
        assert!(matches!(
            TxV5::from_bytes(&t.to_bytes()),
            Err(TxV4Error::Topology(_))
        ));
        // Lock idx beyond the output count (2 outputs in hand_tx).
        let mut t = hand_v5();
        t.swap.flag = 1;
        t.swap.idx = 3;
        t.swap.h = Fp::from(7u64);
        assert!(matches!(
            TxV5::from_bytes(&t.to_bytes()),
            Err(TxV4Error::Topology(_))
        ));
        // Claim with a zero entry.
        let mut t = hand_v5();
        t.swap.flag = 2;
        t.swap.idx = 1;
        t.swap.h = Fp::from(7u64);
        assert!(matches!(
            TxV5::from_bytes(&t.to_bytes()),
            Err(TxV4Error::Topology(_))
        ));
        // Refund carrying a preimage lane.
        let mut t = hand_v5();
        t.swap.flag = 3;
        t.swap.idx = 1;
        t.swap.h = Fp::from(7u64);
        t.swap.entry = Fp::from(9u64);
        t.swap.s0 = Fp::from(1u64);
        assert!(matches!(
            TxV5::from_bytes(&t.to_bytes()),
            Err(TxV4Error::Topology(_))
        ));
        // A canonical lock tail parses.
        let mut t = hand_v5();
        t.swap.flag = 1;
        t.swap.idx = 1;
        t.swap.h = Fp::from(7u64);
        TxV5::from_bytes(&t.to_bytes()).expect("canonical lock tail parses");
    }

    #[test]
    fn tx_v5_sighash_covers_the_swap_tail() {
        let tx = hand_v5();
        let base = tx.sighash();
        // Every tail slot shifts S.
        let mut t = tx.clone();
        t.swap.flag = 1;
        t.swap.idx = 1;
        t.swap.h = Fp::from(7u64);
        assert_ne!(t.sighash(), base);
        let mut t = tx.clone();
        t.swap.s0 = Fp::from(3u64);
        assert_ne!(t.sighash(), base);
        let mut t = tx.clone();
        t.swap.s1 = Fp::from(4u64);
        assert_ne!(t.sighash(), base);
        let mut t = tx.clone();
        t.swap.entry = Fp::from(5u64);
        assert_ne!(t.sighash(), base);
        // Base fields stay covered.
        let mut t = tx.clone();
        t.base.fee += 1;
        assert_ne!(t.sighash(), base);
        let mut t = tx.clone();
        t.base.root += Fp::ONE;
        assert_ne!(t.sighash(), base);
    }

    #[test]
    fn wg26_lock_then_claim_end_to_end() {
        const DEPTH: usize = 8;
        let preimage = [0x5au8; 32];
        let (h, s0, s1) = hashlock_swap(&preimage);

        // Alice locks 500 atoms under H: 1-in / 2-out, locked output
        // first (idx 1), change second. 500 + 450 + 50 fee = 1000 in.
        let (mut tree, notes, idxs) = fixture_tree(DEPTH, 2);
        let locked = WalletNoteV4::random(500);
        let change = WalletNoteV4::random(450);
        let lock_plan = SpendPlanV4 {
            inputs: vec![(notes[0].clone(), idxs[0])],
            outputs: vec![locked.clone(), change],
            fee: 50,
            swap: Some(SwapIntent::Lock { idx: 1, h }),
        };
        let lock_tx = build_zk_spend_v5::<DEPTH>(&tree, &lock_plan).expect("lock builds");
        // The locked output is published with its swap-variant leaf
        // [S4 12 3.1].
        let (d, a, b, rho) = locked.parts().expect("valid note");
        assert_ne!(
            lock_tx.base.leaves[0],
            locked.leaf_point().expect("plain leaf")
        );
        assert_eq!(
            lock_tx.base.leaves[0],
            swap_leaf_point_v2(d, a, b, locked.value, rho, h)
        );
        assert_eq!(lock_tx.swap.flag, 1);
        assert_eq!(lock_tx.swap.h, h);
        assert_eq!(lock_tx.instances_of().len(), SPEND_INSTANCE_SLOTS);
        confirm_zk_tx_v5::<DEPTH>(&lock_tx, &mut tree, &mut HashSet::new(), FEE_FLOOR_TESTNET)
            .expect("lock confirms");

        // The tree now holds the SWAP-variant entry, not the plain one.
        let locked_idx = tree.len() - 2;
        let locked_entry = tree.leaf(locked_idx).expect("locked leaf appended");
        assert_eq!(
            locked_entry,
            swap_leaf_entry_v2(d, a, b, locked.value, rho, h)
        );
        assert_ne!(locked_entry, locked.tree_entry().expect("plain entry"));

        // The lock wire round-trips (tail codec under real material).
        let parsed = TxV5::from_bytes(&lock_tx.to_bytes()).expect("lock wire parses");
        assert_eq!(parsed.swap.h, h);

        // Bob claims by revealing the preimage: 500 -> 460 out + 40 fee.
        let claim_out = WalletNoteV4::random(460);
        let claim_plan = SpendPlanV4 {
            inputs: vec![(locked.clone(), locked_idx)],
            outputs: vec![claim_out.clone()],
            fee: 40,
            swap: Some(SwapIntent::Claim { idx: 1, preimage }),
        };
        let claim_tx = build_zk_spend_v5::<DEPTH>(&tree, &claim_plan).expect("claim builds");
        assert_eq!(claim_tx.swap.flag, 2);
        assert_eq!(claim_tx.swap.h, h);
        assert_eq!(claim_tx.swap.s0, s0);
        assert_eq!(claim_tx.swap.s1, s1);
        assert_eq!(claim_tx.swap.entry, locked_entry, "published swap entry");
        confirm_zk_tx_v5::<DEPTH>(&claim_tx, &mut tree, &mut HashSet::new(), FEE_FLOOR_TESTNET)
            .expect("claim confirms");
        assert_eq!(Some(claim_tx.base.leaves[0]), claim_out.leaf_point());

        // A PLAIN spend of the locked note is rejected at build time: the
        // tree holds the swap-variant entry only [S4 12 3.1].
        let plain_plan = SpendPlanV4 {
            inputs: vec![(locked.clone(), locked_idx)],
            outputs: vec![WalletNoteV4::random(460)],
            fee: 40,
            swap: None,
        };
        assert!(matches!(
            build_zk_spend_v5::<DEPTH>(&tree, &plain_plan),
            Err(TxV4Error::UnknownLeaf)
        ));
    }

    #[test]
    fn wg26_lock_then_refund_end_to_end() {
        const DEPTH: usize = 8;
        let preimage = [0xA5u8; 32];
        let (h, _, _) = hashlock_swap(&preimage);

        let (mut tree, notes, idxs) = fixture_tree(DEPTH, 2);
        let locked = WalletNoteV4::random(500);
        let change = WalletNoteV4::random(450);
        let lock_plan = SpendPlanV4 {
            inputs: vec![(notes[0].clone(), idxs[0])],
            outputs: vec![locked.clone(), change],
            fee: 50,
            swap: Some(SwapIntent::Lock { idx: 1, h }),
        };
        let lock_tx = build_zk_spend_v5::<DEPTH>(&tree, &lock_plan).expect("lock builds");
        confirm_zk_tx_v5::<DEPTH>(&lock_tx, &mut tree, &mut HashSet::new(), FEE_FLOOR_TESTNET)
            .expect("lock confirms");
        let locked_idx = tree.len() - 2;

        // The lock owner refunds WITHOUT the preimage: empty lanes.
        let refund_out = WalletNoteV4::random(460);
        let refund_plan = SpendPlanV4 {
            inputs: vec![(locked.clone(), locked_idx)],
            outputs: vec![refund_out.clone()],
            fee: 40,
            swap: Some(SwapIntent::Refund { idx: 1, h }),
        };
        let refund_tx = build_zk_spend_v5::<DEPTH>(&tree, &refund_plan).expect("refund builds");
        assert_eq!(refund_tx.swap.flag, 3);
        assert_eq!(refund_tx.swap.s0, Fp::ZERO);
        assert_eq!(refund_tx.swap.s1, Fp::ZERO);
        let (d, a, b, rho) = locked.parts().expect("valid note");
        assert_eq!(
            refund_tx.swap.entry,
            swap_leaf_entry_v2(d, a, b, locked.value, rho, h)
        );
        confirm_zk_tx_v5::<DEPTH>(
            &refund_tx,
            &mut tree,
            &mut HashSet::new(),
            FEE_FLOOR_TESTNET,
        )
        .expect("refund confirms");
        assert_eq!(Some(refund_tx.base.leaves[0]), refund_out.leaf_point());
    }
}
