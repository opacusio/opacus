//! Light Wallet

use opacus_crypto::keys::SpendingKey;
use opacus_crypto::stealth::{PublicAddress, RecipientKeys};
use std::collections::{HashMap, HashSet};

use crate::tx_v4::WalletNoteV4;
use crate::zk_spend::{
    build_with_depth, fp_to_bytes, SpendInput, TreeState, WalletNote, ZkSpendError, ZkSpendTx,
};
use opacus_zk::prelude::*;

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
    /// WP-D2b: a v4 confirmation arrived out of order. The wallet mirror
    /// is fed by the sync block-by-block, so confirmation heights must
    /// be non-decreasing - otherwise the h_open prefix snapshot would be
    /// ill-defined.
    #[error("out-of-order v4 confirmation: height {got} follows {last}")]
    OutOfOrder { last: u64, got: u64 },
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

/// A v0.4 note tracked by this wallet (WP-D2b): the note bytes plus the
/// position of its tree entry in the wallet's v4 frontier and the chain
/// height at which the entry was confirmed.
#[derive(Clone, Debug)]
pub struct V4TrackedNote {
    pub note: WalletNoteV4,
    /// Leaf index of the note's tree entry in the v4 frontier.
    pub leaf_index: usize,
    /// Confirmation height of the entry (the sync feeds heights in
    /// block order, so they are non-decreasing).
    pub confirmed_height: u64,
    pub spent: bool,
}

/// The wallet-real inputs [`crate::gov::build_ballot`] consumes
/// (WP-D2b, the wallet-gov bridge): the frontier snapshot at the
/// vote-open height plus the wallet's own v4 notes confirmed at or
/// before that height, with their leaf positions in the snapshot.
#[derive(Clone, Debug)]
pub struct GovInputs {
    /// The v4 frontier as it was at `h_open` (its root is the declared
    /// anchor; leaves confirmed after `h_open` are cut off).
    pub frontier: TreeState,
    /// `(leaf_index, note)` pairs, in wallet store order. A note spent
    /// AFTER `h_open` still votes: the weight is the H_open holding, the
    /// double-vote gate is the serial seen-set (GIP-2 R-3), not the
    /// spend state.
    pub notes: Vec<(usize, WalletNoteV4)>,
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
    #[allow(dead_code)] // audit v5: field kept intentionally (pending functionality); review
    keys: RecipientKeys,
    address: String,
    unspent_notes: HashMap<[u8; 32], UnspentNote>,
    balance: Balance,
    /// The wallet's mirror of the global note-commitment tree.
    zk_tree: TreeState,
    zk_notes: HashMap<[u8; 32], ZkTrackedNote>,
    zk_seen_nullifiers: HashSet<[u8; 32]>,
    /// The wallet's v4 frontier (WP-D2b): every GLOBAL v4 commitment,
    /// own or foreign - the anchor root is the root of the whole tree.
    v4_tree: TreeState,
    /// Confirmation height of each v4 leaf, in append order.
    v4_leaf_heights: Vec<u64>,
    /// The wallet's own confirmed v4 notes (the votable set).
    v4_notes: Vec<V4TrackedNote>,
    /// The last confirmation height fed to the v4 side (monotonicity
    /// guard; the sync walks blocks in order).
    v4_confirm_height: u64,
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
            v4_tree: TreeState::new(depth),
            v4_leaf_heights: Vec::new(),
            v4_notes: Vec::new(),
            v4_confirm_height: 0,
        }
    }

    pub fn get_address(&self) -> &str {
        &self.address
    }
    pub fn get_balance(&self) -> &Balance {
        &self.balance
    }

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
        self.zk_notes
            .values()
            .filter(|t| !t.spent)
            .map(|t| t.note.value)
            .sum()
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
            let sk = p
                .recipient_sk
                .unwrap_or_else(|| fp_to_bytes(Fp::random(OsRng)));
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

    // ------------------------------------------------------------------
    // v4 note store + wallet-gov bridge [WP-D2b]
    // ------------------------------------------------------------------

    /// Append one confirmed GLOBAL v4 commitment to the wallet's v4
    /// frontier (a leaf this wallet does not own or has not decrypted).
    /// Heights must be non-decreasing (the sync walks blocks in order).
    pub fn confirm_v4_leaf(
        &mut self,
        entry: Fp,
        confirm_height: u64,
    ) -> Result<usize, WalletError> {
        if confirm_height < self.v4_confirm_height {
            return Err(WalletError::OutOfOrder {
                last: self.v4_confirm_height,
                got: confirm_height,
            });
        }
        self.v4_confirm_height = confirm_height;
        let idx = self.v4_tree.append(entry);
        self.v4_leaf_heights.push(confirm_height);
        Ok(idx)
    }

    /// Track an own confirmed v4 note: its tree entry joins the v4
    /// frontier and the note joins the votable set. The wallet's fiat
    /// `balance` is the old-zk/transparent ledger and is NOT touched -
    /// v4 value is only visible through [`Self::v4_balance`].
    pub fn add_v4_note(
        &mut self,
        note: WalletNoteV4,
        confirm_height: u64,
    ) -> Result<usize, WalletError> {
        let entry = note.tree_entry().ok_or(WalletError::CorruptNote)?;
        let idx = self.confirm_v4_leaf(entry, confirm_height)?;
        self.v4_notes.push(V4TrackedNote {
            note,
            leaf_index: idx,
            confirmed_height: confirm_height,
            spent: false,
        });
        Ok(idx)
    }

    /// Mark an own v4 note spent (the v4 spend pipeline wires this in
    /// later; the gov bridge must already keep spent-after-H_open notes
    /// votable, so the flag exists now).
    pub fn mark_v4_spent(&mut self, leaf_index: usize) -> Result<(), WalletError> {
        match self
            .v4_notes
            .iter_mut()
            .find(|t| t.leaf_index == leaf_index)
        {
            Some(t) => {
                t.spent = true;
                Ok(())
            }
            None => Err(WalletError::Zk(format!(
                "no own v4 note at leaf {leaf_index}"
            ))),
        }
    }

    /// Number of leaves in the wallet's v4 frontier.
    pub fn v4_leaves(&self) -> usize {
        self.v4_tree.len()
    }

    /// Sum of the wallet's unspent v4 notes.
    pub fn v4_balance(&self) -> u64 {
        self.v4_notes
            .iter()
            .filter(|t| !t.spent)
            .map(|t| t.note.value)
            .sum()
    }

    /// `(total_tracked, spent)` v4 note counts.
    pub fn v4_note_counts(&self) -> (usize, usize) {
        let spent = self.v4_notes.iter().filter(|t| t.spent).count();
        (self.v4_notes.len(), spent)
    }

    /// The wallet-gov bridge (WP-D2b): the frontier snapshot at
    /// `h_open` plus the wallet's own v4 notes confirmed at or before
    /// `h_open`, exactly what [`crate::gov::build_ballot`] consumes.
    ///
    /// - The frontier is cut to the leaves confirmed by `h_open` (the
    ///   monotonic-height guard keeps that a prefix); its root is the
    ///   anchor the proposal declares. Leaves confirmed after `h_open`
    ///   carry no weight (GIP-2 R-2) and are not in the snapshot.
    /// - Own notes confirmed after `h_open` are excluded; own notes
    ///   SPENT after `h_open` are kept (the vote happened while the
    ///   wallet held them).
    pub fn gov_inputs_at(&self, h_open: u64) -> Result<GovInputs, WalletError> {
        let n_open = self.v4_leaf_heights.partition_point(|&h| h <= h_open);
        let frontier = self
            .v4_tree
            .snapshot(n_open)
            .ok_or_else(|| WalletError::Zk("h_open snapshot overflow".to_string()))?;
        let notes: Vec<(usize, WalletNoteV4)> = self
            .v4_notes
            .iter()
            .filter(|t| t.confirmed_height <= h_open)
            .map(|t| (t.leaf_index, t.note.clone()))
            .collect();
        debug_assert!(notes.iter().all(|(idx, _)| *idx < n_open));
        Ok(GovInputs { frontier, notes })
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

    // ------------------------------------------------------------------
    // WP-D2b: v4 note store + wallet-gov bridge
    // ------------------------------------------------------------------

    use crate::gov::{build_ballot, verify_ballot, verify_ballot_against_tree, Choice};

    /// A v4 wallet fed by a scripted sync: own notes at heights 10 and
    /// 12, foreign leaves at 11 and 13, an own note at 14 and an own
    /// note at 20 (the chain grows past H_open on purpose).
    fn bridge_wallet() -> (LightWallet, Vec<WalletNoteV4>) {
        let mut w = test_wallet(4);
        let n1 = WalletNoteV4::random(2_000_000);
        let foreign_a = WalletNoteV4::random(1).tree_entry().expect("foreign a");
        let n2 = WalletNoteV4::random(1_500_000);
        let foreign_b = WalletNoteV4::random(1).tree_entry().expect("foreign b");
        let n3 = WalletNoteV4::random(900_000);
        let n4 = WalletNoteV4::random(700_000);
        w.add_v4_note(n1.clone(), 10).unwrap();
        w.confirm_v4_leaf(foreign_a, 11).unwrap();
        w.add_v4_note(n2.clone(), 12).unwrap();
        w.confirm_v4_leaf(foreign_b, 13).unwrap();
        w.add_v4_note(n3.clone(), 14).unwrap();
        w.add_v4_note(n4.clone(), 20).unwrap();
        (w, vec![n1, n2, n3, n4])
    }

    /// The h_open snapshot cuts the frontier AND the votable set at the
    /// declared height: leaves and notes confirmed after H_open carry no
    /// weight (GIP-2 R-2); own notes confirmed before stay in.
    #[test]
    fn gov_snapshot_cuts_post_open_leaves() {
        let (w, notes) = bridge_wallet();
        assert_eq!(w.v4_leaves(), 6);

        let inputs = w.gov_inputs_at(12).expect("snapshot at h_open=12");
        assert_eq!(inputs.frontier.len(), 3, "leaves 3.. confirmed later");
        assert_eq!(
            inputs.notes,
            vec![(0, notes[0].clone()), (2, notes[1].clone())]
        );
        let live_root = w.gov_inputs_at(20).unwrap().frontier.root();
        assert_ne!(
            inputs.frontier.root(),
            live_root,
            "the live v4 frontier grew past H_open"
        );

        // h_open=11: only the note confirmed at 10 votes; the leaf
        // confirmed at 11 is in the frontier, the one at 12 is not.
        let inputs11 = w.gov_inputs_at(11).expect("snapshot at 11");
        assert_eq!(inputs11.frontier.len(), 2);
        assert_eq!(inputs11.notes.len(), 1);

        // h_open=20 (the live height): the full frontier, all four notes.
        let inputs20 = w.gov_inputs_at(20).expect("snapshot at the tip");
        assert_eq!(inputs20.frontier.len(), 6);
        assert_eq!(inputs20.notes.len(), 4);

        // h_open beyond the tip is fine: every leaf confirmed so far is
        // at-or-before h_open, so the snapshot is the full frontier.
        let inputs99 = w.gov_inputs_at(99).expect("snapshot at 99");
        assert_eq!(inputs99.frontier.len(), 6);
        assert_eq!(inputs99.frontier.root(), live_root);
    }

    /// The bridge feeds `build_ballot` wallet-real inputs end to end:
    /// the ballot anchors at the SNAPSHOT root, verifies standalone and
    /// against the snapshot, and is stale against the wallet's grown
    /// frontier (notes confirmed after H_open moved the root).
    #[test]
    fn gov_bridge_feeds_build_ballot() {
        let (w, _notes) = bridge_wallet();
        let inputs = w.gov_inputs_at(12).expect("snapshot at h_open=12");
        let indices: Vec<usize> = inputs.notes.iter().map(|(i, _)| *i).collect();
        let refs: Vec<&WalletNoteV4> = inputs.notes.iter().map(|(_, n)| n).collect();
        assert_eq!(refs.len(), 2);

        let ballot = build_ballot::<4>(&inputs.frontier, &indices, &refs, 2, 0, 12, Choice::For)
            .expect("wallet-real ballot must build");
        assert_eq!(ballot.v, 3_500_000);
        assert_eq!(ballot.anchor, inputs.frontier.root());
        verify_ballot::<4>(&ballot).expect("standalone verify");
        verify_ballot_against_tree::<4>(&ballot, &inputs.frontier)
            .expect("fresh against the snapshot");

        // The wallet's live v4 frontier has moved on (leaves at 13, 14,
        // 20): the ballot is STALE there - exactly the node-side gate a
        // collector applies at H_open.
        let live = w.gov_inputs_at(20).unwrap().frontier;
        let err = verify_ballot_against_tree::<4>(&ballot, &live).unwrap_err();
        assert!(matches!(err, crate::gov::GovError::RootMismatch));
    }

    /// A note spent AFTER H_open still votes with its H_open weight: the
    /// bridge keeps it in the votable set while the balance excludes it.
    #[test]
    fn gov_bridge_keeps_notes_spent_after_h_open() {
        let (mut w, _notes) = bridge_wallet();
        w.mark_v4_spent(0).expect("note at leaf 0 is own");
        assert_eq!(w.v4_note_counts(), (4, 1));
        assert_eq!(w.v4_balance(), 3_100_000, "balance drops the spent note");

        let inputs = w.gov_inputs_at(12).expect("snapshot at h_open=12");
        assert_eq!(
            inputs.notes.len(),
            2,
            "spent-after-H_open still votes (weight is the H_open holding)"
        );
        assert_eq!(inputs.notes[0].0, 0);

        assert!(w.mark_v4_spent(1).is_err(), "leaf 1 is a foreign leaf");
        assert!(w.mark_v4_spent(999).is_err());
    }

    /// The monotonicity guard: a confirmation below the last fed height
    /// is refused - the h_open prefix snapshot would be ill-defined.
    #[test]
    fn gov_bridge_rejects_out_of_order_confirmation() {
        let mut w = test_wallet(4);
        w.confirm_v4_leaf(Fp::ONE, 15).expect("first leaf at 15");
        let err = w
            .confirm_v4_leaf(Fp::from(2u64), 14)
            .expect_err("height 14 cannot follow 15");
        assert!(matches!(err, WalletError::OutOfOrder { last: 15, got: 14 }));
        assert_eq!(w.v4_leaves(), 1, "the rejected leaf left no trace");
        // Equal heights are allowed (same block, several commitments).
        w.confirm_v4_leaf(Fp::from(3u64), 15)
            .expect("same height ok");
        assert_eq!(w.v4_leaves(), 2);
    }

    /// Dust semantics flow through the bridge untouched: a snapshot
    /// whose votable weight sits below T_min fails in build_ballot (the
    /// P-2 gate), not in the bridge.
    #[test]
    fn gov_bridge_passes_dust_gate_to_build_ballot() {
        let mut w = test_wallet(4);
        let small = WalletNoteV4::random(900_000);
        w.add_v4_note(small.clone(), 5).unwrap();
        let inputs = w.gov_inputs_at(5).expect("snapshot");
        let indices: Vec<usize> = inputs.notes.iter().map(|(i, _)| *i).collect();
        let refs: Vec<&WalletNoteV4> = inputs.notes.iter().map(|(_, n)| n).collect();
        let err = build_ballot::<4>(&inputs.frontier, &indices, &refs, 2, 0, 5, Choice::For)
            .expect_err("900k < T_min must be rejected");
        assert!(matches!(
            err,
            crate::gov::GovError::Dust {
                v: 900_000,
                t_min: 1_000_000
            }
        ));
    }
}
