# WG-29 scope: enc_notes - in-transaction note encryption [S4 7 gap]

- **Status**: design frozen (WP-A). Implementation follows as WP-B..WP-E,
  one commit + evidence dump each.
- **Queue**: WG-29 = enc_notes (Track B of the WG-29 WP-2 scout, matrix H).
  Monerod-facing CLSAG verification is the NEXT big theme (v0.4 target);
  the external security audit stays last (item g).
- **Evidence base**: wg29_encnotes_wpa_recon_v1_20261030_090356.dump.txt
  (md5 d3670ff1f2db634fe20caedd0e407ad2, HEAD a901c23, RESULT: OK).

## 1. Problem

TxV4.enc_notes ships empty (tx_v4.rs:26 "the first cut ships them empty"),
so a recipient recovers output notes only through the N3 direct note feed
(notes.rs). Chain data alone is not enough to recover funds: the note
secrets (a, b, rho) live only in the sender's wallet and in the N3 blob.
WG-29 makes the transaction self-contained: every output carries its own
sealed note payload, and the sighash covers it.

## 2. Facts pinned by the recon

- Note model [S4 3]: a note is (d, a, b, rho, v). Leaf point =
  p_leaf(d, a+b, a*b) + leaf_gen() * h_leaf_v2(v, rho); the tree entry is
  tree_rep of that point (spend.rs:192-201). The output witness carries
  only v (SpendNoteOutput, spend.rs:1836); the input witness carries
  d, a, b, rho, v + auth path (SpendNoteInput, spend.rs:1819).
- Value-commitment blinding is PER-TX ephemeral (tx_v4.rs:716-717 draws
  fresh r_in at spend time), so the recipient never needs the sender's
  r_out. The note plaintext therefore needs exactly (d, a, b, rho, v).
- The builder fills enc_notes empty today (tx_v4.rs:782); confirm paths
  never read them; sighash_v4/v5 do not cover them (WG-26 R3 documented
  gap, WG-26-scope:223).
- Caps: ENC_NOTE_MAX = 1024 (tx_v4.rs:52), MAX_IN = 2, MAX_OUT = 4
  (spend.rs), MAX_BLOCK_SIZE = 2 MiB; N3 NOTE_PAYLOAD_MAX = 512.
- The wallet crate has no NodeIdentity and no Address type (recon D1
  greps: 0 hits); key material comes from keys.rs (BIP-39 seed per ADR
  r5; tags ghost_spend_derive_v2 / ghost_view_derive_v2).
- The blake3-only ristretto ECIES (notes.rs:28-48 construction, 244-258
  keys/keystream) is proven code with a full negative-test suite; today
  seal/open consumers are all inside opacus-network (recon E2: 0 wallet
  hits).

## 3. Frozen design decisions

- **D1 plaintext ENoteV1 (137 B, fixed size)**:
  version u8 = 1 || d 32 || a 32 || b 32 || rho 32 || v u64 LE.
  Canonical hand-rolled codec (no serde). No memo field in v1.
- **D2 note-to-output binding**: the recipient recomputes the leaf point
  from (d, a, b, v, rho) through the existing WalletNoteV4::leaf_point()
  and MUST find j with tx.leaves[j] == point; otherwise the note is
  rejected. This binds the sealed payload to the sighash-covered
  commitment: a substituted note cannot match.
- **D3 key model**: wallet-derived note keypair over ristretto:
  note_sk = scalar(blake3("ghost_note_derive_v1" || seed)) (canonical
  reduction), note_pk = [note_sk] * RISTRETTO_BASEPOINT_POINT.
  The sender seals each output to the RECIPIENT's note_pk, obtained
  out-of-band (an address format is a separate roadmap item; the swap
  offer sidecar pattern precedes it). note_sk lives in a zeroizing
  wrapper (the SecretScalar pattern of v0.7 F4).
- **D4 ECIES**: same algebra as notes.rs (ephemeral ristretto scalar,
  blake3::derive_key keystream + keyed MAC, MAC verified before any
  decryption) with WG-29 domain tags: context strings
  "ghost-encnote-v1 keystream" / "ghost-encnote-v1 mac", block tag
  "ghost-encnote-ks-v1", MAC tag "ghost-encnote-mac-v1".
  In-tx wire form is BINARY (no hex): epk 32 || nonce 16 || ct 137 ||
  mac 32 = 217 B <= ENC_NOTE_MAX. The blob also fits the N3 backup
  channel (217 <= NOTE_PAYLOAD_MAX 512).
- **D5 code location**: new crates/opacus-crypto/src/ecies.rs extracted
  from notes.rs (byte-compatible algebra, domain tags as parameters);
  notes.rs refactored onto it with its own tags - no N3 wire change.
  opacus-wallet gains no new external dependency (curve25519-dalek,
  blake3, rand are already workspace deps).
- **D6 sighash coverage (closes WG-26 R3 for the v5 wire)**: enc_notes
  ARE covered by the v5 sighash. Stream extension of sighash_v5
  (spend.rs:275-311): after the swap tail entry, for each output i in
  0..n_out: le32(len_i) || enc_note_i (zero-length stays structurally
  legal; the builder always fills). The v4 sighash is untouched (legacy
  wire). All v5 callers update atomically in one commit: TxV5::sighash,
  confirm_zk_tx_v5, confirm_v5_consensus. Testnet consensus break is
  acceptable pre-mainnet.
- **D7 caps unchanged**: ENC_NOTE_MAX stays 1024 (>= 217), MAX_OUT stays
  4; worst-case tx growth 4 * (4 + 217) = 884 B. Block-size and
  proof-size impact: none.

## 4. WP breakdown (executed in order)

- **WP-B primitive**: extract ecies.rs (D5) + ENoteV1 codec (D1) +
  seal_enote / open_enote (D3, D4). Tests: round-trip, wrong-key MAC
  reject, tampering (ct / epk / nonce / mac), cross-tag isolation from
  notes.rs, ENoteV1 codec vectors, zeroize on the note key.
- **WP-C builder**: SpendPlanV4 gains per-output recipient note_pk;
  build_zk_spend_v5 fills enc_notes (D4) with the covered sighash (D6);
  negative tests: oversize note, missing note_pk, updated sighash
  vectors.
- **WP-D recovery**: wallet scan path: open every enc_note of a
  confirmed v5 tx with the local note_sk, leaf-match (D2), insert as
  WalletNoteV4 only after full confirmation. End-to-end test: tx bytes
  alone -> second wallet recovers the note (N3 off).
- **WP-E consensus + docs**: confirm_v5_consensus on the covered
  sighash; CHANGELOG / README / S4 7 anchor text; bench smoke (proof
  size and rows unchanged); evidence dump.

## 5. Anchors and open points

- Anchors at freeze: HEAD a901c2351cfa23edc6146c0e356a6d0946d35c36;
  strict pins tx_v4.rs 6c6026877a25b60ffd2af7987ddfb852950623b0c4328476b67c3b8cac678279
  (1748 lines), zk v4.rs e2c17c10509077023cd9eb36eec6100a5b650685fc396ca04e9394659ebca06d
  (1051), consensus v4.rs 110aa4a5fa56e761584f8252176e23cd66ee047a8f2bac6de8f85003b2bf5211
  (1166), spend.rs 78c155f92fbc5449057e4fb9f6bd42b552db0c8d9c0f729ad798045055c60316
  (3434), notes.rs 281b16409b3e65efeea5c7ad40bb382351cdbcb0008d6349ac84d84f89b1eaed
  (793).
- O1: opacus-wallet is assumed to depend on opacus-crypto already
  (keys.rs is its key source) - verify at the WP-B gate before the
  ecies extraction moves files.
- O2: WG-26 sighash_v5 test vectors change in WP-C (documented,
  in-repo, same commit).
- O3: doc drift observation - WG-26 scope R2 says the v5 sighash keeps
  the b"GHOST/v4/sighash" domain with le64(5); the code uses
  b"GHOST/v5/sighash" (spend.rs:285). WG-29 does not change the domain
  string; the WG-26 doc line is stale.
- O4: WP-1 evidence chain (swap.rs removal commit) is still open on
  this repo (recon B recorded the pre-edit lib.rs pin; HEAD a901c23 =
  origin/main). Independent of WG-29; must land before the next
  release tag.