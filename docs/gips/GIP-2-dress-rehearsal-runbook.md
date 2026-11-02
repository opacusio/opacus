# GIP-2 dress rehearsal runbook (P-9, WP-D)

Status: plan (this document). The voting core is delivered (WP-1
builder `1691d80`, WP-2 tally `b6cda40`, WP-3 transport `89d5ab7`);
this runbook pins the staged path from "all library parts exist" to
"the first real vote is rehearsed on testnet" - the last P-9 item.

Every stage has an executable definition of done. Stages R0 and R1
need only new harness code in opacus-wallet; no node changes. Stages
R2/R3 touch the CLI/daemon and are explicitly separated so that node
plumbing never blocks protocol rehearsal.

## 0. Ground truth: what exists and what is missing

Exists (library-complete, tested):

| Part | Where | Notes |
| --- | --- | --- |
| Ballot builder | `opacus_wallet::gov::build_ballot::<DEPTH>` | v4 notes + tree frontier -> `GovBallot`, ZK DOM_VS |
| Ballot verify | `gov::verify_ballot`, `verify_ballot_against_tree` | T_MIN dust gate before ZK |
| Tally engine | `tally::tally::<DEPTH, A>(&DeclaredProposal, &[A])` | canonical order, trace, `result_hash` order-invariant |
| Decision rule | `tally::decide` | pure P-6 |
| Transport | `gov_transport::{BallotEnvelope, BallotArchive}` | GBE1 sealed + raw fallback, blind minutes, `archive_id` arrival-ordered |
| Collector key | `gov_transport::ballot_keypair_from_seed(&[u8;64]) -> NoteSecret` | `.public() -> CompressedRistretto` |
| Constants | `T_MIN = 1_000_000`, `MAX_BALLOT_NOTES`, `DEPTH = 32` | as in gov tests |

Missing (becomes the WP-D work items, section 7):

- No end-to-end driver: every part is exercised by unit tests, no
  artifact-producing rehearsal run.
- CLI `ghost start` hardcodes `DaemonConfig::default()`
  (`network: "mainnet"`); `select_consensus` accepts both strings but
  the CLI has no `--network` flag yet.
- `OpacusDaemon::run()` is a heartbeat loop (no chain service, no
  RPC surface beyond the log line) - full-node gov rehearsal needs
  real node work regardless.
- LightWallet has no gov bridge: scan produces wallet notes, not the
  `WalletNoteV4` + frontier pair `build_ballot` consumes.
- No gossip envelope channel (deferred by design in the WP-3 note).

## 1. Stage R0 - deterministic in-process rehearsal (executable NOW)

Goal: one command that runs the WHOLE protocol against a synthetic
frontier with the real prover and records the close artifacts.

Work item: `crates/opacus-wallet/examples/dress_rehearsal.rs`
(WP-D0).

Target command:

```sh
cargo run -p opacus-wallet --example dress_rehearsal -- \
    --voters 7 --seed 42 --out artifacts/
```

Script (deterministic in `--seed`):

1. Build `TreeState::<32>`; append one `WalletNoteV4::random(v_i)`
   per voter (values mixed above/below `T_MIN` on purpose).
2. Declare the proposal: `gip = 2, transition = 0, h_open = 100`,
   `anchor = tree.root()`, `class = VoteClass::Fund`.
3. Derive the collector key: `ballot_keypair_from_seed(seed)`; write
   the declaration (`declared.json`: gip, transition, h_open, anchor
   hex, class, collector pk hex).
4. Per voter: `build_ballot` -> `verify_ballot` ->
   `BallotEnvelope::seal(&b, &collector_pk)` -> `to_bytes()` ->
   `archive.ingest_sealed(...)`. Voter 0 additionally publishes the
   RAW fallback (`ingest_raw`) of the same ballot - the two paths
   must feed the tally identically.
5. Adversarial matrix (all must appear in the trace, none fatal):
   byte-equal retransmission (Retransmission), a double vote
   (second ballot on the same notes -> DuplicateSerial), a dust
   ballot (v < T_MIN -> Dust), a foreign-scope envelope (wrong
   h_open -> HeaderMismatch), an oversized envelope -> Oversize, a
   corrupted envelope byte -> MacMismatch/Truncated.
6. `tally::<32>(&declared, archive.entries())` + `decide(...)`;
   assert the trace covers every injected case; shuffle the archive
   and re-tally: SAME `result_hash`, DIFFERENT `archive_id`.
7. Write `minutes.json` (entries + per-ballot trace + record wire
   hex) and `golden-vectors.json` (result_hash, archive_id, totals,
   outcome).

Definition of done: exit 0; golden files committed under
`crates/opacus-wallet/tests/vectors/`; a `#[test]` replays them;
CI 4/4.

## 2. Stage R1 - two-process rehearsal over a drop directory

Goal: exercise the real serialization boundaries (files, not fn
calls) with zero node work. The transport profile is
transport-agnostic by design; a shared directory stands in for the
network and proves the byte paths.

Work items: split the harness into three small bins (WP-D1):
`dress_voter`, `dress_collector`, `dress_auditor`.

```sh
# 1. The declaration is published first (collector pk inside).
cargo run -p opacus-wallet --bin dress_collector -- declare \
    --gip 2 --transition 0 --h-open 100 --net ./net

# 2. Independent voter processes seal and drop envelopes; the file
#    name is the hex envelope_id (transport dedupe key).
cargo run -p opacus-wallet --bin dress_voter -- --id 3 \
    --choice for   --net ./net
cargo run -p opacus-wallet --bin dress_voter -- --id 4 \
    --choice against --net ./net
# ... plus one deliberate raw-drop and one retransmission drop.

# 3. The collector ingests EVERYTHING in the directory (blind
#    minutes: undecryptable/oversized/mislabelled drops are logged
#    as failed events in minutes.json, never silently dropped),
#    tallies at close and publishes.
cargo run -p opacus-wallet --bin dress_collector -- close \
    --net ./net --minutes ./net/minutes.json

# 4. Any third party replays the minutes independently.
cargo run -p opacus-wallet --bin dress_auditor \
    --minutes ./net/minutes.json
```

Definition of done: the auditor recomputes `result_hash` and
`archive_id` from the published minutes and matches the collector's
close statement; a tampered minutes file (one flipped byte) is
rejected.

## 3. Stage R2 - single-node testnet smoke (build/run surface)

Goal: prove the node bins build, boot and mine on the testnet
parameter set. This is NOT a gov rehearsal: `daemon.run()` is a
heartbeat stub today; the stage pins the launch surface and its
gaps.

Work item: CLI `--network` flag (WP-D2a, tiny).

```sh
cargo build --release -p opacus-cli
./target/release/ghost start --network testnet   # p2p 18080
./target/release/ghost mine --solo --duration-secs 300
./target/release/ghost create-wallet && ./target/release/ghost address
```

Note: pre-mainnet `select_consensus` maps BOTH network strings to
the single (testnet) parameter set - v4 active from genesis, zero
fee floor. Record in the stage log: daemon boot OK, p2p listener
bound, miner hash rate, wallet create/sync.

Definition of done: the three commands above run cleanly in a fresh
`data_dir`; the gap list (chain service, RPC) is re-confirmed in the
stage notes.

## 4. Stage R3 - full gov rehearsal on the testnet (the P-9 gate)

Goal: the real thing. N nodes peering, M wallets voting with notes
that actually live in the wallet, envelopes over the v5 gossip
channel, a collector service, published minutes, independent
replay.

Work items (each independently gated, in order):

- **WP-D2b wallet-gov bridge**: expose the synced frontier +
  `WalletNoteV4` set at `h_open` from LightWallet so
  `build_ballot` consumes wallet-real inputs (snapshot at the
  declared height; notes confirmed after H_open carry no weight).
- **WP-D2c gossip envelope channel**: carry GBE1 frames on the v5
  note path with `envelope_id` dedupe (exactly the WP-3 delivery
  note deferral).
- **WP-D2d collector service**: ingest endpoint + archive + close +
  publish (reuses `BallotArchive` verbatim; no new crypto).

Scenario (scripted, timestamps logged):

1. Bring up N=3 nodes (`ghost start --network testnet`), mine past
   `H_open`.
2. The maintainer publishes `declared.json` (proposal + anchor +
   collector pk).
3. M=5 wallets vote: 3 FOR, 1 AGAINST, 1 ABSTAIN (one wallet votes
   twice on the same notes - must surface as DuplicateSerial in the
   trace).
4. One wallet uses the raw fallback (published weaker by design).
5. At close the collector publishes `minutes.json` +
   `archive_id` + `result_hash`.
6. Every participant (and one offline auditor) replays.

Definition of done: replay result_hash equality everywhere, the
trace shows every injected fault, no node crash, and the whole run
is reproducible from the logs + artifacts.

## 5. Stage R4 - independent audit/replay (standing gate)

The `dress_auditor` path becomes the permanent acceptance tool for
ANY future real vote: given `declared.json` + published minutes, it
recomputes both fingerprints and re-runs `decide`. Golden vectors
from R0 keep the engine byte-pinned in CI.

## 6. Acceptance checklist (per stage, all mandatory)

- `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, full workspace tests green.
- New code ships with tests; harness output committed as artifacts.
- the secret scan (grep the committed HEAD tree for the GitHub PAT
  prefix, `g h p _` without spaces) has zero matches before every
  push; run it AFTER the commit, against HEAD itself.
- CI 4/4 (cargo-deny, RustSec, Rust workspace, Foundry) on every
  pushed stage commit.
- Stage notes appended to the GIP-2 delivery section (P-9 line)
  with the commit hash and the artifact hashes.

## 7. Work item summary

| ID | Deliverable | Size |
| --- | --- | --- |
| WP-D0 | `examples/dress_rehearsal.rs` + golden vectors + replay test | small |
| WP-D1 | `dress_voter` / `dress_collector` / `dress_auditor` bins | small |
| WP-D2a | CLI `--network` flag | tiny |
| WP-D2b | wallet-gov bridge (frontier + v4 notes at h_open) | medium |
| WP-D2c | v5 gossip envelope channel + id dedupe | medium |
| WP-D2d | collector service (ingest/close/publish) | medium |
