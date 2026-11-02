//! GIP-2 WP-D1 (runbook stage R1): the `dress_voter` bin.
//!
//! One independent process per voter: it reads ONLY the published
//! declaration (`declared.json` in the drop directory), rebuilds the
//! anchored frontier from the rehearsal seed, builds its ballot with
//! the real prover at mainnet depth, verifies it standalone, seals it
//! to the collector key and DROPS the envelope file - the file name is
//! the hex `envelope_id` (the transport dedupe key the v5 gossip uses).
//!
//! Transport and fault flags (the deliberate R1 drop matrix, mirroring
//! the R0 adversarial shape):
//!
//! * `--raw` - publish over the raw fallback instead of an envelope
//!   (documented weaker, P-4);
//! * `--retransmit` - additionally re-drop the same ballot over the raw
//!   fallback: a byte-equal RETRANSMISSION (the collector dedupes it);
//! * `--fault <kind>` (repeatable) - the honest ballot is dropped first,
//!   then the fault drop, so every fault rides on a valid vote exactly
//!   like the R0 matrix:
//!   - `double`       second ballot on the SAME notes (DuplicateSerial);
//!   - `foreign`      valid ballot at `h_open + 1` (ProposalMismatch);
//!   - `relabel`      the foreign envelope with its cleartext tag
//!     patched back to the archive scope (HeaderMismatch);
//!   - `corrupt`      the honest envelope with one flipped MAC byte
//!     (MacMismatch);
//!   - `dust-smuggle` the honest raw wire patched to `v = T_MIN - 1`
//!     (blind ingest accepts; the tally rejects Dust);
//!   - `truncated`    an envelope cut below the minimum length;
//!   - `oversize`     a blob one byte over the profile cap;
//!   - `garbage`      a mislabelled non-envelope blob (raw-path reject).
//!
//! ```sh
//! cargo run -p opacus-wallet --bin dress_voter -- --id 3 \
//!     --choice for --net ./net
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use opacus_wallet::gov::{build_ballot, verify_ballot, Choice, GovBallot, T_MIN};
use opacus_wallet::gov_transport::{
    BallotEnvelope, ENVELOPE_HEADER_LEN, ENVELOPE_MAGIC, ENVELOPE_MIN_SEALED_LEN,
    MAX_ENVELOPE_BYTES,
};
use opacus_wallet::tx_v4::WalletNoteV4;
use opacus_wallet::zk_spend::{fp_to_bytes, TreeState};

#[path = "common.rs"]
mod common;
use common::{
    hex_encode, parse_choice, patch_u64_le, rehearsal_tree, Declaration, DEPTH,
    ENVELOPE_H_OPEN_OFFSET, WIRE_V_OFFSET,
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args) {
        Ok(a) => run(&a),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    }
}

struct Args {
    id: usize,
    choice: String,
    net: PathBuf,
    raw: bool,
    retransmit: bool,
    faults: Vec<String>,
}

const FAULT_KINDS: [&str; 8] = [
    "double",
    "foreign",
    "relabel",
    "corrupt",
    "dust-smuggle",
    "truncated",
    "oversize",
    "garbage",
];

/// The next flag value (the flags are strictly pairwise).
fn next_value<'a, I>(it: &mut I, name: &str) -> Result<String, String>
where
    I: Iterator<Item = &'a String>,
{
    it.next()
        .cloned()
        .ok_or_else(|| format!("{name} needs a value"))
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut a = Args {
        id: usize::MAX,
        choice: String::new(),
        net: PathBuf::from("net"),
        raw: false,
        retransmit: false,
        faults: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--id" => {
                a.id = next_value(&mut it, "--id")?
                    .parse()
                    .map_err(|_| "--id must be a number".to_string())?
            }
            "--choice" => a.choice = next_value(&mut it, "--choice")?,
            "--net" => a.net = PathBuf::from(next_value(&mut it, "--net")?),
            "--raw" => a.raw = true,
            "--retransmit" => a.retransmit = true,
            "--fault" => a.faults.push(next_value(&mut it, "--fault")?),
            other => {
                return Err(format!(
                "unknown flag {other} (supported: --id --choice --net --raw --retransmit --fault)"
            ))
            }
        }
    }
    if a.id == usize::MAX {
        return Err("--id is required".to_string());
    }
    if a.choice.is_empty() {
        return Err("--choice is required (for|against|abstain)".to_string());
    }
    for f in &a.faults {
        if !FAULT_KINDS.contains(&f.as_str()) {
            return Err(format!(
                "unknown fault {f:?} (supported: {})",
                FAULT_KINDS.join(" ")
            ));
        }
    }
    if a.raw && a.faults.iter().any(|f| f == "corrupt") {
        return Err(
            "the corrupt fault rides on the sealed envelope; drop --raw or use another fault"
                .to_string(),
        );
    }
    Ok(a)
}

fn run(a: &Args) {
    let declared_path = a.net.join("declared.json");
    let raw = fs::read(&declared_path).unwrap_or_else(|e| {
        panic!(
            "{} must exist (the declaration is published first): {e}",
            declared_path.display()
        )
    });
    let doc: serde_json::Value = serde_json::from_slice(&raw).expect("declared.json is valid JSON");
    let declared = Declaration::from_json(&doc).expect("declared.json is malformed");
    assert!(
        a.id < declared.voters,
        "voter id {} is outside the declared frontier (voters = {})",
        a.id,
        declared.voters
    );

    // The deterministic frontier, rebuilt from the declaration. A voter
    // whose derivation disagrees with the published anchor aborts - the
    // ballot would not be verifiable against the declared root anyway.
    let (tree, notes) = rehearsal_tree(declared.seed, declared.voters);
    assert_eq!(
        fp_to_bytes(tree.root()),
        fp_to_bytes(declared.anchor),
        "the rebuilt frontier root must equal the declared anchor"
    );

    let choice = parse_choice(&a.choice).expect("a valid choice");
    // The honest ballot: real prover at mainnet depth, verified
    // standalone BEFORE it is dropped.
    let ballot = build_ballot::<DEPTH>(
        &tree,
        &[a.id],
        &[&notes[a.id]],
        declared.gip,
        declared.transition,
        declared.h_open,
        choice,
    )
    .expect("the honest voter ballot must build");
    verify_ballot::<DEPTH>(&ballot).expect("the honest voter ballot must verify standalone");
    let raw_wire = ballot.to_bytes();

    let mut written: Vec<String> = Vec::new();
    if a.raw {
        // Raw fallback only (P-4, documented weaker): the canonical
        // ballot bytes, public before close. Name = blake3 of the wire.
        let name = format!("{}.raw", hex_encode(blake3::hash(&raw_wire).as_bytes()));
        drop_file(&a.net, &name, &raw_wire);
        written.push(name);
    } else {
        let env = BallotEnvelope::seal(&ballot, &declared.collector_pk)
            .expect("sealing to the declared collector key must not fail");
        let wire = env.to_bytes();
        // The file name IS the transport dedupe key (hex envelope_id).
        let name = format!(
            "{}.gbe1",
            hex_encode(&env.envelope_id().expect("well-formed envelope"))
        );
        drop_file(&a.net, &name, &wire);
        written.push(name);
        if a.retransmit {
            // Byte-equal re-drop over the fallback: the same canonical
            // ballot, a second arrival - the collector must dedupe it.
            let name = format!("{}.raw", hex_encode(blake3::hash(&raw_wire).as_bytes()));
            drop_file(&a.net, &name, &raw_wire);
            written.push(name);
        }
        // The fault drops (each rides on the honest ballot, R0 shape).
        for kind in &a.faults {
            written.push(drop_fault(
                a, kind, &declared, &tree, &notes, choice, &env, &raw_wire,
            ));
        }
    }

    println!(
        "voter {} ({choice:?}, v={} atoms, transport={}): dropped {} file(s) into {}",
        a.id,
        notes[a.id].value,
        if a.raw { "raw-fallback" } else { "sealed-gbe1" },
        written.len(),
        a.net.display()
    );
    for w in &written {
        println!("  {w}");
    }
}

/// Write one drop into the net directory (the whole serialization
/// boundary of stage R1: bytes on disk, named by their dedupe key).
fn drop_file(net: &Path, name: &str, bytes: &[u8]) {
    let path = net.join(name);
    fs::write(&path, bytes).unwrap_or_else(|e| panic!("{} must be writable: {e}", path.display()));
}

/// The deliberate fault drops, byte-exact injections like the R0 matrix.
#[allow(clippy::too_many_arguments)]
fn drop_fault(
    a: &Args,
    kind: &str,
    declared: &Declaration,
    tree: &TreeState,
    notes: &[WalletNoteV4],
    honest_choice: Choice,
    honest_env: &BallotEnvelope,
    honest_raw: &[u8],
) -> String {
    match kind {
        // A second ballot on the SAME notes: the serials are
        // choice-independent (R-3), the wire differs only in the choice
        // and the blinding, the tally must surface DuplicateSerial.
        "double" => {
            let flip = match honest_choice {
                Choice::For => Choice::Against,
                Choice::Against | Choice::Abstain => Choice::For,
            };
            let second = build_ballot::<DEPTH>(
                tree,
                &[a.id],
                &[&notes[a.id]],
                declared.gip,
                declared.transition,
                declared.h_open,
                flip,
            )
            .expect("the double-vote ballot builds (the proof is valid)");
            seal_and_drop(
                &a.net,
                &second,
                &declared.collector_pk,
                "fault-double",
                a.id,
            )
        }
        // A VALID ballot minted at h_open + 1, sealed to the right
        // collector key: the archive scope gate rejects it before
        // opening (cheap bucket routing, P-4).
        "foreign" => {
            let foreign = foreign_ballot(a, declared, tree, notes);
            seal_and_drop(
                &a.net,
                &foreign,
                &declared.collector_pk,
                "fault-foreign",
                a.id,
            )
        }
        // The foreign envelope with its cleartext h_open patched back to
        // the archive scope: the scope gate passes, the header match
        // AFTER opening fails closed (the WP-3 relabelling guard).
        "relabel" => {
            let foreign = foreign_ballot(a, declared, tree, notes);
            let mut wire = BallotEnvelope::seal(&foreign, &declared.collector_pk)
                .expect("sealing must not fail")
                .to_bytes();
            patch_u64_le(&mut wire, ENVELOPE_H_OPEN_OFFSET, declared.h_open);
            let name = format!("fault-relabel-{}.gbe1", a.id);
            drop_file(&a.net, &name, &wire);
            name
        }
        // One flipped MAC byte on the honest envelope: parse ok, open
        // fails (MacMismatch).
        "corrupt" => {
            let mut wire = honest_env.to_bytes();
            let last = wire.len() - 1;
            wire[last] ^= 0x01;
            let name = format!("fault-corrupt-{}.gbe1", a.id);
            drop_file(&a.net, &name, &wire);
            name
        }
        // The honest raw wire patched to v = T_MIN - 1: the blind raw
        // fallback accepts (it verifies nothing by design), the tally
        // surfaces Malformed(Dust) before the ZK work (P-2 gate order).
        "dust-smuggle" => {
            let mut smuggled = honest_raw.to_vec();
            patch_u64_le(&mut smuggled, WIRE_V_OFFSET, T_MIN - 1);
            let name = format!("fault-dust-{}.raw", a.id);
            drop_file(&a.net, &name, &smuggled);
            name
        }
        // One byte below the minimum envelope length.
        "truncated" => {
            let short = &honest_env.to_bytes()[..ENVELOPE_HEADER_LEN + ENVELOPE_MIN_SEALED_LEN - 1];
            let name = format!("fault-truncated-{}.gbe1", a.id);
            drop_file(&a.net, &name, short);
            name
        }
        // One byte over the profile cap, shaped as a REAL envelope (the
        // GBE1 magic prefix): the blind router parses it as an envelope
        // and the profile gate rejects it (Oversize).
        "oversize" => {
            let mut big = vec![0u8; MAX_ENVELOPE_BYTES + 1];
            big[..ENVELOPE_MAGIC.len()].copy_from_slice(&ENVELOPE_MAGIC);
            let name = format!("fault-oversize-{}.gbe1", a.id);
            drop_file(&a.net, &name, &big);
            name
        }
        // A mislabelled blob: envelope extension, no envelope inside -
        // the raw-path parse rejects it, the event log records it.
        "garbage" => {
            let junk = common::domain_bytes(declared.seed, "garbage-drop", a.id);
            let name = format!("fault-garbage-{}.gbe1", a.id);
            drop_file(&a.net, &name, &junk);
            name
        }
        other => unreachable!("validated fault kind: {other}"),
    }
}

/// The foreign-scope ballot shared by the `foreign` and `relabel` faults.
fn foreign_ballot(
    a: &Args,
    declared: &Declaration,
    tree: &TreeState,
    notes: &[WalletNoteV4],
) -> GovBallot {
    let h_foreign = declared
        .h_open
        .checked_add(1)
        .expect("h_open + 1 overflows");
    build_ballot::<DEPTH>(
        tree,
        &[a.id],
        &[&notes[a.id]],
        declared.gip,
        declared.transition,
        h_foreign,
        Choice::Abstain,
    )
    .expect("the foreign-scope ballot builds")
}

fn seal_and_drop(
    net: &Path,
    ballot: &GovBallot,
    pk: &opacus_crypto::CompressedRistretto,
    stem: &str,
    id: usize,
) -> String {
    let env = BallotEnvelope::seal(ballot, pk).expect("sealing must not fail");
    let name = format!("{stem}-{id}.gbe1");
    drop_file(net, &name, &env.to_bytes());
    name
}
