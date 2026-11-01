//! WG-CLSAG WP-B fixture-driven acceptance tests
//! (docs/WG-CLSAG-verify-scope.md, section 6).
//!
//! Ground truth is REAL mainnet monerod data: tx
//! `43bd6f459b84f14162143e28c83a0fd1d58cb8e4c328070fa79ca198a0c79a23`
//! (height 3796485, RCTTypeBulletproofPlus, 2 inputs, ring size 16),
//! captured as unpruned tx hex plus the ring member one-time keys and
//! amount commitments resolved via get_outs over the absolute key_offsets.
//! Any drift from monerod behavior breaks these tests — they are the
//! acceptance gate.

use opacus_bridge::clsag_verify::{
    pre_mlsag_hash, verify_clsag, verify_tx, MoneroTx, ParseError, RingMember,
};

const FIXTURE: &str = include_str!("fixtures/clsag_mainnet_v1.json");

fn k32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).expect("fixture hex");
    assert_eq!(v.len(), 32, "fixture hex field must be 32 bytes");
    v.try_into().unwrap()
}

fn load_fixture() -> (serde_json::Value, Vec<u8>, MoneroTx) {
    let fx: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture json");
    let blob = hex::decode(fx["tx_hex"].as_str().expect("tx_hex")).expect("tx hex");
    let tx = MoneroTx::parse(&blob).expect("fixture tx must parse");
    (fx, blob, tx)
}

fn rings_from(fx: &serde_json::Value) -> Vec<Vec<RingMember>> {
    fx["inputs"]
        .as_array()
        .expect("inputs")
        .iter()
        .map(|inp| {
            inp["outs"]
                .as_array()
                .expect("outs")
                .iter()
                .map(|o| RingMember {
                    dest: k32(o["key"].as_str().expect("key")),
                    mask: k32(o["mask"].as_str().expect("mask")),
                })
                .collect()
        })
        .collect()
}

/// 6.3 parse_fixture_roundtrip: per-input s/c1/D and pseudoOuts counts
/// match the ring size and the input count; the parsed tx re-serializes to
/// the exact fixture bytes; the parsed tx hash matches the fixture record;
/// our absolute-offset decoding matches the capture pipeline.
#[test]
fn parse_fixture_roundtrip() {
    let (fx, blob, tx) = load_fixture();
    let n_inputs = fx["expected"]["inputs"].as_u64().unwrap() as usize;
    let ring_size = fx["expected"]["ring_size"].as_u64().unwrap() as usize;

    assert_eq!(tx.version, 2);
    assert_eq!(tx.rct_type, fx["rct_type"].as_u64().unwrap() as u8);
    assert_eq!(tx.vin.len(), n_inputs);
    assert_eq!(tx.clsags.len(), n_inputs);
    assert_eq!(tx.pseudo_outs.len(), n_inputs);
    assert_eq!(tx.out_pks.len(), tx.vout.len());
    assert_eq!(tx.ecdh_amounts.len(), tx.vout.len());
    for (i, clsag) in tx.clsags.iter().enumerate() {
        assert_eq!(clsag.s.len(), ring_size, "input {i} s len");
    }
    // key image reconstruction: vin[i].k_image is the CLSAG I
    for (i, vin) in tx.vin.iter().enumerate() {
        assert_eq!(
            hex::encode(vin.k_image),
            fx["inputs"][i]["k_image"].as_str().unwrap(),
            "input {i} k_image"
        );
    }
    // byte-compat pin (section 6.4): parsed tx re-serializes to the exact
    // fixture blob
    assert_eq!(tx.re_serialize(), blob, "full tx re-serialization");
    // the rct base slice starts right after the prefix and is exactly what
    // get_pre_mlsag_hash hashes second
    assert!(!tx.rct_base_bytes().is_empty());
    assert_eq!(
        &blob[..tx.prefix_bytes().len() + tx.rct_base_bytes().len()],
        {
            let mut head = tx.prefix_bytes().to_vec();
            head.extend_from_slice(tx.rct_base_bytes());
            head
        }
    );
    // parsed tx hash matches the captured hash
    assert_eq!(hex::encode(tx.tx_hash()), fx["tx_hash"].as_str().unwrap());
    // absolute offsets match the capture pipeline's prefix sums
    for (i, vin) in tx.vin.iter().enumerate() {
        let expected: Vec<u64> = fx["inputs"][i]["key_offsets_absolute"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();
        let mut acc = 0u64;
        let absolute: Vec<u64> = vin
            .key_offsets
            .iter()
            .map(|d| {
                acc += d;
                acc
            })
            .collect();
        assert_eq!(absolute, expected, "input {i} absolute offsets");
    }
}

/// 6.3 verify_fixture_accepts: the verClsag-equivalent accepts every input
/// of the honest mainnet tx.
#[test]
fn verify_fixture_accepts() {
    let (fx, _blob, tx) = load_fixture();
    let rings = rings_from(&fx);
    assert!(verify_tx(&tx, &rings), "honest mainnet tx must verify");

    // per-input verdicts too
    let message = pre_mlsag_hash(&tx);
    for (i, verdict) in fx["expected"]["verdicts"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        assert!(verdict.as_bool().unwrap());
        assert!(
            verify_clsag(
                &message,
                &tx.clsags[i],
                &tx.vin[i].k_image,
                &rings[i],
                &tx.pseudo_outs[i]
            ),
            "input {i} must verify"
        );
    }
}

/// Flip one bit inside a parsed tx field, re-serialize, re-parse and verify.
fn verify_tampered(
    tx: &MoneroTx,
    rings: &[Vec<RingMember>],
    mutate: impl Fn(&mut MoneroTx),
) -> bool {
    let mut t = tx.clone();
    mutate(&mut t);
    let blob = t.re_serialize();
    match MoneroTx::parse(&blob) {
        Ok(parsed) => verify_tx(&parsed, rings),
        Err(_) => false, // structural reject is a reject
    }
}

/// 6.3 tamper_rejected: flipping one bit in s, c1, I (k_image), D, the
/// pseudo-out or one ring member breaks verification — matrix over all
/// inputs.
#[test]
fn tamper_rejected() {
    let (fx, _blob, tx) = load_fixture();
    let rings = rings_from(&fx);
    let n_inputs = tx.vin.len();
    let ring_size = tx.clsags[0].s.len();

    for i in 0..n_inputs {
        // s: first and last scalar of every input
        assert!(
            !verify_tampered(&tx, &rings, |t| {
                t.clsags[i].s[0][11] ^= 0x10;
            }),
            "input {i}: tampered s[0] accepted"
        );
        assert!(
            !verify_tampered(&tx, &rings, |t| {
                t.clsags[i].s[ring_size - 1][7] ^= 0x01;
            }),
            "input {i}: tampered s[last] accepted"
        );
        // c1
        assert!(
            !verify_tampered(&tx, &rings, |t| {
                t.clsags[i].c1[5] ^= 0x80;
            }),
            "input {i}: tampered c1 accepted"
        );
        // D
        assert!(
            !verify_tampered(&tx, &rings, |t| {
                t.clsags[i].d[9] ^= 0x02;
            }),
            "input {i}: tampered D accepted"
        );
        // I (key image comes from vin)
        assert!(
            !verify_tampered(&tx, &rings, |t| {
                t.vin[i].k_image[13] ^= 0x04;
            }),
            "input {i}: tampered k_image accepted"
        );
        // pseudo-out commitment offset
        assert!(
            !verify_tampered(&tx, &rings, |t| {
                t.pseudo_outs[i][3] ^= 0x20;
            }),
            "input {i}: tampered pseudoOut accepted"
        );
        // one ring member: dest and mask legs
        let mut r = rings.clone();
        r[i][1].dest[7] ^= 0x08;
        assert!(
            !verify_tx(&tx, &r),
            "input {i}: tampered ring dest accepted"
        );
        let mut r = rings.clone();
        r[i][2].mask[17] ^= 0x40;
        assert!(
            !verify_tx(&tx, &r),
            "input {i}: tampered ring mask accepted"
        );
    }

    // range-proof data feeds the message: flipping it must break everything
    let bp_field = if tx.rct_type == opacus_bridge::RCT_TYPE_BULLETPROOF_PLUS {
        "bulletproofs_plus"
    } else {
        "bulletproofs"
    };
    let mut t = tx.clone();
    match bp_field {
        "bulletproofs_plus" => t.bulletproofs_plus[0].l[0][7] ^= 0x10,
        _ => t.bulletproofs[0].l[0][7] ^= 0x10,
    }
    let blob = t.re_serialize();
    let parsed = MoneroTx::parse(&blob).expect("bp tamper stays parseable");
    assert!(!verify_tx(&parsed, &rings), "tampered bulletproof accepted");
}

/// 6.3 ring_substitution_rejected: swapping one decoy for another real
/// chain output (the captured spare outputs) breaks verification, and so
/// does swapping members between the two input rings.
#[test]
fn ring_substitution_rejected() {
    let (fx, _blob, tx) = load_fixture();
    let mut rings = rings_from(&fx);

    // substitute input 0's decoy #3 with a real spare chain output
    let spare_key = k32(fx["spare_outs"][0]["key"].as_str().unwrap());
    let spare_mask = k32(fx["spare_outs"][0]["mask"].as_str().unwrap());
    rings[0][3] = RingMember {
        dest: spare_key,
        mask: spare_mask,
    };
    assert!(!verify_tx(&tx, &rings), "spare substitution accepted");

    // and input 1's decoy #7 with the second spare
    let spare2_key = k32(fx["spare_outs"][1]["key"].as_str().unwrap());
    let spare2_mask = k32(fx["spare_outs"][1]["mask"].as_str().unwrap());
    rings[1][7] = RingMember {
        dest: spare2_key,
        mask: spare2_mask,
    };
    assert!(!verify_tx(&tx, &rings), "spare substitution accepted");

    // swap ring members between the two inputs
    let mut rings = rings_from(&fx);
    let (left, right) = rings.split_at_mut(1);
    std::mem::swap(&mut left[0][5], &mut right[0][5]);
    assert!(!verify_tx(&tx, &rings), "cross-input swap accepted");
}

/// 6.3 non_canonical_scalar_rejected: any s_i >= l rejected pre-crypto.
#[test]
fn non_canonical_scalar_rejected() {
    let (fx, _blob, tx) = load_fixture();
    let rings = rings_from(&fx);
    // curve order l, little-endian
    let l_bytes: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let mut t = tx.clone();
    t.clsags[0].s[0] = l_bytes;
    let blob = t.re_serialize();
    let parsed = MoneroTx::parse(&blob).expect("scalar bytes do not affect parseability");
    assert!(!verify_tx(&parsed, &rings), "s_i >= l accepted");

    let mut t = tx.clone();
    t.clsags[1].c1 = l_bytes;
    let blob = t.re_serialize();
    let parsed = MoneroTx::parse(&blob).expect("scalar bytes do not affect parseability");
    assert!(!verify_tx(&parsed, &rings), "c1 >= l accepted");
}

/// 6.3 buffer_exactly_consumed: trailing or missing signature bytes are a
/// parse error.
#[test]
fn buffer_exactly_consumed() {
    let (_fx, blob, _tx) = load_fixture();

    let mut trailing = blob.clone();
    trailing.push(0x00);
    assert!(matches!(
        MoneroTx::parse(&trailing),
        Err(ParseError::TrailingBytes)
    ));

    assert!(matches!(
        MoneroTx::parse(&blob[..blob.len() - 1]),
        Err(ParseError::UnexpectedEof)
    ));
    assert!(matches!(
        MoneroTx::parse(&blob[..blob.len() - 32]),
        Err(ParseError::UnexpectedEof)
    ));
}
