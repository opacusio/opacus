//! GIP-2 WP-2 sync guard: the tally engine's public quorum denominator
//! (`opacus_wallet::tally::emission_upto`, the P-5
//! `sum(block_reward(0..H_snap))`) MUST equal a naive sum of the
//! consensus schedule. The wallet crate cannot depend on consensus
//! without a dependency cycle (consensus already depends on the
//! wallet), so the two implementations live apart and this test pins
//! them together. An emission-schedule change is a Standards Track GIP
//! (GIP-2 R-7) and MUST touch both files.

use opacus_consensus::block_reward;

#[test]
fn tally_denominator_matches_consensus_schedule() {
    let heights = [
        0u64, 1, 2, 100, 209_999, 210_000, 210_001, 419_999, 420_000, 421_337, 629_999, 630_000,
        630_001, 1_000_000, 2_100_000, 4_000_000, 7_140_000,
    ];
    for &h in &heights {
        let naive: u64 = (0..h).map(block_reward).sum();
        assert_eq!(
            opacus_wallet::tally::emission_upto(h),
            naive,
            "denominator mismatch at h={h}"
        );
    }
}
