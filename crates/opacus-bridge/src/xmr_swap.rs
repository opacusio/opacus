//! XMR <-> GHOST atomic swap protocol (v0.1 coordination layer).
//!
//! Direction: the Maker sells native GHOST and buys XMR; the Taker sells
//! XMR and buys GHOST.
//!
//! Flow (heights are provided by the caller - block heights of the two
//! chains are tracked out of band for now):
//!
//! ```text
//!  Offered      : maker publishes Offer {hashlock, amounts, timeouts}
//!                  plus the WG-21 one-time key sidecar (P, I) on the Frame
//!  Accepted     : taker accepts; accepted_height recorded
//!  XmrLocked    : taker's monero-wallet-rpc transfer with
//!                 payment_id = hashlock, unlock_time = fund timeout
//!  GhostLocked  : maker burns a zk note into the bridge pool, publishing
//!                 the hashlock; the DLEq proof binds their XMR identity
//!  Claimed      : taker reveals preimage to claim GHOST; maker uses the
//!                 revealed preimage to claim the XMR
//!  Refunded     : either side refunds after its timeout expired
//! ```
//!
//! WG-26 landed the hashlock in-circuit (lock / claim / refund modes of the
//! v4 spend) and WG-27 made CLAIM / REFUND a deterministic function of chain
//! state. WG-CLSAG-adaptor-int completes the Monero side: the taker
//! pre-signs the claim spend of the locked XMR as a monerod-compatible CLSAG
//! adaptor ([`XmrClaimAdaptor`], on top of
//! [`crate::clsag_adaptor::sign_adaptor`]) bound to the swap secret
//! [`swap_secret`] derived from the preimage; the maker completes it with
//! his own preimage and the result passes the UNMODIFIED monerod-compatible
//! `verify_clsag` - the Monero-side counterpart of the WG-26 in-circuit
//! hashlock proof. Normative reference: docs/WG-CLSAG-adaptor-int-scope.md.

use blake3::Hasher;
use curve25519_dalek::scalar::Scalar;

use crate::clsag_adaptor::{complete, sign_adaptor, verify_adaptor, ClsagAdaptorSig};
use crate::clsag_verify::{
    decompress_point, hash_to_p3, hash_to_scalar, verify_clsag, ClsagSig, RingMember,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Sells GHOST, buys XMR.
    Maker,
    /// Sells XMR, buys GHOST.
    Taker,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Offered,
    Accepted,
    XmrLocked,
    GhostLocked,
    Claimed,
    Refunded,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SwapError {
    WrongPhase,
    WrongRole,
    BadPreimage,
    NotTimedOut,
    ZeroAmount,
    TimeoutNotPositive,
    /// WG-CLSAG-adaptor-int: the session has no stored preimage (the
    /// maker-side claim completion needs his own preimage).
    MissingPreimage,
    /// WG-CLSAG-adaptor-int: the Monero-side claim adaptor is invalid
    /// (structural, verification, preimage binding or monerod acceptance
    /// failed) or absent where required.
    XmrClaimInvalid,
}

// ---------------------------------------------------------------------------
// WG-CLSAG-adaptor-int: the Monero-side claim adaptor
// ---------------------------------------------------------------------------

const SWAP_SECRET_TAG: &[u8] = b"ghost-bridge/swap-secret-v1";
const SWAP_CLAIM_MSG_TAG: &[u8] = b"ghost-swap/xmr-claim-msg-v1";

/// The swap secret `t` bound into the Monero-side claim adaptor:
/// `hash_to_scalar("ghost-bridge/swap-secret-v1" || preimage)`. Reduced mod
/// l by the monerod `hash_to_scalar`, so the encoding is always a canonical
/// scalar (a raw blake3 digest would be non-canonical for ~2.7% of
/// preimages and `complete` would reject honest completions).
/// Domain-separated from the hashlock (`ghost-swap-hashlock-v1`) and the
/// WG-21 offer OTK (`ghost-bridge/offer-otk-v1`).
pub fn swap_secret(preimage: &[u8; 32]) -> [u8; 32] {
    let mut buf = SWAP_SECRET_TAG.to_vec();
    buf.extend_from_slice(preimage);
    hash_to_scalar(&buf).to_bytes()
}

/// The bilateral claim-tx binding: the pre-signature is only valid for the
/// claim of THIS swap (the offer id already binds the full offer payload).
pub fn swap_claim_message(offer_id: &[u8; 32], hashlock: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(SWAP_CLAIM_MSG_TAG);
    h.update(offer_id);
    h.update(hashlock);
    h.finalize().into()
}

/// Protocol-level record of the taker's pre-signed Monero claim: the
/// monerod-compatible CLSAG adaptor plus everything a verifier needs
/// (ring, key image, Pedersen offset). Bilateral off-chain data; the wire
/// hex form lives in [`crate::swap_p2p::XmrClaimSidecar`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmrClaimAdaptor {
    /// The CLSAG adaptor (pre-signature section + T / T_h / R_G / R_H / di).
    pub adaptor: ClsagAdaptorSig,
    /// The ring (decoys chosen by the taker; ring[di].dest = the locked
    /// one-time output P = [x]G).
    pub ring: Vec<RingMember>,
    /// Key image I = [x]Hp(P) of the claimed output.
    pub key_image: [u8; 32],
    /// Pedersen offset C_offset (the commitment structure is caller data,
    /// exactly as in the WP-B synthetic model).
    pub c_offset: [u8; 32],
}

impl XmrClaimAdaptor {
    /// Taker-side builder: pre-sign the claim spend of the locked one-time
    /// output (spend key `x`, ring[di].dest = [x]G, blinding difference `z`
    /// with [mask_di] - [C_offset] = [z]G) bound to the swap secret
    /// [`swap_secret`]` (preimage)` and the claim message
    /// [`swap_claim_message`]`(offer_id, hashlock)`. Self-checking: the
    /// built adaptor must pass `verify_adaptor` before it is returned.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        spend_key: &[u8; 32],
        blinding: &[u8; 32],
        preimage: &[u8; 32],
        offer_id: &[u8; 32],
        hashlock: &[u8; 32],
        ring: Vec<RingMember>,
        c_offset: [u8; 32],
        di: usize,
    ) -> Result<Self, SwapError> {
        let t = swap_secret(preimage);
        let message = swap_claim_message(offer_id, hashlock);
        let adaptor = sign_adaptor(spend_key, blinding, &t, &message, &ring, &c_offset, di)
            .map_err(|_| SwapError::XmrClaimInvalid)?;
        let dest = decompress_point(&ring[di].dest).ok_or(SwapError::XmrClaimInvalid)?;
        let key_image = (Scalar::from_bytes_mod_order(*spend_key)
            * hash_to_p3(&dest.compress().to_bytes()))
        .compress()
        .to_bytes();
        if !verify_adaptor(&adaptor, &message, &key_image, &ring, &c_offset) {
            return Err(SwapError::XmrClaimInvalid);
        }
        Ok(Self {
            adaptor,
            ring,
            key_image,
            c_offset,
        })
    }

    /// Verify the claim adaptor against THIS swap: the message must be the
    /// bilateral claim binding and the monerod-compatible adaptor checks
    /// (challenge chain + L'/R' binding equations) must hold.
    pub fn verify_for(&self, offer_id: &[u8; 32], hashlock: &[u8; 32]) -> bool {
        let message = swap_claim_message(offer_id, hashlock);
        verify_adaptor(
            &self.adaptor,
            &message,
            &self.key_image,
            &self.ring,
            &self.c_offset,
        )
    }

    /// Maker-side completion with the preimage: `complete` enforces the
    /// preimage binding ([t]G == T with t = [`swap_secret`]` (preimage)`)
    /// and the result must pass the UNMODIFIED monerod-compatible
    /// `verify_clsag` - the acceptance gate. Fail-closed: any failure is
    /// [`SwapError::XmrClaimInvalid`].
    pub fn complete_for(
        &self,
        preimage: &[u8; 32],
        offer_id: &[u8; 32],
        hashlock: &[u8; 32],
    ) -> Result<ClsagSig, SwapError> {
        let message = swap_claim_message(offer_id, hashlock);
        let t = swap_secret(preimage);
        let full = complete(&self.adaptor, &t).map_err(|_| SwapError::XmrClaimInvalid)?;
        if !verify_clsag(&message, &full, &self.key_image, &self.ring, &self.c_offset) {
            return Err(SwapError::XmrClaimInvalid);
        }
        Ok(full)
    }
}

/// A swap offer, serializable for out-of-band exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    // WG-21: the one-time key binding (P, I) travels on the Frame sidecar
    // (swap_p2p::OfferAdaptor), not here - offer ids stay v1-stable.
    /// XMR amount in piconero (1e12).
    pub xmr_piconero: u64,
    /// GHOST amount in atoms.
    pub ghost_atoms: u64,
    /// 32-byte hashlock: blake3(preimage).
    pub hashlock: [u8; 32],
    /// Blocks the taker has to lock XMR after acceptance.
    pub fund_timeout_blocks: u64,
    /// Blocks both sides have to finish after both locks are in.
    pub claim_timeout_blocks: u64,
    pub maker_ghost_address: String,
    pub taker_xmr_address: String,
}

impl Offer {
    pub fn new(
        xmr_piconero: u64,
        ghost_atoms: u64,
        fund_timeout_blocks: u64,
        claim_timeout_blocks: u64,
        maker_ghost_address: impl Into<String>,
        taker_xmr_address: impl Into<String>,
        preimage: &[u8; 32],
    ) -> Result<Self, SwapError> {
        if xmr_piconero == 0 || ghost_atoms == 0 {
            return Err(SwapError::ZeroAmount);
        }
        if fund_timeout_blocks == 0 || claim_timeout_blocks == 0 {
            return Err(SwapError::TimeoutNotPositive);
        }
        Ok(Self {
            xmr_piconero,
            ghost_atoms,
            hashlock: hashlock_of(preimage),
            fund_timeout_blocks,
            claim_timeout_blocks,
            maker_ghost_address: maker_ghost_address.into(),
            taker_xmr_address: taker_xmr_address.into(),
        })
    }
}

/// blake3 hashlock of a 32-byte preimage.
pub fn hashlock_of(preimage: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"ghost-swap-hashlock-v1");
    h.update(preimage);
    h.finalize().into()
}

/// A live swap session on one participant's side.
#[derive(Clone, Debug)]
pub struct SwapSession {
    pub offer: Offer,
    pub role: Role,
    pub phase: Phase,
    /// Height at which the offer was accepted.
    pub accepted_height: u64,
    /// Height at which both locks were present.
    pub both_locked_height: Option<u64>,
    pub preimage: Option<[u8; 32]>,
    /// WG-CLSAG-adaptor-int: the taker's pre-signed Monero claim adaptor
    /// (taker: attached once the preimage was revealed; maker: recorded
    /// from the Claim sidecar before completion).
    pub xmr_claim: Option<XmrClaimAdaptor>,
    /// WG-CLSAG-adaptor-int: maker-side completed claim signature - the
    /// ready-to-publish Monero spend, monerod-valid (verify_clsag gate).
    pub xmr_completed: Option<ClsagSig>,
}

impl SwapSession {
    /// Create a session in the `Offered` phase (maker side).
    pub fn make_offer(offer: Offer, current_height: u64) -> Self {
        let _ = current_height;
        SwapSession {
            offer,
            role: Role::Maker,
            phase: Phase::Offered,
            accepted_height: 0,
            both_locked_height: None,
            preimage: None,
            xmr_claim: None,
            xmr_completed: None,
        }
    }

    /// Taker accepts an offer. Returns the session.
    pub fn accept(offer: Offer, current_height: u64) -> Self {
        SwapSession {
            offer,
            role: Role::Taker,
            phase: Phase::Accepted,
            accepted_height: current_height,
            both_locked_height: None,
            preimage: None,
            xmr_claim: None,
            xmr_completed: None,
        }
    }

    /// Maker reveals the preimage to the taker when the offer is published.
    /// (v0.1: the hashlock is in the offer; the maker MUST have kept the
    /// preimage to be able to claim later.)
    pub fn set_preimage(&mut self, preimage: [u8; 32]) -> Result<(), SwapError> {
        if hashlock_of(&preimage) != self.offer.hashlock {
            return Err(SwapError::BadPreimage);
        }
        self.preimage = Some(preimage);
        Ok(())
    }

    fn require(&self, phase: Phase, role: Role) -> Result<(), SwapError> {
        if self.phase != phase {
            return Err(SwapError::WrongPhase);
        }
        if self.role != role {
            return Err(SwapError::WrongRole);
        }
        Ok(())
    }

    /// Taker locks XMR (after `accept`).
    pub fn lock_xmr(&mut self, current_height: u64) -> Result<u64, SwapError> {
        self.require(Phase::Accepted, Role::Taker)?;
        if current_height > self.accepted_height + self.offer.fund_timeout_blocks {
            self.phase = Phase::Refunded; // offer expired, taker refunds offer
            return Err(SwapError::NotTimedOut);
        }
        self.phase = Phase::XmrLocked;
        Ok(self.offer.xmr_piconero)
    }

    /// Record the observed XMR lock (maker watches for the taker's transfer;
    /// a maker session still in `Offered` implicitly becomes accepted here).
    pub fn mark_xmr_locked(&mut self, current_height: u64) -> Result<(), SwapError> {
        match self.phase {
            Phase::Offered => {
                self.accepted_height = current_height;
            }
            Phase::Accepted => {}
            _ => return Err(SwapError::WrongPhase),
        }
        if self.role == Role::Taker
            && current_height > self.accepted_height + self.offer.fund_timeout_blocks
        {
            self.phase = Phase::Refunded;
            return Err(SwapError::NotTimedOut);
        }
        self.phase = Phase::XmrLocked;
        Ok(())
    }

    /// Record the GHOST lock (maker acting on his own session after locking
    /// the bridge pool; taker calls this too after observing the lock tx).
    /// Moves XmrLocked -> GhostLocked on ANY role.
    pub fn mark_ghost_locked(&mut self, current_height: u64) -> Result<(), SwapError> {
        if self.phase != Phase::XmrLocked {
            return Err(SwapError::WrongPhase);
        }
        self.phase = Phase::GhostLocked;
        self.both_locked_height = Some(current_height);
        Ok(())
    }

    /// Taker reveals the preimage and claims GHOST.
    /// WG-18: consensus [R5] - the claim is valid while `current_height < T`
    /// (strict); at h == T the claim is late.
    pub fn claim(&mut self, preimage: &[u8; 32], current_height: u64) -> Result<(), SwapError> {
        self.require(Phase::GhostLocked, Role::Taker)?;
        let deadline = self
            .both_locked_height
            .unwrap_or(0)
            .saturating_add(self.offer.claim_timeout_blocks);
        if current_height >= deadline {
            self.phase = Phase::Refunded;
            return Err(SwapError::NotTimedOut);
        }
        if hashlock_of(preimage) != self.offer.hashlock {
            return Err(SwapError::BadPreimage);
        }
        self.preimage = Some(*preimage);
        self.phase = Phase::Claimed;
        Ok(())
    }

    /// Timeout refund. Valid once the deadline is reached (h >= T, [R5]).
    pub fn refund(&mut self, current_height: u64) -> Result<(), SwapError> {
        match (self.phase, self.role) {
            // taker locked nothing yet, or the lock window passed
            (Phase::Accepted, Role::Taker) => {
                if current_height <= self.accepted_height + self.offer.fund_timeout_blocks {
                    return Err(SwapError::NotTimedOut);
                }
            }
            // maker locked GHOST but taker never claimed
            (Phase::GhostLocked, Role::Maker) => {
                let deadline = self
                    .both_locked_height
                    .unwrap_or(0)
                    .saturating_add(self.offer.claim_timeout_blocks);
                if current_height < deadline {
                    return Err(SwapError::NotTimedOut);
                }
            }
            _ => return Err(SwapError::WrongPhase),
        }
        self.phase = Phase::Refunded;
        Ok(())
    }

    /// The preimage the maker uses to claim XMR after the taker claimed.
    pub fn revealed_preimage(&self) -> Option<[u8; 32]> {
        self.preimage
    }

    // -- WG-CLSAG-adaptor-int: Monero-side claim adaptor --------------------

    /// Taker: attach the pre-signed Monero claim adaptor. Only meaningful
    /// after the preimage was revealed (the taker needs it to derive the
    /// swap secret the adaptor is bound to), i.e. in `GhostLocked`, before
    /// the claim is published.
    pub fn attach_xmr_claim(&mut self, claim: XmrClaimAdaptor) -> Result<(), SwapError> {
        if self.role != Role::Taker {
            return Err(SwapError::WrongRole);
        }
        if self.phase != Phase::GhostLocked {
            return Err(SwapError::WrongPhase);
        }
        self.xmr_claim = Some(claim);
        Ok(())
    }

    /// Maker: complete the taker's recorded claim adaptor with THIS
    /// session's own preimage (fail-closed: verification, preimage binding
    /// and the monerod acceptance gate must all pass) and store the
    /// completed signature. Any failure leaves the session untouched.
    pub fn complete_xmr_claim(&mut self, offer_id: &[u8; 32]) -> Result<ClsagSig, SwapError> {
        if self.role != Role::Maker {
            return Err(SwapError::WrongRole);
        }
        if self.phase != Phase::GhostLocked {
            return Err(SwapError::WrongPhase);
        }
        let preimage = self.preimage.ok_or(SwapError::MissingPreimage)?;
        let full = {
            let claim = self.xmr_claim.as_ref().ok_or(SwapError::XmrClaimInvalid)?;
            claim.complete_for(&preimage, offer_id, &self.offer.hashlock)?
        };
        self.xmr_completed = Some(full.clone());
        Ok(full)
    }

    /// The completed, monerod-valid claim signature (maker side, after
    /// [`Self::complete_xmr_claim`]).
    pub fn completed_xmr_claim(&self) -> Option<&ClsagSig> {
        self.xmr_completed.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as B;

    fn offer() -> Offer {
        Offer::new(
            2_000_000_000_000, // 2 XMR
            1_000_000_000,     // GHOST atoms
            100,               // fund timeout
            200,               // claim timeout
            "ghost-maker-addr",
            "xmr-taker-addr",
            &[42u8; 32],
        )
        .unwrap()
    }

    #[test]
    fn happy_path_claim() {
        let mut maker = SwapSession::make_offer(offer(), 1000);
        let mut taker = SwapSession::accept(offer(), 1005);
        maker.set_preimage([42u8; 32]).unwrap();

        taker.lock_xmr(1010).unwrap();
        assert_eq!(taker.phase, Phase::XmrLocked);

        // Maker observes the XMR lock, then both sides record the GHOST lock
        // (maker performs it, taker sees it).
        maker.mark_xmr_locked(1010).unwrap();
        maker.mark_ghost_locked(1015).unwrap();
        taker.mark_ghost_locked(1015).unwrap();
        assert_eq!(maker.phase, Phase::GhostLocked);

        taker.claim(&[42u8; 32], 1020).unwrap();
        assert_eq!(taker.phase, Phase::Claimed);
        assert_eq!(taker.revealed_preimage(), Some([42u8; 32]));

        // Maker uses the revealed preimage to claim the XMR side.
        assert_eq!(maker.revealed_preimage(), Some([42u8; 32]));
    }

    #[test]
    fn wrong_phase_order_rejected() {
        let mut taker = SwapSession::accept(offer(), 100);
        // cannot record GHOST lock before XMR lock
        assert_eq!(taker.mark_ghost_locked(100), Err(SwapError::WrongPhase));
        // maker session cannot claim before locks
        let mut maker = SwapSession::make_offer(offer(), 100);
        assert_eq!(maker.claim(&[42u8; 32], 100), Err(SwapError::WrongPhase));
    }

    #[test]
    fn bad_preimage_rejected() {
        let mut taker = SwapSession::accept(offer(), 100);
        taker.lock_xmr(100).unwrap();
        taker.mark_ghost_locked(100).unwrap();
        assert_eq!(taker.claim(&[7u8; 32], 100), Err(SwapError::BadPreimage));
    }

    #[test]
    fn fund_timeout_expires() {
        let mut taker = SwapSession::accept(offer(), 100);
        // 100 + 100 timeout = 200; lock at 301 -> too late
        assert_eq!(taker.lock_xmr(301), Err(SwapError::NotTimedOut));
        assert_eq!(taker.phase, Phase::Refunded);
    }

    #[test]
    fn maker_refund_after_claim_timeout() {
        let mut maker = SwapSession::make_offer(offer(), 100);
        // simulate taker side progress: xmr locked at 110, ghost locked at 120
        let mut taker = SwapSession::accept(offer(), 105);
        taker.lock_xmr(110).unwrap();
        maker.mark_xmr_locked(110).unwrap();
        maker.mark_ghost_locked(120).unwrap();
        // deadline 120 + 200 = 320
        assert_eq!(maker.refund(319), Err(SwapError::NotTimedOut));
        maker.refund(320).unwrap();
        assert_eq!(maker.phase, Phase::Refunded);
    }

    /// WG-18: consensus [R5] alignment - at h == T the claim is LATE
    /// (strict `h < T`); the session flips to `Refunded` (coordination hint).
    #[test]
    fn wg18_claim_at_deadline_is_late() {
        let mut maker = SwapSession::make_offer(offer(), 100);
        let mut taker = SwapSession::accept(offer(), 105);
        taker.lock_xmr(110).unwrap();
        maker.mark_xmr_locked(110).unwrap();
        maker.mark_ghost_locked(120).unwrap();
        taker.mark_ghost_locked(120).unwrap();
        // deadline = 120 + 200 = 320: claiming exactly at the deadline is late
        assert_eq!(taker.claim(&[42u8; 32], 320), Err(SwapError::NotTimedOut));
        assert_eq!(taker.phase, Phase::Refunded);
    }

    /// WG-18: the maker refund is valid from the deadline itself ([R5],
    /// inclusive `h >= T`), not only strictly after it.
    #[test]
    fn wg18_refund_at_deadline_is_valid() {
        let mut maker = SwapSession::make_offer(offer(), 100);
        let mut taker = SwapSession::accept(offer(), 105);
        taker.lock_xmr(110).unwrap();
        maker.mark_xmr_locked(110).unwrap();
        maker.mark_ghost_locked(120).unwrap();
        // deadline = 120 + 200 = 320: refund at exactly h == T succeeds
        maker.refund(320).unwrap();
        assert_eq!(maker.phase, Phase::Refunded);
    }

    #[test]
    fn zero_amounts_rejected() {
        assert_eq!(
            Offer::new(0, 1, 10, 10, "a", "b", &[0u8; 32]),
            Err(SwapError::ZeroAmount)
        );
        assert_eq!(
            Offer::new(1, 0, 10, 10, "a", "b", &[0u8; 32]),
            Err(SwapError::ZeroAmount)
        );
    }

    #[test]
    fn hashlock_is_deterministic_and_binding() {
        assert_eq!(hashlock_of(&[1u8; 32]), hashlock_of(&[1u8; 32]));
        assert_ne!(hashlock_of(&[1u8; 32]), hashlock_of(&[2u8; 32]));
    }

    // -- WG-CLSAG-adaptor-int -----------------------------------------------

    #[test]
    fn swap_secret_is_deterministic_canonical_and_domain_separated() {
        assert_eq!(swap_secret(&[7u8; 32]), swap_secret(&[7u8; 32]));
        assert_ne!(swap_secret(&[7u8; 32]), swap_secret(&[8u8; 32]));
        // always canonical: hash_to_scalar reduces mod l
        for i in 0..64u64 {
            let mut pre = [0u8; 32];
            pre[..8].copy_from_slice(&i.to_le_bytes());
            pre[31] = 0xff; // exercise the high bits
            assert!(
                crate::clsag_verify::canonical_scalar(&swap_secret(&pre)).is_some(),
                "swap_secret must be canonical"
            );
        }
        // domain separation from the hashlock derivation
        assert_ne!(swap_secret(&[9u8; 32]), hashlock_of(&[9u8; 32]));
    }

    #[test]
    fn swap_claim_message_is_deterministic_and_binding() {
        let a = swap_claim_message(&[1u8; 32], &[2u8; 32]);
        assert_eq!(a, swap_claim_message(&[1u8; 32], &[2u8; 32]));
        assert_ne!(a, swap_claim_message(&[3u8; 32], &[2u8; 32]));
        assert_ne!(a, swap_claim_message(&[1u8; 32], &[4u8; 32]));
    }

    /// (ring, x, z, c_offset): decoys are prime-order points, the real
    /// member's mask satisfies [mask_di] - [C_offset] = [z]G.
    fn synthetic_ring(
        n: usize,
        di: usize,
        tag: &[u8],
    ) -> (Vec<RingMember>, [u8; 32], [u8; 32], [u8; 32]) {
        let nz = |parts: &[&[u8]]| -> [u8; 32] {
            let mut buf = tag.to_vec();
            for p in parts {
                buf.extend_from_slice(p);
            }
            hash_to_scalar(&buf).to_bytes()
        };
        let x = nz(&[b"x"]);
        let z = nz(&[b"z"]);
        let k = nz(&[b"k"]);
        let x_s = Scalar::from_bytes_mod_order(x);
        let z_s = Scalar::from_bytes_mod_order(z);
        let k_s = Scalar::from_bytes_mod_order(k);
        let c_offset = (k_s * B).compress().to_bytes();
        let mut ring = Vec::with_capacity(n);
        for i in 0..n {
            if i == di {
                ring.push(RingMember {
                    dest: (x_s * B).compress().to_bytes(),
                    mask: ((k_s + z_s) * B).compress().to_bytes(),
                });
            } else {
                let r = Scalar::from_bytes_mod_order(nz(&[b"dest", &(i as u64).to_le_bytes()]));
                let q = Scalar::from_bytes_mod_order(nz(&[b"mask", &(i as u64).to_le_bytes()]));
                ring.push(RingMember {
                    dest: (r * B).compress().to_bytes(),
                    mask: (q * B).compress().to_bytes(),
                });
            }
        }
        (ring, x, z, c_offset)
    }

    fn offer_for(preimage: &[u8; 32]) -> Offer {
        Offer::new(
            2_000_000_000_000,
            1_000_000_000,
            100,
            200,
            "ghost-maker-addr",
            "xmr-taker-addr",
            preimage,
        )
        .unwrap()
    }

    /// Maker-side completion: honest build -> record -> complete -> the
    /// stored signature is monerod-valid (acceptance gate).
    #[test]
    fn xmr_claim_state_machine_honest_completion() {
        let preimage = [42u8; 32];
        let offer_id = [5u8; 32];
        let (ring, x, z, c_offset) = synthetic_ring(8, 3, b"int-p1");
        let claim = XmrClaimAdaptor::build(
            &x,
            &z,
            &preimage,
            &offer_id,
            &offer_for(&preimage).hashlock,
            ring,
            c_offset,
            3,
        )
        .unwrap();
        assert!(claim.verify_for(&offer_id, &offer_for(&preimage).hashlock));

        // taker side: attach only in GhostLocked
        let mut taker = SwapSession::accept(offer_for(&preimage), 100);
        assert_eq!(
            taker.attach_xmr_claim(claim.clone()),
            Err(SwapError::WrongPhase)
        );
        taker.lock_xmr(110).unwrap();
        taker.mark_ghost_locked(120).unwrap();
        taker.attach_xmr_claim(claim.clone()).unwrap();

        // maker side: full progression, then completion with his own preimage
        let mut maker = SwapSession::make_offer(offer_for(&preimage), 100);
        maker.set_preimage(preimage).unwrap();
        maker.mark_xmr_locked(110).unwrap();
        assert_eq!(
            maker.complete_xmr_claim(&offer_id),
            Err(SwapError::WrongPhase)
        );
        maker.mark_ghost_locked(120).unwrap();
        // no adaptor recorded yet -> invalid
        assert_eq!(
            maker.complete_xmr_claim(&offer_id),
            Err(SwapError::XmrClaimInvalid)
        );
        maker.xmr_claim = Some(claim.clone());
        let full = maker.complete_xmr_claim(&offer_id).unwrap();
        assert!(maker.completed_xmr_claim().is_some());
        // the stored signature passes the UNMODIFIED monerod verifier
        let message = swap_claim_message(&offer_id, &offer_for(&preimage).hashlock);
        assert!(verify_clsag(
            &message,
            &full,
            &claim.key_image,
            &claim.ring,
            &claim.c_offset
        ));
        // taker session cannot complete (wrong role)
        assert_eq!(
            taker.complete_xmr_claim(&offer_id),
            Err(SwapError::WrongRole)
        );
    }

    /// Maker without a stored preimage cannot complete (fail-closed), even
    /// with an otherwise valid adaptor recorded.
    #[test]
    fn xmr_claim_without_preimage_rejected() {
        let preimage = [43u8; 32];
        let offer_id = [6u8; 32];
        let (ring, x, z, c_offset) = synthetic_ring(4, 1, b"int-n11");
        let claim = XmrClaimAdaptor::build(
            &x,
            &z,
            &preimage,
            &offer_id,
            &offer_for(&preimage).hashlock,
            ring,
            c_offset,
            1,
        )
        .unwrap();
        let mut maker = SwapSession::make_offer(offer_for(&preimage), 100);
        // NO set_preimage
        maker.mark_xmr_locked(110).unwrap();
        maker.mark_ghost_locked(120).unwrap();
        maker.xmr_claim = Some(claim);
        assert_eq!(
            maker.complete_xmr_claim(&offer_id),
            Err(SwapError::MissingPreimage)
        );
        assert!(maker.completed_xmr_claim().is_none());
    }

    /// An adaptor bound to a different swap (wrong preimage) fails the
    /// preimage binding at completion ([t]G != T).
    #[test]
    fn xmr_claim_wrong_preimage_completion_rejected() {
        let preimage = [44u8; 32];
        let offer_id = [7u8; 32];
        let (ring, x, z, c_offset) = synthetic_ring(4, 0, b"int-n3");
        let claim = XmrClaimAdaptor::build(
            &x,
            &z,
            &preimage,
            &offer_id,
            &offer_for(&preimage).hashlock,
            ring,
            c_offset,
            0,
        )
        .unwrap();
        let mut maker = SwapSession::make_offer(offer_for(&[45u8; 32]), 100);
        maker.set_preimage([45u8; 32]).unwrap();
        maker.mark_xmr_locked(110).unwrap();
        maker.mark_ghost_locked(120).unwrap();
        maker.xmr_claim = Some(claim);
        assert_eq!(
            maker.complete_xmr_claim(&offer_id),
            Err(SwapError::XmrClaimInvalid)
        );
        assert!(maker.completed_xmr_claim().is_none());
    }

    /// The builder rejects a ring that the primitive rejects (n < 2).
    #[test]
    fn xmr_claim_build_rejects_degenerate_input() {
        let (ring, x, z, c_offset) = synthetic_ring(4, 0, b"int-n-small");
        let e = XmrClaimAdaptor::build(
            &x,
            &z,
            &[46u8; 32],
            &[8u8; 32],
            &offer_for(&[46u8; 32]).hashlock,
            ring[..1].to_vec(),
            c_offset,
            0,
        )
        .unwrap_err();
        assert_eq!(e, SwapError::XmrClaimInvalid);
    }
}
