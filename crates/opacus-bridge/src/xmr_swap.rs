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
//! v0.1 limitation: this module is the protocol state machine + validation.
//! Enforcing the hashlock inside the Ghost zk circuit (and Monero CLSAG
//! adaptor signatures) lands with the value accumulator (v0.4).

use blake3::Hasher;

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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
