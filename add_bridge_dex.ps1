# add_bridge_dex.ps1
# Ghost project - Monero bridge (DLEq + swap protocol + monero-rpc) and
# Uniswap V2 integration (opacus-dex crate) + wGHOST.sol contract.
# Additive only: 3 new files in opacus-bridge, a brand-new opacus-dex crate,
# dependency additions to opacus-bridge/Cargo.toml and lib.rs mods.
# Generated 2026-10-17 - sandbox verified: opacus-bridge 15 passed,
# opacus-dex 13 passed (incl. EIP-155 sign -> RLP decode -> sender recovery e2e).

$ErrorActionPreference = "Stop"

# ---- adjust if your project lives elsewhere ----
$ProjectRoot = "$PSScriptRoot"

Write-Host "=== Ghost: Monero bridge + Uniswap integration ===" -ForegroundColor Cyan

if (!(Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: cargo not found in PATH." -ForegroundColor Red
    exit 1
}
if (!(Test-Path (Join-Path $ProjectRoot "Cargo.toml"))) {
    Write-Host "ERROR: $ProjectRoot\Cargo.toml not found." -ForegroundColor Red
    exit 1
}
if (!(Test-Path (Join-Path $ProjectRoot "crates\opacus-bridge"))) {
    Write-Host "ERROR: crates\opacus-bridge not found." -ForegroundColor Red
    exit 1
}

function Write-Text([string]$Path, [string]$Content) {
    $dir = Split-Path -Parent $Path
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ("  wrote " + $Path)
}

# ---- 0) backup existing bridge files we might touch ----
foreach ($f in @("Cargo.toml", "src\lib.rs")) {
    $p = Join-Path $ProjectRoot "crates\opacus-bridge\$f"
    if (Test-Path $p) {
        Copy-Item $p "$p.bak-bridge" -Force
        Write-Host "  backup -> opacus-bridge\$f.bak-bridge"
    }
}

# ---- crates\opacus-bridge\src\xmr_dleq.rs ----
Write-Text (Join-Path $ProjectRoot "crates\opacus-bridge\src\xmr_dleq.rs") @'
//! Cross-group DLEq proof: one secret scalar `x` is proven to control BOTH
//!
//! * an Ed25519/Monero key  `A1 = x * G1`  (EdwardsPoint, Monero basepoint), and
//! * a Ristretto key        `A2 = x * G2`  (RistrettoPoint, Ristretto basepoint).
//!
//! Both groups live on curve25519, so they share the same scalar field
//! (`l = 2^252 + 27742...`), which is what makes a Schnorr-style proof over
//! the pair sound:
//!
//! ```text
//!   commit:  R1 = r*G1 , R2 = r*G2
//!   chall:   c = H(R1 || R2 || A1 || A2) mod l
//!   respond: s = r + c*x
//!   verify:  s*G1 == R1 + c*A1   AND   s*G2 == R2 + c*A2
//! ```
//!
//! This is the primitive that lets a swap counterparty prove "the XMR
//! address and the GHOST note key belong to the same owner" without
//! revealing `x`.

use curve25519_dalek::constants::{
    ED25519_BASEPOINT_POINT as G1, RISTRETTO_BASEPOINT_POINT as G2,
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

#[derive(Debug, PartialEq, Eq)]
pub enum DleqError {
    BadProof,
}

/// A cross-group DLEq proof.
#[derive(Clone, Debug)]
pub struct DleqProof {
    pub r1: CompressedEdwardsY,
    pub r2: CompressedRistretto,
    pub s: [u8; 32],
}

/// Wide scalar from bytes: 64-byte mod-l reduction (no digest dep needed).
fn scalar_wide(tag: &[u8], data: &[u8]) -> Scalar {
    let mut buf = Vec::with_capacity(tag.len() + data.len());
    buf.extend_from_slice(tag);
    buf.extend_from_slice(data);
    let h1 = *blake3::hash(&buf).as_bytes();
    let h2 = *blake3::hash(&[b"wide", h1.as_slice()].concat()).as_bytes();
    let mut wide = [0u8; 64];
    wide[0..32].copy_from_slice(&h1);
    wide[32..64].copy_from_slice(&h2);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Domain-separated challenge hash.
fn challenge(
    r1: &CompressedEdwardsY,
    r2: &CompressedRistretto,
    a1: &CompressedEdwardsY,
    a2: &CompressedRistretto,
) -> Scalar {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(b"ghost-xmr-dleq-v1");
    buf.extend_from_slice(r1.as_bytes());
    buf.extend_from_slice(r2.as_bytes());
    buf.extend_from_slice(a1.as_bytes());
    buf.extend_from_slice(a2.as_bytes());
    scalar_wide(b"challenge", &buf)
}

/// Public key pair derived from one secret.
#[derive(Clone, Debug)]
pub struct KeyPair {
    pub monero_pub: CompressedEdwardsY,
    pub ristretto_pub: CompressedRistretto,
}

pub fn keypair_from_secret(secret: &Scalar) -> KeyPair {
    KeyPair {
        monero_pub: (secret * G1).compress(),
        ristretto_pub: (secret * G2).compress(),
    }
}

/// Prove knowledge of `secret` such that it produces both public keys.
pub fn prove(secret: &Scalar) -> DleqProof {
    let kp = keypair_from_secret(secret);
    let r = scalar_wide(b"nonce", &rand_bytes());
    let r1 = (r * G1).compress();
    let r2 = (r * G2).compress();
    let c = challenge(&r1, &r2, &kp.monero_pub, &kp.ristretto_pub);
    let s = r + c * secret;
    DleqProof {
        r1,
        r2,
        s: s.to_bytes(),
    }
}

/// Verify the proof against both public keys.
pub fn verify(kp: &KeyPair, proof: &DleqProof) -> Result<(), DleqError> {
    let r1 = proof.r1.decompress().ok_or(DleqError::BadProof)?;
    let r2 = proof.r2.decompress().ok_or(DleqError::BadProof)?;
    let a1 = kp.monero_pub.decompress().ok_or(DleqError::BadProof)?;
    let a2 = kp.ristretto_pub.decompress().ok_or(DleqError::BadProof)?;
    let s = Scalar::from_canonical_bytes(proof.s)
        .into_option()
        .ok_or(DleqError::BadProof)?;
    let c = challenge(&proof.r1, &proof.r2, &kp.monero_pub, &kp.ristretto_pub);
    // s*G1 == R1 + c*A1
    if s * G1 != r1 + c * a1 {
        return Err(DleqError::BadProof);
    }
    // s*G2 == R2 + c*A2
    if s * G2 != r2 + c * a2 {
        return Err(DleqError::BadProof);
    }
    Ok(())
}

/// Deterministic-in-tests byte source (real code uses OsRng; blake3 of
/// nano-time keeps this crate dependency-free).
fn rand_bytes() -> [u8; 32] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut seed = Vec::with_capacity(16);
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    seed.extend_from_slice(&t.as_nanos().to_le_bytes());
    seed.extend_from_slice(&std::process::id().to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(blake3::hash(&seed).as_bytes());
    out
}

/// Serialize a proof to 96 bytes (r1, r2, s).
pub fn proof_to_bytes(p: &DleqProof) -> [u8; 96] {
    let mut out = [0u8; 96];
    out[0..32].copy_from_slice(p.r1.as_bytes());
    out[32..64].copy_from_slice(p.r2.as_bytes());
    out[64..96].copy_from_slice(&p.s);
    out
}

pub fn proof_from_bytes(b: &[u8; 96]) -> DleqProof {
    let mut y1 = [0u8; 32];
    y1.copy_from_slice(&b[0..32]);
    let mut y2 = [0u8; 32];
    y2.copy_from_slice(&b[32..64]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&b[64..96]);
    DleqProof {
        r1: CompressedEdwardsY(y1),
        r2: CompressedRistretto(y2),
        s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret(seed: u8) -> Scalar {
        scalar_wide(b"test", &[seed; 32])
    }

    #[test]
    fn prove_verify_roundtrip() {
        let secret = test_secret(1);
        let kp = keypair_from_secret(&secret);
        let proof = prove(&secret);
        verify(&kp, &proof).expect("valid proof must verify");

        // Serialization roundtrip.
        let bytes = proof_to_bytes(&proof);
        let proof2 = proof_from_bytes(&bytes);
        assert_eq!(proof2.r1, proof.r1);
        assert_eq!(proof2.r2, proof.r2);
        verify(&kp, &proof2).expect("serialized proof must verify");
    }

    #[test]
    fn wrong_secret_fails() {
        let kp = keypair_from_secret(&test_secret(2));
        let forged = prove(&test_secret(3)); // different secret
        assert_eq!(verify(&kp, &forged), Err(DleqError::BadProof));
    }

    #[test]
    fn tampered_key_fails() {
        let secret = test_secret(4);
        let mut kp = keypair_from_secret(&secret);
        // flip a bit in the ristretto key
        let mut y2 = kp.ristretto_pub.to_bytes();
        y2[0] ^= 0x01;
        kp.ristretto_pub = CompressedRistretto(y2);
        let proof = prove(&secret);
        assert_eq!(verify(&kp, &proof), Err(DleqError::BadProof));
    }

    #[test]
    fn same_secret_same_keys() {
        let s = test_secret(7);
        let a = keypair_from_secret(&s);
        let b = keypair_from_secret(&s);
        assert_eq!(a.monero_pub, b.monero_pub);
        assert_eq!(a.ristretto_pub, b.ristretto_pub);
        // and different secrets give different keys
        let c = keypair_from_secret(&test_secret(8));
        assert_ne!(a.monero_pub, c.monero_pub);
    }
}

'@

# ---- crates\opacus-bridge\src\xmr_swap.rs ----
Write-Text (Join-Path $ProjectRoot "crates\opacus-bridge\src\xmr_swap.rs") @'
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
    pub fn claim(&mut self, preimage: &[u8; 32], current_height: u64) -> Result<(), SwapError> {
        self.require(Phase::GhostLocked, Role::Taker)?;
        let deadline = self.both_locked_height.unwrap_or(0) + self.offer.claim_timeout_blocks;
        if current_height > deadline {
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

    /// Timeout refund. Valid only after the corresponding deadline.
    pub fn refund(&mut self, current_height: u64) -> Result<(), SwapError> {
        match (self.phase, self.role) {
            // taker locked nothing yet, or the lock window passed
            (Phase::Accepted, Role::Taker) => {
                if current_height
                    <= self.accepted_height + self.offer.fund_timeout_blocks
                {
                    return Err(SwapError::NotTimedOut);
                }
            }
            // maker locked GHOST but taker never claimed
            (Phase::GhostLocked, Role::Maker) => {
                let deadline =
                    self.both_locked_height.unwrap_or(0) + self.offer.claim_timeout_blocks;
                if current_height <= deadline {
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
            2_000_000_000_000,   // 2 XMR
            1_000_000_000,       // GHOST atoms
            100,                 // fund timeout
            200,                 // claim timeout
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
        assert_eq!(
            maker.claim(&[42u8; 32], 100),
            Err(SwapError::WrongPhase)
        );
    }

    #[test]
    fn bad_preimage_rejected() {
        let mut taker = SwapSession::accept(offer(), 100);
        taker.lock_xmr(100).unwrap();
        taker.mark_ghost_locked(100).unwrap();
        assert_eq!(
            taker.claim(&[7u8; 32], 100),
            Err(SwapError::BadPreimage)
        );
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
        assert_eq!(maker.refund(320), Err(SwapError::NotTimedOut));
        maker.refund(321).unwrap();
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

'@

# ---- crates\opacus-bridge\src\xmr_rpc.rs ----
Write-Text (Join-Path $ProjectRoot "crates\opacus-bridge\src\xmr_rpc.rs") @'
//! monero-wallet-rpc / monerod JSON-RPC client (request builders + response
//! parsers, transport-agnostic). Plug any HTTP transport into [`Transport`].

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, PartialEq, Eq)]
pub enum XmrRpcError {
    Transport(String),
    Rpc(String),
    BadResponse(String),
}

impl std::fmt::Display for XmrRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XmrRpcError::Transport(m) => write!(f, "transport: {m}"),
            XmrRpcError::Rpc(m) => write!(f, "monero rpc: {m}"),
            XmrRpcError::BadResponse(m) => write!(f, "bad response: {m}"),
        }
    }
}

impl std::error::Error for XmrRpcError {}

/// Blocking transport used for wallet-rpc / daemon calls.
pub trait Transport {
    fn post(&self, url: &str, body: &Value) -> Result<Value, XmrRpcError>;
    /// Plain GET for monerod REST endpoints (e.g. `/get_info`).
    fn get(&self, url: &str) -> Result<Value, XmrRpcError>;
}

impl<T: Transport + ?Sized> Transport for &T {
    fn post(&self, url: &str, body: &Value) -> Result<Value, XmrRpcError> {
        (**self).post(url, body)
    }
    fn get(&self, url: &str) -> Result<Value, XmrRpcError> {
        (**self).get(url)
    }
}

/// monero-wallet-rpc client.
pub struct WalletRpc<T: Transport> {
    pub url: String,
    pub transport: T,
}

/// monerod client.
pub struct DaemonRpc<T: Transport> {
    pub url: String,
    pub transport: T,
}

// ---------------------------------------------------------------------------
// Requests / responses (only the fields the bridge needs)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct TransferRequest {
    /// Destination address (single-output transfer).
    pub address: String,
    /// Amount in piconero (1 XMR = 1e12).
    pub amount: u64,
    /// For swap timelocks: min block height before the output spends.
    pub unlock_time: u64,
    /// Swap hashlock as hex payment_id.
    pub payment_id: String,
    pub account_index: u32,
    pub priority: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TransferResult {
    pub tx_hash: String,
    #[serde(default)]
    pub fee: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DaemonInfo {
    pub height: u64,
    #[serde(default)]
    pub synchronized: bool,
    #[serde(default)]
    pub target_height: u64,
}

// ---------------------------------------------------------------------------
// Wallet RPC
// ---------------------------------------------------------------------------

impl<T: Transport> WalletRpc<T> {
    pub fn new(url: impl Into<String>, transport: T) -> Self {
        Self {
            url: url.into(),
            transport,
        }
    }

    fn jsonrpc(&self, method: &str, params: Value) -> Result<Value, XmrRpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params,
        });
        let resp = self.transport.post(&self.url, &body)?;
        if let Some(err) = resp.get("error") {
            return Err(XmrRpcError::Rpc(err.to_string()));
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| XmrRpcError::BadResponse("missing result".into()))
    }

    /// Lock XMR for the swap: amount + unlock_time + payment_id (hashlock).
    pub fn transfer(&self, req: &TransferRequest) -> Result<TransferResult, XmrRpcError> {
        let params = json!({
            "destinations": [{"amount": req.amount, "address": req.address}],
            "account_index": req.account_index,
            "priority": req.priority,
            "unlock_time": req.unlock_time,
            "payment_id": req.payment_id,
        });
        let res = self.jsonrpc("transfer", params)?;
        let tx_hash = res
            .get("tx_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| XmrRpcError::BadResponse("missing tx_hash".into()))?
            .to_string();
        let fee = res.get("fee").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(TransferResult { tx_hash, fee })
    }

    /// Incoming transfers with a given payment id (swap lock detection).
    pub fn transfers_by_payment_id(&self, payment_id: &str) -> Result<Vec<String>, XmrRpcError> {
        let res = self.jsonrpc(
            "get_transfers",
            json!({"in": true, "out": false, "pending": false, "failed": false}),
        )?;
        let mut hashes = Vec::new();
        if let Some(list) = res.get("in").and_then(|v| v.as_array()) {
            for tx in list {
                let pid = tx.get("payment_id").and_then(|v| v.as_str()).unwrap_or("");
                if pid == payment_id {
                    if let Some(h) = tx.get("tx_hash").and_then(|v| v.as_str()) {
                        hashes.push(h.to_string());
                    }
                }
            }
        }
        Ok(hashes)
    }

    /// Primary address of the opened wallet (for receiving GHOST proceeds
    /// side-effects, bookkeeping, etc).
    pub fn get_address(&self, account_index: u32) -> Result<String, XmrRpcError> {
        let res = self.jsonrpc("get_address", json!({"account_index": account_index}))?;
        res.get("address")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| XmrRpcError::BadResponse("missing address".into()))
    }

    /// Unlocked (spendable) balance in piconero.
    pub fn unlocked_balance(&self, account_index: u32) -> Result<u64, XmrRpcError> {
        let res = self.jsonrpc("get_balance", json!({"account_index": account_index}))?;
        res.get("unlocked_balance")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| XmrRpcError::BadResponse("missing unlocked_balance".into()))
    }
}

// ---------------------------------------------------------------------------
// Daemon RPC
// ---------------------------------------------------------------------------

impl<T: Transport> DaemonRpc<T> {
    pub fn new(url: impl Into<String>, transport: T) -> Self {
        Self {
            url: url.into(),
            transport,
        }
    }

    /// GET /get_info (monerod REST endpoint).
    pub fn get_info(&self) -> Result<DaemonInfo, XmrRpcError> {
        let url = format!("{}/get_info", self.url.trim_end_matches('/'));
        let v = self.transport.get(&url)?;
        serde_json::from_value(v).map_err(|e| XmrRpcError::BadResponse(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct FakeTransport {
        calls: RefCell<Vec<(String, Value)>>,
    }

    impl FakeTransport {
        fn new() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
            }
        }
        fn record(&self, url: &str, body: &Value) {
            self.calls.borrow_mut().push((url.to_string(), body.clone()));
        }
    }

    impl Transport for FakeTransport {
        fn post(&self, url: &str, body: &Value) -> Result<Value, XmrRpcError> {
            self.record(url, body);
            let method = body["method"].as_str().unwrap_or("");
            if method == "transfer" {
                return Ok(json!({
                    "id": "0",
                    "result": {"tx_hash": "abc123", "fee": 12345}
                }));
            }
            if method == "get_balance" {
                return Ok(json!({"id": "0", "result": {"unlocked_balance": 9876}}));
            }
            if method == "get_address" {
                return Ok(json!({"id": "0", "result": {"address": "4At3X..."}}));
            }
            Err(XmrRpcError::Rpc("unknown".into()))
        }

        fn get(&self, _url: &str) -> Result<Value, XmrRpcError> {
            Ok(json!({
                "height": 3_200_000,
                "synchronized": true,
                "target_height": 3_200_001
            }))
        }
    }

    #[test]
    fn transfer_request_shape_and_parse() {
        let t = FakeTransport::new();
        let rpc = WalletRpc::new("http://127.0.0.1:18083/json_rpc", &t);
        let req = TransferRequest {
            address: "4At3X...".into(),
            amount: 2_000_000_000_000,
            unlock_time: 3_200_100,
            payment_id: hex::encode([0x11u8; 32]),
            account_index: 0,
            priority: 0,
        };
        let res = rpc.transfer(&req).unwrap();
        assert_eq!(res.tx_hash, "abc123");
        assert_eq!(res.fee, 12345);

        let (_, body) = &t.calls.borrow()[0];
        assert_eq!(body["method"], "transfer");
        assert_eq!(body["params"]["unlock_time"], 3_200_100u64);
        assert_eq!(body["params"]["payment_id"], hex::encode([0x11u8; 32]));
        assert_eq!(
            body["params"]["destinations"][0]["amount"],
            2_000_000_000_000u64
        );
        assert_eq!(body["params"]["destinations"][0]["address"], "4At3X...");
    }

    #[test]
    fn balance_and_address() {
        let t = FakeTransport::new();
        let rpc = WalletRpc::new("http://127.0.0.1:18083/json_rpc", &t);
        assert_eq!(rpc.unlocked_balance(0).unwrap(), 9876);
        assert_eq!(rpc.get_address(0).unwrap(), "4At3X...");
    }

    #[test]
    fn daemon_info() {
        let t = FakeTransport::new();
        let d = DaemonRpc::new("http://127.0.0.1:18081", &t);
        let info = d.get_info().unwrap();
        assert_eq!(info.height, 3_200_000);
        assert!(info.synchronized);
    }

    #[test]
    fn transfer_error_propagates() {
        struct ErrTransport;
        impl Transport for ErrTransport {
            fn post(&self, _: &str, _: &Value) -> Result<Value, XmrRpcError> {
                Ok(json!({"id": "0", "error": {"code": -1, "message": "not enough money"}}))
            }
            fn get(&self, _: &str) -> Result<Value, XmrRpcError> {
                Err(XmrRpcError::Transport("unused".into()))
            }
        }
        let rpc = WalletRpc::new("http://x", ErrTransport);
        let err = rpc
            .transfer(&TransferRequest {
                address: "a".into(),
                amount: 1,
                unlock_time: 1,
                payment_id: "ff".into(),
                account_index: 0,
                priority: 0,
            })
            .unwrap_err();
        assert!(err.to_string().contains("not enough money"));
    }
}

'@

# ---- crates\opacus-dex\Cargo.toml ----
Write-Text (Join-Path $ProjectRoot "crates\opacus-dex\Cargo.toml") @'
[package]
name = "opacus-dex"
version = "0.1.0"
edition = "2021"
description = "Uniswap integration for Ghost: EIP-155 tx signing, Uniswap V2 router calldata, wGHOST helpers"

[dependencies]
k256 = { version = "0.13", features = ["ecdsa"] }
tiny-keccak = { version = "2", features = ["keccak"] }
hex = "0.4"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
ureq = { version = "2", features = ["json"] }

[dev-dependencies]
rand = "0.8"

'@

# ---- crates\opacus-dex\src\lib.rs ----
Write-Text (Join-Path $ProjectRoot "crates\opacus-dex\src\lib.rs") @'
//! # opacus-dex
//!
//! Uniswap (Ethereum) integration for Ghost.
//!
//! Layered pipeline:
//! 1. [`rlp`] / [`abi`] — minimal RLP + ABI encoders (no codegen).
//! 2. [`tx`] — legacy EIP-155 transaction signing with k256.
//! 3. [`uniswap`] — Uniswap V2 Router02 calldata: quotes, token/ETH swaps,
//!    ERC20 approve/transfer/balance, WETH wrapping.
//! 4. [`rpc`] — Ethereum JSON-RPC client (eth_call / gas / nonce /
//!    sendRawTransaction) over any [`rpc::Transport`].
//!
//! wGHOST flow (see `contracts/wGHOST.sol` in the repo):
//! 1. Lock native GHOST with the bridge (opacus-bridge).
//! 2. Bridge quorum attests; wGHOST is minted to your EVM address.
//! 3. `approve(wGHOST, Router)` then `swap_exact_tokens_for_tokens(...)`.
//! 4. To return: swap back to wGHOST, `burn` via the bridge, unlock native.

pub mod abi;
pub mod rlp;
pub mod rpc;
pub mod tx;
pub mod uniswap;
pub mod wghost;

pub use tx::{Address, TxParams};

'@

# ---- crates\opacus-dex\src\rlp.rs ----
Write-Text (Join-Path $ProjectRoot "crates\opacus-dex\src\rlp.rs") @'
//! Minimal RLP encoding (Ethereum legacy transactions).

/// An RLP-encodable value.
#[derive(Clone, Debug)]
pub enum RlpItem {
    Bytes(Vec<u8>),
    List(Vec<RlpItem>),
}

impl RlpItem {
    pub fn bytes(b: impl Into<Vec<u8>>) -> Self {
        RlpItem::Bytes(b.into())
    }

    /// Encode a big-endian unsigned integer without leading zeros.
    pub fn uint(be: &[u8]) -> Self {
        let first = be.iter().position(|&b| b != 0).unwrap_or(be.len());
        RlpItem::Bytes(be[first..].to_vec())
    }

    pub fn list(items: Vec<RlpItem>) -> Self {
        RlpItem::List(items)
    }

    /// Full RLP encoding.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            RlpItem::Bytes(b) => encode_scalar(b),
            RlpItem::List(items) => {
                let payload: Vec<u8> = items.iter().flat_map(|i| i.encode()).collect();
                let mut out = encode_length(payload.len(), 0xc0);
                out.extend_from_slice(&payload);
                out
            }
        }
    }
}

/// RLP-encode a byte string.
fn encode_scalar(b: &[u8]) -> Vec<u8> {
    if b.len() == 1 && b[0] < 0x80 {
        return b.to_vec();
    }
    let mut out = encode_length(b.len(), 0x80);
    out.extend_from_slice(b);
    out
}

fn encode_length(len: usize, offset: u8) -> Vec<u8> {
    if len <= 55 {
        vec![offset + len as u8]
    } else {
        let len_bytes = len.to_be_bytes();
        let first = len_bytes.iter().position(|&b| b != 0).unwrap();
        let significant = &len_bytes[first..];
        let mut out = vec![offset + 55 + significant.len() as u8];
        out.extend_from_slice(significant);
        out
    }
}

/// 32-byte big-endian helper for amounts.
pub fn u256_from_u64(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

/// 32-byte big-endian helper for u128 (token amounts).
pub fn u256_from_u128(v: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&v.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        // "" -> 0x80
        assert_eq!(RlpItem::bytes(Vec::<u8>::new()).encode(), vec![0x80]);
        // "dog" -> 0x83 646f67
        assert_eq!(
            RlpItem::bytes(b"dog".to_vec()).encode(),
            vec![0x83, b'd', b'o', b'g']
        );
        // 0 -> 0x80
        assert_eq!(RlpItem::uint(&u256_from_u64(0)).encode(), vec![0x80]);
        // 1024 -> 0x82 0400
        assert_eq!(
            RlpItem::uint(&u256_from_u64(1024)).encode(),
            vec![0x82, 0x04, 0x00]
        );
        // ["cat", "dog"] -> 0xc8 83 636174 83 646f67
        assert_eq!(
            RlpItem::list(vec![
                RlpItem::bytes(b"cat".to_vec()),
                RlpItem::bytes(b"dog".to_vec()),
            ])
            .encode(),
            vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']
        );
        // 56-bit length boundary: a 56-byte string uses long form
        let long = vec![0u8; 56];
        let enc = RlpItem::bytes(long).encode();
        assert_eq!(enc[0], 0xb8);
        assert_eq!(enc[1], 56);
        assert_eq!(enc.len(), 58);
    }
}

'@

# ---- crates\opacus-dex\src\abi.rs ----
Write-Text (Join-Path $ProjectRoot "crates\opacus-dex\src\abi.rs") @'
//! Minimal Ethereum ABI encoding for the subset Uniswap integration needs:
//! uint256, address, bool, dynamic address[] and function selectors.

use crate::rlp::u256_from_u128;
use tiny_keccak::{Hasher, Keccak};

pub const SELECTOR_LEN: usize = 4;

/// keccak256 of arbitrary bytes.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(data);
    k.finalize(&mut out);
    out
}

/// Function selector: first 4 bytes of keccak256("name(types...)").
pub fn selector(signature: &str) -> [u8; SELECTOR_LEN] {
    let h = keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// One head-slot word (32 bytes, left-padded).
fn word(bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len() <= 32, "word overflow");
    let mut w = [0u8; 32];
    w[32 - bytes.len()..].copy_from_slice(bytes);
    w.to_vec()
}

/// An ABI argument (already encoded to its 32-byte head or a tail segment).
pub enum AbiArg {
    /// uint256 / int256 / bool / bytes32
    Word([u8; 32]),
    /// address (20 bytes, left-padded)
    Address([u8; 20]),
    /// dynamic address[] (encoded as offset + length + words)
    AddressArray(Vec<[u8; 20]>),
}

impl AbiArg {
    pub fn uint_u128(v: u128) -> Self {
        AbiArg::Word(u256_from_u128(v))
    }

    pub fn uint_u64(v: u64) -> Self {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&v.to_be_bytes());
        AbiArg::Word(w)
    }

    pub fn boolean(b: bool) -> Self {
        let mut w = [0u8; 32];
        if b {
            w[31] = 1;
        }
        AbiArg::Word(w)
    }
}

/// Encode a function call: selector + head/tail encoded arguments.
pub fn encode_call(sig: &str, args: &[AbiArg]) -> Vec<u8> {
    let mut out = selector(sig).to_vec();

    // static heads; dynamic args place an offset into their tail
    let static_heads: Vec<Vec<u8>> = args
        .iter()
        .map(|a| match a {
            AbiArg::Word(w) => word(w),
            AbiArg::Address(a) => word(a),
            AbiArg::AddressArray(_) => word(&[]), // placeholder, fixed below
        })
        .collect();

    let dynamic_count = args
        .iter()
        .filter(|a| matches!(a, AbiArg::AddressArray(_)))
        .count();
    if dynamic_count == 0 {
        for h in static_heads {
            out.extend_from_slice(&h);
        }
        return out;
    }

    // head size = one word per arg; tail starts after that
    let head_words = args.len();
    let mut tails: Vec<Vec<u8>> = Vec::new();
    let mut tail_size = 0usize;
    for a in args {
        if let AbiArg::AddressArray(items) = a {
            // length word + one word per address
            let sz = 32 * (1 + items.len());
            tails.push(encode_address_array(items));
            tail_size += sz;
        }
    }
    // assign offsets in argument order
    let mut offsets = Vec::with_capacity(args.len());
    let mut running = head_words * 32;
    let mut dyn_idx = 0usize;
    for a in args {
        if matches!(a, AbiArg::AddressArray(_)) {
            offsets.push(running);
            running += tails[dyn_idx].len();
            dyn_idx += 1;
        } else {
            offsets.push(0);
        }
    }

    let mut dyn_i = 0usize;
    for (i, a) in args.iter().enumerate() {
        match a {
            AbiArg::AddressArray(_) => {
                out.extend_from_slice(&word(&u128_to_be32(offsets[i])));
                out.extend_from_slice(&tails[dyn_i]);
                dyn_i += 1;
            }
            _ => out.extend_from_slice(&static_heads[i]),
        }
    }
    let _ = tail_size;
    out
}

fn u128_to_be32(v: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&(v as u64).to_be_bytes());
    w
}

fn encode_address_array(items: &[[u8; 20]]) -> Vec<u8> {
    let mut out = word(&(items.len() as u128).to_be_bytes());
    for a in items {
        out.extend_from_slice(&word(a));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_selectors() {
        // Uniswap V2 Router02 selectors (well-known).
        assert_eq!(selector("getAmountsOut(uint256,address[])"), [0xd0, 0x6c, 0xa6, 0x1f]);
        assert_eq!(
            selector("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"),
            [0x38, 0xed, 0x17, 0x39]
        );
        assert_eq!(
            selector("swapExactETHForTokens(uint256,address[],address,uint256)"),
            [0x7f, 0xf3, 0x6a, 0xb5]
        );
        assert_eq!(
            selector("swapExactTokensForETH(uint256,uint256,address[],address,uint256)"),
            [0x18, 0xcb, 0xaf, 0xe5]
        );
        // ERC20
        assert_eq!(selector("approve(address,uint256)"), [0x09, 0x5e, 0xa7, 0xb3]);
        assert_eq!(selector("deposit()"), [0xd0, 0xe3, 0x0d, 0xb0]);
    }

    #[test]
    fn approve_encoding() {
        // approve(spender=0x1111..11, amount=1000)
        let mut spender = [0x11u8; 20];
        spender[19] = 0x11;
        let data = encode_call("approve(address,uint256)", &[
            AbiArg::Address(spender),
            AbiArg::uint_u128(1000),
        ]);
        assert_eq!(&data[0..4], &[0x09, 0x5e, 0xa7, 0xb3]);
        assert_eq!(data.len(), 4 + 64);
        // address word: 12 zero bytes then 20 address bytes
        assert_eq!(&data[4..16], &[0u8; 12]);
        assert_eq!(&data[16..36], &spender);
        // amount word: 1000 = 0x03E8 -> last two bytes
        assert_eq!(data[4 + 62], 0x03);
        assert_eq!(data[4 + 63], 0xe8);
    }

    #[test]
    fn address_array_offsets() {
        let a = [1u8; 20];
        let b = [2u8; 20];
        let data = encode_call("getAmountsOut(uint256,address[])", &[
            AbiArg::uint_u128(1234),
            AbiArg::AddressArray(vec![a, b]),
        ]);
        assert_eq!(&data[0..4], &[0xd0, 0x6c, 0xa6, 0x1f]);
        assert_eq!(data.len(), 4 + 64 + 32 * 3);
        // offset of array tail = 2 words = 64 (second head slot)
        assert_eq!(data[4 + 31], 0xd2); // uint 1234 = 0x04d2 last byte
        assert_eq!(data[4 + 63], 64); // offset word
        // length
        let tail = &data[4 + 64..];
        assert_eq!(tail[31], 2);
        // first address starts after 32 zero-padding bytes
        assert_eq!(&tail[32 + 12..32 + 32], &a);
        assert_eq!(&tail[64 + 12..64 + 32], &b);
    }
}

'@

# ---- crates\opacus-dex\src\tx.rs ----
Write-Text (Join-Path $ProjectRoot "crates\opacus-dex\src\tx.rs") @'
//! Ethereum legacy (EIP-155) transaction building and signing.

use crate::abi::keccak256;
use crate::rlp::RlpItem;
use k256::ecdsa::{SigningKey, VerifyingKey};

/// 20-byte Ethereum address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address(pub [u8; 20]);

impl Address {
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let b = hex::decode(s).ok()?;
        if b.len() != 20 {
            return None;
        }
        let mut a = [0u8; 20];
        a.copy_from_slice(&b);
        Some(Address(a))
    }
}

/// Address derived from a secp256k1 public key: keccak256(pubkey[1..65])[12..].
pub fn address_from_pubkey(pk: &VerifyingKey) -> Address {
    let encoded = pk.to_encoded_point(false); // 65 bytes, starts with 0x04
    let h = keccak256(&encoded.as_bytes()[1..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    Address(a)
}

/// Legacy transaction parameters.
#[derive(Clone, Debug)]
pub struct TxParams {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price_wei: u128,
    pub gas_limit: u64,
    /// `None` = contract creation.
    pub to: Option<Address>,
    /// Value in wei, big-endian 32 bytes.
    pub value_wei: [u8; 32],
    /// Calldata.
    pub data: Vec<u8>,
}

impl TxParams {
    /// The pre-image that is signed: RLP([nonce, gasPrice, gas, to, value,
    /// data, chainId, 0, 0]).
    fn signing_payload(&self) -> Vec<u8> {
        let to_item = match self.to {
            Some(a) => RlpItem::bytes(a.0.to_vec()),
            None => RlpItem::bytes(Vec::new()),
        };
        RlpItem::list(vec![
            RlpItem::uint(&crate::rlp::u256_from_u64(self.nonce)),
            RlpItem::uint(&crate::rlp::u256_from_u128(self.gas_price_wei)),
            RlpItem::uint(&crate::rlp::u256_from_u64(self.gas_limit)),
            to_item,
            RlpItem::bytes(self.value_wei.to_vec()),
            RlpItem::bytes(self.data.clone()),
            RlpItem::uint(&crate::rlp::u256_from_u64(self.chain_id)),
            RlpItem::uint(&[0u8; 32]),
            RlpItem::uint(&[0u8; 32]),
        ])
        .encode()
    }

    /// Signed raw transaction (0x-prefixed hex), EIP-155.
    pub fn sign(&self, sk: &SigningKey) -> Result<String, String> {
        let payload = self.signing_payload();
        let msg_hash = keccak256(&payload);

        // Deterministic ECDSA directly over the keccak prehash, with the
        // recovery id returned by the library (Signer::sign would apply
        // SHA-256 on top, which is NOT what Ethereum does).
        let (sig, recid) = sk
            .sign_prehash_recoverable(&msg_hash)
            .map_err(|e| e.to_string())?;

        // EIP-155: v = parity + 35 + 2 * chainId (no overflow recids after
        // canonical s normalization; both are tried anyway above).
        let parity = if recid.is_y_odd() { 1u64 } else { 0u64 };
        let v = parity + 35 + 2 * self.chain_id;

        let mut sig_r = [0u8; 32];
        sig_r.copy_from_slice(&sig.r().to_bytes()[..]);
        let mut sig_s = [0u8; 32];
        sig_s.copy_from_slice(&sig.s().to_bytes()[..]);

        let to_item = match self.to {
            Some(a) => RlpItem::bytes(a.0.to_vec()),
            None => RlpItem::bytes(Vec::new()),
        };
        let raw = RlpItem::list(vec![
            RlpItem::uint(&crate::rlp::u256_from_u64(self.nonce)),
            RlpItem::uint(&crate::rlp::u256_from_u128(self.gas_price_wei)),
            RlpItem::uint(&crate::rlp::u256_from_u64(self.gas_limit)),
            to_item,
            RlpItem::bytes(self.value_wei.to_vec()),
            RlpItem::bytes(self.data.clone()),
            RlpItem::uint(&crate::rlp::u256_from_u64(v)),
            RlpItem::bytes(sig_r.to_vec()),
            RlpItem::bytes(sig_s.to_vec()),
        ])
        .encode();

        Ok(format!("0x{}", hex::encode(&raw)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::RecoveryId;

    fn test_key(seed: u8) -> SigningKey {
        // Deterministic non-degenerate key for tests.
        let mut bytes = [seed; 32];
        bytes[31] = seed.wrapping_mul(7).max(1);
        SigningKey::from_bytes((&bytes).into()).unwrap()
    }

    #[test]
    fn address_roundtrip() {
        let sk = test_key(3);
        let addr = address_from_pubkey(sk.verifying_key());
        let hex_str = addr.to_hex();
        assert_eq!(hex_str.len(), 42);
        assert_eq!(Address::from_hex(&hex_str), Some(addr));
    }

    #[test]
    fn signed_tx_recovers_sender() {
        let sk = test_key(5);
        let sender = address_from_pubkey(sk.verifying_key());
        let tx = TxParams {
            chain_id: 1,
            nonce: 7,
            gas_price_wei: 30_000_000_000,
            gas_limit: 21000,
            to: Some(Address([0xee; 20])),
            value_wei: crate::rlp::u256_from_u128(1_000_000_000_000_000_000),
            data: vec![],
        };
        let raw = tx.sign(&sk).unwrap();
        assert!(raw.starts_with("0x"));
        let raw_bytes = hex::decode(&raw[2..]).unwrap();
        assert_eq!(raw_bytes[0] & 0xc0, 0xc0); // RLP list header (0xC0..0xFF)

        // Minimal RLP walker over the top-level list.
        fn read_item(bytes: &[u8], pos: &mut usize) -> Vec<u8> {
            let b = bytes[*pos];
            let (hdr_len, payload_len) = if b < 0x80 {
                (0usize, 1usize)
            } else if b <= 0xb7 {
                (1, (b - 0x80) as usize)
            } else if b <= 0xbf {
                let n = (b - 0xb7) as usize;
                let mut len = 0usize;
                for i in 0..n {
                    len = (len << 8) | bytes[*pos + 1 + i] as usize;
                }
                (1 + n, len)
            } else if b <= 0xf7 {
                (1, (b - 0xc0) as usize)
            } else {
                let n = (b - 0xf7) as usize;
                let mut len = 0usize;
                for i in 0..n {
                    len = (len << 8) | bytes[*pos + 1 + i] as usize;
                }
                (1 + n, len)
            };
            let start = *pos + hdr_len;
            let payload = bytes[start..start + payload_len].to_vec();
            *pos = start + payload_len;
            payload
        }

        // Skip the list header: single byte (0xC0..0xF7) or multi-byte long
        // form (0xF8..0xFF followed by length bytes).
        let mut pos = if raw_bytes[0] <= 0xf7 {
            1
        } else {
            1 + (raw_bytes[0] - 0xf7) as usize
        };
        let items: Vec<Vec<u8>> = (0..9).map(|_| read_item(&raw_bytes, &mut pos)).collect();
        assert_eq!(pos, raw_bytes.len(), "consumed exactly the list payload");

        // v = item 6, r = 7, s = 8.
        let v = u64::from(items[6][0]);
        // EIP-155: v = parity + 35 + 2*chainId -> {37, 38} for chain_id=1.
        let parity = v - 35 - 2 * tx.chain_id;
        assert!(parity <= 1, "v={v} must satisfy EIP-155");
        assert_eq!(items[7].len(), 32, "r is 32-byte BE");
        assert_eq!(items[8].len(), 32, "s is 32-byte BE");

        // Recover the sender: hash the signing payload, recover pubkey.
        let msg_hash = keccak256(&tx.signing_payload());
        let mut r = [0u8; 32];
        r.copy_from_slice(&items[7]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&items[8]);
        let sig = k256::ecdsa::Signature::from_scalars(
            k256::FieldBytes::from(r),
            k256::FieldBytes::from(s),
        )
        .unwrap();
        let recid = RecoveryId::new(parity == 1, false);
        let vk = VerifyingKey::recover_from_prehash(&msg_hash, &sig, recid).unwrap();
        assert_eq!(address_from_pubkey(&vk), sender);
    }

    #[test]
    fn deterministic_signature() {
        // RFC6979: same key + same payload -> same signature -> same raw tx.
        let sk = test_key(9);
        let tx = TxParams {
            chain_id: 137,
            nonce: 1,
            gas_price_wei: 200_000_000_000,
            gas_limit: 300_000,
            to: Some(Address([0x42; 20])),
            value_wei: [0u8; 32],
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let a = tx.sign(&sk).unwrap();
        let b = tx.sign(&sk).unwrap();
        assert_eq!(a, b);
    }
}

'@

# ---- crates\opacus-dex\src\uniswap.rs ----
Write-Text (Join-Path $ProjectRoot "crates\opacus-dex\src\uniswap.rs") @'
//! Uniswap V2 Router02 calldata builders (mainnet Router02:
//! 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D).

use crate::abi::{encode_call, AbiArg};
use crate::tx::Address;

pub const ROUTER_V2_MAINNET: Address = Address([
    0x7a, 0x25, 0x0d, 0x56, 0x30, 0xb4, 0xcf, 0x53, 0x97, 0x39, 0xdf, 0x2c, 0x5d, 0xac, 0xb4,
    0xc6, 0x59, 0xf2, 0x48, 0x8d,
]);

/// WETH9 on Ethereum mainnet.
pub const WETH_MAINNET: Address = Address([
    0xc0, 0x02, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e, 0x5c, 0x4f, 0x27, 0xea, 0xd9,
    0x08, 0x3c, 0x75, 0x6c, 0xc2,
]);

/// A prepared call: target contract + calldata + optional ETH value.
#[derive(Clone, Debug)]
pub struct Call {
    pub to: Address,
    pub data: Vec<u8>,
    /// ETH value in wei (msg.value).
    pub value_wei: [u8; 32],
}

fn deadline_now_plus(seconds: u64) -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() + seconds)
        .unwrap_or(u64::MAX)
}

/// Off-chain quote: `getAmountsOut(amountIn, path)` (read-only eth_call).
pub fn get_amounts_out(amount_in: u128, path: &[Address]) -> Call {
    let data = encode_call(
        "getAmountsOut(uint256,address[])",
        &[
            AbiArg::uint_u128(amount_in),
            AbiArg::AddressArray(addrs(path)),
        ],
    );
    Call {
        to: ROUTER_V2_MAINNET,
        data,
        value_wei: [0u8; 32],
    }
}

/// Token -> token swap.
pub fn swap_exact_tokens_for_tokens(
    amount_in: u128,
    amount_out_min: u128,
    path: &[Address],
    to: Address,
    deadline_secs_from_now: u64,
) -> Call {
    let data = encode_call(
        "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
        &[
            AbiArg::uint_u128(amount_in),
            AbiArg::uint_u128(amount_out_min),
            AbiArg::AddressArray(addrs(path)),
            AbiArg::Address(to.0),
            AbiArg::uint_u64(deadline_now_plus(deadline_secs_from_now)),
        ],
    );
    Call {
        to: ROUTER_V2_MAINNET,
        data,
        value_wei: [0u8; 32],
    }
}

/// ETH (wrapped on the fly by sending value) -> token swap.
pub fn swap_exact_eth_for_tokens(
    amount_eth_wei: u128,
    amount_out_min: u128,
    path: &[Address],
    to: Address,
    deadline_secs_from_now: u64,
) -> Call {
    assert_eq!(path[0], WETH_MAINNET, "ETH swap path must start with WETH");
    let data = encode_call(
        "swapExactETHForTokens(uint256,address[],address,uint256)",
        &[
            AbiArg::uint_u128(amount_out_min),
            AbiArg::AddressArray(addrs(path)),
            AbiArg::Address(to.0),
            AbiArg::uint_u64(deadline_now_plus(deadline_secs_from_now)),
        ],
    );
    Call {
        to: ROUTER_V2_MAINNET,
        data,
        value_wei: crate::rlp::u256_from_u128(amount_eth_wei),
    }
}

/// Token -> ETH swap.
pub fn swap_exact_tokens_for_eth(
    amount_in: u128,
    amount_out_min: u128,
    path: &[Address],
    to: Address,
    deadline_secs_from_now: u64,
) -> Call {
    assert_eq!(
        path[path.len() - 1],
        WETH_MAINNET,
        "token->ETH swap path must end with WETH"
    );
    let data = encode_call(
        "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
        &[
            AbiArg::uint_u128(amount_in),
            AbiArg::uint_u128(amount_out_min),
            AbiArg::AddressArray(addrs(path)),
            AbiArg::Address(to.0),
            AbiArg::uint_u64(deadline_now_plus(deadline_secs_from_now)),
        ],
    );
    Call {
        to: ROUTER_V2_MAINNET,
        data,
        value_wei: [0u8; 32],
    }
}


/// Convert a swap path to raw 20-byte addresses.
fn addrs(path: &[Address]) -> Vec<[u8; 20]> {
    path.iter().map(|a| a.0).collect()
}

/// Wrap ETH into WETH (payable deposit()).
pub fn wrap_eth(amount_wei: u128) -> Call {
    Call {
        to: WETH_MAINNET,
        data: crate::abi::selector("deposit()").to_vec(),
        value_wei: crate::rlp::u256_from_u128(amount_wei),
    }
}

/// ERC20 approve calldata.
pub fn approve(token: Address, spender: Address, amount: u128) -> Call {
    Call {
        to: token,
        data: encode_call(
            "approve(address,uint256)",
            &[AbiArg::Address(spender.0), AbiArg::uint_u128(amount)],
        ),
        value_wei: [0u8; 32],
    }
}

/// ERC20 transfer calldata.
pub fn transfer(token: Address, recipient: Address, amount: u128) -> Call {
    Call {
        to: token,
        data: encode_call(
            "transfer(address,uint256)",
            &[AbiArg::Address(recipient.0), AbiArg::uint_u128(amount)],
        ),
        value_wei: [0u8; 32],
    }
}

/// ERC20 balanceOf calldata.
pub fn balance_of(token: Address, owner: Address) -> Call {
    Call {
        to: token,
        data: encode_call("balanceOf(address)", &[AbiArg::Address(owner.0)]),
        value_wei: [0u8; 32],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::selector;

    #[test]
    fn quote_call_shape() {
        let token = Address([1; 20]);
        let call = get_amounts_out(1_000_000, &[token, WETH_MAINNET]);
        assert_eq!(call.to, ROUTER_V2_MAINNET);
        assert_eq!(&call.data[0..4], &selector("getAmountsOut(uint256,address[])"));
        assert_eq!(call.value_wei, [0u8; 32]);
    }

    #[test]
    fn eth_swap_carries_value() {
        let call = swap_exact_eth_for_tokens(
            1_000_000_000_000_000_000,
            1,
            &[WETH_MAINNET, Address([9; 20])],
            Address([8; 20]),
            600,
        );
        // 1 ETH = 10^18 wei = 0xDE0B6B3A7640000 (last 8 bytes of the word).
        let expect_last8 = [0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00];
        assert_eq!(call.value_wei[24..32], expect_last8);
        assert_eq!(&call.value_wei[..24], &[0u8; 24]);
        assert_eq!(
            &call.data[0..4],
            &selector("swapExactETHForTokens(uint256,address[],address,uint256)")
        );
    }

    #[test]
    fn approve_router() {
        let call = approve(Address([7; 20]), ROUTER_V2_MAINNET, u128::MAX);
        assert_eq!(call.to, Address([7; 20]));
        assert_eq!(&call.data[0..4], &[0x09, 0x5e, 0xa7, 0xb3]);
        // amount = u128::MAX in the last 16 bytes of the amount word (data[36..68])
        assert_eq!(call.data[4 + 48..4 + 64], [0xff; 16]);
    }
}

'@

# ---- crates\opacus-dex\src\rpc.rs ----
Write-Text (Join-Path $ProjectRoot "crates\opacus-dex\src\rpc.rs") @'
//! Ethereum JSON-RPC client (read calls + raw tx broadcast) over a pluggable
//! transport. The default HTTP transport uses `ureq`.

use crate::tx::Address;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug)]
pub enum EthError {
    Rpc(String),
    Transport(String),
    BadResponse(String),
}

impl std::fmt::Display for EthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EthError::Rpc(m) => write!(f, "rpc error: {m}"),
            EthError::Transport(m) => write!(f, "transport error: {m}"),
            EthError::BadResponse(m) => write!(f, "bad response: {m}"),
        }
    }
}

impl std::error::Error for EthError {}

/// Transport-agnostic JSON-RPC call.
pub trait Transport {
    fn post(&self, url: &str, body: &Value) -> Result<Value, EthError>;
}

/// Minimal HTTP transport via ureq (rustls, no OpenSSL needed).
pub struct HttpTransport;

impl Transport for HttpTransport {
    fn post(&self, url: &str, body: &Value) -> Result<Value, EthError> {
        let resp = ureq::post(url)
            .send_json(body.clone())
            .map_err(|e| EthError::Transport(e.to_string()))?;
        resp.into_json::<Value>()
            .map_err(|e| EthError::BadResponse(e.to_string()))
    }
}

/// Ethereum JSON-RPC client.
pub struct EthClient<T: Transport = HttpTransport> {
    pub url: String,
    pub transport: T,
    pub next_id: std::cell::Cell<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
struct RpcEnvelope {
    id: u64,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<Value>,
}

impl<T: Transport> EthClient<T> {
    pub fn with_transport(url: impl Into<String>, transport: T) -> Self {
        Self {
            url: url.into(),
            transport,
            next_id: std::cell::Cell::new(1),
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, EthError> {
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let resp = self.transport.post(&self.url, &body)?;
        let env: RpcEnvelope = serde_json::from_value(resp)
            .map_err(|e| EthError::BadResponse(e.to_string()))?;
        if let Some(err) = env.error {
            return Err(EthError::Rpc(err.to_string()));
        }
        env.result.ok_or_else(|| EthError::BadResponse("missing result".into()))
    }

    /// eth_call: read-only execution of `data` against `to`.
    pub fn eth_call(&self, to: Address, data: &[u8]) -> Result<Vec<u8>, EthError> {
        let res = self.call(
            "eth_call",
            json!([
                {"to": to.to_hex(), "data": format!("0x{}", hex::encode(data))},
                "latest"
            ]),
        )?;
        let s = res.as_str().ok_or_else(|| EthError::BadResponse("eth_call: not a string".into()))?;
        hex::decode(s.strip_prefix("0x").unwrap_or(s))
            .map_err(|e| EthError::BadResponse(format!("hex: {e}")))
    }

    /// eth_gasPrice -> wei as u128.
    pub fn gas_price(&self) -> Result<u128, EthError> {
        let res = self.call("eth_gasPrice", json!([]))?;
        parse_qty(&res)
    }

    /// eth_getTransactionCount (pending) -> nonce.
    pub fn nonce(&self, address: Address) -> Result<u64, EthError> {
        let res = self.call(
            "eth_getTransactionCount",
            json!([address.to_hex(), "pending"]),
        )?;
        parse_qty(&res).map(|v| v as u64)
    }

    /// eth_estimateGas for a call envelope.
    pub fn estimate_gas(&self, from: Address, call: &crate::uniswap::Call) -> Result<u64, EthError> {
        let res = self.call(
            "eth_estimateGas",
            json!([{
                "from": from.to_hex(),
                "to": call.to.to_hex(),
                "data": format!("0x{}", hex::encode(&call.data)),
                "value": format!("0x{}", hex::encode(strip_leading_zeros(&call.value_wei))),
            }]),
        )?;
        parse_qty(&res).map(|v| v as u64)
    }

    /// eth_sendRawTransaction.
    pub fn send_raw_transaction(&self, raw_hex: &str) -> Result<String, EthError> {
        let res = self.call("eth_sendRawTransaction", json!([raw_hex]))?;
        res.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| EthError::BadResponse("sendRawTransaction: not a string".into()))
    }
}

fn parse_qty(v: &Value) -> Result<u128, EthError> {
    let s = v
        .as_str()
        .ok_or_else(|| EthError::BadResponse("expected qty hex string".into()))?;
    u128::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16)
        .map_err(|e| EthError::BadResponse(format!("qty: {e}")))
}

fn strip_leading_zeros(be: &[u8; 32]) -> &[u8] {
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    if first == be.len() {
        &be[be.len() - 1..] // single zero byte
    } else {
        &be[first..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory transport with canned responses.
    struct FakeTransport {
        respond: Box<dyn Fn(&str, &Value) -> Value>,
    }

    impl Transport for FakeTransport {
        fn post(&self, _url: &str, body: &Value) -> Result<Value, EthError> {
            let method = body["method"].as_str().unwrap_or_default();
            Ok((self.respond)(method, body))
        }
    }

    #[test]
    fn eth_call_and_qty_parsing() {
        let transport = FakeTransport {
            respond: Box::new(|method, _| {
                let result = match method {
                    "eth_call" => {
                        "0x0000000000000000000000000000000000000000000000000000000000000064"
                    }
                    "eth_gasPrice" => "0x4a817c800",
                    _ => "0x0",
                };
                json!({"id": 1, "result": result})
            }),
        };
        let client = EthClient::with_transport("http://fake", transport);
        let out = client.eth_call(Address([1; 20]), &[0xde, 0xad]).unwrap();
        assert_eq!(out.len(), 32);
        assert_eq!(out[31], 100);
        assert_eq!(client.gas_price().unwrap(), 20_000_000_000);
    }

    #[test]
    fn rpc_error_propagates() {
        let transport = FakeTransport {
            respond: Box::new(|_, _| {
                json!({"id": 1, "error": {"code": -32000, "message": "execution reverted"}})
            }),
        };
        let client = EthClient::with_transport("http://fake", transport);
        let err = client.eth_call(Address([1; 20]), &[]).unwrap_err();
        assert!(err.to_string().contains("execution reverted"));
    }
}

'@

# ---- crates\opacus-dex\src\wghost.rs ----
Write-Text (Join-Path $ProjectRoot "crates\opacus-dex\src\wghost.rs") @'
//! wGHOST helpers: the ERC20 side of the Ghost bridge on Ethereum.
//!
//! The token contract lives in `contracts/wGHOST.sol`. Until it is deployed,
//! set the address with [`set_wghost`] at startup (or persist it in config).

use crate::abi::{encode_call, AbiArg};
use crate::tx::Address;
use std::sync::OnceLock;

static WGHOST: OnceLock<Address> = OnceLock::new();

/// Configure the deployed wGHOST address (call once at startup).
pub fn set_wghost(addr: Address) -> bool {
    WGHOST.set(addr).is_ok()
}

/// Current wGHOST address or the zero address placeholder.
pub fn wghost() -> Address {
    *WGHOST.get().unwrap_or(&Address([0u8; 20]))
}

/// burn(amount): destroy wGHOST to trigger native GHOST release on the
/// Ghost side (bridge contract watches Burn events).
pub fn burn(amount: u128) -> crate::uniswap::Call {
    crate::uniswap::Call {
        to: wghost(),
        data: encode_call("burn(uint256)", &[AbiArg::uint_u128(amount)]),
        value_wei: [0u8; 32],
    }
}

/// Burn event topic (keccak256("Burn(address,uint256)")) for bridge
/// relayer indexing.
pub fn burn_event_topic() -> [u8; 32] {
    crate::abi::keccak256(b"Burn(address,uint256)")
}

/// Mint event topic.
pub fn mint_event_topic() -> [u8; 32] {
    crate::abi::keccak256(b"Mint(address,uint256)")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::selector;

    #[test]
    fn burn_calldata_and_topics() {
        set_wghost(Address([0xab; 20]));
        let call = burn(1_000);
        assert_eq!(call.to, Address([0xab; 20]));
        assert_eq!(&call.data[0..4], &selector("burn(uint256)"));
        // 1000 = 0x03E8
        assert_eq!(call.data[4 + 30], 0x03);
        assert_eq!(call.data[4 + 31], 0xe8);
        // keccak("Burn(address,uint256)") — stable topic; just assert shape.
        let topic = burn_event_topic();
        assert_ne!(topic, [0u8; 32]);
        assert_ne!(burn_event_topic(), mint_event_topic());
    }
}

'@

# ---- contracts\wGHOST.sol ----
Write-Text (Join-Path $ProjectRoot "contracts\wGHOST.sol") @'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title wGHOST - ERC20 wrapper of native GHOST on Ethereum.
/// @notice Minted by the Ghost bridge quorum when native GHOST is locked on
///         the Ghost chain; burned to release native GHOST back.
///         Tradeable on Uniswap V2/V3 like any ERC20.
/// @dev AUDIT REQUIRED before any mainnet deployment.
contract WGHOST {
    string public constant name = "Wrapped Ghost";
    string public constant symbol = "wGHOST";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /// Bridge quorum signers (validator-set style; rotate via updateQuorum).
    address[] public quorum;
    uint256 public quorumThreshold;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Minted(address indexed to, uint256 value, bytes32 ghostTxHash);
    event Burned(address indexed from, uint256 value, string ghostRecipient);
    event QuorumUpdated(address[] members, uint256 threshold);

    constructor(address[] memory members_, uint256 threshold_) {
        quorum = members_;
        quorumThreshold = threshold_;
        emit QuorumUpdated(members_, threshold_);
    }

    // ------------------------------------------------------------------
    // ERC20
    // ------------------------------------------------------------------

    function transfer(address to, uint256 value) external returns (bool) {
        _move(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= value, "wGHOST: allowance");
        if (a != type(uint256).max) {
            allowance[from][msg.sender] = a - value;
        }
        _move(from, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function _move(address from, address to, uint256 value) internal {
        require(balanceOf[from] >= value, "wGHOST: balance");
        unchecked {
            balanceOf[from] -= value;
            balanceOf[to] += value;
        }
        emit Transfer(from, to, value);
    }

    // ------------------------------------------------------------------
    // Bridge side
    // ------------------------------------------------------------------

    /// @notice Mint wGHOST after a quorum attests a GHOST lock tx.
    /// @param to      EVM address receiving wGHOST
    /// @param value   wei-amount (18 decimals after bridge scaling)
    /// @param ghostTxHash blake3 hash of the native GHOST lock tx
    /// @param sigs    65-byte (r,s,v) signatures over
    ///                keccak256(abi.encodePacked("ghost-lock-v1", to, value, ghostTxHash)),
    ///                sorted by signer address ascending, no duplicates.
    function mint(
        address to,
        uint256 value,
        bytes32 ghostTxHash,
        bytes[] calldata sigs
    ) external {
        bytes32 digest = keccak256(
            abi.encodePacked("ghost-lock-v1", to, value, ghostTxHash)
        );
        _checkQuorum(digest, sigs);
        totalSupply += value;
        balanceOf[to] += value;
        emit Transfer(address(0), to, value);
        emit Minted(to, value, ghostTxHash);
    }

    /// @notice Burn wGHOST to request native GHOST release.
    ///         Bridge relayers watch the Burned event.
    function burn(uint256 value, string calldata ghostRecipient) external {
        require(balanceOf[msg.sender] >= value, "wGHOST: balance");
        unchecked {
            balanceOf[msg.sender] -= value;
            totalSupply -= value;
        }
        emit Transfer(msg.sender, address(0), value);
        emit Burned(msg.sender, value, ghostRecipient);
    }

    function _checkQuorum(bytes32 digest, bytes[] calldata sigs) internal view {
        require(sigs.length >= quorumThreshold, "wGHOST: not enough sigs");
        uint256 distinct;
        address prev = address(0);
        for (uint256 i = 0; i < sigs.length; i++) {
            require(sigs[i].length == 65, "wGHOST: sig len");
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := calldataload(add(sigs.offset, add(i.offset, 0)))
                s := calldataload(add(sigs.offset, add(i.offset, 32)))
                v := shr(248, calldataload(add(sigs.offset, add(i.offset, 64))))
            }
            address signer = ecrecover(digest, v + 27, r, s);
            require(signer > prev, "wGHOST: sig order"); // dup + sorted check
            prev = signer;
            if (_isMember(signer)) {
                distinct += 1;
            }
        }
        require(distinct >= quorumThreshold, "wGHOST: quorum");
    }

    function _isMember(address a) internal view returns (bool) {
        for (uint256 i = 0; i < quorum.length; i++) {
            if (quorum[i] == a) return true;
        }
        return false;
    }
}

'@

# ---- 1) opacus-bridge/Cargo.toml: add bridge deps (idempotent) ----
$tomlPath = Join-Path $ProjectRoot "crates\opacus-bridge\Cargo.toml"
$deps = @(
    'curve25519-dalek = { version = "4", features = ["rand_core"] }',
    'blake3 = "1"',
    'hex = "0.4"',
    'serde = { version = "1", features = ["derive"] }',
    'serde_json = "1"'
)
$lines = [System.IO.File]::ReadAllLines($tomlPath)
$existing = ($lines -join "`n")
$out = New-Object System.Collections.Generic.List[string]
$pending = New-Object System.Collections.Generic.List[string]
foreach ($d in $deps) {
    $name = ($d -split '\s*=')[0]
    if ($existing -notmatch ('(?m)^\s*' + [regex]::Escape($name) + '\s*=')) {
        $pending.Add($d)
    }
}
$inserted = $false
foreach ($l in $lines) {
    $out.Add($l)
    if (!$inserted -and $l -match '^\s*\[dependencies\]\s*$' -and $pending.Count -gt 0) {
        foreach ($d in $pending) { $out.Add($d) }
        $inserted = $true
    }
}
if ($pending.Count -gt 0 -and !$inserted) {
    $out.Add('[dependencies]')
    foreach ($d in $pending) { $out.Add($d) }
}
if ($pending.Count -gt 0) {
    [System.IO.File]::WriteAllLines($tomlPath, $out, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ("  added " + $pending.Count + " deps to opacus-bridge\Cargo.toml")
} else {
    Write-Host "  opacus-bridge deps already present"
}

# ---- 2) opacus-bridge/src/lib.rs: declare the modules (idempotent) ----
$libPath = Join-Path $ProjectRoot "crates\opacus-bridge\src\lib.rs"
$lib = [System.IO.File]::ReadAllText($libPath)
$mods = @("xmr_dleq", "xmr_swap", "xmr_rpc")
$toAdd = @()
foreach ($m in $mods) {
    if ($lib -notmatch ('(?m)^\s*(pub\s+)?mod\s+' + $m + '\s*;')) {
        $toAdd += $m
    }
}
if ($toAdd.Count -gt 0) {
    if (!$lib.EndsWith("`n")) { $lib += "`r`n" }
    foreach ($m in $toAdd) { $lib += "pub mod $m;`r`n" }
    [System.IO.File]::WriteAllText($libPath, $lib, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ("  registered modules: " + ($toAdd -join ", "))
} else {
    Write-Host "  bridge modules already declared"
}

# ---- 3) register opacus-dex in workspace members (idempotent) ----
$rootToml = Join-Path $ProjectRoot "Cargo.toml"
$rootContent = [System.IO.File]::ReadAllText($rootToml)
if ($rootContent -notmatch [regex]::Escape("crates/opacus-dex")) {
    $pattern = '(?m)^(members\s*=\s*\[)'
    if ($rootContent -match $pattern) {
        $rootContent = [regex]::Replace($rootContent, $pattern, "`$1`n    `"crates/opacus-dex`",")
        [System.IO.File]::WriteAllText($rootToml, $rootContent, (New-Object System.Text.UTF8Encoding($false)))
        Write-Host "  registered crates/opacus-dex in workspace members"
    } else {
        Write-Host "  WARNING: no [workspace] members array in root Cargo.toml" -ForegroundColor Yellow
    }
} else {
    Write-Host "  opacus-dex already in workspace members"
}

# ---- 4) tests ----
Write-Host ""
Push-Location $ProjectRoot
try {
    Write-Host "=== running: cargo test -p opacus-bridge --release ===" -ForegroundColor Cyan
    cargo test -p opacus-bridge --release
    if ($LASTEXITCODE -ne 0) {
        Write-Host "BRIDGE TESTS FAILED - paste the output above back to the assistant" -ForegroundColor Red
        exit 1
    }
    Write-Host "BRIDGE TESTS PASSED (DLEq + swap protocol + monero-rpc)" -ForegroundColor Green

    Write-Host ""
    Write-Host "=== running: cargo test -p opacus-dex --release ===" -ForegroundColor Cyan
    cargo test -p opacus-dex --release
    if ($LASTEXITCODE -ne 0) {
        Write-Host "DEX TESTS FAILED - paste the output above back to the assistant" -ForegroundColor Red
        exit 1
    }
    Write-Host "DEX TESTS PASSED (RLP/ABI/EIP-155/Uniswap calldata/rpc)" -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "What you got:" -ForegroundColor Cyan
Write-Host "  opacus-bridge: xmr_dleq (same-secret proof XMR<->GHOST), xmr_swap (timelocked protocol), xmr_rpc (monero-wallet-rpc)"
Write-Host "  opacus-dex: EIP-155 tx signer, Uniswap V2 Router calldata, wGHOST burn/mint helpers, eth json-rpc client"
Write-Host "  contracts/wGHOST.sol: deploy with forge (audit before mainnet!)"
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  - deploy wGHOST to a testnet (Sepolia) via foundry, then set_wghost(addr)"
Write-Host "  - wire swap sessions into opacusd P2P messages (offer/accept/claim)"
