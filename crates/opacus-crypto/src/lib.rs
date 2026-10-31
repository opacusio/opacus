//! Ghost Cryptographic Primitives
pub mod commitment;
pub mod ecies;
pub mod keys;
pub mod stealth;

pub use commitment::Commitment;
pub use curve25519_dalek::ristretto::CompressedRistretto;
pub use ecies::{note_keypair_from_seed, open_enote, seal_enote, EnoteError, EnoteV1, NoteSecret};
pub use keys::SpendingKey;
pub use stealth::{PublicAddress, RecipientKeys, StealthAddress};

pub const PROTOCOL_VERSION: u8 = 1;
pub const GHOST_ATOMS_PER_UNIT: u64 = 1_000_000_000;
