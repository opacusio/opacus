//! Opacus Network Layer
pub mod p2p;

pub use net_node::{NetEvent, NetNode, NetNodeConfig, NetNodeError};
pub use notes::{open_note, seal_note, NoteBlob, NoteError, NoteInbox};
pub use p2p::{NetworkConfig, PeerInfo};
pub use peers::{PeerStore, PeerStoreError, PeerStoreLoad};
pub mod gov_channel;
pub mod handshake;
pub mod identity;
pub mod net_node;
pub mod notes;
pub mod peers;
pub mod swap_node;

// GIP-2 WP-D2c: the gossip envelope channel (GBE1 frames over the v5
// note path; the WP-3 delivery-note deferral). Key surface re-exported
// for the wallet/collector callers.
pub use gov_channel::{
    chunk_stream, feed_note, frames_of, parse_chunk, seal_stream, GovAssembler, GovChannelError,
    GovChunkHeader, GOV_CHANNEL_MAGIC, GOV_CHANNEL_VERSION, GOV_CHUNK_DATA_MAX,
    GOV_CHUNK_HEADER_LEN, GOV_MAX_CHUNKS, GOV_MAX_STREAM_BYTES,
};
