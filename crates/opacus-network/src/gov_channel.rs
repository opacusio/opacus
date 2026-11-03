//! GIP-2 WP-D2c: the gossip envelope channel - GBE1 ballot frames
//! carried over the v5 note path.
//!
//! This closes the WP-3 delivery-note deferral ("Envelope ids ... are
//! defined for v5 gossip relay dedupe; wiring the gossip channel is
//! node-integration work"): the v5 note feed (`crate::notes`) moves
//! opaque sealed payloads of at most [`NOTE_PAYLOAD_MAX`] bytes per
//! blob, while one GBE1 ballot envelope at the rehearsal depth is
//! ~22.7 KB. The channel bridges the two with a deterministic chunk
//! layout and a bounded reassembler:
//!
//! * the SENDER chunks the envelope wire (`chunk_stream`), seals every
//!   chunk to the collector node identity with the ordinary note ECIES
//!   (`seal_stream` -> `seal_note`), and ships the blobs in `Notes`
//!   frames (at most [`NOTES_MAX_COUNT`] per frame, `frames_of`);
//! * the network never interprets the chunks: a chunk is an opaque note
//!   payload, stored and relayed exactly like any other note. The chunk
//!   header lives INSIDE the sealed payload, so only the collector sees
//!   it;
//! * the COLLECTOR opens every inbox blob addressed to it (`feed_note`),
//!   parses the chunk header and feeds [`GovAssembler`], which
//!   reassembles streams keyed by the 32-byte `stream_id` - the caller
//!   passes the ballot `envelope_id` (the WG-29 id digest under the
//!   ballot tags), so the envelope-level dedupe is exact: a byte-equal
//!   retransmission of an already-delivered envelope - even relayed
//!   over different paths with different blob ids - re-opens to the
//!   same chunk bytes and is dropped by the assembler (`Ok(None)`).
//!
//! Fail-closed discipline (mirrors the note feed): structural chunk
//! violations on a payload that DID open for this collector are hard
//! errors (never silently dropped); payloads that do not open, or open
//! without the channel magic, are simply not gov chunks (`Ok(None)`) -
//! the collector's inbox deliberately carries relayed third-party
//! traffic. Every completed stream is checksummed (blake3 over the full
//! payload, identical in every chunk header) before it is emitted: a
//! chunk belonging to no honest stream can never complete one. Memory
//! is bounded on every axis: bytes per chunk blob, chunks per stream,
//! live streams and the completed-stream dedupe window are all capped.
//!
//! std-only; no new dependencies (blake3 and the note feed are already
//! here).

use std::collections::{HashMap, HashSet, VecDeque};

use blake3::Hasher;
use curve25519_dalek::ristretto::CompressedRistretto;

use crate::identity::NodeIdentity;
use crate::notes::{open_note, seal_note, NoteBlob, NoteError, NOTES_MAX_COUNT};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Channel magic at the head of every chunk payload (inside the sealed
/// note payload - only the collector parses it).
pub const GOV_CHANNEL_MAGIC: [u8; 4] = *b"GOV1";
/// Chunk layout version.
pub const GOV_CHANNEL_VERSION: u8 = 1;
/// Header: magic 4 | version 1 | total le16 | index le16 | stream_id 32
/// | payload hash 32.
pub const GOV_CHUNK_HEADER_LEN: usize = 4 + 1 + 2 + 2 + 32 + 32;
/// Chunk data budget: the note payload cap minus the header. Every chunk
/// except the last carries exactly this many bytes (canonical chunking),
/// so one payload maps to ONE deterministic chunk set.
pub const GOV_CHUNK_DATA_MAX: usize = crate::notes::NOTE_PAYLOAD_MAX - GOV_CHUNK_HEADER_LEN;
/// Hard cap on chunks per stream: 256 * [`GOV_CHUNK_DATA_MAX`] = 112,640
/// bytes of envelope - the DEPTH=32 GBE1 frame (~22.7 KB) uses 52.
pub const GOV_MAX_CHUNKS: usize = 256;
/// Largest stream the channel accepts.
pub const GOV_MAX_STREAM_BYTES: usize = GOV_MAX_CHUNKS * GOV_CHUNK_DATA_MAX;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from chunking, parsing or reassembling a gov stream. Only
/// raised for payloads that opened for THIS collector and carry the
/// channel magic - anything else is not a gov chunk by definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovChannelError {
    /// The stream payload is empty; a stream is 1..=`GOV_MAX_STREAM_BYTES`.
    EmptyStream,
    /// The stream payload exceeds [`GOV_MAX_STREAM_BYTES`].
    StreamTooLarge(usize),
    /// A chunk data section exceeds [`GOV_CHUNK_DATA_MAX`].
    ChunkTooLarge(usize),
    /// More than [`GOV_MAX_CHUNKS`] chunks would be needed.
    TooManyChunks { needed: usize },
    /// Chunk `index` outside `0..total`, or a zero total.
    IndexOutOfRange { index: usize, total: usize },
    /// A chunk claims the channel magic but carries an unknown version.
    BadChunkVersion(u8),
    /// A non-final chunk that is not exactly [`GOV_CHUNK_DATA_MAX`] bytes
    /// (the canonical chunking is the only accepted one).
    ChunkNotCanonical { index: usize, len: usize },
    /// Two different (total, hash) descriptions of one stream id.
    StreamConflict,
    /// More live (incomplete) streams than the assembler cap.
    TooManyStreams(usize),
    /// The reassembled stream does not hash to the announced digest.
    HashMismatch,
    /// The underlying note feed rejected the blob.
    Note(NoteError),
}

impl std::fmt::Display for GovChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GovChannelError::EmptyStream => write!(f, "gov stream payload is empty"),
            GovChannelError::StreamTooLarge(n) => {
                write!(f, "gov stream payload {n} exceeds {GOV_MAX_STREAM_BYTES}")
            }
            GovChannelError::ChunkTooLarge(n) => {
                write!(f, "gov chunk data {n} exceeds {GOV_CHUNK_DATA_MAX}")
            }
            GovChannelError::TooManyChunks { needed } => {
                write!(
                    f,
                    "gov stream needs {needed} chunks, cap is {GOV_MAX_CHUNKS}"
                )
            }
            GovChannelError::IndexOutOfRange { index, total } => {
                write!(f, "gov chunk index {index} outside 0..{total}")
            }
            GovChannelError::BadChunkVersion(v) => {
                write!(
                    f,
                    "gov chunk version {v} unsupported (want {GOV_CHANNEL_VERSION})"
                )
            }
            GovChannelError::ChunkNotCanonical { index, len } => write!(
                f,
                "gov chunk {index} carries {len} bytes; only the final chunk may be short"
            ),
            GovChannelError::StreamConflict => {
                write!(f, "conflicting (total, hash) for one gov stream id")
            }
            GovChannelError::TooManyStreams(cap) => write!(f, "more than {cap} live gov streams"),
            GovChannelError::HashMismatch => {
                write!(f, "reassembled gov stream fails its blake3 digest")
            }
            GovChannelError::Note(e) => write!(f, "note feed: {e}"),
        }
    }
}

impl std::error::Error for GovChannelError {}

impl From<NoteError> for GovChannelError {
    fn from(e: NoteError) -> Self {
        GovChannelError::Note(e)
    }
}

// ---------------------------------------------------------------------------
// Chunk layout
// ---------------------------------------------------------------------------

/// The parsed header of one chunk. `stream_id` is opaque to the network:
/// the wallet layer passes the ballot `envelope_id` (the WG-29 id digest
/// under the ballot tags), which makes the assembler's dedupe exact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovChunkHeader {
    /// Total chunks of the stream (1..=[`GOV_MAX_CHUNKS`]).
    pub total: usize,
    /// This chunk's position, `0..total`.
    pub index: usize,
    /// 32-byte stream id (= the ballot `envelope_id` for GBE1 frames).
    pub stream_id: [u8; 32],
    /// blake3 digest of the WHOLE stream payload - identical in every
    /// chunk of one honest stream.
    pub payload_hash: [u8; 32],
}

fn stream_hash(payload: &[u8]) -> [u8; 32] {
    *Hasher::new().update(payload).finalize().as_bytes()
}

/// Chunk a stream payload into sealed-note-ready plaintexts
/// (header || data). Canonical: one payload maps to exactly one chunk
/// set; every chunk except the last is exactly [`GOV_CHUNK_DATA_MAX`]
/// bytes.
pub fn chunk_stream(payload: &[u8], stream_id: [u8; 32]) -> Result<Vec<Vec<u8>>, GovChannelError> {
    if payload.is_empty() {
        return Err(GovChannelError::EmptyStream);
    }
    if payload.len() > GOV_MAX_STREAM_BYTES {
        return Err(GovChannelError::StreamTooLarge(payload.len()));
    }
    let total = payload.len().div_ceil(GOV_CHUNK_DATA_MAX);
    let hash = stream_hash(payload);
    let mut chunks = Vec::with_capacity(total);
    for index in 0..total {
        let start = index * GOV_CHUNK_DATA_MAX;
        let end = ((index + 1) * GOV_CHUNK_DATA_MAX).min(payload.len());
        chunks.push(encode_chunk(
            &GovChunkHeader {
                total,
                index,
                stream_id,
                payload_hash: hash,
            },
            &payload[start..end],
        ));
    }
    Ok(chunks)
}

/// Serialize header || data. `data` must be 1..=[`GOV_CHUNK_DATA_MAX`]
/// bytes (asserted: honest callers go through [`chunk_stream`], and the
/// reassembler validates again on ingest).
pub fn encode_chunk(h: &GovChunkHeader, data: &[u8]) -> Vec<u8> {
    assert!(
        !data.is_empty() && data.len() <= GOV_CHUNK_DATA_MAX,
        "gov chunk data must be 1..={GOV_CHUNK_DATA_MAX} bytes"
    );
    let mut out = Vec::with_capacity(GOV_CHUNK_HEADER_LEN + data.len());
    out.extend_from_slice(&GOV_CHANNEL_MAGIC);
    out.push(GOV_CHANNEL_VERSION);
    out.extend_from_slice(&(h.total as u16).to_le_bytes());
    out.extend_from_slice(&(h.index as u16).to_le_bytes());
    out.extend_from_slice(&h.stream_id);
    out.extend_from_slice(&h.payload_hash);
    out.extend_from_slice(data);
    out
}

/// Parse one opened note payload. Tri-state:
///
/// * `Ok(None)` - not a gov chunk (different magic or version): ordinary
///   note traffic the collector must ignore;
/// * `Ok(Some((header, data)))` - a well-formed chunk;
/// * `Err` - claims the channel magic but violates the protocol (a hard
///   error, never silently dropped).
pub fn parse_chunk(plain: &[u8]) -> Result<Option<(GovChunkHeader, Vec<u8>)>, GovChannelError> {
    if plain.len() < GOV_CHUNK_HEADER_LEN || plain[..4] != GOV_CHANNEL_MAGIC {
        return Ok(None);
    }
    if plain[4] != GOV_CHANNEL_VERSION {
        return Err(GovChannelError::BadChunkVersion(plain[4]));
    }
    let total = u16::from_le_bytes([plain[5], plain[6]]) as usize;
    let index = u16::from_le_bytes([plain[7], plain[8]]) as usize;
    let mut stream_id = [0u8; 32];
    stream_id.copy_from_slice(&plain[9..41]);
    let mut payload_hash = [0u8; 32];
    payload_hash.copy_from_slice(&plain[41..73]);
    let h = GovChunkHeader {
        total,
        index,
        stream_id,
        payload_hash,
    };
    let data = plain[GOV_CHUNK_HEADER_LEN..].to_vec();
    validate_chunk(&h, &data)?;
    Ok(Some((h, data)))
}

fn validate_chunk(h: &GovChunkHeader, data: &[u8]) -> Result<(), GovChannelError> {
    if h.total == 0 || h.total > GOV_MAX_CHUNKS {
        return Err(GovChannelError::IndexOutOfRange {
            index: h.index,
            total: h.total,
        });
    }
    if h.index >= h.total {
        return Err(GovChannelError::IndexOutOfRange {
            index: h.index,
            total: h.total,
        });
    }
    if data.is_empty() {
        return Err(GovChannelError::ChunkNotCanonical {
            index: h.index,
            len: 0,
        });
    }
    if data.len() > GOV_CHUNK_DATA_MAX {
        return Err(GovChannelError::ChunkTooLarge(data.len()));
    }
    if h.index != h.total - 1 && data.len() != GOV_CHUNK_DATA_MAX {
        return Err(GovChannelError::ChunkNotCanonical {
            index: h.index,
            len: data.len(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sender side
// ---------------------------------------------------------------------------

/// Chunk + seal a stream to the collector node identity: the sender-side
/// one-liner. The chunks ride ordinary `Notes` frames - batch them with
/// [`frames_of`].
pub fn seal_stream(
    payload: &[u8],
    stream_id: [u8; 32],
    collector: &CompressedRistretto,
) -> Result<Vec<NoteBlob>, GovChannelError> {
    chunk_stream(payload, stream_id)?
        .iter()
        .map(|c| seal_note(c, collector).map_err(GovChannelError::Note))
        .collect()
}

/// Split sealed blobs into `Notes`-frame-sized batches
/// ([`NOTES_MAX_COUNT`] per frame).
pub fn frames_of(blobs: &[NoteBlob]) -> Vec<Vec<NoteBlob>> {
    blobs
        .chunks(NOTES_MAX_COUNT)
        .map(<[NoteBlob]>::to_vec)
        .collect()
}

// ---------------------------------------------------------------------------
// Reassembler
// ---------------------------------------------------------------------------

struct LiveStream {
    total: usize,
    payload_hash: [u8; 32],
    received: usize,
    slots: Vec<Option<Vec<u8>>>,
}

/// Bounded reassembler of gov streams. Keyed by the 32-byte `stream_id`;
/// a completed stream is closed (the `seen` window) so retransmissions -
/// including byte-equal envelope re-drops arriving over different relay
/// paths with different blob ids - never emit twice. All memory is
/// bounded: live streams, chunks per stream and the dedupe window are
/// capped.
pub struct GovAssembler {
    max_streams: usize,
    seen_cap: usize,
    live: HashMap<[u8; 32], LiveStream>,
    seen: HashSet<[u8; 32]>,
    seen_order: VecDeque<[u8; 32]>,
    completed: usize,
    duplicates: usize,
}

impl GovAssembler {
    /// `max_streams` live streams at once; `seen_cap` completed stream
    /// ids in the dedupe window.
    pub fn new(max_streams: usize, seen_cap: usize) -> GovAssembler {
        GovAssembler {
            max_streams: max_streams.max(1),
            seen_cap: seen_cap.max(1),
            live: HashMap::new(),
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
            completed: 0,
            duplicates: 0,
        }
    }

    /// Live (incomplete) stream count.
    pub fn live_streams(&self) -> usize {
        self.live.len()
    }

    /// Completed streams since construction.
    pub fn completed_streams(&self) -> usize {
        self.completed
    }

    /// Chunks dropped as retransmissions of already-completed streams.
    pub fn duplicate_chunks(&self) -> usize {
        self.duplicates
    }

    /// Feed one opened chunk. `Ok(Some(payload))` completes the stream
    /// (exactly once per stream id inside the dedupe window); `Ok(None)`
    /// means "kept, not complete" or "already delivered".
    pub fn ingest(
        &mut self,
        h: GovChunkHeader,
        data: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, GovChannelError> {
        validate_chunk(&h, &data)?;
        if self.seen.contains(&h.stream_id) {
            self.duplicates += 1;
            return Ok(None);
        }
        if let Some(s) = self.live.get(&h.stream_id) {
            if s.total != h.total || s.payload_hash != h.payload_hash {
                return Err(GovChannelError::StreamConflict);
            }
        } else if self.live.len() >= self.max_streams {
            return Err(GovChannelError::TooManyStreams(self.max_streams));
        }
        let (total, hash, received) = {
            let s = self.live.entry(h.stream_id).or_insert_with(|| LiveStream {
                total: h.total,
                payload_hash: h.payload_hash,
                received: 0,
                slots: vec![None; h.total],
            });
            if s.slots[h.index].is_none() {
                s.slots[h.index] = Some(data);
                s.received += 1;
            }
            (s.total, s.payload_hash, s.received)
        };
        if received < total {
            return Ok(None);
        }
        // received == total with dedupe-on-empty-slot means every slot
        // is filled exactly once: assemble and verify.
        let mut payload = Vec::with_capacity(total * GOV_CHUNK_DATA_MAX);
        let stream = self.live.remove(&h.stream_id).expect("live entry held");
        for slot in stream.slots {
            payload.extend_from_slice(&slot.expect("received == total fills every slot"));
        }
        if stream_hash(&payload) != hash {
            return Err(GovChannelError::HashMismatch);
        }
        self.mark_seen(h.stream_id);
        self.completed += 1;
        Ok(Some(payload))
    }

    fn mark_seen(&mut self, id: [u8; 32]) {
        if self.seen.insert(id) {
            self.seen_order.push_back(id);
            while self.seen_order.len() > self.seen_cap {
                if let Some(old) = self.seen_order.pop_front() {
                    self.seen.remove(&old);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Collector side
// ---------------------------------------------------------------------------

/// Open one inbox blob as the collector and feed the assembler.
///
/// Any `open_note` failure means "not addressed to me" - the collector's
/// inbox deliberately carries relayed third-party traffic, so that is
/// `Ok(None)`, never an error. A payload that opens but carries no
/// channel magic is ordinary note traffic (`Ok(None)`). A payload that
/// opens AND claims the channel magic but violates the protocol is a
/// hard error.
pub fn feed_note(
    blob: &NoteBlob,
    collector: &NodeIdentity,
    asm: &mut GovAssembler,
) -> Result<Option<Vec<u8>>, GovChannelError> {
    let plain = match open_note(blob, collector) {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };
    match parse_chunk(&plain)? {
        None => Ok(None),
        Some((h, data)) => asm.ingest(h, data),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notes::{NOTES_MAX_HOPS, NOTE_PAYLOAD_MAX};

    fn test_id(seed: u8) -> NodeIdentity {
        let mut buf = [0u8; 32];
        buf[0] = seed;
        buf[31] = seed.wrapping_add(7);
        NodeIdentity::from_secret(curve25519_dalek::scalar::Scalar::from_bytes_mod_order(buf))
    }

    fn test_stream(seed: u8) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(b"gov-channel-test");
        h.update(&[seed]);
        *h.finalize().as_bytes()
    }

    fn deterministic_payload(len: usize, seed: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut ctr: u32 = 0;
        while out.len() < len {
            let mut h = Hasher::new();
            h.update(b"gov-channel-payload");
            h.update(&[seed]);
            h.update(&ctr.to_le_bytes());
            out.extend_from_slice(h.finalize().as_bytes());
            ctr += 1;
        }
        out.truncate(len);
        out
    }

    #[test]
    fn chunk_layout_is_canonical() {
        let sid = test_stream(1);
        for (len, want_chunks) in [
            (1usize, 1usize),
            (GOV_CHUNK_DATA_MAX, 1),
            (GOV_CHUNK_DATA_MAX + 1, 2),
            (GOV_CHUNK_DATA_MAX * 51, 51),
        ] {
            let payload = deterministic_payload(len, 3);
            let chunks = chunk_stream(&payload, sid).unwrap();
            assert_eq!(chunks.len(), want_chunks, "len {len}");
            for (i, c) in chunks.iter().enumerate() {
                let tail = if i == want_chunks - 1 {
                    len - (want_chunks - 1) * GOV_CHUNK_DATA_MAX
                } else {
                    GOV_CHUNK_DATA_MAX
                };
                assert_eq!(c.len(), GOV_CHUNK_HEADER_LEN + tail);
                let (h, data) = parse_chunk(c).unwrap().unwrap();
                assert_eq!(h.total, want_chunks);
                assert_eq!(h.index, i);
                assert_eq!(h.stream_id, sid);
                assert_eq!(
                    data,
                    &payload[i * GOV_CHUNK_DATA_MAX..((i + 1) * GOV_CHUNK_DATA_MAX).min(len)]
                );
            }
            let hash = stream_hash(&payload);
            for c in &chunks {
                let (h, _) = parse_chunk(c).unwrap().unwrap();
                assert_eq!(h.payload_hash, hash);
            }
        }
        // the DEPTH=32 GBE1 shape: 22,686 bytes -> 52 chunks (51 full + tail)
        let gbe1 = deterministic_payload(22_686, 4);
        let chunks = chunk_stream(&gbe1, sid).unwrap();
        assert_eq!(chunks.len(), 52);
        assert_eq!(
            chunks[51].len(),
            GOV_CHUNK_HEADER_LEN + (22_686 - 51 * GOV_CHUNK_DATA_MAX)
        );
    }

    #[test]
    fn chunk_stream_rejects_empty_and_oversize() {
        let sid = test_stream(2);
        assert_eq!(chunk_stream(&[], sid), Err(GovChannelError::EmptyStream));
        let big = deterministic_payload(GOV_MAX_STREAM_BYTES + 1, 5);
        assert_eq!(
            chunk_stream(&big, sid),
            Err(GovChannelError::StreamTooLarge(GOV_MAX_STREAM_BYTES + 1))
        );
    }

    #[test]
    fn assembler_completes_out_of_order_and_byte_exact() {
        let sid = test_stream(6);
        let payload = deterministic_payload(22_686, 7);
        let chunks = chunk_stream(&payload, sid).unwrap();
        let mut asm = GovAssembler::new(8, 64);
        // reversed feed: only the very last chunk completes the stream
        for (i, c) in chunks.iter().enumerate().rev() {
            let (h, data) = parse_chunk(c).unwrap().unwrap();
            let done = asm.ingest(h, data).unwrap();
            if i == 0 {
                assert_eq!(done.as_deref(), Some(payload.as_slice()));
            } else {
                assert!(done.is_none());
            }
        }
        assert_eq!(asm.live_streams(), 0);
        assert_eq!(asm.completed_streams(), 1);
    }

    #[test]
    fn assembler_returns_exact_payload_once() {
        let sid = test_stream(8);
        let payload = deterministic_payload(2_000, 9);
        let chunks = chunk_stream(&payload, sid).unwrap();
        let mut asm = GovAssembler::new(8, 64);
        let mut got = None;
        for (i, c) in chunks.iter().enumerate() {
            let (h, data) = parse_chunk(c).unwrap().unwrap();
            let done = asm.ingest(h, data).unwrap();
            if i == chunks.len() - 1 {
                got = done;
            } else {
                assert!(done.is_none());
            }
        }
        assert_eq!(got.as_deref(), Some(payload.as_slice()));
        // a retransmission of ANY chunk after completion: dropped silently
        let (h, data) = parse_chunk(&chunks[0]).unwrap().unwrap();
        assert_eq!(asm.ingest(h, data).unwrap(), None);
        assert_eq!(asm.duplicate_chunks(), 1);
        assert_eq!(asm.completed_streams(), 1);
    }

    #[test]
    fn assembler_rejects_conflicting_stream_descriptions() {
        let sid = test_stream(10);
        let payload = deterministic_payload(1_000, 11);
        let chunks = chunk_stream(&payload, sid).unwrap();
        let mut asm = GovAssembler::new(8, 64);
        // first chunk establishes the stream
        let (h, data) = parse_chunk(&chunks[0]).unwrap().unwrap();
        asm.ingest(h, data).unwrap();
        // a tampered header (different total) on the same stream id; the
        // data must stay canonical (non-final chunk, full width) so the
        // CONFLICT check is what fires, not the layout check
        let mut bad = parse_chunk(&chunks[1]).unwrap().unwrap().0;
        bad.total = 99;
        assert_eq!(
            asm.ingest(bad, vec![0u8; GOV_CHUNK_DATA_MAX]),
            Err(GovChannelError::StreamConflict)
        );
        // a tampered digest on the same stream id
        let (mut h2, data2) = parse_chunk(&chunks[2]).unwrap().unwrap();
        h2.payload_hash[0] ^= 0x01;
        assert_eq!(asm.ingest(h2, data2), Err(GovChannelError::StreamConflict));
        // the honest stream still completes byte-exact
        for (i, c) in chunks.iter().enumerate().skip(1) {
            let (h, data) = parse_chunk(c).unwrap().unwrap();
            let done = asm.ingest(h, data).unwrap();
            if i == chunks.len() - 1 {
                assert_eq!(done.as_deref(), Some(payload.as_slice()));
            }
        }
    }

    #[test]
    fn parse_chunk_rejects_protocol_violations() {
        let sid = test_stream(12);
        let payload = deterministic_payload(GOV_CHUNK_DATA_MAX + 10, 13);
        let chunks = chunk_stream(&payload, sid).unwrap();
        assert_eq!(chunks.len(), 2);
        // index out of range
        let (mut h, d) = parse_chunk(&chunks[0]).unwrap().unwrap();
        h.index = h.total;
        assert_eq!(
            validate_chunk(&h, &d),
            Err(GovChannelError::IndexOutOfRange {
                index: h.index,
                total: h.total
            })
        );
        // zero total
        let (mut h, d) = parse_chunk(&chunks[0]).unwrap().unwrap();
        h.total = 0;
        assert!(matches!(
            validate_chunk(&h, &d),
            Err(GovChannelError::IndexOutOfRange { .. })
        ));
        // oversize data section
        let (h, d) = parse_chunk(&chunks[0]).unwrap().unwrap();
        let mut big = encode_chunk(&h, &d);
        big.extend_from_slice(&[0u8; 8]);
        assert!(matches!(
            parse_chunk(&big),
            Err(GovChannelError::ChunkTooLarge(_))
        ));
        // non-final short chunk
        let (h, d) = parse_chunk(&chunks[0]).unwrap().unwrap();
        assert_eq!(
            validate_chunk(&h, &d[..5]),
            Err(GovChannelError::ChunkNotCanonical { index: 0, len: 5 })
        );
        // not a gov chunk: magic-less payloads of any shape
        assert_eq!(parse_chunk(b"hello world, not gov"), Ok(None));
        assert_eq!(parse_chunk(b"AB"), Ok(None));
        // wrong version with the magic present: hard error
        let mut v = chunks[0].clone();
        v[4] = 9;
        assert_eq!(parse_chunk(&v), Err(GovChannelError::BadChunkVersion(9)));
    }

    #[test]
    fn assembler_hash_mismatch_drops_the_stream() {
        let sid = test_stream(14);
        let payload = deterministic_payload(GOV_CHUNK_DATA_MAX + 5, 15);
        let mut chunks = chunk_stream(&payload, sid).unwrap();
        // corrupt the FINAL chunk's data; the chunk stays canonical, the
        // stream still assembles, and the announced digest catches it
        let last = chunks.len() - 1;
        let (h, mut data) = parse_chunk(&chunks[last]).unwrap().unwrap();
        data[0] ^= 0x01;
        chunks[last] = encode_chunk(&h, &data);
        let mut asm = GovAssembler::new(8, 64);
        for (i, c) in chunks.iter().enumerate() {
            let (h, data) = parse_chunk(c).unwrap().unwrap();
            match asm.ingest(h, data) {
                Err(GovChannelError::HashMismatch) => assert_eq!(i, last),
                Ok(None) => assert_ne!(i, last),
                other => panic!("unexpected at {i}: {other:?}"),
            }
        }
        assert_eq!(asm.live_streams(), 0, "failed stream is dropped");
        assert_eq!(asm.completed_streams(), 0);
    }

    #[test]
    fn assembler_bounds_live_streams_and_seen_window() {
        let mut asm = GovAssembler::new(2, 2);
        // two live streams fill the cap; a third is refused
        for seed in [1u8, 2] {
            let (h, d) = parse_chunk(
                &chunk_stream(&deterministic_payload(500, seed), test_stream(seed)).unwrap()[0],
            )
            .unwrap()
            .unwrap();
            asm.ingest(h, d).unwrap();
        }
        let (h, d) =
            parse_chunk(&chunk_stream(&deterministic_payload(500, 3), test_stream(3)).unwrap()[0])
                .unwrap()
                .unwrap();
        assert_eq!(asm.ingest(h, d), Err(GovChannelError::TooManyStreams(2)));
        // completing stream 1 frees the capacity
        let sid1 = test_stream(1);
        let payload1 = deterministic_payload(500, 1);
        for c in chunk_stream(&payload1, sid1).unwrap() {
            let (h, d) = parse_chunk(&c).unwrap().unwrap();
            asm.ingest(h, d).unwrap();
        }
        assert_eq!(asm.completed_streams(), 1);
        assert_eq!(asm.live_streams(), 1);
        // stream 3 now fits and completes
        let sid3 = test_stream(3);
        let payload3 = deterministic_payload(500, 3);
        for c in chunk_stream(&payload3, sid3).unwrap() {
            let (h, d) = parse_chunk(&c).unwrap().unwrap();
            asm.ingest(h, d).unwrap();
        }
        assert_eq!(asm.completed_streams(), 2);
        // the 2-wide seen window holds {1, 3}: a retransmission dedupes
        let (h, d) = parse_chunk(&chunk_stream(&payload1, sid1).unwrap()[0])
            .unwrap()
            .unwrap();
        assert_eq!(asm.ingest(h, d).unwrap(), None);
        // a third completion evicts stream 1 from the window (bounded
        // memory): its chunks would start a NEW live stream
        let sid4 = test_stream(4);
        for c in chunk_stream(&deterministic_payload(500, 4), sid4).unwrap() {
            let (h, d) = parse_chunk(&c).unwrap().unwrap();
            asm.ingest(h, d).unwrap();
        }
        assert_eq!(asm.completed_streams(), 3);
        assert_eq!(asm.live_streams(), 1, "stream 2 still live");
    }

    #[test]
    fn seal_and_feed_loopback_over_one_identity() {
        let collector = test_id(20);
        let foreign = test_id(21);
        let sid = test_stream(22);
        let payload = deterministic_payload(1_500, 23);
        let blobs = seal_stream(&payload, sid, &collector.pr).unwrap();
        assert_eq!(blobs.len(), 4);
        for b in &blobs {
            assert_eq!(b.hops, NOTES_MAX_HOPS);
            assert!(hex::decode(&b.payload).unwrap().len() <= NOTE_PAYLOAD_MAX);
        }
        let mut asm = GovAssembler::new(8, 64);
        let mut got = None;
        for b in &blobs {
            got = feed_note(b, &collector, &mut asm).unwrap();
        }
        assert_eq!(got.as_deref(), Some(payload.as_slice()));
        // a foreign blob (sealed to somebody else) is ignored, not an error
        let f = seal_note(b"not for the collector", &foreign.pr).unwrap();
        assert_eq!(feed_note(&f, &collector, &mut asm).unwrap(), None);
        // a note addressed to the collector without the channel magic
        let plain = seal_note(b"ordinary wallet note", &collector.pr).unwrap();
        assert_eq!(feed_note(&plain, &collector, &mut asm).unwrap(), None);
    }

    #[test]
    fn frames_of_respects_the_wire_cap() {
        let collector = test_id(24);
        let payload = deterministic_payload(22_686, 25);
        let blobs = seal_stream(&payload, test_stream(26), &collector.pr).unwrap();
        assert_eq!(blobs.len(), 52);
        let frames = frames_of(&blobs);
        assert_eq!(frames.len(), 2);
        assert!(frames[0].len() <= NOTES_MAX_COUNT);
        assert!(frames[1].len() <= NOTES_MAX_COUNT);
        assert_eq!(frames[0].len() + frames[1].len(), blobs.len());
        for f in &frames {
            assert!(crate::notes::validate_note_blobs(f).is_ok());
        }
    }

    // -- live-network e2e ---------------------------------------------------

    fn gov_node(seed: u8) -> std::sync::Arc<crate::net_node::NetNode> {
        let cfg = crate::net_node::NetNodeConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            advertise_addr: "127.0.0.1:65534".to_string(),
            ..Default::default()
        };
        let mut buf = [0u8; 32];
        buf[0] = seed;
        buf[31] = seed.wrapping_add(11);
        crate::net_node::NetNode::start(
            cfg,
            NodeIdentity::from_secret(curve25519_dalek::scalar::Scalar::from_bytes_mod_order(buf)),
        )
        .expect("gov e2e node start")
    }

    fn gov_wait(secs: u64, mut cond: impl FnMut() -> bool) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
        loop {
            if cond() {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// The full R3 gossip path: voter -> relay -> collector, a GBE1-sized
    /// stream (22,686 bytes = 52 chunks = 2 Notes frames), then a
    /// retransmission over a fresh seal (new blob ids, same envelope id)
    /// that the assembler must dedupe.
    #[test]
    fn gossip_relay_e2e_gbe1_sized_stream_and_retransmit() {
        let a = gov_node(30); // voter
        let b = gov_node(31); // relay
        let c = gov_node(32); // collector node
        let collector_id = test_id(32); // the collector note identity
        let b_addr = b.local_addr().unwrap().to_string();
        let b_hex = b.node_id_hex();
        let a_hex = a.node_id_hex();
        let c_hex = c.node_id_hex();
        a.dial(&b_addr).unwrap();
        c.dial(&b_addr).unwrap();
        assert!(gov_wait(10, || {
            b.connected().contains(&a_hex)
                && b.connected().contains(&c_hex)
                && a.connected().contains(&b_hex)
                && c.connected().contains(&b_hex)
        }));

        let payload = deterministic_payload(22_686, 33);
        let sid = test_stream(34);
        let blobs = seal_stream(&payload, sid, &collector_id.pr).unwrap();
        assert_eq!(blobs.len(), 52);
        for frame in frames_of(&blobs) {
            a.send_notes(&b_hex, &frame).unwrap();
        }
        // B stores + relays (hops 4 -> 3); C must end up with all 52
        assert!(gov_wait(10, || c.inbox().len() >= 52));

        let mut asm = GovAssembler::new(16, 1024);
        let mut got = None;
        let inbox = c.inbox();
        for blob in &inbox {
            got = feed_note(blob, &collector_id, &mut asm).unwrap();
        }
        assert_eq!(got.as_deref(), Some(payload.as_slice()));
        assert_eq!(asm.completed_streams(), 1);
        assert_eq!(asm.live_streams(), 0);

        // retransmission over a fresh seal: canonical chunking gives the
        // SAME chunk plaintexts, fresh ECIES gives NEW blob ids - the
        // relay-level dedupe cannot catch this, the envelope-level one
        // must
        let again = seal_stream(&payload, sid, &collector_id.pr).unwrap();
        assert_ne!(again[0].id, blobs[0].id, "fresh seal = new blob id");
        for frame in frames_of(&again[..3]) {
            a.send_notes(&b_hex, &frame).unwrap();
        }
        assert!(gov_wait(10, || c.inbox().len() >= 55));
        let inbox2 = c.inbox();
        let mut dup_seen = 0usize;
        for blob in inbox2.iter().skip(52) {
            if feed_note(blob, &collector_id, &mut asm).unwrap().is_none() {
                dup_seen += 1;
            }
        }
        assert_eq!(dup_seen, 3, "every retransmitted chunk dedupes");
        assert_eq!(asm.completed_streams(), 1, "exactly one emission");
        assert_eq!(asm.duplicate_chunks(), 3);
    }
}
