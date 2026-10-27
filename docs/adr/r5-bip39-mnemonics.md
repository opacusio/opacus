# ADR: Adopt BIP-39 mnemonics for wallet key material (R5)

- **Status**: Accepted (design decision; implementation is a separate gated work item, proposed as WG-25)
- **Scope**: `crates/opacus-crypto/src/keys.rs` (+ its tests; `Cargo.toml` dependency)
- **Register**: R5 = audit MEDIUM "pseudo-mnemonic (hex words, no BIP-39/KDF)"; related R12 (v0.3 planning)
- **Evidence base**: witnessed keys.rs:1-60 window (wg23_scout_dump_v3.txt, triage @196aa0c4)

## Context

The current implementation (witnessed, keys.rs:21-58):

- `SpendingKey::generate()` draws 32 bytes from the caller-provided `RngCore + CryptoRng`,
  hashes them with blake3, and formats the digest as the pseudo-mnemonic
  `"ghost {} {} ..." x11 hex chunks` - a "ghost"-prefixed hex string split into
  12 pseudo-words.
- `SpendingKey::from_mnemonic()` validates only `split_whitespace().count() >= 12`.
- Spend and view keys are derived as
  `blake3("ghost_spend_derive_v1" || mnemonic)` and
  `blake3("ghost_view_derive_v1" || mnemonic)`.

Problems, ordered by severity:

1. **No integrity.** Pseudo-words carry no checksum. A single mistyped or truncated
   character silently derives a *different, valid-looking* keypair; funds sent to the
   intended address become unrecoverable from the mistyped backup.
2. **No KDF.** Derivation is one unkeyed hash evaluation. If the phrase leaks, key
   extraction is instantaneous; there is no stretching to slow offline brute force of
   weak human-chosen phrases.
3. **Non-standard format.** "ghost-prefixed hex chunks" cannot be imported into or
   exported from any standard wallet and have no test-vector ecosystem.
4. **Count is not validation.** A word-count check accepts arbitrary garbage; typos in
   hex chunks are indistinguishable from valid words.

## Decision

1. Replace the pseudo-mnemonic with **standard BIP-39** (English wordlist):
   - `generate()`: 256-bit entropy from the existing injected `RngCore + CryptoRng` ->
     **24 words**. 128-bit / 12 words is permitted only in test-only code paths.
   - Restore path: strict BIP-39 validation - wordlist membership **and** checksum.
     `from_mnemonic` MUST reject anything failing either check (replaces the count>=12 check).
2. Seed derivation per BIP-39:
   `seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048 iterations)` -> 64 bytes.
   Optional **passphrase** (the "25th word") is supported; default empty.
3. Key derivation keeps the existing domain-separated blake3 construction, re-tagged to
   prevent cross-version confusion:
   - `spend = blake3("ghost_spend_derive_v2" || seed)`
   - `view  = blake3("ghost_view_derive_v2" || seed)`
   BIP-32 hierarchical derivation is explicitly out of scope (no multi-account need today).
4. **Breaking change, no legacy path by default.** v1 pseudo-mnemonics are rejected by the
   new restore path. Rationale: current keys are testnet-only throwaways (witnessed:
   publish_ghost.ps1 header - "Testnet keys are throwaway and never committed"); migrating
   real funds is not applicable at this stage. The breaking change must be documented in
   CHANGELOG.
5. Dependency: the maintained `bip39` crate (rust-bitcoin org) with the `zeroize` feature;
   wordlist embedded at compile time. No BIP-32 / SLIP-39 dependencies.

## Security invariants (implementation MUST hold)

- The mnemonic lives only inside `Zeroize + ZeroizeOnDrop` types (already the pattern on
  `SpendingKey`); no `Debug`/`Display` impl may expose it.
- The mnemonic MUST NOT be logged; tracing near key code is reviewed at the impl gate.
- Entropy always from the injected CSPRNG, never from time/PID (lesson of the closed
  CRITICAL C-01 nonce finding in xmr_dleq.rs).
- Unit tests use fixed official BIP-39 test vectors; no RNG in tests.

## Test plan

- Official BIP-39 English vectors: entropy -> mnemonic -> seed round-trips.
- Checksum rejection (bit flip), wordlist rejection, 12/15/18/24-word acceptance matrix.
- Non-empty passphrase derives different keys than empty passphrase.
- v1 pseudo-mnemonic rejected by the v2 restore path.
- Derivation stability: fixed seed -> fixed spend/view key bytes.

## Consequences

- +1 small dependency (`bip39`); PBKDF2 2048 iterations adds millisecond-scale cost to
  key load - acceptable.
- Backups become 24 standard words: better UX, future interop with standard tooling.
- Old v1 hex-phrase backups stop working - documented breaking change (testnet-only).
- Implementation is contained in keys.rs + tests + one Cargo.toml line; wire formats and
  other crates are unaffected (keys are local, never serialized into protocol messages).
