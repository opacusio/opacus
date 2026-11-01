# GIP-0: The GIP Process

- GIP: 0
- Title: The GIP Process
- Type: Process
- Status: Activated (2026-11-01)
- Created: 2026-11-01
- Base: 0027e63 (post-v0.9.0, [Unreleased])
- Analog: ZIP 0 (zips.z.cash)
- Changes: docs-only (no Rust, no circuit, no wire changes)

## 1. Abstract

This document defines the Ghost Improvement Proposal (GIP) process for the
Opacus network: what a GIP is, which types exist, how a proposal moves
through its lifecycle, how GIPs are numbered and stored, the normative
section template, and how WG/WP work packages reference the GIPs they
implement. GIP-0 is itself a Process GIP and the root of the GIP series;
future governance items - the Opacus Grants (OG) funding model, decentralized
OG/OC voting, and the Opacus Community (OC) umbrella - are expected to land
as GIP documents before any code.

## 2. Motivation

The project already operates a de facto process: WG-26, WG-27, WG-29 and the
WG-CLSAG series each froze a design in a scope doc before implementation, and
every work package is listed in the README roadmap with a commit trail and
green CI as evidence. GIP-0 formalizes this discipline so that:

1. a specification is pinned (and citable) before code lands;
2. every WG/WP has an unambiguous normative anchor, not just a narrative
   roadmap bullet;
3. governance and economics proposals (OG funding, voting) have the same
   review path as protocol changes;
4. release discipline (SemVer + Keep a Changelog) is written down once,
   instead of living in maintainer memory.

## 3. GIP types

- **Standards Track** - normative changes with a reference implementation:
  - *Consensus*: chain rules, circuit semantics, validity of transactions
    and blocks;
  - *Network*: wire format, P2P protocol, note transmission;
  - *Bridge / Wallet / Apps*: swap coordination, wGHOST tooling, wallet
    behavior.
- **Process** - process and governance documents (this document, future OG/OC
  GIPs). A Process GIP has no code obligation and is Activated by maintainer
  consensus.
- **Informational** - guidelines, rationale, recommendations; no normative
  force.

## 4. Lifecycle

```
Idea -> Draft -> RFC -> Accepted -> Activated
                     \-> Rejected / Withdrawn / Superseded
```

- **Draft** - the proposal is scoped and filed as `docs/gips/GIP-N-short-name.md`
  with `Status: Draft`. Scope must be complete enough to review.
- **RFC** - public review window of at least 7 days. Comments are resolved in
  the document (or explicitly deferred as issues), never silently dropped.
- **Accepted** - the design is frozen; a Standards Track proposal that needs
  implementation gets a scope doc in `docs/` (the existing WG/WP convention).
- **Activated** - for Standards Track: the reference implementation is merged,
  tests and all CI gates are green, and the README roadmap carries the
  delivered bullet with its commit range. For Process: maintainer consensus.
  Activation date is recorded in the header.
- **Rejected / Withdrawn** - terminal states with a reason.
- **Superseded** - terminal state pointing at the replacing GIP-M; the
  superseded document stays for history and is never edited retroactively.

## 5. Numbering and files

- GIP numbers are monotonically increasing integers, allocated on first
  filing, and **never reused**; gaps in numbering are forbidden (see
  section 8 for the release-tag counterpart of this rule).
- One document per GIP: `docs/gips/GIP-N-short-name.md`.
- Header block (all fields mandatory unless marked optional): `GIP`, `Title`,
  `Type`, `Status`, `Created`, `Requires` (optional), `Supersedes`
  (optional), `Analog` (optional, for traceability to BIP/ZIP/EIP sources).

## 6. Template (normative section order)

1. Header block (section 5);
2. **Abstract** - one paragraph, what and why;
3. **Motivation** - the problem, not the solution;
4. **Specification** - the normative core (MUST/SHOULD language);
5. **Rationale** - design decisions and rejected alternatives;
6. **Backwards Compatibility** - wire/circuit/state compatibility analysis;
   any breaking change must be explicit;
7. **Test Plan** / *Reference Implementation* - how conformance is proven
   (test matrix P/N numbering follows the existing WG convention);
8. **Security Considerations** - failure modes, fail-closed analysis.

## 7. WG/WP linkage (normative)

- WG-XX denotes a work group; WP-n denotes a work package inside it.
- Every WG/WP that changes consensus, wire format, bridge, wallet or
  economics behavior MUST cite the GIP (and section) it implements in its
  scope doc and in its README roadmap bullet.
- A WG/WP without a GIP anchor is limited to housekeeping, refactoring and
  documentation, and MUST state the absence of a GIP anchor explicitly.
- **Grandfathering**: WG-16 through WG-29, WG-CLSAG and its adaptor /
  adaptor-int successors, and PROVER-10S predate GIP-0. They are
  retroactively covered by this document; their normative content lives in
  the respective scope docs under `docs/` and the CHANGELOG sections
  0.3.0 - 0.9.0. No retroactive renumbering.

## 8. Release discipline

- Releases follow [Semantic Versioning](https://semver.org/) and
  [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) (see README
  "Versioning and changelog").
- A release tag MUST map 1:1 to a CHANGELOG section, and release notes are
  composed from that section.
- Minor release numbers are consecutive; a skipped number is a process bug.
- Historical note (verified 2026-11-01): the tag chain
  v0.3.0 - v0.4.0 - v0.5.0 - v0.6.0 - v0.7.0 - v0.8.0 - v0.9.0 is
  consecutive with no gaps; v0.8.0 (da222bf, 2026-10-28) shipped the BIP-39
  wallet keys and the fused Poseidon spend (k = 11).

## 9. Security considerations

GIP documents are public; they MUST NOT contain secrets, keys, tokens or
unpublished vulnerabilities (the repository-wide leak check applies). A
Process GIP cannot bypass CI gates: activation of a Standards Track GIP
always requires the full green gate set (fmt, build, tests, real-prover,
clippy, plus the auxiliary RustSec / cargo-deny / Foundry checks).

## 10. Prior art

Zcash ZIP 0 (process) and ZIP 1014 / 1015 / 1016 (funding models and
coinholder voting), Bitcoin BIP 2, Ethereum EIP 1; Monero CCS (off-chain
transparency), Dash masternode treasury, Decred Politeia. These are
references for the future OG/OC funding and voting GIPs and are not part of
this document.
