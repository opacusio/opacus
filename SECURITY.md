# Security Policy

## Supported versions

Opacus is pre-release software and has no tagged security-support line
yet. The only supported target is the current `main` branch (workspace
version 0.7.0, the [Unreleased] section of CHANGELOG.md). Security
fixes land on `main` first and ship with the next release; older
commits and tags are not patched in place.

## Reporting a vulnerability

Do NOT open a public GitHub issue for anything with security impact:
key handling, proof circuits, consensus, the network protocol, bridge
custody, the wOPACUS contract and the legacy wGHOST deployment, tooling.

Report privately instead, in this order:

1. Preferred: GitHub private vulnerability reporting on the
   `opacusio/opacus` repository (tab "Security", then "Report a
   vulnerability"). This keeps the report, the coordination and the
   eventual credit in one private place.
2. If the Security tab is unavailable, open a public issue titled
   "security: please enable a private channel" WITHOUT any technical
   detail, and continue the conversation privately.

Please include whatever applies:

- the affected component: a workspace crate (opacus-crypto, opacus-zk,
  opacus-network, opacus-node, opacus-wallet, opacus-bridge,
  opacus-dex, opacus-miner, opacus-consensus, opacus-light-client,
  opacus-cli), the contracts under `contracts/`, or CI/tooling,
- the affected commit, tag or release,
- a minimal reproduction (test, transaction, RPC capture, script),
- your assessment of impact and severity,
- any mitigation you are aware of.

## What to expect

The project is currently maintained by a single maintainer; the
targets below are best-effort commitments, not guarantees:

- acknowledgement of your report: within 72 hours,
- triage (affected components, severity, fix plan): within 7 days,
- fix and coordinated disclosure: agreed with you per severity, with
  targets of 14 days (high), 30 days (medium) and 90 days (low);
  critical issues are handled as fast as the fix allows.

Reporters are credited by default (GitHub advisory credit and release
notes); say so in your report if you prefer to remain anonymous.

## Mainnet gate (mandatory)

Mainnet access is gated on an external security audit. Before any
mainnet use of the protocol, the contracts or the tooling, an
independent third-party audit of the current `main` MUST be completed
and its findings triaged; internal self-review does not satisfy this
gate. The audit report (or its redacted summary) ships with the first
mainnet release.

Testnet credentials are strictly one-time. Burner keys are generated
per deployment round, never reused across rounds, never shared across
networks and never funded with anything but faucet tokens. Any key
that has touched a testnet MUST be treated as burned: it is never
promoted to a network carrying real value and never derived from, or
derived into, any other key.

## Scope

In scope:

- all workspace crates under `crates/` and `cli/`,
- the Solidity contracts and the deployment scripts under `contracts/`
  and in the repository root,
- the node and CLI tooling, and the CI pipelines under `.github/`.

Out of scope:

- volumetric denial of service (traffic flooding, brute resource
  exhaustion) without an underlying protocol defect,
- attacks on third-party services (public RPC providers, exchanges,
  indexers) rather than Opacus itself,
- social engineering,
- issues in dependencies that RustSec already tracks and that have no
  workspace-level remediation path; these are handled through
  `.cargo/audit.toml` and `deny.toml` (still report a usable upgrade
  path if you find one),
- test-only code and fixtures.

## Safe harbor

Good-faith research is welcome. We will not pursue or support action
against anyone who avoids privacy violations, data destruction,
service degradation and public disclosure before a fix is coordinated.
