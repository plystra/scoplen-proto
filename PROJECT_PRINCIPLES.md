# Scoplen protocol principles

This repository is a component of Scoplen, a Plystra project. The project-level adoption record is
[`scoplen-docs/PROJECT_PRINCIPLES.md`](../scoplen-docs/PROJECT_PRINCIPLES.md).

## Review record

- Philosophy version reviewed: Plystra Craft 1.0.1
- Source commit reviewed: `plystra/craft@dd617b370203d5dce1d30b8b81284d16d96a432c`
- Review date and maintainer: 2026-10-06, immoses (Moses Qiu)
- Maturity: Exploration
- Maintenance: Active
- Components: Rust libraries and shared known-answer test vectors
- Public data surface: none; the crates do not collect user data
- Review status: Open gaps remain while contract implementations are built

## Applicable standards

The repository applies `plystra-craft` and `plystra-craft-code` from `.agents/skills/`. The source
license is Apache-2.0. Security-sensitive protocol and cryptographic behavior is implemented only
after its contract is specified in `scoplen-docs` and covered by vectors and failure-path tests.

## Open gaps

- The S1 baseline and S2 object-model gate are complete, including schema handling, model limits,
  merge laws, and known-answer vectors. S3 has its primitives, key hierarchy, device certificates,
  encrypted envelopes, recovery, Shamir, escrow wrapping, and vectors for the implemented
  constructions. CPace/QR pairing and its vectors remain open. S4 has a per-Host algorithm policy,
  role-specific transport negotiation, and strict-KEX state validation, while concrete transport,
  authentication, channels, and interoperability remain open. S6 has the error contract, K-3 device-auth
  JSON codecs, and K-4 session and sync codecs, while the remaining wire contracts remain open.
  S5 and S7 have no completed gate evidence.
- Independent security review and interoperability evidence are required before a Stable release.
