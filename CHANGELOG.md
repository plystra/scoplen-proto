# Changelog

All notable changes to `scoplen-proto` will be recorded here.

## Unreleased

- Added the Rust workspace baseline and shared known-answer vector loader (roadmap S1).
- Added the deterministic K-1 object model: strict CBOR, UUIDv7/HLC clocks, typed envelopes,
  tombstones, limits, merge algebra, and orphan detection (roadmap S2).
- Completed the Phase 1 schema-version gate, boundary coverage for model limits, and executable
  CBOR and merge known-answer vectors (roadmap S2).
- Added the S3 primitive boundary: redacted zeroizing secrets, system randomness,
  XChaCha20-Poly1305, HKDF-SHA-256, and the specified Argon2id derivation.
