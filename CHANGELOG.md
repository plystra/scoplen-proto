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
- Added P-256 and Ed25519 signing wrappers and HPKE base-mode wrapping for device and account
  recipients, with malformed-input and authentication failure tests.
- Published executable K-2 known-answer vectors for primitives, signatures, HPKE opening, key
  wrapping, signed certificates and envelopes, recovery, Shamir, escrow, and safety numbers.
- Added K-7 client algorithm preferences with explicit per-Host legacy selection and host
  certificate preference; SSH transport and negotiation remain unimplemented.
- Added the stable HTTP error-code registry and RFC 9457 problem details with JSON and deterministic
  CBOR codecs, including malformed-input tests and a published CBOR vector.
- Added deterministic K-4 sync session request and response codecs, validation of limits and vault
  identifiers, forward-compatible vault kinds, and published session vectors.
- Added the K-3 QR pairing payload, strict parser, and constant-time verification of relayed
  device keys against a published known-answer vector.
- Added the K-3 typed-code CPace Ristretto255/SHA-512 exchange with fixed transcript context,
  Crockford code parsing, zeroizing session material, constant-time confirmations, and a
  nonce-checked XChaCha20-Poly1305 payload channel, with a published known-answer vector.
- Added K-4 change-feed query and response codecs with canonical pagination parameters, strict
  ordering and cursor validation, failure-path coverage, and published deterministic CBOR vectors.
