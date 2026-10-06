# scoplen-proto

Shared Rust contracts and protocol libraries for Scoplen.

Scoplen is a Plystra project. This repository is the shared foundation for the client and server
workstreams; it does not contain the desktop client or the server process. Its crates are licensed
under Apache-2.0.

## Status

Maturity: Exploration. Maintenance: Active. The repository baseline (roadmap gate S1) and the K-1
object model (roadmap gate S2) are complete. The model includes deterministic CBOR, schema-version
handling, per-object limits, merge properties, and executable known-answer vectors. Protocol,
cryptographic, and wire behavior is added only from the canonical specifications in `scoplen-docs`;
the S3 primitive boundary now includes zeroizing secret containers, operating-system randomness,
XChaCha20-Poly1305, HKDF-SHA-256, Argon2id, P-256 and Ed25519 signatures, and HPKE key wrapping
for device and account recipients. The published K-2 known-answer set is exercised through the
`scoplen-crypto` public API; S3 remains incomplete while pairing is unimplemented.
The `scoplen-ssh` crate exposes K-7's ordered client algorithm policy with explicit per-Host
legacy opt-in. It does not yet establish SSH connections; transport, authentication, channels,
strict key exchange, and interoperability work remain open.
The `scoplen-api` crate exposes the K-3/K-4/K-5 error-code registry and RFC 9457 problem details
in JSON and deterministic CBOR, plus K-4 session, change-feed, write-batch, acknowledgement,
snapshot, version-history, and content-free notification codecs. OpenAPI resources, Cedar schema,
gateway tickets, and protobuf contracts remain open.

## Repository shape

The Cargo workspace contains `scoplen-ssh`, `scoplen-model`, `scoplen-crypto`, `scoplen-api`, and
`scoplen-test-vectors`. K-1 vectors are in `vectors/baseline.json`; K-2 cryptographic vectors are
in `vectors/crypto.json`. The published API problem, sync session, change-feed, and remaining
K-4 message vectors are in `vectors/api-problem.json`, `vectors/sync-session.json`,
`vectors/sync-changes.json`, `vectors/sync-messages.json`, and `vectors/sync-notifications.json`.
The shared loader is usable by both workstreams.

## Development

Rust 1.85.0 is pinned in `rust-toolchain.toml`.

```text
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

The local Cargo patch file used for cross-repository development is intentionally ignored. Do not
publish crates, tags, or packages from an agent checkout.

## Security

Report vulnerabilities privately to `scoplen-security@plystra.com`; see [SECURITY.md](SECURITY.md).
Do not put secrets or private infrastructure details in issues, examples, vectors, or logs.

## License

The source code is Apache-2.0. See [LICENSE](LICENSE).
