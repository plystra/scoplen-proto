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
XChaCha20-Poly1305, HKDF-SHA-256, and Argon2id.

## Repository shape

The Cargo workspace contains `scoplen-ssh`, `scoplen-model`, `scoplen-crypto`, `scoplen-api`, and
`scoplen-test-vectors`. Contract-specific behavior and vectors are introduced in later roadmap
gates; the vector loader is already usable by both workstreams.

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
