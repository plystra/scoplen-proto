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
The `scoplen-ssh` crate exposes K-7's ordered algorithm policy, role-specific offers, strict key
exchange state, and engine-independent authentication boundaries. Software Ed25519, P-256, and
RSA/SHA-2 signers, FIDO2 security-key hooks, RFC 4252 `none`, password and keyboard-interactive
codecs, certificate validation, and host-verification callbacks are available. Agent support
includes bounded Unix-socket and Windows named-pipe streams, Pageant named-pipe compatibility,
identity and signing requests, add/remove/lock/smart-card management, opaque extensions, and
fail-closed forwarding policy.
Bounded RFC 4254 channel codecs cover session and forwarding requests. A bounded SFTP v3 packet
boundary covers negotiation, core file and directory/path requests and responses, bounded request
correlation, and the OpenSSH `limits@openssh.com` extension, with binary-safe handles and extension
data. These are protocol boundaries; concrete russh connection
and channel engines, legacy Pageant WM_COPYDATA discovery, SSH `auth-agent` channel integration,
full SFTP operations and extensions, dynamic SOCKS listeners, and interoperability work remain open.
The `scoplen-api` crate exposes the K-3 error-code registry, RFC 9457 problem details, and device
challenge, signed-device request, and token response JSON codecs, plus K-4 session, change-feed,
write-batch, acknowledgement, snapshot, version-history, content-free notification, and account
key-bundle codecs in JSON and deterministic CBOR. OpenAPI resources, Cedar schema, gateway tickets,
and protobuf contracts remain open.

## Repository shape

The Cargo workspace contains `scoplen-ssh`, `scoplen-model`, `scoplen-crypto`, `scoplen-api`, and
`scoplen-test-vectors`. K-1 vectors are in `vectors/baseline.json`; K-2 cryptographic vectors are
in `vectors/crypto.json`. The published K-3 auth and API problem, sync session, change-feed, and
remaining K-4 message vectors are in `vectors/api-auth.json`, `vectors/api-problem.json`,
`vectors/sync-session.json`, `vectors/sync-changes.json`, `vectors/sync-messages.json`, and
`vectors/sync-notifications.json`, and `vectors/sync-keys.json`. The shared loader is usable by
both workstreams.

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
