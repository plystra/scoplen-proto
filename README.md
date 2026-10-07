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
`scoplen-crypto` public API, including account/request-bound escrow share contexts and the
administrator recovery verification code. S3 remains incomplete while pairing is unimplemented.
The `scoplen-ssh` crate exposes K-7's ordered algorithm policy, role-specific offers, strict key
exchange state, a bounded direct TCP byte transport, and engine-independent authentication
boundaries. `TcpTransport` limits host resolution, uses bounded RFC 8305 style staggered Happy
Eyeballs attempts under one total connect timeout, and enables `TCP_NODELAY`; its synchronous
boundary cancels and joins all async attempts before returning. `Socks5Transport` and `HttpConnectTransport` add bounded no-auth SOCKS5 and HTTP
CONNECT proxy composition with handshake-only socket timeouts. SOCKS5 username/password and HTTP
CONNECT Basic proxy authentication are bounded and keep passwords out of transport state. The
transports do not perform SSH negotiation or authentication. `ProxyCommandTransport` provides
bounded direct child-process stdin/stdout composition without shell interpolation and reaps the
child on shutdown or drop.
`ClientConnection::connect_via_socks5` and `connect_via_http_connect` compose the existing bounded
proxy handshakes with the concrete async SSH client, preserving proxy rejection and timeout errors.
Software Ed25519, P-256, and
RSA/SHA-2 signers, FIDO2 security-key hooks, RFC 4252 `none`, password and keyboard-interactive
codecs, certificate validation, and host-verification callbacks are available. Agent support
includes bounded Unix-socket and Windows named-pipe streams, Pageant named-pipe compatibility,
identity and signing requests, add/remove/lock/smart-card management, opaque extensions, and
fail-closed forwarding policy.
Bounded RFC 4254 channel codecs cover session and forwarding requests. The engine-independent
`AuthAgentChannel` composes the `auth-agent@openssh.com` channel lifecycle with bounded agent
framing, per-signature forwarding authorization, peer packet limits, and clean/truncated close
outcomes.

Legacy Pageant `WM_COPYDATA` has a bounded, fail-closed protocol adapter with deterministic
mapping names and an injectable platform backend; the crate keeps native Win32 FFI out of its safe
protocol boundary.

A bounded SFTP v3 packet boundary covers negotiation, core file, directory/path, and metadata
requests and responses, bounded
request correlation, and the OpenSSH `limits@openssh.com`, `posix-rename@openssh.com`,
`statvfs@openssh.com`, `fstatvfs@openssh.com`, `hardlink@openssh.com`, `fsync@openssh.com`,
`lsetstat@openssh.com`, `expand-path@openssh.com`, and `copy-data` extensions, with binary-safe
handles and extension data. A concrete `russh` adapter now owns TCP or caller-supplied stream
handshakes, validates raw keys and host certificates before invoking the trust callback, supports
password authentication, and exposes opaque session and `direct-tcpip` channels with PTY, shell,
exec, window-change, bounded data, EOF, close, and peer-event operations. A `ClientChannelStream`
can carry a target handshake through a jump host with
`ClientConnection::connect_via_direct_tcpip`; repeating the operation composes arbitrary jump
depth while retaining each parent connection. One connection multiplexes session and forwarding
channels with a configurable simultaneous-channel cap; channel or stream drop releases a slot.
The adapter keeps the engine types out of the public API. A bounded SOCKS4a/SOCKS5 dynamic
listener now composes the handshake with `direct-tcpip`, including cancellation, concurrency
limits, bidirectional forwarding, EOF/close propagation, and protocol failure mapping. A native
Win32 backend for the injected Pageant
discovery adapter and interoperability work remain open. `SftpChannel`
now composes the bounded v3 handshake and packet framing over an accepted SSH `session` channel
with bounded subsystem failure and truncation mapping; `SftpSession` adds bounded pipelining and
request correlation, resume-by-offset uploads/downloads, and progress callbacks on that channel. The auth-agent channel boundary does not claim concrete engine scheduling or wire
interoperability until those workstreams are implemented and tested.
The `scoplen-api` crate exposes the K-3 error-code registry, RFC 9457 problem details, and device
challenge, signed-device request, and token response JSON codecs, plus K-4 session, change-feed,
write-batch, acknowledgement, snapshot, version-history, content-free notification, and account
key-bundle codecs in JSON and deterministic CBOR. K-6 now includes the bounded gateway client-hello
frame (`ticket` and `dpop_proof`) with a published vector and failure-path coverage. OpenAPI
resources now have an authored OpenAPI 3.1 document at `crates/scoplen-api/openapi/v1.yaml`,
generated Rust envelope/query types, and the local `@scoplen/api` TypeScript package surface.
The internal `spl.gateway.v1.Control` and `spl.agent.v1.Agent` protobuf source contracts are
also checked in under `crates/scoplen-api/proto`. The built-in Cedar schema and role policies are
parsed and strictly validated in the API crate's tests; runtime policy evaluation, generated
protobuf bindings, and concrete gRPC services remain open.

## Repository shape

The Cargo workspace contains `scoplen-ssh`, `scoplen-model`, `scoplen-crypto`, `scoplen-api`, and
`scoplen-test-vectors`. K-1 vectors are in `vectors/baseline.json`; K-2 cryptographic vectors are
in `vectors/crypto.json`. The published K-3 auth and API problem, sync session, change-feed, and
remaining K-4 message vectors are in `vectors/api-auth.json`, `vectors/api-problem.json`,
`vectors/sync-session.json`, `vectors/sync-changes.json`, `vectors/sync-messages.json`, and
`vectors/sync-notifications.json`, `vectors/sync-keys.json`, and `vectors/gateway.json`. The shared
loader is usable by both workstreams.

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
