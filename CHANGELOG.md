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
  certificate preference, role-specific transport offers, deterministic algorithm negotiation, and
  a strict-KEX state machine with KEXINIT-first admission, KEX-family checks, sequence bounds, and
  NEWKEYS sequence resets.
- Added the engine-independent K-7 publickey boundary for Ed25519 and P-256 signers, RFC 4252
  session-bound probes and signed requests, bounded OpenSSH user and host certificate validation,
  and host-key trust callbacks. The concrete SSH transport, remaining authentication methods,
  channels, SFTP, and interoperability work remain open.
- Added the engine-independent K-7 FIDO2 security-key boundary with resident-key discovery,
  `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com` public-key and signature
  codecs, RFC 4252 session binding, application scoping, authenticator flags and counters, and
  malformed-input and requirement failure tests.
- Added the bounded K-7 SSH agent request-identities and sign request/response codecs, a
  transport-neutral agent client, and server dispatch with opaque failure mapping and loopback
  and malformed-frame tests. Platform channels, forwarding, and the remaining agent protocol
  operations remain open.
- Added the bounded blocking agent stream channel with fragmented-read handling and platform
  constructors for Unix-domain sockets and Windows named pipes, including pre-write request
  validation and oversized-response tests. Pageant compatibility and forwarding remain open.
- Added a bounded Pageant named-pipe agent adapter on Windows, reusing the standard agent framing
  and covering fragmented responses, malformed frames, and oversized responses.
- Added bounded agent management requests for removing all identities and locking or unlocking
  an agent, with opaque failure mapping and passphrase limits.
- Added bounded smart-card provider load and removal requests with PIN redaction, flag preservation,
  opaque failure mapping, and client/server store hooks.
- Added bounded `SSH_AGENTC_EXTENSION` requests with opaque success and extension-failure responses,
  client and server hooks, and malformed, oversize, and debug-redaction coverage.
- Added bounded RFC 4254 channel-open, channel-data, lifecycle, session-request, agent-forwarding,
  direct/forwarded TCP and streamlocal, and global forwarding codecs with strict field limits and
  malformed-input tests.
- Added bounded blocking agent-server serving that validates fragmented request frames, dispatches
  multiple requests until clean peer close, and refuses oversized input before allocation.
- Added exact-key remove-identity requests with bounded public-key blobs, client helpers, server
  dispatch, and failure-path coverage.
- Added the `agent_decoder` cargo-fuzz target and wired every current decoder target into the Linux
  CI fuzz-build job.
- Redacted signed data and lock or unlock passphrases from `AgentMessage` debug output, with a
  regression test for the public logging surface.
- Added a fail-closed per-profile forwarding policy and authorizer hook that gates every forwarded
  signature before server dispatch, including framed-stream serving and allow or deny tests.
- Added a bounded forwarded-agent channel adapter that reassembles fragmented and multi-frame
  channel data, splits responses at the channel limit, rejects management and extension requests,
  and distinguishes clean close from truncation.
- Added bounded RFC 4252 `none`, `password` and password-change, and keyboard-interactive request,
  prompt, and response codecs; password and response bytes use zeroizing secret storage and
  malformed, NUL, truncation, and size failure paths are covered.
- Added RSA software signers with strict `rsa-sha2-256` and `rsa-sha2-512` selection, SSH `ssh-rsa`
  public-key blobs, certificate subject binding, and hash-substitution and malformed-key failures.
- Added a bounded SFTP v3 packet boundary for INIT/VERSION negotiation, core file requests and
  responses, binary-safe handles and extension data, malformed-input rejection, and pipelined
  request correlation.
- Added the stable HTTP error-code registry and RFC 9457 problem details with JSON and deterministic
  CBOR codecs, including malformed-input tests and a published CBOR vector.
- Extended the stable error-code registry for authenticated sync HTTP adapters with
  `auth.authentication_required`, `sync.invalid_request`, and `sync.storage_unavailable`.
- Added strict K-3 challenge, signed-device request, and token response JSON codecs with canonical
  nonce, UUIDv7, timestamp, signature, token-type, lifetime, and failure-path validation, plus
  published authentication vectors.
- Added deterministic K-4 sync session request and response codecs, validation of limits and vault
  identifiers, forward-compatible vault kinds, and published session vectors.
- Added the K-3 QR pairing payload, strict parser, and constant-time verification of relayed
  device keys against a published known-answer vector.
- Added the K-3 typed-code CPace Ristretto255/SHA-512 exchange with fixed transcript context,
  Crockford code parsing, zeroizing session material, constant-time confirmations, and a
  nonce-checked XChaCha20-Poly1305 payload channel, with a published known-answer vector.
- Added K-4 change-feed query and response codecs with canonical pagination parameters, strict
  ordering and cursor validation, failure-path coverage, and published deterministic CBOR vectors.
- Added K-4 write-batch and assignment codecs with atomic-batch limits, acknowledgement request and
  response codecs, objects snapshot pages, bounded versions history pages, strict failure paths,
  published deterministic CBOR vectors, and the cursor-ahead and object-not-found error codes.
- Added content-free K-4 WebSocket notification codecs for vault advancement, pending rotation, and
  device revocation, with strict event validation, extension tolerance, failure-path tests, and
  published deterministic CBOR vectors.
- Added K-4 account key-bundle GET and PUT codecs with opaque artifact limits, sorted device wraps
  and certificate lists, signed canonical-CBOR input helpers, replay revision validation, failure
  paths, and published deterministic CBOR vectors.
- Accepted `null` in optional scalar fields as a clear that merges by its clock and reads as absent
  (D-57), with a published merge vector; required fields still reject `null`.
