# Shared repository architecture

`scoplen-proto` is the contract implementation shared by the client and server workstreams. It has
no runtime dependency on either consumer.

| Crate | Contract or role |
| --- | --- |
| `scoplen-ssh` | K-7 protocol core |
| `scoplen-model` | K-1 object model |
| `scoplen-crypto` | K-2 cryptographic formats |
| `scoplen-api` | K-3 through K-6 wire contracts |
| `scoplen-test-vectors` | Known-answer vector envelope and loader |

The K-1 crate owns strict deterministic CBOR, UUIDv7/HLC values, object envelopes, typed field
validation, tombstones, and pure merge helpers. Later gates add contract behavior in the order
defined by `scoplen-docs/17-implementation-roadmap.md`; no consumer may define a second copy of a
wire format or cryptographic construction.

The K-7 crate owns the client algorithm preference lists from `10-protocol-core.md` §3.
`HostAlgorithmPolicy::with_legacy` validates an explicit list for one Host and appends accepted
legacy names after modern defaults. Host certificate algorithms precede raw host keys (D-42).
`TransportOffer` turns those lists into role-specific KEXINIT offers, selects the first local
preference present in each peer list, and enables RFC 8308 and strict-KEX markers only when both
roles advertise them. `StrictKeyExchange` enforces the initial KEXINIT-first rule, KEX-family
message admission, one-message limits, sequence-wrap refusal, and sequence-number reset after
NEWKEYS. The engine-independent authentication boundary supplies Ed25519, P-256, and RSA/SHA-2
`Signer` adapters, FIDO2 `SecurityKeyProvider` adapters, RFC 4252 publickey probes and signed requests,
bounded OpenSSH certificate parsing and validation, and a host-key trust callback that is called
only after validation. Security-key requests preserve the OpenSSH application, user-presence and
user-verification flags, and authenticator counter while rejecting malformed or unbounded input.
The agent boundary provides bounded request-identities, signing, identity management, smart-card,
lock, unlock, and `SSH_AGENTC_EXTENSION` request/response codecs, transport-neutral client calls,
and server dispatch that maps key-store errors to opaque failures. `FramedAgentChannel` applies
bounded read/write framing over a blocking stream, with platform constructors for Unix-domain
sockets and Windows named pipes. The forwarded-agent adapter reassembles fragmented and multi-frame
channel data, applies the fail-closed per-profile authorizer, and bounds response count and
channel-data fragments. `AuthAgentChannel` composes that adapter with the bounded RFC 4254
`auth-agent@openssh.com` open, data, EOF, and close lifecycle; it validates channel numbers and
peer packet limits and reports clean versus truncated close outcomes. Pageant named-pipe
compatibility is available on Windows through the same bounded framing; legacy WM_COPYDATA discovery
remains open. The concrete `russh` client adapter now owns TCP and caller-supplied stream
 handshakes, validates host keys and certificates before the trust callback, supports password
 authentication, and exposes opaque session and `direct-tcpip` channels with PTY, shell, exec,
 bounded data, EOF, close, and peer-event operations. The native Pageant backend, dynamic SOCKS
 listeners, SFTP channel composition, and interoperability work remain open.
The agent server can consume
multiple bounded frames from a blocking stream through clean peer close while applying the same
malformed and oversized-frame checks.
The supported management surface includes exact-key removal, smart-card provider load and removal,
remove-all, lock, and unlock; private-key add-identity remains intentionally outside this opaque
boundary until its algorithm-specific fields have a dedicated contract.
Agent message debug output reports only bounded lengths and non-sensitive metadata, so signing
payloads and lock credentials are not emitted through ordinary diagnostics.
Forwarded agent serving uses an explicit per-profile policy that is disabled by default and invokes
an authorizer for each signature before the key store; management and extension requests are
rejected on a forwarded channel. The `AuthAgentChannel` boundary keeps that policy in force while
leaving channel allocation, window updates, and engine scheduling to the concrete SSH engine.
The channel boundary exposes bounded RFC 4254 channel-open, data, lifecycle, session-request, and
global forwarding codecs, including direct and forwarded TCP, Unix streamlocal, and agent-forwarding
channel types. It validates exact message consumption, field limits, request names, booleans, signal
names, and forwarding failure reasons; the concrete engine, dynamic SOCKS listeners, and connection
composition remain separate outcomes.
The authentication boundary also encodes `none`, `password` and password-change, and
keyboard-interactive exchanges with bounded context, prompt, and response fields; password and
interactive response bytes are held in zeroizing secret containers. `RsaSshSigner` accepts only RSA
private keys and binds the selected `rsa-sha2-256` or `rsa-sha2-512` hash to the signature wrapper;
raw `ssh-rsa` SHA-1 authentication is rejected. The SFTP boundary provides bounded v3 negotiation,
core open/read/write/close/stat packets, directory and path operations (opendir, readdir, remove,
mkdir, rmdir, and realpath), metadata and symbolic-link operations (setstat, fsetstat, readlink,
and symlink), binary-safe handles and extension data, attributes, status, and directory-entry
responses, request-id correlation for bounded pipelining, and the OpenSSH `limits@openssh.com`,
`posix-rename@openssh.com`, `statvfs@openssh.com`, `fstatvfs@openssh.com`, `hardlink@openssh.com`,
`fsync@openssh.com`, `lsetstat@openssh.com`, `expand-path@openssh.com`, and `copy-data`
requests and responses. The `russh` channel adapter covers session and `direct-tcpip` channel
 operations; transfer resume/progress, SFTP channel composition, and the interoperability matrix
 remain open.
