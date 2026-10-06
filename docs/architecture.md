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
NEWKEYS. The engine-independent authentication boundary supplies Ed25519 and P-256 `Signer`
adapters, FIDO2 `SecurityKeyProvider` adapters, RFC 4252 publickey probes and signed requests,
bounded OpenSSH certificate parsing and validation, and a host-key trust callback that is called
only after validation. Security-key requests preserve the OpenSSH application, user-presence and
user-verification flags, and authenticator counter while rejecting malformed or unbounded input.
The agent boundary provides bounded request-identities and sign request/response codecs,
transport-neutral client calls, and server dispatch that maps key-store errors to the opaque SSH
agent failure response. `FramedAgentChannel` applies bounded read/write framing over a blocking
stream, with platform constructors for Unix-domain sockets and Windows named pipes. Pageant
compatibility and agent forwarding remain open; bounded remove-all, lock, and unlock requests are
also dispatched with opaque failure mapping. The concrete SSH transport, remaining authentication
methods, channels, SFTP, and interoperability work remain open. The agent server can consume
multiple bounded frames from a blocking stream through clean peer close while applying the same
malformed and oversized-frame checks.
The supported management surface includes exact-key removal in addition to remove-all, lock, and
unlock; private-key add-identity and smart-card operations remain intentionally outside this
opaque boundary until their algorithm-specific fields have a dedicated contract.
Agent message debug output reports only bounded lengths and non-sensitive metadata, so signing
payloads and lock credentials are not emitted through ordinary diagnostics.
Forwarded agent serving uses an explicit per-profile policy that is disabled by default and invokes
an authorizer for each signature before the key store; the SSH `auth-agent` channel integration is
still open.
