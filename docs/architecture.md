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

The K-7 crate currently owns the client algorithm preference lists from `10-protocol-core.md` §3.
`HostAlgorithmPolicy::with_legacy` validates an explicit list for one Host and appends accepted
legacy names after modern defaults. Host certificate algorithms precede raw host keys (D-42).
The policy can select the first local preference present in a peer's offer. It is not wired to an
SSH transport yet; a future transport must use these lists and implement strict key exchange
before claiming the S4 transport outcome.
