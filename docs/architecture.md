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

The baseline keeps crate roots intentionally small. Later gates add contract behavior in the order
defined by `scoplen-docs/17-implementation-roadmap.md`; no consumer may define a second copy of a
wire format or cryptographic construction.

\n