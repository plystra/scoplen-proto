# Contributing

Scoplen is a Plystra project. Read the workspace guidance in `../AGENTS.md` and the canonical
specification in `../scoplen-docs` before changing a contract.

## Checks

Run the following before requesting review:

```text
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Contract changes follow `scoplen-docs/03-contract-boundary.md`: specification first, then this
repository and vectors, then consumer pins. Every source file carries an SPDX header. Contributions
must use the Developer Certificate of Origin sign-off (`git commit -s`).

Do not push, publish crates, or change shared history from an agent checkout.

\n