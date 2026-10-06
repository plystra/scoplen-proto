# Repository guidance

The workspace guidance at [`../AGENTS.md`](../AGENTS.md) is authoritative for this repository.
The canonical contracts live in [`../scoplen-docs`](../scoplen-docs). Preserve unrelated changes,
keep shared contracts in this repository, and do not depend on client or server source trees.

## Commands

Use the pinned Rust toolchain and run `cargo fmt --all -- --check`, `cargo test --workspace`, and
`cargo clippy --workspace --all-targets --all-features -- -D warnings` before review.
