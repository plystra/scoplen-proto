// SPDX-License-Identifier: Apache-2.0
//! Shared SSH protocol core for Scoplen clients and gateways.
//!
//! The protocol implementation is introduced after the repository baseline. The crate root is
//! intentionally small so every consumer can depend on the same named package from the first
//! revision.

#![forbid(unsafe_code)]

/// The contract identifier used by the protocol-core crate.
pub const CONTRACT: &str = "K-7";
\n