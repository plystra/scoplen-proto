// SPDX-License-Identifier: Apache-2.0
//! Cryptographic formats shared by Scoplen clients and services.
//!
//! Implementations are kept in this crate so callers do not compose primitives independently.

#![forbid(unsafe_code)]

/// The contract identifier implemented by this crate.
pub const CONTRACT: &str = "K-2";
\n