// SPDX-License-Identifier: Apache-2.0
//! Cryptographic formats shared by Scoplen clients and services.
//!
//! Implementations are kept in this crate so callers do not compose primitives independently.

#![forbid(unsafe_code)]

mod primitives;
mod secret;

pub use primitives::{
    ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, ARGON2_TIME_COST, PrimitiveError, argon2id_derive,
    hkdf_sha256, random_bytes, random_key, random_nonce, xchacha20poly1305_open,
    xchacha20poly1305_seal,
};
pub use secret::{SecretBytes, SecretVec, SymmetricKey, XChaChaNonce};

/// The contract identifier implemented by this crate.
pub const CONTRACT: &str = "K-2";
