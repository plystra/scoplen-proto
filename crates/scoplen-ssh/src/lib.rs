// SPDX-License-Identifier: Apache-2.0
//! Shared SSH protocol core for Scoplen clients and gateways.
//!
//! The algorithm policy is the first part of K-7. SSH transport, authentication, channels, and
//! strict key exchange are not yet implemented by this crate.

#![forbid(unsafe_code)]

/// The contract identifier used by the protocol-core crate.
pub const CONTRACT: &str = "K-7";

mod policy;

pub use policy::{AlgorithmCategory, AlgorithmPolicyError, HostAlgorithmPolicy};
