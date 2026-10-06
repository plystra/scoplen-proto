// SPDX-License-Identifier: Apache-2.0
//! Shared SSH protocol core for Scoplen clients and gateways.
//!
//! The algorithm policy and engine-independent transport boundary are the first parts of K-7.
//! Authentication, channels, SFTP, and the concrete russh connection remain open.

#![forbid(unsafe_code)]

/// The contract identifier used by the protocol-core crate.
pub const CONTRACT: &str = "K-7";

mod policy;
mod transport;

pub use policy::{AlgorithmCategory, AlgorithmPolicyError, HostAlgorithmPolicy};
pub use transport::{
    EXT_INFO_CLIENT, EXT_INFO_SERVER, KeyExchangeFamily, NegotiatedTransport, STRICT_KEX_CLIENT,
    STRICT_KEX_CLIENT_STANDARD, STRICT_KEX_SERVER, STRICT_KEX_SERVER_STANDARD, StrictKexError,
    StrictKexPacket, StrictKexPhase, StrictKeyExchange, TransportDirection,
    TransportNegotiationError, TransportOffer, TransportRole,
};
