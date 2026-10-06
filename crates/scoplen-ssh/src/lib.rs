// SPDX-License-Identifier: Apache-2.0
//! Shared SSH protocol core for Scoplen clients and gateways.
//!
//! The algorithm policy, engine-independent transport boundary, and authentication boundary for
//! K-7. The concrete SSH engine, channels, SFTP, and agent transports remain separate so callers
//! do not depend on a particular engine.

#![forbid(unsafe_code)]

/// The contract identifier used by the protocol-core crate.
pub const CONTRACT: &str = "K-7";

mod authentication;
mod policy;
mod transport;

pub use authentication::{
    CertificateKind, CertificateValidationError, CertificateValidationPolicy, Ed25519SshSigner,
    HostKey, HostKeyVerificationError, HostKeyVerifier, P256SshSigner, PublicKeyAuthContext,
    PublicKeyAuthRequest, PublicKeyIdentity, SignatureAlgorithm, Signer, SignerError,
    SshCertificate, UserCertificate, verify_host_key,
};
pub use policy::{AlgorithmCategory, AlgorithmPolicyError, HostAlgorithmPolicy};
pub use transport::{
    EXT_INFO_CLIENT, EXT_INFO_SERVER, KeyExchangeFamily, NegotiatedTransport, STRICT_KEX_CLIENT,
    STRICT_KEX_CLIENT_STANDARD, STRICT_KEX_SERVER, STRICT_KEX_SERVER_STANDARD, StrictKexError,
    StrictKexPacket, StrictKexPhase, StrictKeyExchange, TransportDirection,
    TransportNegotiationError, TransportOffer, TransportRole,
};
