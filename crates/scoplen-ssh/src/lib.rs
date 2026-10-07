// SPDX-License-Identifier: Apache-2.0
//! Shared SSH protocol core for Scoplen clients and gateways.
//!
//! The algorithm policy, engine-independent transport boundary, authentication boundary, and
//! security-key wire support for K-7. The concrete SSH engine, channels, SFTP, and agent
//! transports remain separate so callers do not depend on a particular engine.

#![forbid(unsafe_code)]

/// The contract identifier used by the protocol-core crate.
pub const CONTRACT: &str = "K-7";

mod agent;
mod authentication;
mod channels;
mod policy;
mod security_key;
mod transport;

#[cfg(unix)]
pub use agent::connect_unix_agent;
#[cfg(windows)]
pub use agent::connect_windows_agent;
pub use agent::{
    AGENT_SIGN_FLAG_RSA_SHA2_256, AGENT_SIGN_FLAG_RSA_SHA2_512, AgentChannel, AgentClient,
    AgentConstraint, AgentError, AgentForwardingAuthorizer, AgentForwardingPolicy, AgentIdentity,
    AgentKeyStore, AgentMessage, AgentPrivateKey, AgentServer, FramedAgentChannel,
    MAX_AGENT_COMMENT, MAX_AGENT_CONSTRAINTS, MAX_AGENT_EXTENSION_DATA,
    MAX_AGENT_EXTENSION_DETAILS, MAX_AGENT_EXTENSION_NAME, MAX_AGENT_FRAME, MAX_AGENT_IDENTITIES,
    MAX_AGENT_KEY_BLOB, MAX_AGENT_PRIVATE_KEY, MAX_AGENT_SIGN_DATA,
};
pub use authentication::{
    AuthMethodError, CertificateKind, CertificateValidationError, CertificateValidationPolicy,
    Ed25519SshSigner, HostKey, HostKeyVerificationError, HostKeyVerifier,
    KeyboardInteractiveInfoRequest, KeyboardInteractivePrompt, KeyboardInteractiveRequest,
    KeyboardInteractiveResponse, NoneAuthRequest, P256SshSigner, PasswordAuthRequest,
    PublicKeyAuthContext, PublicKeyAuthRequest, PublicKeyIdentity, RsaSshSigner,
    SignatureAlgorithm, Signer, SignerError, SshCertificate, UserAuthContext, UserCertificate,
    verify_host_key,
};
pub use channels::{
    ChannelClose, ChannelCodecError, ChannelData, ChannelEof, ChannelExtendedData, ChannelFailure,
    ChannelOpen, ChannelOpenConfirmation, ChannelOpenFailure, ChannelOpenFailureReason,
    ChannelOpenType, ChannelRequest, ChannelRequestType, ChannelSuccess, ChannelWindowAdjust,
    ExitSignalRequest, ExtendedDataType, GlobalRequest, GlobalRequestFailure, GlobalRequestSuccess,
    GlobalRequestType, MAX_CHANNEL_ADDRESS, MAX_CHANNEL_MESSAGE, MAX_CHANNEL_NAME,
    MAX_CHANNEL_STRING, MAX_CHANNEL_TEXT, MAX_PTY_MODES, PtyRequest, Signal, WindowChangeRequest,
};
pub use policy::{AlgorithmCategory, AlgorithmPolicyError, HostAlgorithmPolicy};
pub use security_key::{
    SecurityKeyAlgorithm, SecurityKeyAuthRequest, SecurityKeyError, SecurityKeyProvider,
    SecurityKeyPublicKey, SecurityKeySignOptions, SecurityKeySignature,
};
pub use transport::{
    EXT_INFO_CLIENT, EXT_INFO_SERVER, KeyExchangeFamily, NegotiatedTransport, STRICT_KEX_CLIENT,
    STRICT_KEX_CLIENT_STANDARD, STRICT_KEX_SERVER, STRICT_KEX_SERVER_STANDARD, StrictKexError,
    StrictKexPacket, StrictKexPhase, StrictKeyExchange, TransportDirection,
    TransportNegotiationError, TransportOffer, TransportRole,
};
