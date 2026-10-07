// SPDX-License-Identifier: Apache-2.0
//! Shared SSH protocol core for Scoplen clients and gateways.
//!
//! The algorithm policy, direct byte transport boundary, engine-independent authentication and
//! channel boundaries, security-key wire support, and bounded proxy composition for K-7. The
//! concrete SSH handshake engine, channel scheduling, and SFTP transfer engine remain separate so
//! callers do not depend on a particular engine.

#![forbid(unsafe_code)]

/// The contract identifier used by the protocol-core crate.
pub const CONTRACT: &str = "K-7";

mod agent;
mod authentication;
mod channels;
mod policy;
mod proxy;
mod russh_adapter;
mod security_key;
mod sftp;
mod socks;
mod socks_listener;
mod tcp;
mod transport;

#[cfg(unix)]
pub use agent::connect_unix_agent;
pub use agent::{
    AGENT_SIGN_FLAG_RSA_SHA2_256, AGENT_SIGN_FLAG_RSA_SHA2_512, AgentChannel, AgentClient,
    AgentConstraint, AgentError, AgentForwardingAdapter, AgentForwardingAuthorizer,
    AgentForwardingPolicy, AgentIdentity, AgentKeyStore, AgentMessage, AgentPrivateKey,
    AgentServer, AuthAgentChannel, AuthAgentChannelError, AuthAgentChannelState,
    FramedAgentChannel, MAX_AGENT_COMMENT, MAX_AGENT_CONSTRAINTS, MAX_AGENT_EXTENSION_DATA,
    MAX_AGENT_EXTENSION_DETAILS, MAX_AGENT_EXTENSION_NAME, MAX_AGENT_FORWARD_BUFFER,
    MAX_AGENT_FORWARD_RESPONSES, MAX_AGENT_FRAME, MAX_AGENT_IDENTITIES, MAX_AGENT_KEY_BLOB,
    MAX_AGENT_PRIVATE_KEY, MAX_AGENT_SIGN_DATA, MAX_AUTH_AGENT_CHANNEL_PACKET,
    MAX_AUTH_AGENT_CHANNEL_WINDOW, PAGEANT_WM_COPYDATA_ID, PAGEANT_WM_COPYDATA_MAPPING_NAME_LEN,
    PAGEANT_WM_COPYDATA_MAX_MSGLEN, PAGEANT_WM_COPYDATA_WINDOW_CLASS,
    PAGEANT_WM_COPYDATA_WINDOW_TITLE, PageantAgentChannel, PageantWmCopyData,
    PageantWmCopyDataBackend, PageantWmCopyDataChannel, pageant_wm_copydata_mapping_name,
    validate_pageant_wm_copydata_mapping_name,
};
#[cfg(windows)]
pub use agent::{connect_pageant_agent, connect_windows_agent};
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
pub use proxy::{
    HttpConnectTransport, MAX_HTTP_CONNECT_RESPONSE, MAX_PROXY_HOST, ProxyError, ProxyOperation,
    ProxyProtocol, ProxyTransportError, Socks5Transport,
};
pub use russh_adapter::{
    ChannelEvent, ClientChannel, ClientConfig, ClientConnection, ClientError, HostKeyPolicy,
    PublicKeyAuthError,
};
pub use security_key::{
    SecurityKeyAlgorithm, SecurityKeyAuthRequest, SecurityKeyError, SecurityKeyProvider,
    SecurityKeyPublicKey, SecurityKeySignOptions, SecurityKeySignature,
};
pub use sftp::{
    MAX_SFTP_EXTENSION_DATA, MAX_SFTP_EXTENSIONS, MAX_SFTP_HANDLE, MAX_SFTP_NAME_ENTRIES,
    MAX_SFTP_OUTSTANDING, MAX_SFTP_PACKET, MAX_SFTP_STRING, SftpAttributes, SftpClient, SftpError,
    SftpExtension, SftpLimits, SftpNameEntry, SftpPacket, SftpStatvfs,
};
pub use socks::{
    MAX_SOCKS_BUFFER, MAX_SOCKS_DOMAIN, MAX_SOCKS_USER_ID, SocksAddress, SocksBindAddress,
    SocksConnectRequest, SocksError, SocksHandshake, SocksProgress, SocksReply, SocksVersion,
};
pub use socks_listener::{
    DEFAULT_SOCKS_HANDSHAKE_TIMEOUT, DEFAULT_SOCKS_IO_BUFFER, DEFAULT_SOCKS_MAX_CONNECTIONS,
    MAX_SOCKS_IO_BUFFER, SocksCancellation, SocksChannel, SocksChannelError, SocksChannelEvent,
    SocksConnector, SocksForwardError, SocksListener, SocksListenerConfig, SocksListenerError,
    SocksListenerOperation, SocksOpenError,
};
pub use tcp::{
    MAX_TCP_ADDRESSES, MAX_TCP_HOST, TcpTransport, Transport, TransportError, TransportOperation,
};
pub use transport::{
    EXT_INFO_CLIENT, EXT_INFO_SERVER, KeyExchangeFamily, NegotiatedTransport, STRICT_KEX_CLIENT,
    STRICT_KEX_CLIENT_STANDARD, STRICT_KEX_SERVER, STRICT_KEX_SERVER_STANDARD, StrictKexError,
    StrictKexPacket, StrictKexPhase, StrictKeyExchange, TransportDirection,
    TransportNegotiationError, TransportOffer, TransportRole,
};
