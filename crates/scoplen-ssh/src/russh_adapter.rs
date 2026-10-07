// SPDX-License-Identifier: Apache-2.0
//! Concrete SSH client integration backed by `russh`.
//!
//! This module is the first concrete S4 slice.  It owns the `russh` event loop and translates its
//! connection and channel handles into an opaque API for the rest of Scoplen.  No `russh` type is
//! part of the public surface, so the engine can be replaced without changing consumers.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::{
    borrow::Cow,
    fmt, io,
    pin::Pin,
    str,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use russh::{
    ChannelMsg, Pty, Signer as RusshSigner,
    client::{self, Handler},
    keys::agent::AgentIdentity,
    keys::{Algorithm, EcdsaCurve, HashAlg, PublicKeyOrCertificate},
};
use scoplen_crypto::SecretVec;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroize;

use crate::{
    CertificateValidationPolicy, ExtendedDataType, HostKeyVerificationError, HostKeyVerifier,
    MAX_CHANNEL_TEXT, PtyRequest, PublicKeyAuthContext, PublicKeyAuthRequest, PublicKeyIdentity,
    SignatureAlgorithm, Signer, SignerError, WindowChangeRequest, verify_host_key,
};

const MAX_CLIENT_HOST: usize = 4096;
const MAX_CERTIFICATE_PRINCIPAL: usize = 4096;
const MAX_PUBLICKEY_AUTH_PAYLOAD: usize = 256 * 1024;
const DEFAULT_CLIENT_CHANNEL_LIMIT: usize = 64;
/// Maximum number of channels that one client connection may keep open.
pub const MAX_CLIENT_CHANNEL_LIMIT: usize = 256;
const USERAUTH_REQUEST: u8 = 50;

/// Errors raised while creating a concrete SSH client configuration.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ClientConfigError {
    /// A required text field is empty or contains a NUL byte.
    #[error("invalid SSH client configuration field: {0}")]
    InvalidField(&'static str),
    /// A configuration text field exceeds its bounded input limit.
    #[error("SSH client configuration field is too large: {0}")]
    FieldTooLarge(&'static str),
    /// The TCP destination port is not valid for an SSH endpoint.
    #[error("SSH client configuration port must be non-zero")]
    InvalidPort,
    /// The simultaneous channel limit is zero or exceeds the supported bound.
    #[error("SSH client channel limit must be between 1 and {MAX_CLIENT_CHANNEL_LIMIT}")]
    InvalidChannelLimit,
}

/// Host-certificate policy used by the concrete host-key callback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostKeyPolicy {
    expected_principal: String,
    now: u64,
}

impl HostKeyPolicy {
    /// Build a policy requiring `expected_principal` and evaluating validity at `now`.
    pub fn new(expected_principal: impl Into<String>, now: u64) -> Result<Self, ClientConfigError> {
        let expected_principal = expected_principal.into();
        validate_text(
            expected_principal.as_bytes(),
            MAX_CERTIFICATE_PRINCIPAL,
            "certificate principal",
            true,
        )?;
        Ok(Self { expected_principal, now })
    }

    /// Return the certificate principal checked before the trust callback.
    #[must_use]
    pub fn expected_principal(&self) -> &str {
        &self.expected_principal
    }

    /// Return the Unix timestamp used for certificate validity.
    #[must_use]
    pub const fn now(&self) -> u64 {
        self.now
    }
}

/// A concrete SSH client configuration.
///
/// The config deliberately accepts a trust callback rather than a known-hosts file.  Storage and
/// policy for host keys belong to the caller; the callback is invoked only after the shared
/// certificate and key parser has validated the presented bytes.
pub struct ClientConfig {
    host: String,
    port: u16,
    host_key_policy: HostKeyPolicy,
    verifier: Arc<dyn HostKeyVerifier + Send + Sync>,
    inactivity_timeout: Option<Duration>,
    keepalive_interval: Option<Duration>,
    keepalive_max: usize,
    channel_limit: usize,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("host_key_policy", &self.host_key_policy)
            .field("inactivity_timeout", &self.inactivity_timeout)
            .field("keepalive_interval", &self.keepalive_interval)
            .field("keepalive_max", &self.keepalive_max)
            .field("channel_limit", &self.channel_limit)
            .finish_non_exhaustive()
    }
}

impl Clone for ClientConfig {
    fn clone(&self) -> Self {
        Self {
            host: self.host.clone(),
            port: self.port,
            host_key_policy: self.host_key_policy.clone(),
            verifier: Arc::clone(&self.verifier),
            inactivity_timeout: self.inactivity_timeout,
            keepalive_interval: self.keepalive_interval,
            keepalive_max: self.keepalive_max,
            channel_limit: self.channel_limit,
        }
    }
}

impl ClientConfig {
    /// Build a client configuration with the host name as the default certificate principal.
    pub fn new<V>(
        host: impl Into<String>,
        port: u16,
        verifier: V,
    ) -> Result<Self, ClientConfigError>
    where
        V: HostKeyVerifier + Send + Sync + 'static,
    {
        let host = host.into();
        validate_text(host.as_bytes(), MAX_CLIENT_HOST, "host", true)?;
        if port == 0 {
            return Err(ClientConfigError::InvalidPort);
        }
        let host_key_policy = HostKeyPolicy::new(host.clone(), unix_time_seconds())?;
        Ok(Self {
            host,
            port,
            host_key_policy,
            verifier: Arc::new(verifier),
            inactivity_timeout: None,
            keepalive_interval: None,
            keepalive_max: 3,
            channel_limit: DEFAULT_CLIENT_CHANNEL_LIMIT,
        })
    }

    /// Replace the host-certificate policy while retaining the endpoint and trust callback.
    #[must_use]
    pub fn with_host_key_policy(mut self, policy: HostKeyPolicy) -> Self {
        self.host_key_policy = policy;
        self
    }

    /// Configure the inactivity timeout used by the underlying event loop.
    #[must_use]
    pub fn with_inactivity_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.inactivity_timeout = timeout;
        self
    }

    /// Configure periodic keepalives used by the underlying event loop.
    #[must_use]
    pub fn with_keepalive(mut self, interval: Option<Duration>, max_missed: usize) -> Self {
        self.keepalive_interval = interval;
        self.keepalive_max = max_missed;
        self
    }

    /// Bound simultaneous session and forwarding channels on one SSH connection.
    pub fn with_channel_limit(mut self, limit: usize) -> Result<Self, ClientConfigError> {
        if !(1..=MAX_CLIENT_CHANNEL_LIMIT).contains(&limit) {
            return Err(ClientConfigError::InvalidChannelLimit);
        }
        self.channel_limit = limit;
        Ok(self)
    }

    /// Return the configured host name.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Return the configured TCP port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    fn russh_config(&self) -> client::Config {
        // Keep the concrete engine offer as the ordered intersection of the K-7 policy and the
        // algorithms implemented by russh.  In particular, sntrup and umac remain in the shared
        // policy but are not advertised here because this russh release cannot negotiate them.
        let preferred = russh::Preferred {
            kex: Cow::Owned(vec![
                russh::kex::MLKEM768X25519_SHA256,
                russh::kex::CURVE25519,
                russh::kex::ECDH_SHA2_NISTP256,
                russh::kex::ECDH_SHA2_NISTP384,
                russh::kex::ECDH_SHA2_NISTP521,
                russh::kex::DH_G16_SHA512,
                russh::kex::DH_G18_SHA512,
                russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
                russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
            ]),
            key: Cow::Owned(vec![
                Algorithm::Ed25519,
                Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 },
                Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 },
                Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 },
                Algorithm::Rsa { hash: Some(HashAlg::Sha512) },
                Algorithm::Rsa { hash: Some(HashAlg::Sha256) },
            ]),
            cipher: Cow::Owned(vec![
                russh::cipher::CHACHA20_POLY1305,
                russh::cipher::AES_256_GCM,
                russh::cipher::AES_128_GCM,
                russh::cipher::AES_256_CTR,
                russh::cipher::AES_192_CTR,
                russh::cipher::AES_128_CTR,
            ]),
            mac: Cow::Owned(vec![russh::mac::HMAC_SHA512_ETM, russh::mac::HMAC_SHA256_ETM]),
            compression: Cow::Owned(vec![russh::compression::NONE, russh::compression::ZLIB]),
            // Certificate algorithms precede raw keys on the wire (D-42).  russh derives the
            // certificate names from this separate list.
            host_key_certificates: Cow::Owned(vec![
                Algorithm::Ed25519,
                Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 },
                Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 },
                Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 },
                Algorithm::Rsa { hash: Some(HashAlg::Sha512) },
                Algorithm::Rsa { hash: Some(HashAlg::Sha256) },
            ]),
        };
        client::Config {
            preferred,
            inactivity_timeout: self.inactivity_timeout,
            keepalive_interval: self.keepalive_interval,
            keepalive_max: self.keepalive_max,
            nodelay: true,
            ..client::Config::default()
        }
    }
}

/// Errors returned by the concrete SSH client.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Configuration validation failed before a connection was opened.
    #[error(transparent)]
    Config(#[from] ClientConfigError),
    /// The server key was malformed, failed certificate validation, or was rejected by policy.
    #[error("SSH host-key verification failed: {0}")]
    HostKey(#[from] HostKeyVerificationError),
    /// The supplied password cannot be represented by the current `russh` password API.
    #[error("SSH password must be valid UTF-8")]
    PasswordEncoding,
    /// The server rejected password authentication.
    #[error("SSH password authentication was rejected")]
    AuthenticationRejected {
        /// Whether the server accepted the method as a partial multi-factor step.
        partial_success: bool,
    },
    /// The public-key signer or its session-bound request was invalid.
    #[error("SSH public-key authentication could not be completed: {0}")]
    PublicKey(#[from] PublicKeyAuthError),
    /// The server requires authentication before the requested channel operation.
    #[error("SSH authentication is required")]
    NotAuthenticated,
    /// A TCP or stream I/O operation failed.
    #[error("SSH transport I/O failed: {0}")]
    Transport(#[source] std::io::Error),
    /// The peer refused a channel open request.
    #[error("SSH channel open failed ({code}): {reason}")]
    ChannelOpen { code: u32, reason: String },
    /// A channel operation could not be delivered or completed.
    #[error("SSH channel operation failed")]
    Channel,
    /// The configured number of simultaneous channels is already open.
    #[error("SSH channel limit of {max} has been reached")]
    ChannelLimitReached { max: usize },
    /// The peer closed the connection or the event loop stopped.
    #[error("SSH connection closed")]
    ConnectionClosed,
    /// The SSH protocol negotiation or packet validation failed.
    #[error("SSH protocol negotiation failed")]
    Protocol,
    /// A peer extended-data type is outside the shared channel contract.
    #[error("unsupported SSH extended-data type: {0}")]
    UnsupportedExtendedData(u32),
    /// A local channel request exceeded the shared channel boundary.
    #[error("invalid SSH channel input: {0}")]
    InvalidInput(&'static str),
    /// A channel event belongs to an engine-internal request rather than a peer response.
    #[error("unexpected SSH channel event")]
    UnexpectedChannelEvent,
}

/// Errors raised while adapting the engine-independent signer to `russh`.
#[derive(Debug, Error)]
pub enum PublicKeyAuthError {
    /// The signer failed while producing a key or signature.
    #[error(transparent)]
    Signer(#[from] SignerError),
    /// The russh event loop could not receive the signature response.
    #[error("SSH event loop is unavailable")]
    Send(#[from] russh::SendError),
    /// A payload supplied by russh did not have the RFC 4252 shape expected by the shared core.
    #[error("malformed russh public-key signing payload: {0}")]
    MalformedPayload(&'static str),
    /// The engine asked the signer to sign with a different key than the offered identity.
    #[error("russh public-key identity does not match the signer")]
    KeyMismatch,
}

impl From<russh::Error> for ClientError {
    fn from(error: russh::Error) -> Self {
        match error {
            russh::Error::IO(error) => Self::Transport(error),
            russh::Error::ChannelOpenFailure(failure) => {
                Self::ChannelOpen { code: failure.code(), reason: failure.description().to_owned() }
            }
            russh::Error::WrongChannel
            | russh::Error::SendError
            | russh::Error::RecvError
            | russh::Error::RequestDenied
            | russh::Error::Pending => Self::Channel,
            russh::Error::NotAuthenticated => Self::NotAuthenticated,
            russh::Error::Disconnect
            | russh::Error::HUP
            | russh::Error::ConnectionTimeout
            | russh::Error::KeepaliveTimeout
            | russh::Error::InactivityTimeout => Self::ConnectionClosed,
            russh::Error::UnknownKey | russh::Error::WrongServerSig => {
                Self::HostKey(HostKeyVerificationError::InvalidEncoding)
            }
            _ => Self::Protocol,
        }
    }
}

/// A connected and authenticated-capable SSH client.
pub struct ClientConnection {
    handle: client::Handle<ClientHandler>,
    channel_slots: Arc<Semaphore>,
    channel_limit: usize,
}

impl fmt::Debug for ClientConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ClientConnection").finish_non_exhaustive()
    }
}

impl ClientConnection {
    /// Connect to the configured TCP endpoint and complete SSH key exchange.
    pub async fn connect(config: ClientConfig) -> Result<Self, ClientError> {
        let handler = ClientHandler::new(&config);
        let address = (config.host.clone(), config.port);
        let handle = client::connect(Arc::new(config.russh_config()), address, handler).await?;
        Ok(Self {
            handle,
            channel_slots: Arc::new(Semaphore::new(config.channel_limit)),
            channel_limit: config.channel_limit,
        })
    }

    /// Connect over a caller-provided byte stream and complete SSH key exchange.
    pub async fn connect_stream<S>(config: ClientConfig, stream: S) -> Result<Self, ClientError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let handler = ClientHandler::new(&config);
        let handle =
            client::connect_stream(Arc::new(config.russh_config()), stream, handler).await?;
        Ok(Self {
            handle,
            channel_slots: Arc::new(Semaphore::new(config.channel_limit)),
            channel_limit: config.channel_limit,
        })
    }

    /// Connect to a target through an already connected and authenticated jump host.
    ///
    /// The jump host opens an RFC 4254 `direct-tcpip` channel to the target. The channel is
    /// adapted to the same asynchronous stream boundary as [`Self::connect_stream`], so the
    /// target performs its own key exchange, host-key verification, and authentication. Retain
    /// the `jump` connection for as long as the returned target connection is in use. Calling
    /// this method again with the returned connection composes another hop, allowing arbitrary
    /// chain depth without exposing `russh` types.
    pub async fn connect_via_direct_tcpip(
        config: ClientConfig,
        jump: &ClientConnection,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<Self, ClientError> {
        let channel = jump
            .open_direct_tcpip(
                &config.host,
                u32::from(config.port),
                originator_address,
                originator_port,
            )
            .await?;
        Self::connect_stream(config, channel.into_stream()).await
    }

    /// Authenticate with a session-bound RFC 4252 public-key request.
    ///
    /// The private key stays behind [`Signer`]. `russh` supplies the exact bytes it is about to
    /// sign; the adapter parses those bytes into [`PublicKeyAuthRequest`] before asking the signer
    /// to produce the signature. This keeps the concrete engine on the same algorithm, identity,
    /// and session-binding boundary as the engine-independent implementation.
    pub async fn authenticate_publickey<S>(
        &mut self,
        username: &str,
        signer: &S,
    ) -> Result<(), ClientError>
    where
        S: Signer + Sync,
    {
        validate_text(username.as_bytes(), MAX_CLIENT_HOST, "username", true)
            .map_err(ClientError::Config)?;
        let identity =
            PublicKeyIdentity::from_signer(signer).map_err(PublicKeyAuthError::Signer)?;
        let key = ssh_key::PublicKey::from_bytes(identity.key_blob())
            .map_err(|_| PublicKeyAuthError::MalformedPayload("signer public key"))?;
        let hash_alg = rsa_hash_algorithm(signer.algorithm());
        let mut adapter = RusshSignerAdapter { signer, identity, username: username.to_owned() };
        let result = self
            .handle
            .authenticate_publickey_with(username.to_owned(), key, hash_alg, &mut adapter)
            .await
            .map_err(ClientError::PublicKey)?;
        match result {
            russh::client::AuthResult::Success => Ok(()),
            russh::client::AuthResult::Failure { partial_success, .. } => {
                Err(ClientError::AuthenticationRejected { partial_success })
            }
        }
    }

    /// Authenticate with RFC 4252 password authentication.
    pub async fn authenticate_password(
        &mut self,
        username: &str,
        password: &[u8],
    ) -> Result<(), ClientError> {
        validate_text(username.as_bytes(), MAX_CLIENT_HOST, "username", true)
            .map_err(ClientError::Config)?;
        let secret = SecretVec::new(password.to_vec());
        let mut password = str::from_utf8(secret.as_bytes())
            .map(str::to_owned)
            .map_err(|_| ClientError::PasswordEncoding)?;
        let result = self
            .handle
            .authenticate_password(username.to_owned(), password.clone())
            .await
            .map_err(ClientError::from);
        password.zeroize();
        match result? {
            russh::client::AuthResult::Success => Ok(()),
            russh::client::AuthResult::Failure { partial_success, .. } => {
                Err(ClientError::AuthenticationRejected { partial_success })
            }
        }
    }

    /// Open an RFC 4254 `session` channel.
    pub async fn open_session(&self) -> Result<ClientChannel, ClientError> {
        let permit = self.channel_permit()?;
        self.handle
            .channel_open_session()
            .await
            .map(|channel| ClientChannel::new(channel, permit))
            .map_err(ClientError::from)
    }

    /// Open an RFC 4254 `direct-tcpip` channel through this connection.
    pub async fn open_direct_tcpip(
        &self,
        target_address: &str,
        target_port: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ClientChannel, ClientError> {
        validate_text(target_address.as_bytes(), MAX_CLIENT_HOST, "target address", true)
            .map_err(ClientError::Config)?;
        validate_text(originator_address.as_bytes(), MAX_CLIENT_HOST, "originator address", true)
            .map_err(ClientError::Config)?;
        let permit = self.channel_permit()?;
        self.handle
            .channel_open_direct_tcpip(
                target_address.to_owned(),
                target_port,
                originator_address.to_owned(),
                originator_port,
            )
            .await
            .map(|channel| ClientChannel::new(channel, permit))
            .map_err(ClientError::from)
    }

    fn channel_permit(&self) -> Result<OwnedSemaphorePermit, ClientError> {
        Arc::clone(&self.channel_slots)
            .try_acquire_owned()
            .map_err(|_| ClientError::ChannelLimitReached { max: self.channel_limit })
    }

    /// Ask the peer to disconnect this SSH connection.
    pub async fn disconnect(&self) -> Result<(), ClientError> {
        self.handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await
            .map_err(ClientError::from)
    }
}

/// Peer events surfaced by a concrete SSH channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelEvent {
    /// Standard channel data.
    Data(Vec<u8>),
    /// Extended channel data, normally standard error.
    ExtendedData { data_type: ExtendedDataType, data: Vec<u8> },
    /// The peer sent channel EOF.
    Eof,
    /// The peer sent channel close.
    Close,
    /// The remote process exited with a status.
    ExitStatus(u32),
    /// The remote process exited because of a signal.
    ExitSignal {
        /// Signal name without the `SIG` prefix.
        signal: String,
        /// Whether the remote process produced a core dump.
        core_dumped: bool,
        /// Remote diagnostic text.
        error_message: String,
        /// RFC 3066 language tag.
        language_tag: String,
    },
    /// A channel request succeeded.
    Success,
    /// A channel request failed.
    Failure,
    /// The peer refused a channel open request after the channel wrapper was created.
    OpenFailure { code: u32, reason: String },
}

/// A concrete session or forwarding channel.
pub struct ClientChannel {
    channel: russh::Channel<client::Msg>,
    permit: OwnedSemaphorePermit,
}

impl fmt::Debug for ClientChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ClientChannel").finish_non_exhaustive()
    }
}

impl ClientChannel {
    fn new(channel: russh::Channel<client::Msg>, permit: OwnedSemaphorePermit) -> Self {
        Self { channel, permit }
    }

    /// Return the engine-local channel number for diagnostics and recorder correlation.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.channel.id().number()
    }

    /// Request a pseudo-terminal using the shared bounded PTY request shape.
    pub async fn request_pty(
        &self,
        request: &PtyRequest,
        want_reply: bool,
    ) -> Result<(), ClientError> {
        let term = str::from_utf8(&request.term)
            .map_err(|_| ClientError::InvalidInput("terminal type must be UTF-8"))?;
        validate_text(&request.term, MAX_CHANNEL_TEXT, "terminal type", true)
            .map_err(ClientError::Config)?;
        let modes = decode_terminal_modes(&request.modes)?;
        self.channel
            .request_pty(
                want_reply,
                term,
                request.columns,
                request.rows,
                request.pixel_width,
                request.pixel_height,
                &modes,
            )
            .await
            .map_err(ClientError::from)
    }

    /// Request the remote login shell.
    pub async fn request_shell(&self, want_reply: bool) -> Result<(), ClientError> {
        self.channel.request_shell(want_reply).await.map_err(ClientError::from)
    }

    /// Notify the remote PTY of a bounded terminal resize.
    ///
    /// The dimensions use the same RFC 4254 `window-change` shape as the engine-independent
    /// channel codec. The four fields are fixed-width protocol values, so the request cannot
    /// allocate based on peer-controlled input.
    pub async fn window_change(&self, request: &WindowChangeRequest) -> Result<(), ClientError> {
        self.channel
            .window_change(request.columns, request.rows, request.pixel_width, request.pixel_height)
            .await
            .map_err(ClientError::from)
    }

    /// Execute one bounded remote command.
    pub async fn exec(&self, want_reply: bool, command: &[u8]) -> Result<(), ClientError> {
        validate_text(command, MAX_CHANNEL_TEXT, "command", true).map_err(ClientError::Config)?;
        self.channel.exec(want_reply, command.to_vec()).await.map_err(ClientError::from)
    }

    /// Send one data chunk to the remote channel.
    pub async fn send_data(&self, data: &[u8]) -> Result<(), ClientError> {
        self.channel.data_bytes(data.to_vec()).await.map_err(ClientError::from)
    }

    /// Send channel EOF.
    pub async fn send_eof(&self) -> Result<(), ClientError> {
        self.channel.eof().await.map_err(ClientError::from)
    }

    /// Request channel close.
    pub async fn close(&self) -> Result<(), ClientError> {
        self.channel.close().await.map_err(ClientError::from)
    }

    /// Consume the channel as a bidirectional asynchronous byte stream.
    ///
    /// The stream carries only `direct-tcpip` channel data and lifecycle bytes. It is intended for
    /// [`ClientConnection::connect_stream`] and [`ClientConnection::connect_via_direct_tcpip`].
    #[must_use]
    pub fn into_stream(self) -> ClientChannelStream {
        ClientChannelStream { inner: self.channel.into_stream(), _permit: self.permit }
    }

    /// Wait for the next peer event. `Ok(None)` means the engine closed the event stream.
    pub async fn next_event(&mut self) -> Result<Option<ChannelEvent>, ClientError> {
        loop {
            let Some(message) = self.channel.wait().await else {
                return Ok(None);
            };
            let event = match message {
                ChannelMsg::Data { data } => ChannelEvent::Data(data.to_vec()),
                ChannelMsg::ExtendedData { data, ext } => ChannelEvent::ExtendedData {
                    data_type: ExtendedDataType::try_from(ext)
                        .map_err(|_| ClientError::UnsupportedExtendedData(ext))?,
                    data: data.to_vec(),
                },
                ChannelMsg::Eof => ChannelEvent::Eof,
                ChannelMsg::Close => ChannelEvent::Close,
                ChannelMsg::ExitStatus { exit_status } => ChannelEvent::ExitStatus(exit_status),
                ChannelMsg::ExitSignal { signal_name, core_dumped, error_message, lang_tag } => {
                    ChannelEvent::ExitSignal {
                        signal: signal_name_text(&signal_name).to_owned(),
                        core_dumped,
                        error_message,
                        language_tag: lang_tag,
                    }
                }
                ChannelMsg::Success => ChannelEvent::Success,
                ChannelMsg::Failure => ChannelEvent::Failure,
                ChannelMsg::OpenFailure(failure) => ChannelEvent::OpenFailure {
                    code: failure.code(),
                    reason: failure.description().to_owned(),
                },
                // Window updates and request echoes are consumed by the engine and are not
                // user-visible channel events.
                ChannelMsg::WindowAdjusted { .. }
                | ChannelMsg::RequestPty { .. }
                | ChannelMsg::RequestShell { .. }
                | ChannelMsg::Exec { .. }
                | ChannelMsg::Signal { .. }
                | ChannelMsg::RequestSubsystem { .. }
                | ChannelMsg::RequestX11 { .. }
                | ChannelMsg::SetEnv { .. }
                | ChannelMsg::WindowChange { .. }
                | ChannelMsg::AgentForward { .. }
                | ChannelMsg::XonXoff { .. }
                | ChannelMsg::Open { .. } => continue,
                _ => return Err(ClientError::UnexpectedChannelEvent),
            };
            return Ok(Some(event));
        }
    }
}

/// Opaque asynchronous stream backed by one SSH channel.
pub struct ClientChannelStream {
    inner: russh::ChannelStream<client::Msg>,
    _permit: OwnedSemaphorePermit,
}

impl fmt::Debug for ClientChannelStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ClientChannelStream").finish_non_exhaustive()
    }
}

impl AsyncRead for ClientChannelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for ClientChannelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

struct RusshSignerAdapter<'a, S: Signer + Sync> {
    signer: &'a S,
    identity: PublicKeyIdentity,
    username: String,
}

impl<S: Signer + Sync> RusshSignerAdapter<'_, S> {
    fn sign_request(
        &self,
        presented_key: &AgentIdentity,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, PublicKeyAuthError> {
        let presented_key = presented_key
            .public_key()
            .to_bytes()
            .map_err(|_| PublicKeyAuthError::MalformedPayload("presented public key"))?;
        if presented_key != self.identity.signing_key_blob() {
            return Err(PublicKeyAuthError::KeyMismatch);
        }
        let (context, identity) = decode_publickey_payload(&payload)?;
        if context.username() != self.username || context.service() != "ssh-connection" {
            return Err(PublicKeyAuthError::MalformedPayload("authentication context changed"));
        }
        if identity != self.identity {
            return Err(PublicKeyAuthError::KeyMismatch);
        }
        let request = PublicKeyAuthRequest::signed(context, identity, self.signer)?;
        if request.signature_payload() != payload {
            return Err(PublicKeyAuthError::MalformedPayload("session-bound payload changed"));
        }
        let signature = request
            .signature()
            .ok_or(PublicKeyAuthError::MalformedPayload("missing SSH signature"))?;
        let mut signed = payload;
        append_ssh_string(&mut signed, signature)?;
        Ok(signed)
    }
}

impl<S: Signer + Sync> RusshSigner for RusshSignerAdapter<'_, S> {
    type Error = PublicKeyAuthError;

    fn auth_sign(
        &mut self,
        key: &AgentIdentity,
        _hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        let result = self.sign_request(key, to_sign);
        async move { result }
    }
}

fn rsa_hash_algorithm(algorithm: SignatureAlgorithm) -> Option<HashAlg> {
    match algorithm {
        SignatureAlgorithm::RsaSha2_256 => Some(HashAlg::Sha256),
        SignatureAlgorithm::RsaSha2_512 => Some(HashAlg::Sha512),
        SignatureAlgorithm::Ed25519 | SignatureAlgorithm::EcdsaSha2Nistp256 => None,
    }
}

fn decode_publickey_payload(
    payload: &[u8],
) -> Result<(PublicKeyAuthContext, PublicKeyIdentity), PublicKeyAuthError> {
    if payload.len() > MAX_PUBLICKEY_AUTH_PAYLOAD {
        return Err(PublicKeyAuthError::MalformedPayload("payload is too large"));
    }
    let mut rest = payload;
    let session_id = read_ssh_string(&mut rest, "session identifier")?;
    let message = rest
        .first()
        .copied()
        .ok_or(PublicKeyAuthError::MalformedPayload("missing userauth message"))?;
    rest = &rest[1..];
    if message != USERAUTH_REQUEST {
        return Err(PublicKeyAuthError::MalformedPayload("unexpected userauth message"));
    }
    let username = read_ssh_string(&mut rest, "username")?;
    let service = read_ssh_string(&mut rest, "service")?;
    let method = read_ssh_string(&mut rest, "method")?;
    if method != b"publickey" {
        return Err(PublicKeyAuthError::MalformedPayload("unexpected authentication method"));
    }
    if rest.first().copied() != Some(1) {
        return Err(PublicKeyAuthError::MalformedPayload("unsigned public-key payload"));
    }
    rest = &rest[1..];
    let algorithm = read_ssh_string(&mut rest, "algorithm")?;
    let algorithm = str::from_utf8(algorithm)
        .map_err(|_| PublicKeyAuthError::MalformedPayload("algorithm is not UTF-8"))?;
    let key_blob = read_ssh_string(&mut rest, "public key")?;
    if !rest.is_empty() {
        return Err(PublicKeyAuthError::MalformedPayload("payload has trailing bytes"));
    }
    let username = str::from_utf8(username)
        .map_err(|_| PublicKeyAuthError::MalformedPayload("username is not UTF-8"))?;
    let service = str::from_utf8(service)
        .map_err(|_| PublicKeyAuthError::MalformedPayload("service is not UTF-8"))?;
    let context = PublicKeyAuthContext::new(session_id.to_vec(), username, service)
        .map_err(PublicKeyAuthError::Signer)?;
    let identity =
        PublicKeyIdentity::new(algorithm, key_blob.to_vec()).map_err(PublicKeyAuthError::Signer)?;
    Ok((context, identity))
}

fn read_ssh_string<'a>(
    input: &mut &'a [u8],
    field: &'static str,
) -> Result<&'a [u8], PublicKeyAuthError> {
    let length = input
        .get(..4)
        .ok_or(PublicKeyAuthError::MalformedPayload("truncated SSH string length"))?;
    let length = u32::from_be_bytes(
        length
            .try_into()
            .map_err(|_| PublicKeyAuthError::MalformedPayload("invalid SSH string length"))?,
    ) as usize;
    if length > MAX_PUBLICKEY_AUTH_PAYLOAD {
        return Err(PublicKeyAuthError::MalformedPayload(field));
    }
    let end = 4usize.checked_add(length).ok_or(PublicKeyAuthError::MalformedPayload(field))?;
    let value = input.get(4..end).ok_or(PublicKeyAuthError::MalformedPayload(field))?;
    *input = &input[end..];
    Ok(value)
}

fn append_ssh_string(output: &mut Vec<u8>, value: &[u8]) -> Result<(), PublicKeyAuthError> {
    let length = u32::try_from(value.len())
        .map_err(|_| PublicKeyAuthError::MalformedPayload("signature is too large"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct ClientHandler {
    host: String,
    host_key_policy: HostKeyPolicy,
    verifier: Arc<dyn HostKeyVerifier + Send + Sync>,
}

impl ClientHandler {
    fn new(config: &ClientConfig) -> Self {
        Self {
            host: config.host.clone(),
            host_key_policy: config.host_key_policy.clone(),
            verifier: Arc::clone(&config.verifier),
        }
    }
}

impl Handler for ClientHandler {
    type Error = ClientError;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let encoded = match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key
                .to_bytes()
                .map_err(|_| ClientError::HostKey(HostKeyVerificationError::InvalidEncoding))?,
            PublicKeyOrCertificate::Certificate(certificate) => certificate
                .to_bytes()
                .map_err(|_| ClientError::HostKey(HostKeyVerificationError::InvalidEncoding))?,
        };
        let certificate_policy = CertificateValidationPolicy::host(
            &self.host_key_policy.expected_principal,
            self.host_key_policy.now,
        );
        verify_host_key(&self.host, &encoded, &certificate_policy, self.verifier.as_ref())
            .map(|_| true)
            .map_err(ClientError::HostKey)
    }
}

fn decode_terminal_modes(input: &[u8]) -> Result<Vec<(Pty, u32)>, ClientError> {
    if input.is_empty() {
        return Err(ClientError::InvalidInput("terminal modes must end with TTY_OP_END"));
    }
    let mut modes = Vec::new();
    let mut offset = 0;
    while offset < input.len() {
        let opcode = input[offset];
        offset += 1;
        if opcode == 0 {
            if offset != input.len() {
                return Err(ClientError::InvalidInput("terminal modes have trailing bytes"));
            }
            return Ok(modes);
        }
        let end = offset
            .checked_add(4)
            .ok_or(ClientError::InvalidInput("terminal modes length overflow"))?;
        let value = input
            .get(offset..end)
            .ok_or(ClientError::InvalidInput("terminal mode value is truncated"))?;
        let pty = Pty::from_u8(opcode)
            .ok_or(ClientError::InvalidInput("terminal mode opcode is unsupported"))?;
        let value = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
        modes.push((pty, value));
        offset = end;
    }
    Err(ClientError::InvalidInput("terminal modes must end with TTY_OP_END"))
}

fn signal_name_text(signal: &russh::Sig) -> &str {
    match signal {
        russh::Sig::ABRT => "ABRT",
        russh::Sig::ALRM => "ALRM",
        russh::Sig::FPE => "FPE",
        russh::Sig::HUP => "HUP",
        russh::Sig::ILL => "ILL",
        russh::Sig::INT => "INT",
        russh::Sig::KILL => "KILL",
        russh::Sig::PIPE => "PIPE",
        russh::Sig::QUIT => "QUIT",
        russh::Sig::SEGV => "SEGV",
        russh::Sig::TERM => "TERM",
        russh::Sig::USR1 => "USR1",
        russh::Sig::Custom(name) => name,
    }
}

fn validate_text(
    value: &[u8],
    limit: usize,
    field: &'static str,
    non_empty: bool,
) -> Result<(), ClientConfigError> {
    if value.len() > limit {
        return Err(ClientConfigError::FieldTooLarge(field));
    }
    if non_empty && value.is_empty() || value.contains(&0) {
        return Err(ClientConfigError::InvalidField(field));
    }
    Ok(())
}

fn unix_time_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use russh::keys::PrivateKey;
    use scoplen_crypto::{Ed25519SigningKey, P256SigningKey};
    use ssh_key::Algorithm;
    use tokio::io::duplex;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;
    use tokio::time::{Duration, timeout};

    use super::*;
    use crate::{Ed25519SshSigner, HostKey, P256SshSigner, RsaSshSigner};

    #[derive(Clone)]
    struct ResizeServer {
        changes: mpsc::Sender<WindowChangeRequest>,
    }

    impl russh::server::Handler for ResizeServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: russh::Channel<russh::server::Msg>,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn window_change_request(
            &mut self,
            channel: russh::ChannelId,
            columns: u32,
            rows: u32,
            pixel_width: u32,
            pixel_height: u32,
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            let _ = self
                .changes
                .send(WindowChangeRequest { columns, rows, pixel_width, pixel_height })
                .await;
            let _ = session.channel_success(channel);
            Ok(())
        }

        async fn data(
            &mut self,
            channel: russh::ChannelId,
            data: &[u8],
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            session.data(channel, data.to_vec())
        }
    }

    #[test]
    fn config_rejects_empty_host_and_zero_port() {
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        assert!(matches!(
            ClientConfig::new("", 22, verifier),
            Err(ClientConfigError::InvalidField("host"))
        ));
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        assert!(matches!(
            ClientConfig::new("example.test", 0, verifier),
            Err(ClientConfigError::InvalidPort)
        ));
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("example.test", 22, verifier).expect("config");
        assert!(matches!(
            config.clone().with_channel_limit(0),
            Err(ClientConfigError::InvalidChannelLimit)
        ));
        assert!(matches!(
            config.with_channel_limit(MAX_CLIENT_CHANNEL_LIMIT + 1),
            Err(ClientConfigError::InvalidChannelLimit)
        ));
    }

    #[test]
    fn terminal_modes_are_bounded_and_require_end_marker() {
        assert!(matches!(decode_terminal_modes(&[0]), Ok(modes) if modes.is_empty()));
        assert!(matches!(
            decode_terminal_modes(&[Pty::ECHO as u8, 0, 0, 0, 1, 0]),
            Ok(modes) if modes == vec![(Pty::ECHO, 1)]
        ));
        assert!(matches!(
            decode_terminal_modes(&[Pty::ECHO as u8, 0, 0]),
            Err(ClientError::InvalidInput("terminal mode value is truncated"))
        ));
        assert!(matches!(
            decode_terminal_modes(&[Pty::ECHO as u8, 0, 0, 0, 1]),
            Err(ClientError::InvalidInput("terminal modes must end with TTY_OP_END"))
        ));
    }

    #[tokio::test]
    async fn host_key_callback_validates_before_invoking_trust_callback() {
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("test key");
        let public_key = key.public_key().clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let verifier = move |host: &str, presented: &HostKey| {
            assert_eq!(host, "host.example");
            assert!(matches!(presented, HostKey::Raw { .. }));
            callback_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };
        let config = ClientConfig::new("host.example", 22, verifier).expect("config");
        let mut handler = ClientHandler::new(&config);
        assert!(
            handler
                .check_server_key(&PublicKeyOrCertificate::PublicKey {
                    key: public_key,
                    hash_alg: None,
                })
                .await
                .expect("callback accepts key")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn connect_stream_reaches_server_banner_before_protocol_error() {
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("host.example", 22, verifier).expect("config");
        let (client, mut peer) = duplex(128);
        let task =
            tokio::spawn(async move { ClientConnection::connect_stream(config, client).await });
        tokio::io::AsyncWriteExt::write_all(&mut peer, b"not-ssh\r\n").await.expect("write banner");
        drop(peer);
        let result =
            timeout(Duration::from_secs(5), task).await.expect("bounded handshake").expect("join");
        assert!(matches!(
            result,
            Err(ClientError::Protocol | ClientError::ConnectionClosed | ClientError::Transport(_))
        ));
    }

    #[tokio::test]
    async fn window_change_forwards_bounded_dimensions() {
        let (changes, mut received) = mpsc::channel(1);
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let address = listener.local_addr().expect("server address");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let _ =
                russh::server::run_stream(server_config, stream, ResizeServer { changes }).await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");
        let channel = connection.open_session().await.expect("open session");
        let expected = WindowChangeRequest {
            columns: u32::MAX,
            rows: u32::MAX - 1,
            pixel_width: u32::MAX - 2,
            pixel_height: u32::MAX - 3,
        };
        channel.window_change(&expected).await.expect("send resize");
        let observed = timeout(Duration::from_secs(5), received.recv())
            .await
            .expect("resize callback")
            .expect("resize event");
        assert_eq!(observed, expected);
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn one_connection_multiplexes_and_bounds_independent_channels() {
        let (changes, _received) = mpsc::channel(1);
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let address = listener.local_addr().expect("server address");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let _ =
                russh::server::run_stream(server_config, stream, ResizeServer { changes }).await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier)
            .expect("config")
            .with_channel_limit(2)
            .expect("channel limit");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");

        let mut first = connection.open_session().await.expect("first channel");
        let mut second = connection.open_session().await.expect("second channel");
        assert_ne!(first.id(), second.id());
        assert!(matches!(
            connection.open_session().await,
            Err(ClientError::ChannelLimitReached { max: 2 })
        ));
        assert!(matches!(
            connection.open_direct_tcpip("example.test", 22, "127.0.0.1", 1).await,
            Err(ClientError::ChannelLimitReached { max: 2 })
        ));

        first.send_data(b"first").await.expect("send first");
        second.send_data(b"second").await.expect("send second");
        assert!(matches!(
            timeout(Duration::from_secs(5), first.next_event()).await.expect("first response"),
            Ok(Some(ChannelEvent::Data(bytes))) if bytes == b"first"
        ));
        assert!(matches!(
            timeout(Duration::from_secs(5), second.next_event()).await.expect("second response"),
            Ok(Some(ChannelEvent::Data(bytes))) if bytes == b"second"
        ));

        drop(first);
        let rejected = timeout(
            Duration::from_secs(5),
            connection.open_direct_tcpip("example.test", 22, "127.0.0.1", 1),
        )
        .await
        .expect("direct channel rejection");
        assert!(matches!(rejected, Err(ClientError::ChannelOpen { .. })));
        let third = connection.open_session().await.expect("slot released on channel drop");
        drop(third);
        let stream = second.into_stream();
        let extra = connection.open_session().await.expect("one stream still reserves one slot");
        assert!(matches!(
            connection.open_session().await,
            Err(ClientError::ChannelLimitReached { max: 2 })
        ));
        drop(stream);
        let fourth = connection.open_session().await.expect("stream drop releases slot");
        drop(fourth);
        drop(extra);
        connection.disconnect().await.expect("disconnect client");
    }

    #[test]
    fn channel_stream_is_sendable_async_byte_transport() {
        fn assert_stream<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>() {}

        assert_stream::<ClientChannelStream>();
    }

    async fn assert_publickey_adapter_round_trip<S>(signer: &S)
    where
        S: Signer + Sync,
    {
        let identity = PublicKeyIdentity::from_signer(signer).expect("identity");
        let context =
            PublicKeyAuthContext::new([3; 32], "alice", "ssh-connection").expect("context");
        let probe = PublicKeyAuthRequest::probe(context.clone(), identity.clone()).expect("probe");
        let payload = probe.signature_payload();
        let expected = PublicKeyAuthRequest::signed(context, identity.clone(), signer)
            .expect("signed request");
        let expected_signature = expected.signature().expect("signature");
        let public_key =
            ssh_key::PublicKey::from_bytes(identity.signing_key_blob()).expect("public key");
        let agent_identity = AgentIdentity::from(public_key);
        let mut adapter = RusshSignerAdapter { signer, identity, username: "alice".to_owned() };
        let signed_payload = <RusshSignerAdapter<'_, S> as RusshSigner>::auth_sign(
            &mut adapter,
            &agent_identity,
            rsa_hash_algorithm(signer.algorithm()),
            payload.clone(),
        )
        .await
        .expect("adapter signs");
        assert!(signed_payload.starts_with(&payload));
        let suffix = &signed_payload[payload.len()..];
        let length = u32::from_be_bytes(suffix[..4].try_into().expect("length")) as usize;
        assert_eq!(length, expected_signature.len());
        assert_eq!(&suffix[4..], expected_signature);
    }

    #[tokio::test]
    async fn publickey_adapter_uses_shared_boundary_for_ed25519_and_p256() {
        let ed25519 =
            Ed25519SshSigner::new(Ed25519SigningKey::from_bytes(&[9; 32]).expect("Ed25519 key"));
        assert_publickey_adapter_round_trip(&ed25519).await;
        let p256 = P256SshSigner::new(P256SigningKey::from_bytes(&[1; 32]).expect("P-256 key"));
        assert_publickey_adapter_round_trip(&p256).await;
    }

    #[tokio::test]
    async fn publickey_adapter_uses_selected_rsa_sha2_algorithm() {
        let mut rng = ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng);
        let key = PrivateKey::random(&mut rng, Algorithm::Rsa { hash: None }).expect("RSA key");
        let signer = RsaSshSigner::new(key, SignatureAlgorithm::RsaSha2_512).expect("RSA signer");
        assert_publickey_adapter_round_trip(&signer).await;
    }

    #[tokio::test]
    async fn publickey_adapter_rejects_malformed_payload_and_key_substitution() {
        let signer =
            Ed25519SshSigner::new(Ed25519SigningKey::from_bytes(&[9; 32]).expect("Ed25519 key"));
        let identity = PublicKeyIdentity::from_signer(&signer).expect("identity");
        let public_key =
            ssh_key::PublicKey::from_bytes(identity.signing_key_blob()).expect("public key");
        let agent_identity = AgentIdentity::from(public_key);
        let mut adapter =
            RusshSignerAdapter { signer: &signer, identity, username: "alice".to_owned() };
        assert!(matches!(
            <RusshSignerAdapter<'_, Ed25519SshSigner> as RusshSigner>::auth_sign(
                &mut adapter,
                &agent_identity,
                None,
                vec![0; 4],
            )
            .await,
            Err(PublicKeyAuthError::MalformedPayload(_))
        ));

        let other = Ed25519SshSigner::new(
            Ed25519SigningKey::from_bytes(&[8; 32]).expect("other Ed25519 key"),
        );
        let identity = PublicKeyIdentity::from_signer(&signer).expect("identity");
        let context =
            PublicKeyAuthContext::new([3; 32], "alice", "ssh-connection").expect("context");
        let payload = PublicKeyAuthRequest::probe(context, identity.clone())
            .expect("probe")
            .signature_payload();
        let other_identity = PublicKeyIdentity::from_signer(&other).expect("other identity");
        let other_key = ssh_key::PublicKey::from_bytes(other_identity.signing_key_blob())
            .expect("other public key");
        let mut adapter =
            RusshSignerAdapter { signer: &signer, identity, username: "alice".to_owned() };
        assert!(matches!(
            <RusshSignerAdapter<'_, Ed25519SshSigner> as RusshSigner>::auth_sign(
                &mut adapter,
                &AgentIdentity::from(other_key),
                None,
                payload,
            )
            .await,
            Err(PublicKeyAuthError::KeyMismatch)
        ));
    }
}
