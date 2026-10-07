// SPDX-License-Identifier: Apache-2.0
//! Concrete SSH client integration backed by `russh`.
//!
//! This module is the first concrete S4 slice.  It owns the `russh` event loop and translates its
//! connection and channel handles into an opaque API for the rest of Scoplen.  No `russh` type is
//! part of the public surface, so the engine can be replaced without changing consumers.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::{borrow::Cow, fmt, str, sync::Arc, time::Duration};

use russh::{
    ChannelMsg, Pty,
    client::{self, Handler},
    keys::{Algorithm, EcdsaCurve, HashAlg, PublicKeyOrCertificate},
};
use scoplen_crypto::SecretVec;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroize;

use crate::{
    CertificateValidationPolicy, ExtendedDataType, HostKeyVerificationError, HostKeyVerifier,
    MAX_CHANNEL_TEXT, PtyRequest, verify_host_key,
};

const MAX_CLIENT_HOST: usize = 4096;
const MAX_CERTIFICATE_PRINCIPAL: usize = 4096;

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
        Ok(Self { handle })
    }

    /// Connect over a caller-provided byte stream and complete SSH key exchange.
    pub async fn connect_stream<S>(config: ClientConfig, stream: S) -> Result<Self, ClientError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let handler = ClientHandler::new(&config);
        let handle =
            client::connect_stream(Arc::new(config.russh_config()), stream, handler).await?;
        Ok(Self { handle })
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
        self.handle.channel_open_session().await.map(ClientChannel::new).map_err(ClientError::from)
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
        self.handle
            .channel_open_direct_tcpip(
                target_address.to_owned(),
                target_port,
                originator_address.to_owned(),
                originator_port,
            )
            .await
            .map(ClientChannel::new)
            .map_err(ClientError::from)
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
}

impl fmt::Debug for ClientChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ClientChannel").finish_non_exhaustive()
    }
}

impl ClientChannel {
    fn new(channel: russh::Channel<client::Msg>) -> Self {
        Self { channel }
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
    use ssh_key::Algorithm;
    use tokio::io::duplex;
    use tokio::time::{Duration, timeout};

    use super::*;
    use crate::HostKey;

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
}
