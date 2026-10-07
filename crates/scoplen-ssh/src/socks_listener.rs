// SPDX-License-Identifier: Apache-2.0
//! A bounded dynamic SOCKS listener backed by SSH `direct-tcpip` channels.
//!
//! The listener deliberately owns only the local TCP socket and forwarding lifecycle.  The
//! [`SocksConnector`] and [`SocksChannel`] traits keep the public boundary independent of the
//! concrete SSH engine, while the implementations at the bottom of this module adapt the
//! `russh`-backed client types without exposing any `russh` type to callers.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Notify, Semaphore},
    task::JoinSet,
};

use crate::{
    ChannelEvent, ClientChannel, ClientConnection, ClientError, MAX_SOCKS_BUFFER, SocksAddress,
    SocksBindAddress, SocksConnectRequest, SocksError, SocksHandshake, SocksReply,
};

/// The largest local I/O buffer permitted by [`SocksListenerConfig`].
pub const MAX_SOCKS_IO_BUFFER: usize = 64 * 1024;
/// The default number of simultaneous SOCKS connections.
pub const DEFAULT_SOCKS_MAX_CONNECTIONS: usize = 64;
/// The default timeout for each handshake or channel-open operation.
pub const DEFAULT_SOCKS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// The default local read/write buffer size.
pub const DEFAULT_SOCKS_IO_BUFFER: usize = 16 * 1024;

/// The operation that failed while binding or accepting the listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocksListenerOperation {
    /// Binding the listening socket.
    Bind,
    /// Accepting a local connection.
    Accept,
}

/// Errors raised by the listener itself.  Per-connection failures are mapped to a SOCKS failure
/// response and do not tear down unrelated connections.
#[derive(Debug, Error)]
pub enum SocksListenerError {
    /// A configuration value would make the listener unbounded or unusable.
    #[error("invalid SOCKS listener configuration: {0}")]
    InvalidConfig(&'static str),
    /// Binding or accepting the local TCP socket failed.
    #[error("SOCKS listener {operation:?} failed: {source}")]
    Io {
        /// The local operation that failed.
        operation: SocksListenerOperation,
        /// The underlying operating-system error.
        #[source]
        source: io::Error,
    },
}

/// Errors raised while forwarding one accepted connection.
#[derive(Debug, Error)]
pub enum SocksForwardError {
    /// The peer sent an invalid or incomplete SOCKS handshake.
    #[error(transparent)]
    Handshake(#[from] SocksError),
    /// A local socket operation failed.
    #[error("SOCKS local {operation} failed: {source}")]
    Io {
        /// The local operation that failed.
        operation: &'static str,
        /// The underlying operating-system error.
        #[source]
        source: io::Error,
    },
    /// The direct-tcpip channel could not be opened.
    #[error(transparent)]
    Open(#[from] SocksOpenError),
    /// An established channel operation failed.
    #[error(transparent)]
    Channel(#[from] SocksChannelError),
    /// A bounded operation exceeded its timeout.
    #[error("SOCKS forwarding operation timed out")]
    Timeout,
    /// The listener was cancelled while this connection was active.
    #[error("SOCKS forwarding was cancelled")]
    Cancelled,
}

/// An error opening one requested target through `direct-tcpip`.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("direct-tcpip open failed ({reply:?}): {message}")]
pub struct SocksOpenError {
    /// The SOCKS response code that best describes the failure.
    pub reply: SocksReply,
    /// An engine-local diagnostic that is never sent to the SOCKS peer.
    pub message: String,
}

impl SocksOpenError {
    /// Build an open error with a protocol-visible failure mapping and a private diagnostic.
    #[must_use]
    pub fn new(reply: SocksReply, message: impl Into<String>) -> Self {
        Self { reply, message: message.into() }
    }
}

/// Errors raised by an established direct-tcpip channel.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SocksChannelError {
    /// The engine rejected a channel operation.
    #[error("channel operation failed: {0}")]
    Failed(String),
    /// The channel produced an event that is not valid for a byte-forwarding channel.
    #[error("channel produced an unexpected event")]
    UnexpectedEvent,
}

/// Events from a direct-tcpip channel that can be represented on a byte stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocksChannelEvent {
    /// Bytes received from the remote target.
    Data(Vec<u8>),
    /// The remote side sent channel EOF.
    Eof,
    /// The remote side closed the channel.
    Close,
}

/// A future returned by [`SocksChannel`] operations.
pub type SocksChannelFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, SocksChannelError>> + Send + 'a>>;

/// An opaque direct-tcpip channel used by the dynamic listener.
pub trait SocksChannel: Send {
    /// Send one bounded byte fragment to the remote target.
    fn send_data<'a>(&'a self, data: &'a [u8]) -> SocksChannelFuture<'a, ()>;
    /// Send channel EOF after the local peer has finished writing.
    fn send_eof(&self) -> SocksChannelFuture<'_, ()>;
    /// Close the channel and discard any remaining data.
    fn close(&self) -> SocksChannelFuture<'_, ()>;
    /// Wait for the next remote event. `None` means the engine ended the event stream.
    fn next_event(&mut self) -> SocksChannelFuture<'_, Option<SocksChannelEvent>>;
}

/// A future returned by [`SocksConnector`].
pub type SocksConnectorFuture =
    Pin<Box<dyn Future<Output = Result<Box<dyn SocksChannel>, SocksOpenError>> + Send>>;

/// Opens direct-tcpip channels without exposing a concrete SSH engine.
pub trait SocksConnector: Send + Sync + 'static {
    /// Open the requested target. The `Arc<Self>` receiver keeps the operation alive when the
    /// listener spawns one bounded task per accepted TCP connection.
    fn open_socks_direct_tcpip(
        self: Arc<Self>,
        request: SocksConnectRequest,
        originator: SocketAddr,
    ) -> SocksConnectorFuture;
}

/// A cancellation handle shared by a listener and all of its active connections.
#[derive(Clone, Debug)]
pub struct SocksCancellation {
    state: Arc<SocksCancellationState>,
}

#[derive(Debug)]
struct SocksCancellationState {
    cancelled: AtomicBool,
    notify: Notify,
}

impl Default for SocksCancellation {
    fn default() -> Self {
        Self::new()
    }
}

impl SocksCancellation {
    /// Create a not-yet-cancelled handle.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(SocksCancellationState {
                cancelled: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    /// Request listener shutdown. The operation is idempotent.
    pub fn cancel(&self) {
        if !self.state.cancelled.swap(true, Ordering::SeqCst) {
            self.state.notify.notify_waiters();
        }
    }

    /// Return whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::SeqCst)
    }

    async fn cancelled(&self) {
        loop {
            if self.is_cancelled() {
                return;
            }
            self.state.notify.notified().await;
        }
    }
}

/// Configuration for a dynamic SOCKS listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocksListenerConfig {
    /// Maximum number of accepted connections being handshaken or forwarded concurrently.
    pub max_connections: usize,
    /// Timeout applied to each handshake read, response write, and direct-tcpip open.
    pub handshake_timeout: Duration,
    /// Per-connection read/write buffer size.
    pub io_buffer_size: usize,
}

impl Default for SocksListenerConfig {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_SOCKS_MAX_CONNECTIONS,
            handshake_timeout: DEFAULT_SOCKS_HANDSHAKE_TIMEOUT,
            io_buffer_size: DEFAULT_SOCKS_IO_BUFFER,
        }
    }
}

impl SocksListenerConfig {
    fn validate(self) -> Result<Self, SocksListenerError> {
        if self.max_connections == 0 {
            return Err(SocksListenerError::InvalidConfig("max_connections must be non-zero"));
        }
        if self.handshake_timeout.is_zero() {
            return Err(SocksListenerError::InvalidConfig("handshake_timeout must be non-zero"));
        }
        if self.io_buffer_size == 0 {
            return Err(SocksListenerError::InvalidConfig("io_buffer_size must be non-zero"));
        }
        if self.io_buffer_size > MAX_SOCKS_IO_BUFFER {
            return Err(SocksListenerError::InvalidConfig("io_buffer_size exceeds the bound"));
        }
        Ok(self)
    }
}

/// A bounded local TCP listener that exposes a remote SSH connection as SOCKS4a/SOCKS5.
pub struct SocksListener {
    listener: TcpListener,
    config: SocksListenerConfig,
}

impl std::fmt::Debug for SocksListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SocksListener")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl SocksListener {
    /// Bind a dynamic forwarding listener to a local address.
    pub async fn bind(
        address: SocketAddr,
        config: SocksListenerConfig,
    ) -> Result<Self, SocksListenerError> {
        let config = config.validate()?;
        let listener = TcpListener::bind(address).await.map_err(|source| {
            SocksListenerError::Io { operation: SocksListenerOperation::Bind, source }
        })?;
        Ok(Self { listener, config })
    }

    /// Return the address selected by the operating system.
    pub fn local_addr(&self) -> Result<SocketAddr, SocksListenerError> {
        self.listener.local_addr().map_err(|source| SocksListenerError::Io {
            operation: SocksListenerOperation::Accept,
            source,
        })
    }

    /// Run until cancellation, retaining at most `max_connections` active connection tasks.
    ///
    /// Incoming connections that arrive while the cap is full are closed immediately. A failed
    /// SOCKS handshake or direct-tcpip open is isolated to that connection and does not stop the
    /// listener. Cancellation is propagated to every active operation and all tasks are joined
    /// before this method returns.
    pub async fn run(
        self,
        connector: Arc<dyn SocksConnector>,
        cancellation: SocksCancellation,
    ) -> Result<(), SocksListenerError> {
        let permits = Arc::new(Semaphore::new(self.config.max_connections));
        let mut tasks = JoinSet::new();

        loop {
            tokio::select! {
                () = cancellation.cancelled() => break,
                accepted = self.listener.accept() => {
                    let (stream, originator) = accepted.map_err(|source| SocksListenerError::Io {
                        operation: SocksListenerOperation::Accept,
                        source,
                    })?;
                    let Ok(permit) = permits.clone().try_acquire_owned() else {
                        // The configured cap is deliberately fail-closed. Closing the socket
                        // here avoids an unbounded queue of handshakes behind the listener.
                        continue;
                    };
                    let config = self.config;
                    let connector = Arc::clone(&connector);
                    let cancellation = cancellation.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let _ = forward_connection(
                            stream,
                            originator,
                            connector,
                            config,
                            cancellation,
                        )
                        .await;
                    });
                }
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    let _ = joined;
                }
            }
        }

        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}

async fn forward_connection(
    mut stream: TcpStream,
    originator: SocketAddr,
    connector: Arc<dyn SocksConnector>,
    config: SocksListenerConfig,
    cancellation: SocksCancellation,
) -> Result<(), SocksForwardError> {
    let mut handshake = SocksHandshake::new();
    let mut buffer = vec![0; config.io_buffer_size.min(MAX_SOCKS_BUFFER)];
    let (channel, trailing) = loop {
        let read = tokio::select! {
            () = cancellation.cancelled() => return Err(SocksForwardError::Cancelled),
            result = tokio::time::timeout(config.handshake_timeout, stream.read(&mut buffer)) => {
                result.map_err(|_| SocksForwardError::Timeout)?.map_err(|source| SocksForwardError::Io {
                    operation: "read",
                    source,
                })?
            }
        };
        if read == 0 {
            handshake.finish()?;
            return Ok(());
        }
        let progress = handshake.feed(&buffer[..read])?;
        if !progress.response.is_empty() {
            write_with_cancel(
                &mut stream,
                &progress.response,
                &cancellation,
                config.handshake_timeout,
            )
            .await?;
        }
        if progress.done {
            return Ok(());
        }
        let Some(request) = progress.request else {
            continue;
        };
        let opened = tokio::select! {
            () = cancellation.cancelled() => return Err(SocksForwardError::Cancelled),
            result = tokio::time::timeout(
                config.handshake_timeout,
                connector.clone().open_socks_direct_tcpip(request, originator),
            ) => match result {
                Ok(result) => result,
                Err(_) => Err(SocksOpenError::new(
                    SocksReply::GeneralFailure,
                    "direct-tcpip open timed out",
                )),
            },
        };
        let channel = match opened {
            Ok(channel) => channel,
            Err(error) => {
                let response = handshake.reject(error.reply)?;
                write_with_cancel(&mut stream, &response, &cancellation, config.handshake_timeout)
                    .await?;
                return Ok(());
            }
        };
        let bound = SocksBindAddress::new(SocksAddress::Ipv4([0, 0, 0, 0]), 0)
            .map_err(SocksForwardError::Handshake)?;
        let response = handshake.accept(&bound).map_err(SocksForwardError::Handshake)?;
        write_with_cancel(&mut stream, &response, &cancellation, config.handshake_timeout).await?;
        break (channel, progress.trailing);
    };

    forward_bytes(stream, channel, trailing, buffer, cancellation).await
}

async fn write_with_cancel(
    stream: &mut TcpStream,
    bytes: &[u8],
    cancellation: &SocksCancellation,
    timeout_duration: Duration,
) -> Result<(), SocksForwardError> {
    tokio::select! {
        () = cancellation.cancelled() => Err(SocksForwardError::Cancelled),
        result = tokio::time::timeout(timeout_duration, stream.write_all(bytes)) => {
            result.map_err(|_| SocksForwardError::Timeout)?.map_err(|source| SocksForwardError::Io {
                operation: "write",
                source,
            })
        }
    }
}

async fn forward_bytes(
    mut stream: TcpStream,
    mut channel: Box<dyn SocksChannel>,
    trailing: Vec<u8>,
    mut buffer: Vec<u8>,
    cancellation: SocksCancellation,
) -> Result<(), SocksForwardError> {
    if !trailing.is_empty() {
        channel.send_data(&trailing).await?;
    }
    let mut local_eof = false;
    let mut remote_eof = false;
    let mut channel_eof_sent = false;

    while !(local_eof && remote_eof) {
        if local_eof {
            let event = tokio::select! {
                () = cancellation.cancelled() => return close_after_cancel(channel).await,
                event = channel.next_event() => event?,
            };
            if apply_remote_event(&mut stream, event, &mut remote_eof).await? {
                break;
            }
            continue;
        }
        if remote_eof {
            let read = tokio::select! {
                () = cancellation.cancelled() => return close_after_cancel(channel).await,
                result = stream.read(&mut buffer) => result.map_err(|source| SocksForwardError::Io {
                    operation: "read",
                    source,
                })?,
            };
            if read == 0 {
                local_eof = true;
                if !channel_eof_sent {
                    channel.send_eof().await?;
                    channel_eof_sent = true;
                }
            } else {
                channel.send_data(&buffer[..read]).await?;
            }
            continue;
        }

        tokio::select! {
            () = cancellation.cancelled() => return close_after_cancel(channel).await,
            result = stream.read(&mut buffer) => {
                let read = result.map_err(|source| SocksForwardError::Io {
                    operation: "read",
                    source,
                })?;
                if read == 0 {
                    local_eof = true;
                    if !channel_eof_sent {
                        channel.send_eof().await?;
                        channel_eof_sent = true;
                    }
                } else {
                    channel.send_data(&buffer[..read]).await?;
                }
            }
            event = channel.next_event() => {
                if apply_remote_event(&mut stream, event?, &mut remote_eof).await? {
                    break;
                }
            }
        }
    }
    channel.close().await?;
    Ok(())
}

async fn apply_remote_event(
    stream: &mut TcpStream,
    event: Option<SocksChannelEvent>,
    remote_eof: &mut bool,
) -> Result<bool, SocksForwardError> {
    match event {
        Some(SocksChannelEvent::Data(data)) => {
            stream
                .write_all(&data)
                .await
                .map_err(|source| SocksForwardError::Io { operation: "write", source })?;
            Ok(false)
        }
        Some(SocksChannelEvent::Eof | SocksChannelEvent::Close) | None => {
            *remote_eof = true;
            stream
                .shutdown()
                .await
                .map_err(|source| SocksForwardError::Io { operation: "shutdown", source })?;
            Ok(matches!(event, Some(SocksChannelEvent::Close) | None))
        }
    }
}

async fn close_after_cancel(channel: Box<dyn SocksChannel>) -> Result<(), SocksForwardError> {
    let _ = channel.close().await;
    Ok(())
}

fn target_text(address: &SocksAddress) -> Result<String, SocksOpenError> {
    match address {
        SocksAddress::Ipv4(value) => Ok(std::net::Ipv4Addr::from(*value).to_string()),
        SocksAddress::Ipv6(value) => Ok(std::net::Ipv6Addr::from(*value).to_string()),
        SocksAddress::Domain(value) => String::from_utf8(value.clone()).map_err(|_| {
            SocksOpenError::new(SocksReply::GeneralFailure, "SOCKS domain name is not valid UTF-8")
        }),
    }
}

fn client_open_error(error: &ClientError) -> SocksOpenError {
    let reply = match &error {
        ClientError::ChannelOpen { code, .. } => match code {
            1 => SocksReply::ConnectionNotAllowed,
            2 => SocksReply::ConnectionRefused,
            3 => SocksReply::CommandNotSupported,
            _ => SocksReply::GeneralFailure,
        },
        ClientError::Transport(error) => match error.kind() {
            io::ErrorKind::ConnectionRefused => SocksReply::ConnectionRefused,
            io::ErrorKind::HostUnreachable => SocksReply::HostUnreachable,
            io::ErrorKind::NetworkUnreachable => SocksReply::NetworkUnreachable,
            _ => SocksReply::GeneralFailure,
        },
        ClientError::NotAuthenticated => SocksReply::ConnectionNotAllowed,
        _ => SocksReply::GeneralFailure,
    };
    SocksOpenError::new(reply, error.to_string())
}

impl SocksConnector for ClientConnection {
    fn open_socks_direct_tcpip(
        self: Arc<Self>,
        request: SocksConnectRequest,
        originator: SocketAddr,
    ) -> SocksConnectorFuture {
        Box::pin(async move {
            let target = target_text(&request.address)?;
            let channel = self
                .open_direct_tcpip(
                    &target,
                    u32::from(request.port),
                    &originator.ip().to_string(),
                    u32::from(originator.port()),
                )
                .await
                .map_err(|error| client_open_error(&error))?;
            Ok(Box::new(channel) as Box<dyn SocksChannel>)
        })
    }
}

impl SocksChannel for ClientChannel {
    fn send_data<'a>(&'a self, data: &'a [u8]) -> SocksChannelFuture<'a, ()> {
        Box::pin(async move {
            ClientChannel::send_data(self, data)
                .await
                .map_err(|error| SocksChannelError::Failed(error.to_string()))
        })
    }

    fn send_eof(&self) -> SocksChannelFuture<'_, ()> {
        Box::pin(async move {
            ClientChannel::send_eof(self)
                .await
                .map_err(|error| SocksChannelError::Failed(error.to_string()))
        })
    }

    fn close(&self) -> SocksChannelFuture<'_, ()> {
        Box::pin(async move {
            ClientChannel::close(self)
                .await
                .map_err(|error| SocksChannelError::Failed(error.to_string()))
        })
    }

    fn next_event(&mut self) -> SocksChannelFuture<'_, Option<SocksChannelEvent>> {
        Box::pin(async move {
            match ClientChannel::next_event(self)
                .await
                .map_err(|error| SocksChannelError::Failed(error.to_string()))?
            {
                Some(ChannelEvent::Data(data)) => Ok(Some(SocksChannelEvent::Data(data))),
                Some(ChannelEvent::Eof) => Ok(Some(SocksChannelEvent::Eof)),
                Some(ChannelEvent::Close) => Ok(Some(SocksChannelEvent::Close)),
                None => Ok(None),
                Some(_) => Err(SocksChannelError::UnexpectedEvent),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::{
        io::AsyncReadExt,
        net::TcpStream,
        sync::mpsc,
        time::{Duration, timeout},
    };

    use super::*;

    #[derive(Debug)]
    enum FakeInput {
        Data(Vec<u8>),
        Eof,
    }

    struct FakeChannel {
        input: mpsc::Sender<FakeInput>,
        events: mpsc::Receiver<SocksChannelEvent>,
        closed: Arc<AtomicBool>,
    }

    impl SocksChannel for FakeChannel {
        fn send_data<'a>(&'a self, data: &'a [u8]) -> SocksChannelFuture<'a, ()> {
            let input = self.input.clone();
            let data = data.to_vec();
            Box::pin(async move {
                input
                    .send(FakeInput::Data(data))
                    .await
                    .map_err(|_| SocksChannelError::Failed("fake channel input closed".to_owned()))
            })
        }

        fn send_eof(&self) -> SocksChannelFuture<'_, ()> {
            let input = self.input.clone();
            Box::pin(async move {
                input
                    .send(FakeInput::Eof)
                    .await
                    .map_err(|_| SocksChannelError::Failed("fake channel input closed".to_owned()))
            })
        }

        fn close(&self) -> SocksChannelFuture<'_, ()> {
            self.closed.store(true, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }

        fn next_event(&mut self) -> SocksChannelFuture<'_, Option<SocksChannelEvent>> {
            Box::pin(async move { Ok(self.events.recv().await) })
        }
    }

    struct FakeConnector {
        opens: Arc<AtomicUsize>,
        failure: Mutex<Option<SocksOpenError>>,
    }

    impl FakeConnector {
        fn success() -> Arc<Self> {
            Arc::new(Self { opens: Arc::new(AtomicUsize::new(0)), failure: Mutex::new(None) })
        }

        fn failure(reply: SocksReply) -> Arc<Self> {
            Arc::new(Self {
                opens: Arc::new(AtomicUsize::new(0)),
                failure: Mutex::new(Some(SocksOpenError::new(reply, "fake refusal"))),
            })
        }

        fn open_count(&self) -> usize {
            self.opens.load(Ordering::SeqCst)
        }
    }

    impl SocksConnector for FakeConnector {
        fn open_socks_direct_tcpip(
            self: Arc<Self>,
            _request: SocksConnectRequest,
            _originator: SocketAddr,
        ) -> SocksConnectorFuture {
            self.opens.fetch_add(1, Ordering::SeqCst);
            if let Some(error) = self.failure.lock().expect("fake failure lock").clone() {
                return Box::pin(async move { Err(error) });
            }
            Box::pin(async move {
                let (input_tx, mut input_rx) = mpsc::channel(8);
                let (event_tx, event_rx) = mpsc::channel(8);
                let closed = Arc::new(AtomicBool::new(false));
                let task_closed = Arc::clone(&closed);
                tokio::spawn(async move {
                    while let Some(input) = input_rx.recv().await {
                        match input {
                            FakeInput::Data(data) => {
                                if event_tx.send(SocksChannelEvent::Data(data)).await.is_err() {
                                    break;
                                }
                            }
                            FakeInput::Eof => {
                                let _ = event_tx.send(SocksChannelEvent::Eof).await;
                                let _ = event_tx.send(SocksChannelEvent::Close).await;
                                break;
                            }
                        }
                    }
                    task_closed.store(true, Ordering::SeqCst);
                });
                Ok(Box::new(FakeChannel { input: input_tx, events: event_rx, closed })
                    as Box<dyn SocksChannel>)
            })
        }
    }

    fn listener_config(max_connections: usize) -> SocksListenerConfig {
        SocksListenerConfig {
            max_connections,
            handshake_timeout: Duration::from_secs(2),
            io_buffer_size: 1024,
        }
    }

    async fn spawn_listener(
        connector: Arc<dyn SocksConnector>,
        config: SocksListenerConfig,
    ) -> (SocketAddr, SocksCancellation, tokio::task::JoinHandle<Result<(), SocksListenerError>>)
    {
        let listener = SocksListener::bind(([127, 0, 0, 1], 0).into(), config)
            .await
            .expect("bind SOCKS listener");
        let address = listener.local_addr().expect("listener address");
        let cancellation = SocksCancellation::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move { listener.run(connector, task_cancellation).await });
        (address, cancellation, task)
    }

    async fn read_response(stream: &mut TcpStream, length: usize) -> Vec<u8> {
        let mut response = vec![0; length];
        timeout(Duration::from_secs(2), stream.read_exact(&mut response))
            .await
            .expect("response timeout")
            .expect("response bytes");
        response
    }

    #[tokio::test]
    async fn socks5_listener_forwards_data_and_propagates_eof() {
        let connector = FakeConnector::success();
        let (address, cancellation, task) =
            spawn_listener(connector.clone(), listener_config(2)).await;
        let mut stream = TcpStream::connect(address).await.expect("connect listener");
        stream
            .write_all(&[5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 80, b'p', b'i', b'n', b'g'])
            .await
            .expect("SOCKS request");
        assert_eq!(read_response(&mut stream, 2).await, vec![5, 0]);
        assert_eq!(read_response(&mut stream, 10).await, vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(read_response(&mut stream, 4).await, b"ping");
        stream.shutdown().await.expect("local EOF");
        cancellation.cancel();
        task.await.expect("listener task").expect("listener result");
        assert_eq!(connector.open_count(), 1);
    }

    #[tokio::test]
    async fn socks4a_listener_forwards_data() {
        let connector = FakeConnector::success();
        let (address, cancellation, task) =
            spawn_listener(connector.clone(), listener_config(1)).await;
        let mut stream = TcpStream::connect(address).await.expect("connect listener");
        let mut request = vec![4, 1, 0, 80, 0, 0, 0, 1, b'u', 0];
        request.extend_from_slice(b"example.test");
        request.extend_from_slice(&[0, b'x']);
        stream.write_all(&request).await.expect("SOCKS4a request");
        assert_eq!(read_response(&mut stream, 8).await, vec![0, 90, 0, 0, 0, 0, 0, 0]);
        assert_eq!(read_response(&mut stream, 1).await, b"x");
        cancellation.cancel();
        task.await.expect("listener task").expect("listener result");
        assert_eq!(connector.open_count(), 1);
    }

    #[tokio::test]
    async fn open_failure_maps_to_protocol_response_and_listener_survives() {
        let connector = FakeConnector::failure(SocksReply::ConnectionRefused);
        let (address, cancellation, task) =
            spawn_listener(connector.clone(), listener_config(1)).await;
        let mut stream = TcpStream::connect(address).await.expect("connect listener");
        stream.write_all(&[5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 80]).await.expect("SOCKS request");
        assert_eq!(read_response(&mut stream, 2).await, vec![5, 0]);
        let response = read_response(&mut stream, 10).await;
        assert_eq!(response[0..5], [5, 5, 0, 1, 0]);
        drop(stream);
        cancellation.cancel();
        task.await.expect("listener task").expect("listener result");
        assert_eq!(connector.open_count(), 1);
    }

    #[tokio::test]
    async fn active_connection_cap_closes_excess_peers() {
        let connector = FakeConnector::success();
        let (address, cancellation, task) =
            spawn_listener(connector.clone(), listener_config(1)).await;
        let mut first = TcpStream::connect(address).await.expect("first connection");
        first.write_all(&[5, 1, 0]).await.expect("first greeting");
        assert_eq!(read_response(&mut first, 2).await, vec![5, 0]);
        let mut second = TcpStream::connect(address).await.expect("second connection");
        second.write_all(&[5, 1, 0]).await.expect("second greeting");
        let mut byte = [0; 1];
        let _ = timeout(Duration::from_secs(2), second.read(&mut byte)).await;
        assert_eq!(connector.open_count(), 0);
        drop(first);
        cancellation.cancel();
        task.await.expect("listener task").expect("listener result");
    }

    #[tokio::test]
    async fn cancellation_interrupts_incomplete_handshake() {
        let connector = FakeConnector::success();
        let (address, cancellation, task) = spawn_listener(connector, listener_config(1)).await;
        let _stream = TcpStream::connect(address).await.expect("connect listener");
        cancellation.cancel();
        timeout(Duration::from_secs(2), task)
            .await
            .expect("listener cancellation timeout")
            .expect("listener task")
            .expect("listener result");
    }
}
