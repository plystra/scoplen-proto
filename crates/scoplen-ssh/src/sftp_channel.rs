//! Bounded SFTP v3 framing over one authenticated SSH session channel.

use std::{collections::BTreeMap, io};

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    ChannelEvent, ClientChannelStream, ClientConnection, ClientError, MAX_SFTP_PACKET, SftpClient,
    SftpError, SftpExtension, SftpPacket,
};

/// Errors raised while opening or using an SFTP SSH channel.
#[derive(Debug, Error)]
pub enum SftpChannelError {
    /// The SSH channel could not be opened or used.
    #[error(transparent)]
    Ssh(#[from] ClientError),
    /// The peer rejected the SFTP subsystem request.
    #[error("SSH server rejected the SFTP subsystem")]
    SubsystemRejected,
    /// The SSH channel ended before the subsystem was accepted.
    #[error("SSH channel closed before the SFTP subsystem started")]
    SubsystemClosed,
    /// The peer sent channel output before accepting the subsystem.
    #[error("SSH server sent an unexpected SFTP subsystem response")]
    UnexpectedSubsystemResponse,
    /// The SFTP packet or version handshake was invalid.
    #[error(transparent)]
    Protocol(#[from] SftpError),
    /// The peer closed the stream between complete packets.
    #[error("SFTP channel closed")]
    Closed,
    /// The peer closed the stream partway through a packet.
    #[error("SFTP channel ended inside a packet")]
    Truncated,
    /// Reading or writing the channel failed.
    #[error("SFTP channel I/O failed: {0}")]
    Io(#[from] io::Error),
    /// The server rejected a transfer request with an SFTP status code.
    #[error("SFTP server returned status code {code}")]
    RemoteStatus { code: u32 },
}

/// Progress reported after a contiguous transfer chunk is committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SftpTransferProgress {
    /// Remote offset immediately after the committed bytes.
    pub offset: u64,
    /// Total bytes committed during this transfer.
    pub transferred: u64,
    /// Expected final remote offset, when known.
    pub total: Option<u64>,
}

/// One SFTP v3 subsystem on an existing authenticated SSH connection.
///
/// Requests built by [`SftpClient`] can be sent with [`Self::write_packet`], then correlated with
/// responses from [`Self::read_packet`]. Keeping this channel and a terminal open on the same
/// [`ClientConnection`] reuses one SSH transport.
#[derive(Debug)]
pub struct SftpChannel {
    stream: ClientChannelStream,
    extensions: Vec<SftpExtension>,
}

/// A negotiated SFTP channel with bounded request correlation and pipelining.
#[derive(Debug)]
pub struct SftpSession {
    channel: SftpChannel,
    client: SftpClient,
}

impl SftpSession {
    /// Open and negotiate an SFTP v3 channel with a bounded outstanding-request pipeline.
    ///
    /// # Errors
    ///
    /// Returns an error when the SSH subsystem or SFTP handshake fails, or when the pipeline
    /// bound is outside [`crate::MAX_SFTP_OUTSTANDING`].
    pub async fn open(
        connection: &ClientConnection,
        max_outstanding: usize,
    ) -> Result<Self, SftpChannelError> {
        let channel = SftpChannel::open(connection).await?;
        let mut client = SftpClient::new(max_outstanding)?;
        client.accept_version(&SftpPacket::Version {
            version: 3,
            extensions: channel.extensions.clone(),
        })?;
        Ok(Self { channel, client })
    }

    /// Return the bounded extensions advertised by the server.
    #[must_use]
    pub fn extensions(&self) -> &[SftpExtension] {
        self.channel.extensions()
    }

    /// Borrow the request builder and bounded correlation state.
    #[must_use]
    pub fn client_mut(&mut self) -> &mut SftpClient {
        &mut self.client
    }

    /// Number of requests awaiting a response.
    #[must_use]
    pub fn pending_requests(&self) -> usize {
        self.client.pending_requests()
    }

    /// Send a request previously built by [`Self::client_mut`].
    ///
    /// # Errors
    ///
    /// Returns an error when the packet does not refer to a request tracked by this session or
    /// the channel cannot write it. A failed write releases its request slot.
    pub async fn send_request(&mut self, packet: &SftpPacket) -> Result<(), SftpChannelError> {
        let Some(id) = packet.request_id() else {
            return Err(SftpError::Malformed("request has no request id").into());
        };
        if !self.client.tracks_request(id) {
            return Err(SftpError::UnknownRequest.into());
        }
        if let Err(error) = self.channel.write_packet(packet).await {
            self.client.release_request(id);
            return Err(error);
        }
        Ok(())
    }

    /// Read and correlate one response, releasing its pipeline slot.
    ///
    /// # Errors
    ///
    /// Returns an error when the channel ends, the packet is malformed, or its request id is not
    /// currently pending.
    pub async fn read_response(&mut self) -> Result<SftpPacket, SftpChannelError> {
        let packet = self.channel.read_packet().await?;
        self.client.accept_response(&packet)?;
        Ok(packet)
    }

    /// Download a handle into an async sink with bounded pipelining and resume-by-offset.
    ///
    /// `start_offset` is the remote offset represented by the sink's current position. `total`,
    /// when present, is the remote end offset. A missing total reads until the server returns
    /// `SSH_FX_EOF`. The callback runs after each contiguous chunk is written.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds, a failed or rejected request, malformed responses,
    /// or sink I/O. A failed transfer releases all request slots reserved by this operation.
    #[allow(clippy::too_many_arguments)]
    pub async fn download_to<W, F>(
        &mut self,
        handle: &[u8],
        start_offset: u64,
        total: Option<u64>,
        chunk_size: u32,
        pipeline: usize,
        sink: &mut W,
        progress: F,
    ) -> Result<u64, SftpChannelError>
    where
        W: AsyncWrite + Unpin,
        F: FnMut(SftpTransferProgress),
    {
        if total.is_some_and(|end| end < start_offset) {
            return Err(SftpError::InvalidValue("transfer range").into());
        }
        validate_transfer(handle, chunk_size, pipeline, self.pending_requests())?;
        let result = self
            .download_to_inner(handle, start_offset, total, chunk_size, pipeline, sink, progress)
            .await;
        if result.is_err() {
            self.client.clear_pending();
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn download_to_inner<W, F>(
        &mut self,
        handle: &[u8],
        start_offset: u64,
        total: Option<u64>,
        chunk_size: u32,
        pipeline: usize,
        sink: &mut W,
        mut progress: F,
    ) -> Result<u64, SftpChannelError>
    where
        W: AsyncWrite + Unpin,
        F: FnMut(SftpTransferProgress),
    {
        let mut next_offset = start_offset;
        let mut committed_offset = start_offset;
        let mut transferred = 0_u64;
        let mut eof = false;
        let mut inflight = BTreeMap::<u32, (u64, u32)>::new();
        let mut ready = BTreeMap::<u64, (Vec<u8>, u32)>::new();
        progress(SftpTransferProgress { offset: start_offset, transferred, total });

        loop {
            while !eof
                && inflight.len() < pipeline
                && self.client.available_requests() > 0
                && total.is_none_or(|end| next_offset < end)
            {
                let remaining = total.map(|end| end.saturating_sub(next_offset));
                let length = remaining.map_or(chunk_size, |value| {
                    u32::try_from(value.min(u64::from(chunk_size))).unwrap_or(chunk_size)
                });
                let request = self.client.read(handle.to_vec(), next_offset, length)?;
                let id = request.request_id().ok_or(SftpError::Malformed("read request id"))?;
                self.send_request(&request).await?;
                inflight.insert(id, (next_offset, length));
                next_offset = next_offset
                    .checked_add(u64::from(length))
                    .ok_or(SftpError::InvalidValue("read offset"))?;
            }

            if inflight.is_empty() {
                break;
            }
            let response = self.read_response().await?;
            let id = response.request_id().ok_or(SftpError::Malformed("read response id"))?;
            let Some((offset, expected)) = inflight.remove(&id) else {
                return Err(SftpError::UnknownRequest.into());
            };
            match response {
                SftpPacket::Data { data, .. } => {
                    if data.len() > expected as usize {
                        return Err(SftpError::InvalidValue("read response length").into());
                    }
                    if data.len() < expected as usize {
                        eof = true;
                    }
                    ready.insert(offset, (data, expected));
                }
                SftpPacket::Status { code: 1, .. } => eof = true,
                SftpPacket::Status { code, .. } => {
                    return Err(SftpChannelError::RemoteStatus { code });
                }
                _ => return Err(SftpError::Malformed("read response type").into()),
            }

            while let Some((data, expected)) = ready.remove(&committed_offset) {
                sink.write_all(&data).await?;
                committed_offset = committed_offset
                    .checked_add(data.len() as u64)
                    .ok_or(SftpError::InvalidValue("transfer offset"))?;
                transferred = transferred
                    .checked_add(data.len() as u64)
                    .ok_or(SftpError::InvalidValue("transfer length"))?;
                progress(SftpTransferProgress { offset: committed_offset, transferred, total });
                if data.len() < expected as usize {
                    eof = true;
                }
            }
        }
        sink.flush().await?;
        Ok(transferred)
    }

    /// Upload bytes to a remote handle with bounded pipelining and resume-by-offset.
    ///
    /// `start_offset` is the remote offset represented by the first byte in `data`; callers can
    /// resume a local source by slicing it at the matching offset. The callback runs after each
    /// successful write response.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds, failed writes, malformed responses, or a non-zero
    /// remote status. A failed transfer releases all request slots reserved by this operation.
    pub async fn upload(
        &mut self,
        handle: &[u8],
        start_offset: u64,
        data: &[u8],
        chunk_size: u32,
        pipeline: usize,
        progress: impl FnMut(SftpTransferProgress),
    ) -> Result<u64, SftpChannelError> {
        start_offset
            .checked_add(data.len() as u64)
            .ok_or(SftpError::InvalidValue("transfer length"))?;
        validate_transfer(handle, chunk_size, pipeline, self.pending_requests())?;
        let result =
            self.upload_inner(handle, start_offset, data, chunk_size, pipeline, progress).await;
        if result.is_err() {
            self.client.clear_pending();
        }
        result
    }

    async fn upload_inner(
        &mut self,
        handle: &[u8],
        start_offset: u64,
        data: &[u8],
        chunk_size: u32,
        pipeline: usize,
        mut progress: impl FnMut(SftpTransferProgress),
    ) -> Result<u64, SftpChannelError> {
        let total = start_offset + data.len() as u64;
        let mut next = 0_usize;
        let mut transferred = 0_u64;
        let mut committed_offset = start_offset;
        let mut inflight = BTreeMap::<u32, (u64, usize)>::new();
        let mut completed = BTreeMap::<u64, usize>::new();
        progress(SftpTransferProgress { offset: start_offset, transferred, total: Some(total) });

        loop {
            while next < data.len()
                && inflight.len() < pipeline
                && self.client.available_requests() > 0
            {
                let end = (next + chunk_size as usize).min(data.len());
                let request = self.client.write(
                    handle.to_vec(),
                    start_offset + next as u64,
                    data[next..end].to_vec(),
                )?;
                let id = request.request_id().ok_or(SftpError::Malformed("write request id"))?;
                self.send_request(&request).await?;
                inflight.insert(id, (start_offset + next as u64, end - next));
                next = end;
            }
            if inflight.is_empty() {
                break;
            }
            let response = self.read_response().await?;
            let id = response.request_id().ok_or(SftpError::Malformed("write response id"))?;
            let Some((offset, length)) = inflight.remove(&id) else {
                return Err(SftpError::UnknownRequest.into());
            };
            match response {
                SftpPacket::Status { code: 0, .. } => {
                    completed.insert(offset, length);
                    while let Some(length) = completed.remove(&committed_offset) {
                        committed_offset = committed_offset
                            .checked_add(length as u64)
                            .ok_or(SftpError::InvalidValue("transfer offset"))?;
                        transferred = transferred
                            .checked_add(length as u64)
                            .ok_or(SftpError::InvalidValue("transfer length"))?;
                        progress(SftpTransferProgress {
                            offset: committed_offset,
                            transferred,
                            total: Some(total),
                        });
                    }
                }
                SftpPacket::Status { code, .. } => {
                    return Err(SftpChannelError::RemoteStatus { code });
                }
                _ => return Err(SftpError::Malformed("write response type").into()),
            }
        }
        Ok(transferred)
    }
}

fn validate_transfer(
    handle: &[u8],
    chunk_size: u32,
    pipeline: usize,
    pending: usize,
) -> Result<(), SftpChannelError> {
    if handle.is_empty() {
        return Err(SftpError::InvalidValue("transfer handle").into());
    }
    if handle.len() > crate::MAX_SFTP_HANDLE {
        return Err(SftpError::FieldTooLarge("transfer handle").into());
    }
    if chunk_size == 0 || usize::try_from(chunk_size).unwrap_or(usize::MAX) > MAX_SFTP_PACKET - 64 {
        return Err(SftpError::InvalidValue("transfer chunk size").into());
    }
    if pipeline == 0 || pipeline > crate::MAX_SFTP_OUTSTANDING {
        return Err(SftpError::InvalidValue("transfer pipeline").into());
    }
    if pending != 0 {
        return Err(SftpError::InvalidValue("transfer requires an empty pipeline").into());
    }
    Ok(())
}

impl SftpChannel {
    /// Open a session, require SFTP subsystem acceptance, and negotiate SFTP version 3.
    ///
    /// # Errors
    ///
    /// Returns an error when the SSH channel cannot be opened, the subsystem is rejected, or the
    /// peer sends an invalid or truncated version packet.
    pub async fn open(connection: &ClientConnection) -> Result<Self, SftpChannelError> {
        let mut channel = connection.open_session().await?;
        channel.request_subsystem("sftp", true).await?;
        match channel.next_event().await? {
            Some(ChannelEvent::Success) => {}
            Some(ChannelEvent::Failure) => return Err(SftpChannelError::SubsystemRejected),
            None | Some(ChannelEvent::Close | ChannelEvent::Eof) => {
                return Err(SftpChannelError::SubsystemClosed);
            }
            Some(_) => return Err(SftpChannelError::UnexpectedSubsystemResponse),
        }

        let mut sftp = Self { stream: channel.into_stream(), extensions: Vec::new() };
        sftp.write_packet(&SftpPacket::Init { version: 3 }).await?;
        let version = sftp.read_packet().await?;
        let mut handshake = SftpClient::new(1)?;
        handshake.accept_version(&version)?;
        if let SftpPacket::Version { extensions, .. } = version {
            sftp.extensions = extensions;
        }
        Ok(sftp)
    }

    /// Return the bounded extensions advertised in the v3 VERSION packet.
    #[must_use]
    pub fn extensions(&self) -> &[SftpExtension] {
        &self.extensions
    }

    /// Write one complete SFTP packet over the SSH channel.
    ///
    /// # Errors
    ///
    /// Returns an error when packet encoding rejects a bounded field or the SSH channel cannot
    /// accept the complete frame.
    pub async fn write_packet(&mut self, packet: &SftpPacket) -> Result<(), SftpChannelError> {
        let frame = packet.encode()?;
        self.stream.write_all(&frame).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Read one complete SFTP packet, rejecting its length before allocating the body.
    ///
    /// # Errors
    ///
    /// Returns an error when the peer closes or truncates the channel, declares an oversized
    /// packet, or sends an invalid SFTP frame.
    pub async fn read_packet(&mut self) -> Result<SftpPacket, SftpChannelError> {
        let mut length = [0_u8; 4];
        if self.stream.read(&mut length[..1]).await? == 0 {
            return Err(SftpChannelError::Closed);
        }
        read_exact(&mut self.stream, &mut length[1..]).await?;
        let body_len = u32::from_be_bytes(length) as usize;
        if body_len > MAX_SFTP_PACKET - 4 {
            return Err(SftpError::PacketTooLarge.into());
        }
        if body_len == 0 {
            return Err(SftpError::Malformed("empty packet").into());
        }
        let mut frame = vec![0_u8; body_len + 4];
        frame[..4].copy_from_slice(&length);
        read_exact(&mut self.stream, &mut frame[4..]).await?;
        Ok(SftpPacket::decode(&frame)?)
    }
}

async fn read_exact(
    stream: &mut ClientChannelStream,
    buffer: &mut [u8],
) -> Result<(), SftpChannelError> {
    match stream.read_exact(buffer).await {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(SftpChannelError::Truncated)
        }
        Err(error) => Err(SftpChannelError::Io(error)),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use russh::keys::PrivateKey;
    use ssh_key::Algorithm;
    use tokio::net::TcpListener;

    use super::*;
    use crate::{ClientConfig, HostKey, SftpAttributes, SftpNameEntry};

    struct SftpServer {
        buffer: Vec<u8>,
        file: Vec<u8>,
    }

    impl russh::server::Handler for SftpServer {
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

        async fn subsystem_request(
            &mut self,
            channel: russh::ChannelId,
            name: &str,
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            if name == "sftp" {
                let _ = session.channel_success(channel);
            } else {
                let _ = session.channel_failure(channel);
            }
            Ok(())
        }

        async fn data(
            &mut self,
            channel: russh::ChannelId,
            data: &[u8],
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            self.buffer.extend_from_slice(data);
            loop {
                if self.buffer.len() < 4 {
                    return Ok(());
                }
                let body_len = u32::from_be_bytes(self.buffer[..4].try_into().unwrap()) as usize;
                if body_len > MAX_SFTP_PACKET - 4 || self.buffer.len() < body_len + 4 {
                    return Ok(());
                }
                let frame: Vec<_> = self.buffer.drain(..body_len + 4).collect();
                let Ok(packet) = SftpPacket::decode(&frame) else {
                    return Ok(());
                };
                let response = match packet {
                    SftpPacket::Init { .. } => {
                        SftpPacket::Version { version: 3, extensions: Vec::new() }
                    }
                    SftpPacket::Realpath { id, .. } => SftpPacket::Name {
                        id,
                        entries: vec![
                            SftpNameEntry::new(
                                b"/srv".to_vec(),
                                Vec::new(),
                                SftpAttributes::default(),
                            )
                            .unwrap(),
                        ],
                    },
                    SftpPacket::Read { id, offset, length, .. } => match usize::try_from(offset) {
                        Ok(start) if start < self.file.len() => {
                            let end = start.saturating_add(length as usize).min(self.file.len());
                            SftpPacket::Data { id, data: self.file[start..end].to_vec() }
                        }
                        _ => SftpPacket::Status {
                            id,
                            code: 1,
                            message: Vec::new(),
                            language: Vec::new(),
                        },
                    },
                    SftpPacket::Write { id, offset, data, .. } => {
                        let Ok(start) = usize::try_from(offset) else {
                            return Ok(());
                        };
                        let end = start.saturating_add(data.len());
                        if end > self.file.len() {
                            self.file.resize(end, 0);
                        }
                        self.file[start..end].copy_from_slice(&data);
                        SftpPacket::Status {
                            id,
                            code: 0,
                            message: Vec::new(),
                            language: Vec::new(),
                        }
                    }
                    _ => continue,
                };
                let Ok(encoded) = response.encode() else {
                    return Ok(());
                };
                let _ = session.data(channel, encoded);
            }
        }
    }

    #[tokio::test]
    async fn opens_subsystem_negotiates_v3_and_round_trips_packets() {
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
            let _ = russh::server::run_stream(
                server_config,
                stream,
                SftpServer { buffer: Vec::new(), file: Vec::new() },
            )
            .await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");
        let mut channel = SftpChannel::open(&connection).await.expect("open sftp");
        assert!(channel.extensions().is_empty());
        channel
            .write_packet(&SftpPacket::Realpath { id: 1, path: b".".to_vec() })
            .await
            .expect("write realpath");
        assert!(matches!(
            channel.read_packet().await.expect("read realpath"),
            SftpPacket::Name { id: 1, entries } if entries[0].filename == b"/srv"
        ));
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn session_pipelines_bounded_requests_and_releases_responses() {
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
            let _ = russh::server::run_stream(
                server_config,
                stream,
                SftpServer { buffer: Vec::new(), file: Vec::new() },
            )
            .await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");
        let mut session = SftpSession::open(&connection, 2).await.expect("open sftp session");
        let first = session.client_mut().realpath(b"/first").expect("first request");
        let second = session.client_mut().realpath(b"/second").expect("second request");
        assert!(matches!(
            session.client_mut().realpath(b"/third"),
            Err(SftpError::OutstandingLimit)
        ));
        session.send_request(&first).await.expect("send first");
        session.send_request(&second).await.expect("send second");
        assert_eq!(session.pending_requests(), 2);
        assert!(matches!(
            session.read_response().await.expect("first response"),
            SftpPacket::Name { id: 1, .. }
        ));
        assert!(matches!(
            session.read_response().await.expect("second response"),
            SftpPacket::Name { id: 2, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn transfer_helpers_resume_and_report_contiguous_progress() {
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
            let _ = russh::server::run_stream(
                server_config,
                stream,
                SftpServer { buffer: Vec::new(), file: b"abcdef".to_vec() },
            )
            .await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");
        let mut session = SftpSession::open(&connection, 2).await.expect("open sftp session");

        let mut downloaded = Vec::new();
        let mut download_progress = Vec::new();
        let count = session
            .download_to(b"h", 2, Some(6), 2, 2, &mut downloaded, |event| {
                download_progress.push(event);
            })
            .await
            .expect("download");
        assert_eq!(count, 4);
        assert_eq!(downloaded, b"cdef");
        assert_eq!(download_progress.last().unwrap().offset, 6);
        assert_eq!(download_progress.last().unwrap().transferred, 4);

        let mut upload_progress = Vec::new();
        let count = session
            .upload(b"h", 6, b"ghij", 2, 2, |event| upload_progress.push(event))
            .await
            .expect("upload");
        assert_eq!(count, 4);
        assert_eq!(upload_progress.last().unwrap().offset, 10);
        assert_eq!(upload_progress.last().unwrap().transferred, 4);
        connection.disconnect().await.expect("disconnect client");
    }
}
