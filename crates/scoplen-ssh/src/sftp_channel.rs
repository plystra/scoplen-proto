//! Bounded SFTP v3 framing over one authenticated SSH session channel.

use std::io;

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
            let _ =
                russh::server::run_stream(server_config, stream, SftpServer { buffer: Vec::new() })
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
}
