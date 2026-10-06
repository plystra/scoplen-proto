// SPDX-License-Identifier: Apache-2.0
//! SSH transport negotiation and strict key-exchange state.
//!
//! This module is deliberately independent of the eventual SSH engine. It owns the K-7
//! preference and state-machine boundary that an engine must use when encoding and processing
//! `SSH_MSG_KEXINIT`, key-exchange messages, and `SSH_MSG_NEWKEYS`.

use thiserror::Error;

use crate::{AlgorithmCategory, HostAlgorithmPolicy};

/// The RFC 8308 client marker carried in the client's KEXINIT key-exchange list.
pub const EXT_INFO_CLIENT: &str = "ext-info-c";
/// The RFC 8308 server marker carried in the server's KEXINIT key-exchange list.
pub const EXT_INFO_SERVER: &str = "ext-info-s";
/// The pre-standard OpenSSH strict-KEX client marker required by K-7.
pub const STRICT_KEX_CLIENT: &str = "kex-strict-c-v00@openssh.com";
/// The pre-standard OpenSSH strict-KEX server marker required by K-7.
pub const STRICT_KEX_SERVER: &str = "kex-strict-s-v00@openssh.com";
/// The standard strict-KEX client marker accepted from peers.
pub const STRICT_KEX_CLIENT_STANDARD: &str = "kex-strict-c";
/// The standard strict-KEX server marker accepted from peers.
pub const STRICT_KEX_SERVER_STANDARD: &str = "kex-strict-s";

/// Which endpoint owns a transport offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportRole {
    /// The endpoint that initiates an SSH connection.
    Client,
    /// The endpoint that accepts an SSH connection.
    Server,
}

impl TransportRole {
    const fn extension_marker(self) -> &'static str {
        match self {
            Self::Client => EXT_INFO_CLIENT,
            Self::Server => EXT_INFO_SERVER,
        }
    }

    const fn strict_marker(self) -> &'static str {
        match self {
            Self::Client => STRICT_KEX_CLIENT,
            Self::Server => STRICT_KEX_SERVER,
        }
    }

    const fn standard_strict_marker(self) -> &'static str {
        match self {
            Self::Client => STRICT_KEX_CLIENT_STANDARD,
            Self::Server => STRICT_KEX_SERVER_STANDARD,
        }
    }
}

/// One endpoint's ordered KEXINIT algorithm lists.
///
/// The directional lists are kept separate because SSH negotiates each direction independently.
/// A parser or SSH engine may construct this type directly after validating the wire strings;
/// [`Self::from_policy`] is the safe default for Scoplen's client and server roles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportOffer {
    /// The endpoint role that produced this offer.
    pub role: TransportRole,
    /// Ordered key-exchange methods, including extension pseudo-algorithms.
    pub key_exchange: Vec<String>,
    /// Ordered host-key algorithms.
    pub host_key: Vec<String>,
    /// Ordered client-to-server ciphers.
    pub cipher_client_to_server: Vec<String>,
    /// Ordered server-to-client ciphers.
    pub cipher_server_to_client: Vec<String>,
    /// Ordered client-to-server MACs.
    pub mac_client_to_server: Vec<String>,
    /// Ordered server-to-client MACs.
    pub mac_server_to_client: Vec<String>,
    /// Ordered client-to-server compression methods.
    pub compression_client_to_server: Vec<String>,
    /// Ordered server-to-client compression methods.
    pub compression_server_to_client: Vec<String>,
}

impl TransportOffer {
    /// Build the role's K-7 offer from a per-Host algorithm policy.
    #[must_use]
    pub fn from_policy(role: TransportRole, policy: &HostAlgorithmPolicy) -> Self {
        let mut key_exchange = names(policy.offers(AlgorithmCategory::KeyExchange));
        key_exchange.push(role.extension_marker().to_owned());
        key_exchange.push(role.strict_marker().to_owned());
        Self {
            role,
            key_exchange,
            host_key: names(policy.offers(AlgorithmCategory::HostKey)),
            cipher_client_to_server: names(policy.offers(AlgorithmCategory::Cipher)),
            cipher_server_to_client: names(policy.offers(AlgorithmCategory::Cipher)),
            mac_client_to_server: names(policy.offers(AlgorithmCategory::Mac)),
            mac_server_to_client: names(policy.offers(AlgorithmCategory::Mac)),
            compression_client_to_server: names(policy.offers(AlgorithmCategory::Compression)),
            compression_server_to_client: names(policy.offers(AlgorithmCategory::Compression)),
        }
    }

    /// Negotiate the first local preference that also occurs in every peer list.
    ///
    /// The returned selection is deterministic and never treats extension pseudo-algorithms as
    /// key-exchange methods. Strict KEX and RFC 8308 support are enabled only when both roles
    /// advertise their matching markers.
    ///
    /// # Errors
    ///
    /// Returns [`TransportNegotiationError::RoleMismatch`] when both offers claim the same role,
    /// or [`TransportNegotiationError::NoCommonAlgorithm`] when any required category has no
    /// common method.
    pub fn negotiate(&self, peer: &Self) -> Result<NegotiatedTransport, TransportNegotiationError> {
        if self.role == peer.role {
            return Err(TransportNegotiationError::RoleMismatch { role: self.role });
        }
        Ok(NegotiatedTransport {
            key_exchange: select(
                AlgorithmCategory::KeyExchange,
                &self.key_exchange,
                &peer.key_exchange,
            )?,
            host_key: select(AlgorithmCategory::HostKey, &self.host_key, &peer.host_key)?,
            cipher_client_to_server: select(
                AlgorithmCategory::Cipher,
                &self.cipher_client_to_server,
                &peer.cipher_client_to_server,
            )?,
            cipher_server_to_client: select(
                AlgorithmCategory::Cipher,
                &self.cipher_server_to_client,
                &peer.cipher_server_to_client,
            )?,
            mac_client_to_server: select(
                AlgorithmCategory::Mac,
                &self.mac_client_to_server,
                &peer.mac_client_to_server,
            )?,
            mac_server_to_client: select(
                AlgorithmCategory::Mac,
                &self.mac_server_to_client,
                &peer.mac_server_to_client,
            )?,
            compression_client_to_server: select(
                AlgorithmCategory::Compression,
                &self.compression_client_to_server,
                &peer.compression_client_to_server,
            )?,
            compression_server_to_client: select(
                AlgorithmCategory::Compression,
                &self.compression_server_to_client,
                &peer.compression_server_to_client,
            )?,
            strict_kex: self.advertises_strict() && peer.advertises_strict(),
            ext_info: self.advertises_ext_info() && peer.advertises_ext_info(),
        })
    }

    fn advertises_strict(&self) -> bool {
        contains_any(
            &self.key_exchange,
            &[self.role.strict_marker(), self.role.standard_strict_marker()],
        )
    }

    fn advertises_ext_info(&self) -> bool {
        self.key_exchange.iter().any(|name| name == self.role.extension_marker())
    }
}

fn names(values: &[&'static str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn contains_any(values: &[String], names: &[&str]) -> bool {
    values.iter().any(|value| names.iter().any(|name| value == name))
}

fn select(
    category: AlgorithmCategory,
    local: &[String],
    peer: &[String],
) -> Result<String, TransportNegotiationError> {
    local
        .iter()
        .find(|candidate| {
            (!matches!(category, AlgorithmCategory::KeyExchange) || !is_extension_marker(candidate))
                && peer.iter().any(|offered| offered == *candidate)
        })
        .cloned()
        .ok_or(TransportNegotiationError::NoCommonAlgorithm { category })
}

fn is_extension_marker(name: &str) -> bool {
    matches!(
        name,
        EXT_INFO_CLIENT
            | EXT_INFO_SERVER
            | STRICT_KEX_CLIENT
            | STRICT_KEX_SERVER
            | STRICT_KEX_CLIENT_STANDARD
            | STRICT_KEX_SERVER_STANDARD
    )
}

/// The algorithms selected for one transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedTransport {
    /// Selected key-exchange method.
    pub key_exchange: String,
    /// Selected host-key algorithm.
    pub host_key: String,
    /// Selected client-to-server cipher.
    pub cipher_client_to_server: String,
    /// Selected server-to-client cipher.
    pub cipher_server_to_client: String,
    /// Selected client-to-server MAC.
    pub mac_client_to_server: String,
    /// Selected server-to-client MAC.
    pub mac_server_to_client: String,
    /// Selected client-to-server compression method.
    pub compression_client_to_server: String,
    /// Selected server-to-client compression method.
    pub compression_server_to_client: String,
    /// Whether both endpoints advertised strict KEX.
    pub strict_kex: bool,
    /// Whether both endpoints advertised RFC 8308 extension information.
    pub ext_info: bool,
}

/// KEX message family used to validate strict-KEX packet admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyExchangeFamily {
    /// The fixed-group `diffie-hellman-group*` methods.
    DiffieHellman,
    /// The `diffie-hellman-group-exchange-*` methods.
    GroupExchange,
    /// ECDH, curve25519, and the sntrup hybrid methods using ECDH packet types.
    Ecdh,
    /// ML-KEM hybrid methods using the hybrid packet types.
    Hybrid,
}

impl KeyExchangeFamily {
    /// Classify a negotiated method using the SSH packet family it requires.
    #[must_use]
    pub fn for_algorithm(name: &str) -> Option<Self> {
        if name.starts_with("diffie-hellman-group-exchange-") {
            Some(Self::GroupExchange)
        } else if name.starts_with("diffie-hellman-group") {
            Some(Self::DiffieHellman)
        } else if name == "mlkem768x25519-sha256" {
            Some(Self::Hybrid)
        } else if name == "sntrup761x25519-sha512"
            || name == "curve25519-sha256"
            || name.starts_with("ecdh-sha2-")
        {
            Some(Self::Ecdh)
        } else {
            None
        }
    }

    const fn allows(self, packet: StrictKexPacket) -> bool {
        match self {
            Self::DiffieHellman => {
                matches!(packet, StrictKexPacket::KexDhInit | StrictKexPacket::KexDhReply)
            }
            Self::GroupExchange => matches!(
                packet,
                StrictKexPacket::KexDhGexRequestOld
                    | StrictKexPacket::KexDhGexRequest
                    | StrictKexPacket::KexDhGexGroup
                    | StrictKexPacket::KexDhGexInit
                    | StrictKexPacket::KexDhGexReply
            ),
            Self::Ecdh => {
                matches!(packet, StrictKexPacket::KexEcdhInit | StrictKexPacket::KexEcdhReply)
            }
            Self::Hybrid => {
                matches!(packet, StrictKexPacket::KexHybridInit | StrictKexPacket::KexHybridReply)
            }
        }
    }
}

/// A packet classification supplied by the SSH engine to the strict-KEX gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StrictKexPacket {
    /// `SSH_MSG_KEXINIT`.
    KexInit,
    /// `SSH_MSG_NEWKEYS`.
    NewKeys,
    /// `SSH_MSG_KEXDH_INIT`.
    KexDhInit,
    /// `SSH_MSG_KEXDH_REPLY`.
    KexDhReply,
    /// `SSH_MSG_KEX_DH_GEX_REQUEST_OLD`.
    KexDhGexRequestOld,
    /// `SSH_MSG_KEX_DH_GEX_REQUEST`.
    KexDhGexRequest,
    /// `SSH_MSG_KEX_DH_GEX_GROUP`.
    KexDhGexGroup,
    /// `SSH_MSG_KEX_DH_GEX_INIT`.
    KexDhGexInit,
    /// `SSH_MSG_KEX_DH_GEX_REPLY`.
    KexDhGexReply,
    /// `SSH_MSG_KEX_ECDH_INIT` or a sntrup hybrid init.
    KexEcdhInit,
    /// `SSH_MSG_KEX_ECDH_REPLY` or a sntrup hybrid reply.
    KexEcdhReply,
    /// `SSH_MSG_KEX_HYBRID_INIT`.
    KexHybridInit,
    /// `SSH_MSG_KEX_HYBRID_REPLY`.
    KexHybridReply,
    /// `SSH_MSG_EXT_INFO`.
    ExtInfo,
    /// Any other SSH transport packet, carrying its message number for diagnostics.
    Other(u8),
}

impl StrictKexPacket {
    const fn index(self) -> Option<usize> {
        match self {
            Self::KexInit => Some(0),
            Self::NewKeys => Some(1),
            Self::KexDhInit => Some(2),
            Self::KexDhReply => Some(3),
            Self::KexDhGexRequestOld => Some(4),
            Self::KexDhGexRequest => Some(5),
            Self::KexDhGexGroup => Some(6),
            Self::KexDhGexInit => Some(7),
            Self::KexDhGexReply => Some(8),
            Self::KexEcdhInit => Some(9),
            Self::KexEcdhReply => Some(10),
            Self::KexHybridInit => Some(11),
            Self::KexHybridReply => Some(12),
            Self::ExtInfo | Self::Other(_) => None,
        }
    }

    const fn is_new_keys(self) -> bool {
        matches!(self, Self::NewKeys)
    }

    const fn is_kex_control(self) -> bool {
        !matches!(self, Self::ExtInfo | Self::Other(_))
    }
}

/// Which packet direction caused a strict-KEX error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportDirection {
    /// A locally generated packet.
    Send,
    /// A packet received from the peer.
    Receive,
}

/// The current phase of a strict-KEX exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StrictKexPhase {
    /// The initial exchange is in progress.
    Initial,
    /// A later rekey exchange is in progress.
    Rekey,
    /// Both endpoints have sent and received `SSH_MSG_NEWKEYS`.
    Established,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectionState {
    first_packet: bool,
    new_keys: bool,
    counts: [u8; 13],
    sequence: u32,
}

impl DirectionState {
    const fn new() -> Self {
        Self { first_packet: false, new_keys: false, counts: [0; 13], sequence: 0 }
    }

    const fn reset_exchange(&mut self) {
        self.first_packet = false;
        self.new_keys = false;
        self.counts = [0; 13];
    }
}

/// A strict-KEX packet admission and sequence-number state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictKeyExchange {
    enabled: bool,
    family: KeyExchangeFamily,
    phase: StrictKexPhase,
    send: DirectionState,
    receive: DirectionState,
}

impl StrictKeyExchange {
    /// Start an initial KEX exchange for the selected method.
    #[must_use]
    pub const fn new(enabled: bool, family: KeyExchangeFamily) -> Self {
        Self {
            enabled,
            family,
            phase: StrictKexPhase::Initial,
            send: DirectionState::new(),
            receive: DirectionState::new(),
        }
    }

    /// Whether strict KEX enforcement is active.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Return the current exchange phase.
    #[must_use]
    pub const fn phase(&self) -> StrictKexPhase {
        self.phase
    }

    /// Return the next sequence number that will be used for a local packet.
    #[must_use]
    pub const fn send_sequence(&self) -> u32 {
        self.send.sequence
    }

    /// Return the next sequence number expected from the peer.
    #[must_use]
    pub const fn receive_sequence(&self) -> u32 {
        self.receive.sequence
    }

    /// Begin a rekey exchange after the initial exchange is established.
    ///
    /// # Errors
    ///
    /// Returns [`StrictKexError::RekeyBeforeEstablished`] if the initial exchange is incomplete.
    pub fn begin_rekey(&mut self) -> Result<(), StrictKexError> {
        if self.phase != StrictKexPhase::Established {
            return Err(StrictKexError::RekeyBeforeEstablished { phase: self.phase });
        }
        self.phase = StrictKexPhase::Rekey;
        self.send.reset_exchange();
        self.receive.reset_exchange();
        Ok(())
    }

    /// Admit a locally generated packet and return its sequence number.
    ///
    /// # Errors
    ///
    /// Returns a [`StrictKexError`] when the packet violates the active KEX phase, message family,
    /// message count, first-packet rule, or sequence-number bound.
    pub fn on_send(&mut self, packet: StrictKexPacket) -> Result<u32, StrictKexError> {
        self.process(TransportDirection::Send, packet)
    }

    /// Admit a packet received from the peer and return its expected sequence number.
    ///
    /// # Errors
    ///
    /// Returns a [`StrictKexError`] when the packet violates the active KEX phase, message family,
    /// message count, first-packet rule, or sequence-number bound.
    pub fn on_receive(&mut self, packet: StrictKexPacket) -> Result<u32, StrictKexError> {
        self.process(TransportDirection::Receive, packet)
    }

    fn process(
        &mut self,
        direction: TransportDirection,
        packet: StrictKexPacket,
    ) -> Result<u32, StrictKexError> {
        let in_kex = self.phase != StrictKexPhase::Established;
        let first_seen = match direction {
            TransportDirection::Send => &mut self.send.first_packet,
            TransportDirection::Receive => &mut self.receive.first_packet,
        };

        if self.enabled && in_kex {
            if !*first_seen {
                if packet != StrictKexPacket::KexInit {
                    return Err(StrictKexError::FirstPacketMustBeKexInit { direction, packet });
                }
                *first_seen = true;
            } else if packet == StrictKexPacket::KexInit {
                return Err(StrictKexError::KexMessageRepeated { direction, packet });
            }

            if self.direction_completed(direction) && !packet.is_new_keys() {
                return Err(StrictKexError::PacketAfterNewKeys { direction, packet });
            }
            self.validate_kex_packet(direction, packet)?;
        } else if self.enabled && packet.is_kex_control() {
            return Err(StrictKexError::RekeyNotStarted);
        }

        let sequence = match direction {
            TransportDirection::Send => self.send.sequence,
            TransportDirection::Receive => self.receive.sequence,
        };
        if self.enabled && in_kex && sequence == u32::MAX {
            return Err(StrictKexError::SequenceNumberExhausted { direction });
        }

        let next = sequence.wrapping_add(1);
        match direction {
            TransportDirection::Send => self.send.sequence = next,
            TransportDirection::Receive => self.receive.sequence = next,
        }
        if packet.is_new_keys() {
            match direction {
                TransportDirection::Send => {
                    self.send.new_keys = true;
                    if self.enabled {
                        self.send.sequence = 0;
                    }
                }
                TransportDirection::Receive => {
                    self.receive.new_keys = true;
                    if self.enabled {
                        self.receive.sequence = 0;
                    }
                }
            }
            if self.send.new_keys && self.receive.new_keys {
                self.phase = StrictKexPhase::Established;
            }
        }
        Ok(sequence)
    }

    fn direction_completed(&self, direction: TransportDirection) -> bool {
        match direction {
            TransportDirection::Send => self.send.new_keys,
            TransportDirection::Receive => self.receive.new_keys,
        }
    }

    fn validate_kex_packet(
        &mut self,
        direction: TransportDirection,
        packet: StrictKexPacket,
    ) -> Result<(), StrictKexError> {
        if packet == StrictKexPacket::ExtInfo || matches!(packet, StrictKexPacket::Other(_)) {
            return Err(StrictKexError::UnexpectedPacket { phase: self.phase, packet });
        }
        if packet != StrictKexPacket::KexInit
            && packet != StrictKexPacket::NewKeys
            && !self.family.allows(packet)
        {
            return Err(StrictKexError::KexMessageNotAllowed { family: self.family, packet });
        }
        let Some(index) = packet.index() else {
            return Ok(());
        };
        let counts = match direction {
            TransportDirection::Send => &mut self.send.counts,
            TransportDirection::Receive => &mut self.receive.counts,
        };
        if counts[index] != 0 {
            return Err(StrictKexError::KexMessageRepeated { direction, packet });
        }
        counts[index] = 1;
        Ok(())
    }
}

/// An error raised while selecting a transport algorithm.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportNegotiationError {
    /// Both offers use the same endpoint role.
    #[error("both transport offers claim the {role:?} role")]
    RoleMismatch { role: TransportRole },
    /// No common algorithm exists in one required category.
    #[error("no mutually supported {category:?} algorithm")]
    NoCommonAlgorithm { category: AlgorithmCategory },
}

/// An error raised by the strict-KEX packet gate.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StrictKexError {
    /// The first packet in one direction was not `SSH_MSG_KEXINIT`.
    #[error("the first {direction:?} packet must be KEXINIT, got {packet:?}")]
    FirstPacketMustBeKexInit { direction: TransportDirection, packet: StrictKexPacket },
    /// A KEX message was sent more than once in one direction.
    #[error("strict KEX message {packet:?} was repeated in the {direction:?} direction")]
    KexMessageRepeated { direction: TransportDirection, packet: StrictKexPacket },
    /// A packet was sent after that direction had already sent or received NEWKEYS.
    #[error("packet {packet:?} arrived after NEWKEYS in the {direction:?} direction")]
    PacketAfterNewKeys { direction: TransportDirection, packet: StrictKexPacket },
    /// A non-KEX packet appeared before both NEWKEYS packets completed the exchange.
    #[error("packet {packet:?} is not permitted during {phase:?} strict KEX")]
    UnexpectedPacket { phase: StrictKexPhase, packet: StrictKexPacket },
    /// The packet type does not belong to the negotiated KEX family.
    #[error("packet {packet:?} is not valid for {family:?} KEX")]
    KexMessageNotAllowed { family: KeyExchangeFamily, packet: StrictKexPacket },
    /// A strict sequence number would wrap before KEX completion.
    #[error("the {direction:?} strict-KEX sequence number would wrap before NEWKEYS")]
    SequenceNumberExhausted { direction: TransportDirection },
    /// A rekey was requested before both endpoints completed the initial exchange.
    #[error("cannot begin rekey while the exchange is {phase:?}")]
    RekeyBeforeEstablished { phase: StrictKexPhase },
    /// A second KEXINIT was seen without beginning a rekey exchange.
    #[error("KEXINIT was received after the exchange was established without begin_rekey")]
    RekeyNotStarted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_sequence_refuses_to_wrap_before_new_keys() {
        let mut state = StrictKeyExchange::new(true, KeyExchangeFamily::Ecdh);
        state.send.first_packet = true;
        state.send.sequence = u32::MAX;

        assert_eq!(
            state.on_send(StrictKexPacket::KexEcdhInit),
            Err(StrictKexError::SequenceNumberExhausted { direction: TransportDirection::Send })
        );
    }
}
