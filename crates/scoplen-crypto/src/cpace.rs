// SPDX-License-Identifier: Apache-2.0
//! Typed-code `CPace` pairing and its authenticated payload channel for K-3.
//!
//! This module is the one place where callers compose the `CPace` transcript,
//! key confirmation, and channel binding.  Callers never receive the raw
//! intermediate session key; it is held in a zeroizing wrapper for the
//! lifetime of the channel session.

use std::collections::HashSet;
use std::fmt;
use std::sync::Mutex;

use getrandom_04::SysRng;
use pakery_cpace::{CpaceError, CpaceInitiator, CpaceMode, CpaceResponder, InitiatorState};
use pakery_crypto::CpaceRistretto255;
use rand_core_010::{CryptoRng, UnwrapErr};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    PrimitiveError, SecretBytes, SymmetricKey, XChaChaNonce, hkdf_sha256, random_bytes,
    random_nonce, xchacha20poly1305_open, xchacha20poly1305_seal,
};
use scoplen_model::validate_uuid_v7;

/// The fixed `CPace` channel identifier from `06-identity-and-authentication.md` §2.
pub const CPACE_CHANNEL_IDENTIFIER: &[u8] = b"spl-pairing-v1/cpace-ristretto255-sha512";
const INITIATOR_AD_PREFIX: &[u8] = b"spl-pairing-v1/initiator";
const RESPONDER_AD_PREFIX: &[u8] = b"spl-pairing-v1/responder";
const CONFIRMATION_INFO_PREFIX: &[u8] = b"spl-pairing-confirm-v1";
const CHANNEL_INFO_PREFIX: &[u8] = b"spl-pairing-channel-v1";
const FRAME_INFO_PREFIX: &[u8] = b"spl-pairing-frame-v1";
const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// One of the two fixed `CPace` transcript roles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingRole {
    /// The existing device starts the exchange.
    Initiator,
    /// The new device responds to the exchange.
    Responder,
}

impl PairingRole {
    const fn ad_prefix(self) -> &'static [u8] {
        match self {
            Self::Initiator => INITIATOR_AD_PREFIX,
            Self::Responder => RESPONDER_AD_PREFIX,
        }
    }

    const fn label(self) -> &'static [u8] {
        match self {
            Self::Initiator => b"initiator",
            Self::Responder => b"responder",
        }
    }

    const fn byte(self) -> u8 {
        match self {
            Self::Initiator => 0x01,
            Self::Responder => 0x02,
        }
    }

    const fn peer(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }
}

/// Errors returned by typed-code pairing and the authenticated channel.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PairingError {
    /// A pairing or device identifier is not `UUIDv7`, or the two device IDs match.
    #[error("invalid pairing context")]
    InvalidContext,
    /// The typed code is not exactly eight uppercase Crockford symbols.
    #[error("invalid pairing code")]
    InvalidCode,
    /// The `CPace` share is not a canonical, non-identity Ristretto255 point.
    #[error("invalid CPace share")]
    InvalidShare,
    /// `CPace` rejected an identity point.
    #[error("identity point in CPace exchange")]
    IdentityPoint,
    /// The peer's confirmation did not match the transcript.
    #[error("pairing confirmation mismatch")]
    ConfirmationMismatch,
    /// The frame is too short to contain a nonce and an authentication tag.
    #[error("pairing frame is truncated")]
    FrameTruncated,
    /// A frame was sent under the wrong transcript role.
    #[error("invalid pairing frame role")]
    WrongRole,
    /// A sender attempted to reuse a channel nonce.
    #[error("pairing frame nonce was already used")]
    NonceReuse,
    /// Frame authentication failed.  The error does not reveal whether the
    /// nonce, associated data, or ciphertext was wrong.
    #[error("pairing frame authentication failed")]
    Authentication,
    /// The operating system did not provide randomness.
    #[error("pairing randomness failed: {0}")]
    Randomness(String),
    /// An internal `CPace` output had an unexpected length.
    #[error("invalid CPace output")]
    InvalidOutput,
}

impl From<PrimitiveError> for PairingError {
    fn from(error: PrimitiveError) -> Self {
        match error {
            PrimitiveError::Randomness(message) => Self::Randomness(message),
            PrimitiveError::Authentication => Self::Authentication,
            _ => Self::InvalidOutput,
        }
    }
}

/// The pairing session identifiers and device ordering bound into `CPace`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingContext {
    pairing_id: Uuid,
    initiator_device_id: Uuid,
    responder_device_id: Uuid,
}

impl PairingContext {
    /// Construct a context after validating all identifiers and role ordering.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::InvalidContext`] for non-UUIDv7 values or if
    /// both roles use the same device identifier.
    pub fn new(
        pairing_id: Uuid,
        initiator_device_id: Uuid,
        responder_device_id: Uuid,
    ) -> Result<Self, PairingError> {
        for id in [pairing_id, initiator_device_id, responder_device_id] {
            validate_uuid_v7(id).map_err(|_| PairingError::InvalidContext)?;
        }
        if initiator_device_id == responder_device_id {
            return Err(PairingError::InvalidContext);
        }
        Ok(Self { pairing_id, initiator_device_id, responder_device_id })
    }

    /// Return the one-time pairing identifier.
    #[must_use]
    pub const fn pairing_id(self) -> Uuid {
        self.pairing_id
    }

    /// Return the existing device identifier used as the initiator.
    #[must_use]
    pub const fn initiator_device_id(self) -> Uuid {
        self.initiator_device_id
    }

    /// Return the new device identifier used as the responder.
    #[must_use]
    pub const fn responder_device_id(self) -> Uuid {
        self.responder_device_id
    }

    fn sid(&self) -> &[u8; 16] {
        self.pairing_id.as_bytes()
    }

    fn additional_data(self, role: PairingRole) -> Vec<u8> {
        let mut ad = Vec::with_capacity(role.ad_prefix().len() + 48);
        ad.extend_from_slice(role.ad_prefix());
        ad.extend_from_slice(self.sid());
        ad.extend_from_slice(self.initiator_device_id.as_bytes());
        ad.extend_from_slice(self.responder_device_id.as_bytes());
        ad
    }
}

/// The eight-symbol uppercase Crockford code used for typed pairing.
///
/// The code is kept in a zeroizing container and its debug representation is
/// redacted.  Callers should transmit it only through the pairing relay.
pub struct PairingCode(SecretBytes<8>);

impl PairingCode {
    /// Generate a code with the operating-system CSPRNG.
    ///
    /// The alphabet has 32 symbols, so selecting the low five bits of each
    /// byte is exactly uniform and has no modulo bias.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Randomness`] when the operating system cannot
    /// provide fresh random bytes.
    pub fn generate() -> Result<Self, PairingError> {
        let mut code = [0u8; 8];
        random_bytes(&mut code)?;
        for byte in &mut code {
            *byte = CODE_ALPHABET[usize::from(*byte & 0x1f)];
        }
        Ok(Self(SecretBytes::new(code)))
    }

    /// Parse exactly eight uppercase Crockford symbols.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::InvalidCode`] for lowercase, ambiguous, or
    /// non-ASCII symbols and for any length other than eight.
    pub fn from_ascii(value: &[u8]) -> Result<Self, PairingError> {
        if value.len() != 8 || value.iter().any(|byte| !CODE_ALPHABET.contains(byte)) {
            return Err(PairingError::InvalidCode);
        }
        Ok(Self(SecretBytes::from_slice(value).ok_or(PairingError::InvalidCode)?))
    }

    /// Borrow the ASCII code for the `CPace` password input.
    #[must_use]
    pub fn as_ascii(&self) -> &[u8; 8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingCode([REDACTED])")
    }
}

/// Initiator state held between the two `CPace` share messages.
pub struct PairingInitiator {
    state: InitiatorState<CpaceRistretto255>,
    context: PairingContext,
}

impl fmt::Debug for PairingInitiator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingInitiator([REDACTED])")
    }
}

impl PairingInitiator {
    /// Start `CPace` with operating-system randomness.
    ///
    /// The returned share is exactly 32 bytes of compressed Ristretto255.
    ///
    /// # Errors
    ///
    /// Returns a pairing error when the operating-system RNG or `CPace`
    /// generator fails.
    pub fn start(
        context: &PairingContext,
        code: &PairingCode,
    ) -> Result<(Self, [u8; 32]), PairingError> {
        let mut rng = UnwrapErr(SysRng);
        Self::start_with_rng(context, code, &mut rng)
    }

    /// Start `CPace` with a caller-provided cryptographic RNG.
    ///
    /// This is useful for deterministic interoperability tests.  Production
    /// callers should use [`Self::start`].
    ///
    /// # Errors
    ///
    /// Returns a pairing error when `CPace` cannot derive a valid share.
    pub fn start_with_rng<R: CryptoRng>(
        context: &PairingContext,
        code: &PairingCode,
        rng: &mut R,
    ) -> Result<(Self, [u8; 32]), PairingError> {
        let ad_i = context.additional_data(PairingRole::Initiator);
        let (share, state) = CpaceInitiator::<CpaceRistretto255>::start(
            code.as_ascii(),
            CPACE_CHANNEL_IDENTIFIER,
            context.sid(),
            &ad_i,
            rng,
        )
        .map_err(|error| map_cpace_error(&error))?;
        let share = share.try_into().map_err(|_| PairingError::InvalidOutput)?;
        Ok((Self { state, context: *context }, share))
    }

    /// Finish `CPace` after receiving the responder's share.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::InvalidShare`] or
    /// [`PairingError::IdentityPoint`] for an invalid peer share.
    pub fn finish(self, responder_share: &[u8]) -> Result<PairingSession, PairingError> {
        let ad_r = self.context.additional_data(PairingRole::Responder);
        let output = self
            .state
            .finish(responder_share, &ad_r, CpaceMode::InitiatorResponder)
            .map_err(|error| map_cpace_error(&error))?;
        PairingSession::from_output(self.context, PairingRole::Initiator, &output)
    }
}

/// The responder's completed `CPace` session.
pub struct PairingResponder;

impl PairingResponder {
    /// Process the initiator's share with operating-system randomness.
    ///
    /// The returned share is exactly 32 bytes of compressed Ristretto255.
    ///
    /// # Errors
    ///
    /// Returns a pairing error when the operating-system RNG or `CPace`
    /// generator fails.
    pub fn respond(
        context: &PairingContext,
        code: &PairingCode,
        initiator_share: &[u8],
    ) -> Result<(PairingSession, [u8; 32]), PairingError> {
        let mut rng = UnwrapErr(SysRng);
        Self::respond_with_rng(context, code, initiator_share, &mut rng)
    }

    /// Process the initiator's share with a caller-provided cryptographic RNG.
    ///
    /// This is useful for deterministic interoperability tests.  Production
    /// callers should use [`Self::respond`].
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::InvalidShare`] or
    /// [`PairingError::IdentityPoint`] for an invalid peer share.
    pub fn respond_with_rng<R: CryptoRng>(
        context: &PairingContext,
        code: &PairingCode,
        initiator_share: &[u8],
        rng: &mut R,
    ) -> Result<(PairingSession, [u8; 32]), PairingError> {
        let ad_i = context.additional_data(PairingRole::Initiator);
        let ad_r = context.additional_data(PairingRole::Responder);
        let (share, output) = CpaceResponder::<CpaceRistretto255>::respond(
            initiator_share,
            code.as_ascii(),
            CPACE_CHANNEL_IDENTIFIER,
            context.sid(),
            &ad_i,
            &ad_r,
            CpaceMode::InitiatorResponder,
            rng,
        )
        .map_err(|error| map_cpace_error(&error))?;
        let share = share.try_into().map_err(|_| PairingError::InvalidOutput)?;
        let session = PairingSession::from_output(*context, PairingRole::Responder, &output)?;
        Ok((session, share))
    }
}

/// A completed `CPace` session with confirmation and an `XChaCha20` channel.
pub struct PairingSession {
    role: PairingRole,
    context: PairingContext,
    session_id: [u8; 64],
    // Keep both derivation stages in zeroizing wrappers.  The ISK is never
    // exposed through the public API; only its protocol-derived outputs are.
    isk: SecretBytes<64>,
    channel_key: SymmetricKey,
    // Nonces are tracked for both directions.  This makes accidental reuse
    // under one channel key observable even when a caller supplies a nonce.
    used_nonces: Mutex<HashSet<[u8; 24]>>,
}

impl fmt::Debug for PairingSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingSession")
            .field("role", &self.role)
            .field("pairing_id", &self.context.pairing_id)
            .field("session_id", &self.session_id)
            .field("isk", &"[REDACTED]")
            .field("channel_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl PairingSession {
    fn from_output(
        context: PairingContext,
        role: PairingRole,
        output: &pakery_cpace::CpaceOutput,
    ) -> Result<Self, PairingError> {
        let isk =
            SecretBytes::from_slice(output.isk.as_bytes()).ok_or(PairingError::InvalidOutput)?;
        let session_id: [u8; 64] =
            output.session_id.as_slice().try_into().map_err(|_| PairingError::InvalidOutput)?;

        let channel_key = derive_channel_key(&isk, context.sid(), &session_id)?;

        Ok(Self {
            role,
            context,
            session_id,
            isk,
            channel_key,
            used_nonces: Mutex::new(HashSet::new()),
        })
    }

    /// Return the `CPace` session-id output (64 bytes).
    #[must_use]
    pub const fn session_id(&self) -> &[u8; 64] {
        &self.session_id
    }

    /// Return this side's transcript role.
    #[must_use]
    pub const fn role(&self) -> PairingRole {
        self.role
    }

    /// Derive this side's 32-byte key confirmation value.
    ///
    /// The returned value is intended to be sent to the peer and compared by
    /// [`Self::verify_peer_confirmation`].
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::InvalidOutput`] only if an internal derivation
    /// has an unexpected length.
    pub fn confirmation(&self) -> Result<[u8; 32], PairingError> {
        let mut info = Vec::with_capacity(
            CONFIRMATION_INFO_PREFIX.len() + self.session_id.len() + self.role.label().len(),
        );
        info.extend_from_slice(CONFIRMATION_INFO_PREFIX);
        info.extend_from_slice(&self.session_id);
        info.extend_from_slice(self.role.label());
        let value = hkdf_sha256(self.isk.as_ref(), Some(self.context.sid()), &info, 32)?;
        value.try_into().map_err(|_| PairingError::InvalidOutput)
    }

    /// Constant-time compare a peer confirmation against the expected role.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::ConfirmationMismatch`] for a wrong or malformed
    /// confirmation.
    pub fn verify_peer_confirmation(&self, peer: &[u8]) -> Result<(), PairingError> {
        let expected = self.peer_confirmation().map_err(|_| PairingError::ConfirmationMismatch)?;
        if peer.len() != expected.len() || !bool::from(expected.ct_eq(peer)) {
            return Err(PairingError::ConfirmationMismatch);
        }
        Ok(())
    }

    fn peer_confirmation(&self) -> Result<[u8; 32], PairingError> {
        let peer = self.role.peer();
        let mut info = Vec::with_capacity(
            CONFIRMATION_INFO_PREFIX.len() + self.session_id.len() + peer.label().len(),
        );
        info.extend_from_slice(CONFIRMATION_INFO_PREFIX);
        info.extend_from_slice(&self.session_id);
        info.extend_from_slice(peer.label());
        let value = hkdf_sha256(self.isk.as_ref(), Some(self.context.sid()), &info, 32)?;
        value.try_into().map_err(|_| PairingError::InvalidOutput)
    }

    /// Encrypt a frame with a fresh operating-system nonce.
    ///
    /// The wire format is `nonce (24 bytes) || ciphertext || tag`.  The
    /// sender role, pairing id, and `CPace` session id are authenticated as
    /// additional data.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Randomness`] when a fresh nonce cannot be
    /// generated, or an authentication error if the primitive fails.
    pub fn seal_frame(&self, plaintext: &[u8]) -> Result<Vec<u8>, PairingError> {
        loop {
            let nonce = random_nonce()?;
            if self
                .used_nonces
                .lock()
                .map_err(|_| PairingError::Authentication)?
                .contains(nonce.as_bytes().as_slice())
            {
                continue;
            }
            match self.seal_frame_with_nonce(plaintext, &nonce) {
                Err(PairingError::NonceReuse) => continue,
                result => return result,
            }
        }
    }

    /// Encrypt a frame with an explicit nonce.
    ///
    /// This method exists for deterministic test vectors and controlled
    /// transports.  Reusing a nonce on one session is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::NonceReuse`] when the nonce was already used.
    pub fn seal_frame_with_nonce(
        &self,
        plaintext: &[u8],
        nonce: &XChaChaNonce,
    ) -> Result<Vec<u8>, PairingError> {
        let mut used = self.used_nonces.lock().map_err(|_| PairingError::Authentication)?;
        if !used.insert(*nonce.as_bytes()) {
            return Err(PairingError::NonceReuse);
        }
        drop(used);

        let aad = self.frame_aad(self.role);
        let ciphertext = match xchacha20poly1305_seal(&self.channel_key, nonce, plaintext, &aad) {
            Ok(value) => value,
            Err(error) => {
                // Do not burn a nonce when the primitive itself fails before
                // producing a frame.
                if let Ok(mut used) = self.used_nonces.lock() {
                    used.remove(nonce.as_bytes().as_slice());
                }
                return Err(error.into());
            }
        };
        let mut frame = Vec::with_capacity(nonce.as_bytes().len() + ciphertext.len());
        frame.extend_from_slice(nonce.as_bytes());
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    }

    /// Authenticate and decrypt a peer frame.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::FrameTruncated`],
    /// [`PairingError::WrongRole`], [`PairingError::NonceReuse`], or
    /// [`PairingError::Authentication`] when the frame cannot be accepted.
    pub fn open_frame(
        &self,
        peer_role: PairingRole,
        frame: &[u8],
    ) -> Result<Vec<u8>, PairingError> {
        if peer_role == self.role {
            return Err(PairingError::WrongRole);
        }
        if frame.len() < 24 + 16 {
            return Err(PairingError::FrameTruncated);
        }
        let nonce = XChaChaNonce::from_slice(&frame[..24]).ok_or(PairingError::FrameTruncated)?;
        if self
            .used_nonces
            .lock()
            .map_err(|_| PairingError::Authentication)?
            .contains(nonce.as_bytes().as_slice())
        {
            return Err(PairingError::NonceReuse);
        }
        let aad = self.frame_aad(peer_role);
        let plaintext = xchacha20poly1305_open(&self.channel_key, &nonce, &frame[24..], &aad)
            .map_err(|_| PairingError::Authentication)?;
        if !self
            .used_nonces
            .lock()
            .map_err(|_| PairingError::Authentication)?
            .insert(*nonce.as_bytes())
        {
            return Err(PairingError::NonceReuse);
        }
        Ok(plaintext)
    }

    fn frame_aad(&self, sender: PairingRole) -> Vec<u8> {
        let mut aad = Vec::with_capacity(FRAME_INFO_PREFIX.len() + 1 + 16 + 64);
        aad.extend_from_slice(FRAME_INFO_PREFIX);
        aad.push(sender.byte());
        aad.extend_from_slice(self.context.sid());
        aad.extend_from_slice(&self.session_id);
        aad
    }
}

fn derive_channel_key(
    isk: &SecretBytes<64>,
    sid: &[u8; 16],
    session_id: &[u8; 64],
) -> Result<SymmetricKey, PairingError> {
    let mut info = Vec::with_capacity(CHANNEL_INFO_PREFIX.len() + session_id.len());
    info.extend_from_slice(CHANNEL_INFO_PREFIX);
    info.extend_from_slice(session_id);
    let value = hkdf_sha256(isk.as_ref(), Some(sid), &info, 32)?;
    SecretBytes::from_slice(&value).ok_or(PairingError::InvalidOutput)
}

fn map_cpace_error(error: &CpaceError) -> PairingError {
    match error {
        CpaceError::InvalidPoint => PairingError::InvalidShare,
        CpaceError::IdentityPoint => PairingError::IdentityPoint,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core_010::{TryCryptoRng, TryRng};
    use std::convert::Infallible;

    struct FixedRng {
        bytes: [u8; 128],
        offset: usize,
    }

    impl TryRng for FixedRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut bytes = [0; 4];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u32::from_le_bytes(bytes))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut bytes = [0; 8];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u64::from_le_bytes(bytes))
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
            let end = self.offset + destination.len();
            destination.copy_from_slice(&self.bytes[self.offset..end]);
            self.offset = end;
            Ok(())
        }
    }

    impl TryCryptoRng for FixedRng {}

    fn uuid(text: &str) -> Uuid {
        text.parse().expect("UUIDv7")
    }

    fn context() -> PairingContext {
        PairingContext::new(
            uuid("03000000-0000-7000-8000-000000000000"),
            uuid("03000000-0000-7000-8000-000000000001"),
            uuid("03000000-0000-7000-8000-000000000002"),
        )
        .expect("context")
    }

    #[test]
    fn code_parser_is_strict_and_debug_redacts() {
        let code = PairingCode::from_ascii(b"01234567").expect("code");
        assert_eq!(code.as_ascii(), b"01234567");
        assert!(PairingCode::from_ascii(b"0123456i").is_err());
        assert!(PairingCode::from_ascii(b"0123456").is_err());
        assert_eq!(format!("{code:?}"), "PairingCode([REDACTED])");
    }

    #[test]
    fn cpace_confirmation_and_channel_bind_both_roles() {
        let context = context();
        let code = PairingCode::from_ascii(b"01234567").expect("code");
        let mut initiator_rng = FixedRng { bytes: [7; 128], offset: 0 };
        let (initiator, initiator_share) =
            PairingInitiator::start_with_rng(&context, &code, &mut initiator_rng).expect("start");
        let mut responder_rng = FixedRng { bytes: [8; 128], offset: 0 };
        let (responder, responder_share) = PairingResponder::respond_with_rng(
            &context,
            &code,
            &initiator_share,
            &mut responder_rng,
        )
        .expect("respond");
        let initiator = initiator.finish(&responder_share).expect("finish");

        assert_eq!(initiator.session_id(), responder.session_id());
        let initiator_confirmation = initiator.confirmation().expect("confirmation");
        let responder_confirmation = responder.confirmation().expect("confirmation");
        initiator
            .verify_peer_confirmation(&responder_confirmation)
            .expect("initiator confirmation");
        responder
            .verify_peer_confirmation(&initiator_confirmation)
            .expect("responder confirmation");
        assert_eq!(
            responder.verify_peer_confirmation(&[0; 32]),
            Err(PairingError::ConfirmationMismatch)
        );

        let nonce = XChaChaNonce::new([9; 24]);
        let frame = initiator.seal_frame_with_nonce(b"device package", &nonce).expect("seal");
        assert_eq!(
            responder.open_frame(PairingRole::Initiator, &frame).expect("open"),
            b"device package"
        );
        assert_eq!(
            initiator.seal_frame_with_nonce(b"again", &nonce),
            Err(PairingError::NonceReuse)
        );
        assert_eq!(
            responder.open_frame(PairingRole::Responder, &frame),
            Err(PairingError::WrongRole)
        );
        assert_eq!(
            responder.open_frame(PairingRole::Initiator, &frame),
            Err(PairingError::NonceReuse)
        );

        let second_nonce = XChaChaNonce::new([10; 24]);
        let second_frame =
            initiator.seal_frame_with_nonce(b"tamper me", &second_nonce).expect("second seal");
        let mut tampered = second_frame.clone();
        *tampered.last_mut().expect("tag") ^= 1;
        assert_eq!(
            responder.open_frame(PairingRole::Initiator, &tampered),
            Err(PairingError::Authentication)
        );
        assert_eq!(
            responder.open_frame(PairingRole::Initiator, &second_frame),
            Ok(b"tamper me".to_vec())
        );
        assert_eq!(
            responder.open_frame(PairingRole::Initiator, &[0; 39]),
            Err(PairingError::FrameTruncated)
        );
    }

    #[test]
    fn malformed_or_identity_shares_abort() {
        let context = context();
        let code = PairingCode::from_ascii(b"01234567").expect("code");
        let mut rng = FixedRng { bytes: [7; 128], offset: 0 };
        assert!(matches!(
            PairingResponder::respond_with_rng(&context, &code, &[0; 31], &mut rng),
            Err(PairingError::InvalidShare)
        ));
        assert!(matches!(
            PairingResponder::respond_with_rng(&context, &code, &[0; 32], &mut rng),
            Err(PairingError::IdentityPoint)
        ));
    }

    #[test]
    fn context_rejects_wrong_uuid_versions_and_duplicate_roles() {
        let pairing = uuid("03000000-0000-7000-8000-000000000000");
        let initiator = uuid("03000000-0000-7000-8000-000000000001");
        assert_eq!(
            PairingContext::new(
                Uuid::nil(),
                initiator,
                uuid("03000000-0000-7000-8000-000000000002"),
            ),
            Err(PairingError::InvalidContext)
        );
        assert_eq!(
            PairingContext::new(pairing, initiator, initiator),
            Err(PairingError::InvalidContext)
        );
        assert_eq!(
            PairingContext::new(pairing, initiator, uuid("03000000-0000-4000-8000-000000000002"),),
            Err(PairingError::InvalidContext)
        );
    }

    #[test]
    fn mismatched_device_contexts_do_not_confirm() {
        let context = context();
        let wrong_context = PairingContext::new(
            context.pairing_id(),
            context.initiator_device_id(),
            uuid("03000000-0000-7000-8000-000000000003"),
        )
        .expect("wrong context");
        let code = PairingCode::from_ascii(b"01234567").expect("code");
        let mut initiator_rng = FixedRng { bytes: [7; 128], offset: 0 };
        let (initiator, initiator_share) =
            PairingInitiator::start_with_rng(&context, &code, &mut initiator_rng).expect("start");
        let mut responder_rng = FixedRng { bytes: [8; 128], offset: 0 };
        let (responder, responder_share) = PairingResponder::respond_with_rng(
            &wrong_context,
            &code,
            &initiator_share,
            &mut responder_rng,
        )
        .expect("respond");
        let initiator = initiator.finish(&responder_share).expect("finish");
        assert_ne!(initiator.session_id(), responder.session_id());
        assert_eq!(
            initiator.verify_peer_confirmation(&responder.confirmation().expect("confirmation")),
            Err(PairingError::ConfirmationMismatch)
        );
    }
}
