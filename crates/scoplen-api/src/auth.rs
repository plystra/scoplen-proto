// SPDX-License-Identifier: Apache-2.0
//! K-3 device authentication JSON messages.

use scoplen_model::validate_uuid_v7;
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;
use uuid::Uuid;

/// The lifetime of an access token in seconds.
pub const ACCESS_TOKEN_EXPIRES_IN: u64 = 600;
/// The lifetime of a refresh token in seconds.
pub const REFRESH_TOKEN_EXPIRES_IN: u64 = 2_592_000;

/// Errors returned while decoding or validating K-3 authentication JSON.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AuthCodecError {
    /// A JSON document could not be decoded or encoded.
    #[error("invalid authentication JSON: {0}")]
    Json(String),
    /// A field did not satisfy its K-3 canonical representation.
    #[error("invalid authentication field: {0}")]
    Invalid(String),
}

/// The response from `POST /api/v1/auth/challenge`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthChallengeResponse {
    /// The 32-byte challenge nonce as 64 lowercase hexadecimal characters.
    pub nonce: String,
    /// The server time as an RFC 3339 UTC timestamp ending in `Z`.
    pub server_time: String,
}

impl AuthChallengeResponse {
    /// Construct and validate a challenge response.
    ///
    /// # Errors
    ///
    /// Returns an error when the nonce or timestamp is not canonical.
    pub fn new(
        nonce: impl Into<String>,
        server_time: impl Into<String>,
    ) -> Result<Self, AuthCodecError> {
        let response = Self { nonce: nonce.into(), server_time: server_time.into() };
        response.validate()?;
        Ok(response)
    }

    /// Validate all challenge response fields.
    ///
    /// # Errors
    ///
    /// Returns an error when the nonce is not 32 bytes of lowercase hexadecimal or the timestamp
    /// is not an RFC 3339 UTC value with a `Z` suffix.
    pub fn validate(&self) -> Result<(), AuthCodecError> {
        validate_lower_hex(&self.nonce, 32, "nonce")?;
        validate_rfc3339_utc(&self.server_time)
    }

    /// Decode a challenge response from JSON.
    ///
    /// Unknown response fields are ignored so additive response fields remain compatible.
    ///
    /// # Errors
    ///
    /// Returns an error when the JSON is malformed or a required field is invalid.
    pub fn from_json(input: &str) -> Result<Self, AuthCodecError> {
        serde_json::from_str(input).map_err(|error| AuthCodecError::Json(error.to_string()))
    }

    /// Encode a challenge response as deterministic JSON fields.
    ///
    /// # Errors
    ///
    /// Returns an error when a field is invalid or JSON serialization fails.
    pub fn to_json(&self) -> Result<String, AuthCodecError> {
        self.validate()?;
        serde_json::to_string(self).map_err(|error| AuthCodecError::Json(error.to_string()))
    }
}

impl Serialize for AuthChallengeResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        let mut state = serializer.serialize_struct("AuthChallengeResponse", 2)?;
        state.serialize_field("nonce", &self.nonce)?;
        state.serialize_field("server_time", &self.server_time)?;
        state.end()
    }
}

#[derive(Deserialize)]
struct RawAuthChallengeResponse {
    nonce: String,
    server_time: String,
}

impl<'de> Deserialize<'de> for AuthChallengeResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawAuthChallengeResponse::deserialize(deserializer)?;
        Self::new(raw.nonce, raw.server_time).map_err(serde::de::Error::custom)
    }
}

/// The device-signed body sent to `POST /api/v1/auth/device`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthDeviceRequest {
    /// The enrolled device's lowercase canonical `UUIDv7` identifier.
    pub device_id: Uuid,
    /// The challenge nonce copied as its canonical lowercase hexadecimal string.
    pub nonce: String,
    /// The fixed-width P-256 `r || s` signature as 128 lowercase hexadecimal characters.
    pub signature: String,
}

impl AuthDeviceRequest {
    /// Construct and validate a device-authentication request.
    ///
    /// # Errors
    ///
    /// Returns an error when the device id, nonce, or signature is not canonical.
    pub fn new(
        device_id: Uuid,
        nonce: impl Into<String>,
        signature: impl Into<String>,
    ) -> Result<Self, AuthCodecError> {
        let request = Self { device_id, nonce: nonce.into(), signature: signature.into() };
        request.validate()?;
        Ok(request)
    }

    /// Validate all device-authentication request fields.
    ///
    /// # Errors
    ///
    /// Returns an error when the device id is not `UUIDv7` in lowercase canonical form, the nonce
    /// is not 32 bytes of lowercase hexadecimal, or the signature is not 64 bytes of lowercase
    /// hexadecimal.
    pub fn validate(&self) -> Result<(), AuthCodecError> {
        validate_uuid_v7(self.device_id)
            .map_err(|_| AuthCodecError::Invalid("device_id must be UUIDv7".into()))?;
        validate_lower_hex(&self.nonce, 32, "nonce")?;
        validate_lower_hex(&self.signature, 64, "signature")
    }

    /// Decode a device-authentication request from JSON.
    ///
    /// Request bodies reject unknown fields because the endpoint binds exactly these three
    /// values.
    ///
    /// # Errors
    ///
    /// Returns an error when the JSON is malformed, contains an unknown field, or a required
    /// field is invalid.
    pub fn from_json(input: &str) -> Result<Self, AuthCodecError> {
        serde_json::from_str(input).map_err(|error| AuthCodecError::Json(error.to_string()))
    }

    /// Encode a device-authentication request as deterministic JSON fields.
    ///
    /// # Errors
    ///
    /// Returns an error when a field is invalid or JSON serialization fails.
    pub fn to_json(&self) -> Result<String, AuthCodecError> {
        self.validate()?;
        serde_json::to_string(self).map_err(|error| AuthCodecError::Json(error.to_string()))
    }
}

impl Serialize for AuthDeviceRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        let mut state = serializer.serialize_struct("AuthDeviceRequest", 3)?;
        state.serialize_field("device_id", &self.device_id.to_string())?;
        state.serialize_field("nonce", &self.nonce)?;
        state.serialize_field("signature", &self.signature)?;
        state.end()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAuthDeviceRequest {
    device_id: String,
    nonce: String,
    signature: String,
}

impl<'de> Deserialize<'de> for AuthDeviceRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawAuthDeviceRequest::deserialize(deserializer)?;
        let device_id = Uuid::parse_str(&raw.device_id)
            .map_err(|_| serde::de::Error::custom("device_id must be a UUIDv7"))?;
        if raw.device_id != device_id.to_string() {
            return Err(serde::de::Error::custom(
                "device_id must use lowercase canonical UUID form",
            ));
        }
        Self::new(device_id, raw.nonce, raw.signature).map_err(serde::de::Error::custom)
    }
}

/// The successful response from `POST /api/v1/auth/device`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthTokenResponse {
    /// Opaque DPoP-bound access token.
    pub access_token: String,
    /// Always the literal `DPoP` token type.
    pub token_type: String,
    /// Access-token lifetime in seconds.
    pub expires_in: u64,
    /// Opaque DPoP-bound refresh token.
    pub refresh_token: String,
    /// Refresh-token lifetime in seconds.
    pub refresh_expires_in: u64,
}

impl AuthTokenResponse {
    /// Construct a token response using the contract's default lifetimes.
    ///
    /// # Errors
    ///
    /// Returns an error when either opaque token is empty.
    pub fn new(
        access_token: impl Into<String>,
        refresh_token: impl Into<String>,
    ) -> Result<Self, AuthCodecError> {
        let response = Self {
            access_token: access_token.into(),
            token_type: "DPoP".into(),
            expires_in: ACCESS_TOKEN_EXPIRES_IN,
            refresh_token: refresh_token.into(),
            refresh_expires_in: REFRESH_TOKEN_EXPIRES_IN,
        };
        response.validate()?;
        Ok(response)
    }

    /// Validate all token response fields.
    ///
    /// # Errors
    ///
    /// Returns an error when a token is empty, the token type is not `DPoP`, or a lifetime is not
    /// a positive integer.
    pub fn validate(&self) -> Result<(), AuthCodecError> {
        if self.access_token.is_empty() || self.refresh_token.is_empty() {
            return Err(AuthCodecError::Invalid("tokens must not be empty".into()));
        }
        if self.token_type != "DPoP" {
            return Err(AuthCodecError::Invalid("token_type must be DPoP".into()));
        }
        if self.expires_in == 0 {
            return Err(AuthCodecError::Invalid("expires_in must be a positive integer".into()));
        }
        if self.refresh_expires_in == 0 {
            return Err(AuthCodecError::Invalid(
                "refresh_expires_in must be a positive integer".into(),
            ));
        }
        Ok(())
    }

    /// Decode a token response from JSON.
    ///
    /// Unknown response fields are ignored so additive response fields remain compatible.
    ///
    /// # Errors
    ///
    /// Returns an error when the JSON is malformed or a required field is invalid.
    pub fn from_json(input: &str) -> Result<Self, AuthCodecError> {
        serde_json::from_str(input).map_err(|error| AuthCodecError::Json(error.to_string()))
    }

    /// Encode a token response as deterministic JSON fields.
    ///
    /// # Errors
    ///
    /// Returns an error when a field is invalid or JSON serialization fails.
    pub fn to_json(&self) -> Result<String, AuthCodecError> {
        self.validate()?;
        serde_json::to_string(self).map_err(|error| AuthCodecError::Json(error.to_string()))
    }
}

impl Serialize for AuthTokenResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        let mut state = serializer.serialize_struct("AuthTokenResponse", 5)?;
        state.serialize_field("access_token", &self.access_token)?;
        state.serialize_field("token_type", &self.token_type)?;
        state.serialize_field("expires_in", &self.expires_in)?;
        state.serialize_field("refresh_token", &self.refresh_token)?;
        state.serialize_field("refresh_expires_in", &self.refresh_expires_in)?;
        state.end()
    }
}

#[derive(Deserialize)]
struct RawAuthTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: String,
    refresh_expires_in: u64,
}

impl<'de> Deserialize<'de> for AuthTokenResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawAuthTokenResponse::deserialize(deserializer)?;
        let response = Self {
            access_token: raw.access_token,
            token_type: raw.token_type,
            expires_in: raw.expires_in,
            refresh_token: raw.refresh_token,
            refresh_expires_in: raw.refresh_expires_in,
        };
        response.validate().map_err(serde::de::Error::custom)?;
        Ok(response)
    }
}

fn validate_lower_hex(value: &str, bytes: usize, field: &str) -> Result<(), AuthCodecError> {
    if value.len() != bytes * 2
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AuthCodecError::Invalid(format!(
            "{field} must be {bytes} bytes of lowercase hexadecimal"
        )));
    }
    Ok(())
}

fn validate_rfc3339_utc(value: &str) -> Result<(), AuthCodecError> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || *bytes.last().unwrap_or(&0) != b'Z'
    {
        return Err(AuthCodecError::Invalid(
            "server_time must be an RFC 3339 UTC timestamp ending in Z".into(),
        ));
    }
    let year = parse_digits(&bytes[0..4])?;
    let month = parse_digits(&bytes[5..7])?;
    let day = parse_digits(&bytes[8..10])?;
    let hour = parse_digits(&bytes[11..13])?;
    let minute = parse_digits(&bytes[14..16])?;
    let second = parse_digits(&bytes[17..19])?;
    if !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(AuthCodecError::Invalid("server_time has an invalid date or time".into()));
    }
    if bytes.len() > 20
        && (bytes[19] != b'.'
            || bytes.len() == 21
            || !bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit))
    {
        return Err(AuthCodecError::Invalid("server_time fractional seconds are invalid".into()));
    }
    Ok(())
}

fn parse_digits(bytes: &[u8]) -> Result<u32, AuthCodecError> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(AuthCodecError::Invalid("server_time contains non-digit fields".into()));
    }
    Ok(bytes.iter().fold(0_u32, |value, digit| value * 10 + u32::from(*digit - b'0')))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn is_leap_year(year: u32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const SIGNATURE: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

    fn device_id() -> Uuid {
        Uuid::parse_str("00000000-0000-7000-8000-000000000001").expect("uuid")
    }

    #[test]
    fn challenge_round_trips_with_canonical_field_order() {
        let challenge =
            AuthChallengeResponse::new(NONCE, "2026-10-07T12:34:56.123Z").expect("valid");
        let json = challenge.to_json().expect("json");
        assert_eq!(
            json,
            "{\"nonce\":\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\",\"server_time\":\"2026-10-07T12:34:56.123Z\"}"
        );
        assert_eq!(AuthChallengeResponse::from_json(&json).expect("decode"), challenge);
    }

    #[test]
    fn challenge_rejects_bad_hex_time_and_calendar_values() {
        assert!(AuthChallengeResponse::new("0".repeat(63), "2026-10-07T12:34:56Z").is_err());
        assert!(AuthChallengeResponse::new(NONCE.to_uppercase(), "2026-10-07T12:34:56Z").is_err());
        assert!(AuthChallengeResponse::new(NONCE, "2026-10-07T12:34:56+00:00").is_err());
        assert!(AuthChallengeResponse::new(NONCE, "2026-02-29T12:34:56Z").is_err());
        assert!(AuthChallengeResponse::new(NONCE, "2024-02-29T12:34:56Z").is_ok());
        assert!(AuthChallengeResponse::from_json(&format!("{{\"nonce\":\"{NONCE}\"}}")).is_err());
    }

    #[test]
    fn device_request_rejects_unknown_fields_and_noncanonical_values() {
        let request = AuthDeviceRequest::new(device_id(), NONCE, SIGNATURE).expect("valid");
        let json = request.to_json().expect("json");
        assert_eq!(AuthDeviceRequest::from_json(&json).expect("decode"), request);
        assert!(AuthDeviceRequest::from_json(&format!(
            "{{\"device_id\":\"{}\",\"nonce\":\"{NONCE}\",\"signature\":\"{SIGNATURE}\",\"future\":true}}",
            device_id()
        ))
        .is_err());
        assert!(
            AuthDeviceRequest::from_json(&json.replace(
                "00000000-0000-7000-8000-000000000001",
                "00000000-0000-7000-8000-00000000000A"
            ))
            .is_err()
        );
        assert!(
            AuthDeviceRequest::from_json(&json.replace(
                "00000000-0000-7000-8000-000000000001",
                "00000000-0000-4000-8000-000000000001"
            ))
            .is_err()
        );
        assert!(AuthDeviceRequest::from_json(&json.replace(SIGNATURE, "00")).is_err());
    }

    #[test]
    fn token_response_uses_default_lifetimes_and_tolerates_extensions() {
        let response = AuthTokenResponse::new("access", "refresh").expect("valid");
        let json = response.to_json().expect("json");
        assert_eq!(
            json,
            "{\"access_token\":\"access\",\"token_type\":\"DPoP\",\"expires_in\":600,\"refresh_token\":\"refresh\",\"refresh_expires_in\":2592000}"
        );
        assert_eq!(
            AuthTokenResponse::from_json(
                &(json.trim_end_matches('}').to_owned() + ",\"future\":true}")
            )
            .expect("extension"),
            response
        );
        assert!(AuthTokenResponse::from_json(&json.replace("\"DPoP\"", "\"Bearer\"")).is_err());
        assert!(AuthTokenResponse::from_json(&json.replace("access", "")).is_err());
        assert!(AuthTokenResponse::from_json(
            "{\"access_token\":\"access\",\"token_type\":\"DPoP\",\"expires_in\":600,\"refresh_token\":\"refresh\"}"
        )
        .is_err());
    }

    #[test]
    fn token_response_accepts_any_positive_lifetimes_and_rejects_zero() {
        let response = AuthTokenResponse::from_json(
            "{\"access_token\":\"access\",\"token_type\":\"DPoP\",\"expires_in\":1,\"refresh_token\":\"refresh\",\"refresh_expires_in\":18446744073709551615}",
        )
        .expect("positive lifetimes");
        assert_eq!(response.expires_in, 1);
        assert_eq!(response.refresh_expires_in, u64::MAX);
        assert_eq!(
            response.to_json().expect("encode"),
            "{\"access_token\":\"access\",\"token_type\":\"DPoP\",\"expires_in\":1,\"refresh_token\":\"refresh\",\"refresh_expires_in\":18446744073709551615}"
        );

        assert!(AuthTokenResponse::from_json(
            "{\"access_token\":\"access\",\"token_type\":\"DPoP\",\"expires_in\":0,\"refresh_token\":\"refresh\",\"refresh_expires_in\":1}"
        )
        .is_err());
        assert!(AuthTokenResponse::from_json(
            "{\"access_token\":\"access\",\"token_type\":\"DPoP\",\"expires_in\":1,\"refresh_token\":\"refresh\",\"refresh_expires_in\":0}"
        )
        .is_err());
    }
}
