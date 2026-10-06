// SPDX-License-Identifier: Apache-2.0
//! The K-4 session handshake, encoded with deterministic CBOR.

use std::collections::{BTreeMap, BTreeSet};

use scoplen_model::{
    cbor::{self, Value},
    validate_uuid_v7,
};
use thiserror::Error;
use uuid::Uuid;

/// Errors at the K-4 session wire boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SyncCodecError {
    /// The CBOR was malformed or not deterministic.
    #[error("invalid deterministic CBOR: {0}")]
    Cbor(#[from] cbor::Error),
    /// A required field was missing or invalid.
    #[error("invalid sync session: {0}")]
    Invalid(String),
}

/// Request body for `POST /sync/v1/session`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncSessionRequest {
    /// Client release version.
    pub client_version: String,
    /// Highest object-model version the client understands.
    pub model_version: u64,
    /// Enrolled device making the request.
    pub device_id: Uuid,
}

impl SyncSessionRequest {
    /// Validate the required fields before a request is sent.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty release version, zero model version, or non-v7 device id.
    pub fn validate(&self) -> Result<(), SyncCodecError> {
        nonempty(&self.client_version, "client_version")?;
        positive(self.model_version, "model_version")?;
        valid_uuid(self.device_id, "device_id")
    }

    /// Encode the request as deterministic CBOR.
    ///
    /// # Errors
    ///
    /// Returns an error if fields are invalid or cannot be encoded canonically.
    pub fn to_cbor(&self) -> Result<Vec<u8>, SyncCodecError> {
        self.validate()?;
        encode_map(vec![
            ("client_version", Value::Text(self.client_version.clone())),
            ("model_version", Value::UInt(self.model_version)),
            ("device_id", Value::Bytes(self.device_id.as_bytes().to_vec())),
        ])
    }

    /// Decode a deterministic CBOR request. Unknown request fields are rejected.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed CBOR or invalid required fields.
    pub fn from_cbor(input: &[u8]) -> Result<Self, SyncCodecError> {
        let mut fields = decode_map(input)?;
        let request = Self {
            client_version: take_text(&mut fields, "client_version")?,
            model_version: take_uint(&mut fields, "model_version")?,
            device_id: take_uuid(&mut fields, "device_id")?,
        };
        if !fields.is_empty() {
            return Err(invalid("unknown request field"));
        }
        request.validate()?;
        Ok(request)
    }
}

/// Limits announced by the sync server for this deployment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncLimits {
    pub max_envelope_bytes: u64,
    pub max_batch_objects: u64,
    pub max_batch_bytes: u64,
    pub max_objects_per_vault: u64,
    pub max_shared_vaults_per_account: u64,
    pub max_members_per_shared_vault: u64,
    pub write_requests_per_second: u64,
    pub write_burst: u64,
}

impl SyncLimits {
    fn validate(&self) -> Result<(), SyncCodecError> {
        for (name, value) in [
            ("max_envelope_bytes", self.max_envelope_bytes),
            ("max_batch_objects", self.max_batch_objects),
            ("max_batch_bytes", self.max_batch_bytes),
            ("max_objects_per_vault", self.max_objects_per_vault),
            ("max_shared_vaults_per_account", self.max_shared_vaults_per_account),
            ("max_members_per_shared_vault", self.max_members_per_shared_vault),
            ("write_requests_per_second", self.write_requests_per_second),
            ("write_burst", self.write_burst),
        ] {
            positive(value, name)?;
        }
        Ok(())
    }

    fn into_value(self) -> Value {
        map(vec![
            ("max_envelope_bytes", Value::UInt(self.max_envelope_bytes)),
            ("max_batch_objects", Value::UInt(self.max_batch_objects)),
            ("max_batch_bytes", Value::UInt(self.max_batch_bytes)),
            ("max_objects_per_vault", Value::UInt(self.max_objects_per_vault)),
            ("max_shared_vaults_per_account", Value::UInt(self.max_shared_vaults_per_account)),
            ("max_members_per_shared_vault", Value::UInt(self.max_members_per_shared_vault)),
            ("write_requests_per_second", Value::UInt(self.write_requests_per_second)),
            ("write_burst", Value::UInt(self.write_burst)),
        ])
    }

    fn from_value(value: Value) -> Result<Self, SyncCodecError> {
        let mut fields = expect_map(value)?;
        let limits = Self {
            max_envelope_bytes: take_uint(&mut fields, "max_envelope_bytes")?,
            max_batch_objects: take_uint(&mut fields, "max_batch_objects")?,
            max_batch_bytes: take_uint(&mut fields, "max_batch_bytes")?,
            max_objects_per_vault: take_uint(&mut fields, "max_objects_per_vault")?,
            max_shared_vaults_per_account: take_uint(&mut fields, "max_shared_vaults_per_account")?,
            max_members_per_shared_vault: take_uint(&mut fields, "max_members_per_shared_vault")?,
            write_requests_per_second: take_uint(&mut fields, "write_requests_per_second")?,
            write_burst: take_uint(&mut fields, "write_burst")?,
        };
        limits.validate()?;
        Ok(limits)
    }
}

/// The kind of a vault returned by the server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VaultKind {
    Personal,
    Shared,
    Organization,
    /// An additive future kind that this version must not write to.
    Unknown(String),
}

impl VaultKind {
    fn parse(value: String) -> Result<Self, SyncCodecError> {
        nonempty(&value, "kind")?;
        Ok(match value.as_str() {
            "personal" => Self::Personal,
            "shared" => Self::Shared,
            "organization" => Self::Organization,
            _ => Self::Unknown(value),
        })
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Personal => "personal",
            Self::Shared => "shared",
            Self::Organization => "organization",
            Self::Unknown(value) => value,
        }
    }
}

/// One vault descriptor in the session response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionVault {
    pub id: Uuid,
    pub kind: VaultKind,
    pub seq: u64,
    pub key_epoch: u64,
    pub rotation_pending: bool,
}

impl SessionVault {
    fn validate(&self) -> Result<(), SyncCodecError> {
        valid_uuid(self.id, "vault id")?;
        nonempty(self.kind.as_str(), "kind")?;
        positive(self.key_epoch, "key_epoch")
    }

    fn into_value(self) -> Value {
        map(vec![
            ("id", Value::Bytes(self.id.as_bytes().to_vec())),
            ("kind", Value::Text(self.kind.as_str().to_owned())),
            ("seq", Value::UInt(self.seq)),
            ("key_epoch", Value::UInt(self.key_epoch)),
            ("rotation_pending", Value::Bool(self.rotation_pending)),
        ])
    }

    fn from_value(value: Value) -> Result<Self, SyncCodecError> {
        let mut fields = expect_map(value)?;
        let vault = Self {
            id: take_uuid(&mut fields, "id")?,
            kind: VaultKind::parse(take_text(&mut fields, "kind")?)?,
            seq: take_uint(&mut fields, "seq")?,
            key_epoch: take_uint(&mut fields, "key_epoch")?,
            rotation_pending: take_bool(&mut fields, "rotation_pending")?,
        };
        vault.validate()?;
        Ok(vault)
    }
}

/// Response body for `POST /sync/v1/session`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncSessionResponse {
    pub server_version: String,
    pub max_model_version: u64,
    pub limits: SyncLimits,
    pub vaults: Vec<SessionVault>,
}

impl SyncSessionResponse {
    /// Validate the response, including uniqueness of vault identifiers.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid required fields or duplicate vault identifiers.
    pub fn validate(&self) -> Result<(), SyncCodecError> {
        nonempty(&self.server_version, "server_version")?;
        positive(self.max_model_version, "max_model_version")?;
        self.limits.validate()?;
        let mut seen = BTreeSet::new();
        for vault in &self.vaults {
            vault.validate()?;
            if !seen.insert(vault.id) {
                return Err(invalid("duplicate vault id"));
            }
        }
        Ok(())
    }

    /// Encode the response as deterministic CBOR.
    ///
    /// # Errors
    ///
    /// Returns an error if fields are invalid or cannot be encoded canonically.
    pub fn to_cbor(&self) -> Result<Vec<u8>, SyncCodecError> {
        self.validate()?;
        encode_map(vec![
            ("server_version", Value::Text(self.server_version.clone())),
            ("max_model_version", Value::UInt(self.max_model_version)),
            ("limits", self.limits.clone().into_value()),
            (
                "vaults",
                Value::Array(self.vaults.iter().cloned().map(SessionVault::into_value).collect()),
            ),
        ])
    }

    /// Decode a deterministic CBOR response. Unknown extension fields are ignored.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed CBOR or invalid required fields.
    pub fn from_cbor(input: &[u8]) -> Result<Self, SyncCodecError> {
        let mut fields = decode_map(input)?;
        let vaults = match fields.remove("vaults") {
            Some(Value::Array(values)) => {
                values.into_iter().map(SessionVault::from_value).collect::<Result<Vec<_>, _>>()?
            }
            _ => return Err(invalid("vaults must be an array")),
        };
        let limits = SyncLimits::from_value(
            fields.remove("limits").ok_or_else(|| invalid("missing limits"))?,
        )?;
        let response = Self {
            server_version: take_text(&mut fields, "server_version")?,
            max_model_version: take_uint(&mut fields, "max_model_version")?,
            limits,
            vaults,
        };
        response.validate()?;
        Ok(response)
    }
}

fn invalid(message: impl Into<String>) -> SyncCodecError {
    SyncCodecError::Invalid(message.into())
}

fn nonempty(value: &str, key: &str) -> Result<(), SyncCodecError> {
    if value.trim().is_empty() { Err(invalid(format!("{key} must not be empty"))) } else { Ok(()) }
}

fn positive(value: u64, key: &str) -> Result<(), SyncCodecError> {
    if value == 0 { Err(invalid(format!("{key} must be positive"))) } else { Ok(()) }
}

fn valid_uuid(value: Uuid, key: &str) -> Result<(), SyncCodecError> {
    validate_uuid_v7(value).map_err(|_| invalid(format!("{key} must be UUIDv7")))
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(key, value)| (Value::Text(key.into()), value)).collect())
}

fn encode_map(entries: Vec<(&str, Value)>) -> Result<Vec<u8>, SyncCodecError> {
    cbor::encode(&map(entries)).map_err(Into::into)
}

fn decode_map(input: &[u8]) -> Result<BTreeMap<String, Value>, SyncCodecError> {
    expect_map(cbor::decode(input)?)
}

fn expect_map(value: Value) -> Result<BTreeMap<String, Value>, SyncCodecError> {
    let Value::Map(entries) = value else {
        return Err(invalid("value must be a map"));
    };
    let mut fields = BTreeMap::new();
    for (key, value) in entries {
        let Value::Text(key) = key else {
            return Err(invalid("map keys must be text"));
        };
        fields.insert(key, value);
    }
    Ok(fields)
}

fn take_text(fields: &mut BTreeMap<String, Value>, key: &str) -> Result<String, SyncCodecError> {
    match fields.remove(key) {
        Some(Value::Text(value)) => Ok(value),
        _ => Err(invalid(format!("{key} must be a text string"))),
    }
}

fn take_uint(fields: &mut BTreeMap<String, Value>, key: &str) -> Result<u64, SyncCodecError> {
    match fields.remove(key) {
        Some(Value::UInt(value)) => Ok(value),
        _ => Err(invalid(format!("{key} must be an unsigned integer"))),
    }
}

fn take_bool(fields: &mut BTreeMap<String, Value>, key: &str) -> Result<bool, SyncCodecError> {
    match fields.remove(key) {
        Some(Value::Bool(value)) => Ok(value),
        _ => Err(invalid(format!("{key} must be a boolean"))),
    }
}

fn take_uuid(fields: &mut BTreeMap<String, Value>, key: &str) -> Result<Uuid, SyncCodecError> {
    let Some(Value::Bytes(bytes)) = fields.remove(key) else {
        return Err(invalid(format!("{key} must be a 16-byte UUID")));
    };
    let bytes: [u8; 16] =
        bytes.try_into().map_err(|_| invalid(format!("{key} must be a 16-byte UUID")))?;
    let id = Uuid::from_bytes(bytes);
    valid_uuid(id, key)?;
    Ok(id)
}
