// SPDX-License-Identifier: Apache-2.0
//! K-4 sync wire messages and canonical change-feed query parameters.

use std::collections::{BTreeMap, BTreeSet};

use scoplen_model::{
    cbor::{self, Value},
    validate_uuid_v7,
};
use thiserror::Error;
use uuid::Uuid;

/// Maximum number of writes accepted in one atomic batch.
pub const MAX_SYNC_BATCH_OBJECTS: usize = 500;
/// Maximum encoded size of one write request body.
pub const MAX_SYNC_BATCH_BYTES: usize = 4 * 1024 * 1024;
/// Maximum number of retained historical versions in addition to the current version.
pub const MAX_SYNC_RETAINED_VERSIONS: usize = 20;
/// Maximum size of one opaque account-key artifact in the K-4 key-bundle codecs.
pub const MAX_SYNC_KEY_ARTIFACT_BYTES: usize = 64 * 1024;
/// Maximum number of device ARK wraps in one K-4 account-key update.
pub const MAX_SYNC_KEY_DEVICE_WRAPS: usize = 1_000;
/// Maximum encoded size of an account-key request or response body.
pub const MAX_SYNC_KEY_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Fixed Ed25519 signature size carried by an account-key update.
pub const SYNC_KEY_SIGNATURE_BYTES: usize = 64;
/// Domain separator covered by an account-key update signature.
pub const SYNC_KEYS_SIGNATURE_DOMAIN: &[u8] = b"spl-sync-keys-v1";

/// Errors at the K-4 sync wire boundary.
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

/// A content-free event delivered on the K-4 notification WebSocket.
///
/// Notifications only tell a client which follow-up action is needed. Object content is never
/// sent on this channel; a vault advancement is followed by a change-feed pull, and a pending
/// rotation is followed by key retrieval. The `device_revoked` marker is intentionally a boolean
/// until the protocol specifies a device identifier or other payload for that event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncNotification {
    /// A vault has a newer change sequence.
    VaultAdvanced { vault: Uuid, seq: u64 },
    /// A vault needs key rotation before the next sync operation.
    RotationPending { vault: Uuid },
    /// The authenticated device was revoked.
    DeviceRevoked,
}

impl SyncNotification {
    /// Validate the event fields independent of the WebSocket session.
    ///
    /// # Errors
    ///
    /// Returns an error when a vault is not `UUIDv7` or an advancement sequence is zero.
    pub fn validate(&self) -> Result<(), SyncCodecError> {
        match self {
            Self::VaultAdvanced { vault, seq } => {
                valid_uuid(*vault, "notification vault")?;
                positive(*seq, "notification sequence")
            }
            Self::RotationPending { vault } => valid_uuid(*vault, "notification vault"),
            Self::DeviceRevoked => Ok(()),
        }
    }

    /// Encode a notification as deterministic CBOR.
    ///
    /// # Errors
    ///
    /// Returns an error when event fields are invalid or deterministic CBOR encoding fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, SyncCodecError> {
        self.validate()?;
        let value = match self {
            Self::VaultAdvanced { vault, seq } => map(vec![
                ("vault", Value::Bytes(vault.as_bytes().to_vec())),
                ("seq", Value::UInt(*seq)),
            ]),
            Self::RotationPending { vault } => map(vec![
                ("rotation_pending", Value::Bool(true)),
                ("vault", Value::Bytes(vault.as_bytes().to_vec())),
            ]),
            Self::DeviceRevoked => map(vec![("device_revoked", Value::Bool(true))]),
        };
        cbor::encode(&value).map_err(Into::into)
    }

    /// Decode a deterministic CBOR notification, ignoring additive response fields.
    ///
    /// The event marker is required to be unambiguous. Known fields from a different event are
    /// rejected, while unknown extension fields are ignored as required for response messages.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed CBOR, an unknown or ambiguous event, wrong field types, an
    /// invalid UUID, or a zero advancement sequence.
    pub fn from_cbor(input: &[u8]) -> Result<Self, SyncCodecError> {
        let mut fields = decode_map(input)?;
        let device_revoked = fields.remove("device_revoked");
        let rotation_pending = fields.remove("rotation_pending");
        let seq = fields.remove("seq");
        let vault = fields.remove("vault");
        let markers = usize::from(device_revoked.is_some())
            + usize::from(rotation_pending.is_some())
            + usize::from(seq.is_some());
        if markers > 1 {
            return Err(invalid("notification event is ambiguous"));
        }
        match (device_revoked, rotation_pending, seq, vault) {
            (Some(value), None, None, None) => {
                if !decode_bool(&value, "device_revoked")? {
                    return Err(invalid("device_revoked must be true"));
                }
                Ok(Self::DeviceRevoked)
            }
            (None, Some(value), None, Some(vault)) => {
                if !decode_bool(&value, "rotation_pending")? {
                    return Err(invalid("rotation_pending must be true"));
                }
                Ok(Self::RotationPending { vault: decode_uuid(vault, "notification vault")? })
            }
            (None, None, Some(seq), Some(vault)) => Ok(Self::VaultAdvanced {
                vault: decode_uuid(vault, "notification vault")?,
                seq: decode_uint(&seq, "notification sequence")?,
            }),
            (Some(_), _, _, _) => {
                Err(invalid("device_revoked notification has extra known fields"))
            }
            (None, Some(_), _, _) => {
                Err(invalid("rotation_pending notification requires only a vault"))
            }
            (None, None, Some(_), _) => {
                Err(invalid("vault advanced notification requires a vault"))
            }
            (None, None, None, Some(_) | None) => {
                Err(invalid("notification is missing an event marker"))
            }
        }
    }
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

/// Query parameters for `GET /sync/v1/vaults/{vault}/changes`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncChangesQuery {
    /// Highest sequence already applied by the caller.
    pub after: u64,
    /// Maximum number of change entries in one page.
    pub limit: u16,
}

impl SyncChangesQuery {
    /// Validate the change-feed page size.
    ///
    /// # Errors
    ///
    /// Returns an error when `limit` is outside 1 through 1,000.
    pub fn validate(&self) -> Result<(), SyncCodecError> {
        if (1..=1_000).contains(&self.limit) {
            Ok(())
        } else {
            Err(invalid("limit must be between 1 and 1000"))
        }
    }

    /// Format the canonical query string, without a leading `?`.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid page size.
    pub fn to_query(&self) -> Result<String, SyncCodecError> {
        self.validate()?;
        Ok(format!("after={}&limit={}", self.after, self.limit))
    }

    /// Parse required canonical decimal parameters in either order.
    ///
    /// `input` is the raw query string without a leading `?`.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, duplicate, unknown, malformed, or out-of-range parameters.
    pub fn from_query(input: &str) -> Result<Self, SyncCodecError> {
        let (mut after, mut limit) = (None, None);
        for parameter in input.split('&') {
            let (key, value) =
                parameter.split_once('=').ok_or_else(|| invalid("invalid query parameter"))?;
            match key {
                "after" if after.is_none() => after = Some(canonical_decimal(value, "after")?),
                "limit" if limit.is_none() => {
                    let value = canonical_decimal(value, "limit")?;
                    limit =
                        Some(u16::try_from(value).map_err(|_| invalid("limit is out of range"))?);
                }
                "after" | "limit" => return Err(invalid("duplicate query parameter")),
                _ => return Err(invalid("unknown query parameter")),
            }
        }
        let query = Self {
            after: after.ok_or_else(|| invalid("missing after"))?,
            limit: limit.ok_or_else(|| invalid("missing limit"))?,
        };
        query.validate()?;
        Ok(query)
    }
}

/// One latest object version in a change-feed page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncChange {
    pub object_id: Uuid,
    pub seq: u64,
    /// Opaque encrypted envelope, or a deterministic CBOR organization object.
    pub payload: Vec<u8>,
    pub tombstone: bool,
    /// `None` for organization objects.
    pub signer_device_id: Option<Uuid>,
}

impl SyncChange {
    fn validate(&self) -> Result<(), SyncCodecError> {
        valid_uuid(self.object_id, "object id")?;
        positive(self.seq, "change seq")?;
        if let Some(id) = self.signer_device_id {
            valid_uuid(id, "signer device id")?;
        }
        Ok(())
    }

    fn into_value(self) -> Value {
        Value::Map(vec![
            (Value::UInt(1), Value::Bytes(self.object_id.as_bytes().to_vec())),
            (Value::UInt(2), Value::UInt(self.seq)),
            (Value::UInt(3), Value::Bytes(self.payload)),
            (Value::UInt(4), Value::Bool(self.tombstone)),
            (
                Value::UInt(5),
                self.signer_device_id
                    .map_or(Value::Null, |id| Value::Bytes(id.as_bytes().to_vec())),
            ),
        ])
    }

    fn from_value(value: Value) -> Result<Self, SyncCodecError> {
        let mut fields = expect_integer_map(value)?;
        let change = Self {
            object_id: decode_uuid(take_integer(&mut fields, 1)?, "object id")?,
            seq: decode_uint(&take_integer(&mut fields, 2)?, "change seq")?,
            payload: decode_bytes(take_integer(&mut fields, 3)?, "payload")?,
            tombstone: decode_bool(&take_integer(&mut fields, 4)?, "tombstone")?,
            signer_device_id: match take_integer(&mut fields, 5)? {
                Value::Null => None,
                value => Some(decode_uuid(value, "signer device id")?),
            },
        };
        change.validate()?;
        Ok(change)
    }
}

/// Response body for `GET /sync/v1/vaults/{vault}/changes`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncChangesResponse {
    pub changes: Vec<SyncChange>,
    pub next_cursor: u64,
    pub more: bool,
}

impl SyncChangesResponse {
    /// Validate structural page invariants independent of the request and vault snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid entries, ordering, duplicate objects, or cursor shape.
    pub fn validate(&self) -> Result<(), SyncCodecError> {
        if self.changes.len() > 1_000 {
            return Err(invalid("changes exceeds 1000 entries"));
        }
        let mut ids = BTreeSet::new();
        let mut previous_seq = 0;
        for change in &self.changes {
            change.validate()?;
            if change.seq <= previous_seq {
                return Err(invalid("changes must have strictly increasing sequence numbers"));
            }
            if !ids.insert(change.object_id) {
                return Err(invalid("duplicate change object id"));
            }
            previous_seq = change.seq;
        }
        if self.next_cursor < previous_seq {
            return Err(invalid("next_cursor precedes a returned change"));
        }
        if self.more && (self.changes.is_empty() || self.next_cursor != previous_seq) {
            return Err(invalid("non-final page cursor must equal its last change sequence"));
        }
        Ok(())
    }

    /// Validate a page against the request that produced it.
    ///
    /// The caller must separately verify that a final page cursor equals the server's snapshot
    /// sequence; that server-only value is not present in this wire message.
    ///
    /// # Errors
    ///
    /// Returns an error if the page exceeds `limit`, includes old entries, or regresses the cursor.
    pub fn validate_for_query(&self, query: &SyncChangesQuery) -> Result<(), SyncCodecError> {
        query.validate()?;
        self.validate()?;
        if self.changes.len() > usize::from(query.limit) {
            return Err(invalid("changes exceeds requested limit"));
        }
        if self.next_cursor < query.after
            || self.changes.first().is_some_and(|change| change.seq <= query.after)
        {
            return Err(invalid("change page precedes after cursor"));
        }
        Ok(())
    }

    /// Encode the page as deterministic CBOR.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid page or non-encodable CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>, SyncCodecError> {
        self.validate()?;
        encode_map(vec![
            (
                "changes",
                Value::Array(self.changes.iter().cloned().map(SyncChange::into_value).collect()),
            ),
            ("next_cursor", Value::UInt(self.next_cursor)),
            ("more", Value::Bool(self.more)),
        ])
    }

    /// Decode a deterministic CBOR page, ignoring unknown response fields.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed CBOR or invalid required fields.
    pub fn from_cbor(input: &[u8]) -> Result<Self, SyncCodecError> {
        let mut fields = decode_map(input)?;
        let changes = match fields.remove("changes") {
            Some(Value::Array(values)) => {
                values.into_iter().map(SyncChange::from_value).collect::<Result<Vec<_>, _>>()?
            }
            _ => return Err(invalid("changes must be an array")),
        };
        let response = Self {
            changes,
            next_cursor: take_uint(&mut fields, "next_cursor")?,
            more: take_bool(&mut fields, "more")?,
        };
        response.validate()?;
        Ok(response)
    }
}

/// One compare-and-swap object write in a K-4 batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncWrite {
    /// Object identifier being created or replaced.
    pub object_id: Uuid,
    /// Sequence from which the client merged, or `None` for a new object.
    pub base_seq: Option<u64>,
    /// Opaque encrypted envelope.
    pub payload: Vec<u8>,
    /// Whether this write records a tombstone.
    pub tombstone: bool,
}

impl SyncWrite {
    /// Validate the write independently of the vault's current state.
    ///
    /// # Errors
    ///
    /// Returns an error when the object id is not `UUIDv7`.
    pub fn validate(&self) -> Result<(), SyncCodecError> {
        valid_uuid(self.object_id, "write object id")
    }

    fn into_value(self) -> Value {
        Value::Map(vec![
            (Value::UInt(1), Value::Bytes(self.object_id.as_bytes().to_vec())),
            (Value::UInt(2), self.base_seq.map_or(Value::Null, Value::UInt)),
            (Value::UInt(3), Value::Bytes(self.payload)),
            (Value::UInt(4), Value::Bool(self.tombstone)),
        ])
    }

    fn from_value(value: Value) -> Result<Self, SyncCodecError> {
        let mut fields = expect_integer_map_with(value, "write")?;
        reject_unknown_integer_fields(&fields, &[1, 2, 3, 4], "write")?;
        let base_seq = match take_integer(&mut fields, 2)? {
            Value::Null => None,
            Value::UInt(value) => Some(value),
            _ => return Err(invalid("write base must be an unsigned integer or null")),
        };
        let write = Self {
            object_id: decode_uuid(take_integer(&mut fields, 1)?, "write object id")?,
            base_seq,
            payload: decode_bytes(take_integer(&mut fields, 3)?, "write payload")?,
            tombstone: decode_bool(&take_integer(&mut fields, 4)?, "write tombstone")?,
        };
        write.validate()?;
        Ok(write)
    }
}

/// Request body for `POST /sync/v1/vaults/{vault}/objects`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncWriteBatch {
    /// Writes are applied atomically and retain their input order on the wire.
    pub writes: Vec<SyncWrite>,
}

impl SyncWriteBatch {
    /// Validate write count, object uniqueness, and each write's shape.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or oversized batch, duplicate ids, or an invalid write.
    pub fn validate(&self) -> Result<(), SyncCodecError> {
        if self.writes.is_empty() {
            return Err(invalid("write batch must not be empty"));
        }
        if self.writes.len() > MAX_SYNC_BATCH_OBJECTS {
            return Err(invalid("write batch exceeds 500 objects"));
        }
        let mut ids = BTreeSet::new();
        for write in &self.writes {
            write.validate()?;
            if !ids.insert(write.object_id) {
                return Err(invalid("duplicate write object id"));
            }
        }
        Ok(())
    }

    /// Encode the batch as a direct deterministic CBOR array.
    ///
    /// # Errors
    ///
    /// Returns an error when validation fails or the encoded body exceeds 4 MiB.
    pub fn to_cbor(&self) -> Result<Vec<u8>, SyncCodecError> {
        self.validate()?;
        let encoded = cbor::encode(&Value::Array(
            self.writes.iter().cloned().map(SyncWrite::into_value).collect(),
        ))?;
        if encoded.len() > MAX_SYNC_BATCH_BYTES {
            return Err(invalid("write batch exceeds 4 MiB"));
        }
        Ok(encoded)
    }

    /// Decode a direct deterministic CBOR write array.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or non-canonical CBOR, invalid entries, or batch limits.
    pub fn from_cbor(input: &[u8]) -> Result<Self, SyncCodecError> {
        if input.len() > MAX_SYNC_BATCH_BYTES {
            return Err(invalid("write batch exceeds 4 MiB"));
        }
        let Value::Array(values) = cbor::decode(input)? else {
            return Err(invalid("write batch must be an array"));
        };
        if values.len() > MAX_SYNC_BATCH_OBJECTS {
            return Err(invalid("write batch exceeds 500 objects"));
        }
        let batch = Self {
            writes: values.into_iter().map(SyncWrite::from_value).collect::<Result<Vec<_>, _>>()?,
        };
        batch.validate()?;
        Ok(batch)
    }
}

/// A sequence assignment returned for one accepted write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncWriteAssignment {
    pub object_id: Uuid,
    pub seq: u64,
}

impl SyncWriteAssignment {
    fn validate(&self) -> Result<(), SyncCodecError> {
        valid_uuid(self.object_id, "assignment object id")?;
        positive(self.seq, "assignment sequence")
    }

    fn into_value(self) -> Value {
        Value::Map(vec![
            (Value::UInt(1), Value::Bytes(self.object_id.as_bytes().to_vec())),
            (Value::UInt(2), Value::UInt(self.seq)),
        ])
    }

    fn from_value(value: Value) -> Result<Self, SyncCodecError> {
        let mut fields = expect_integer_map_with(value, "assignment")?;
        reject_unknown_integer_fields(&fields, &[1, 2], "assignment")?;
        let assignment = Self {
            object_id: decode_uuid(take_integer(&mut fields, 1)?, "assignment object id")?,
            seq: decode_uint(&take_integer(&mut fields, 2)?, "assignment sequence")?,
        };
        assignment.validate()?;
        Ok(assignment)
    }
}

/// Successful response body for an atomic write batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncWriteBatchResponse {
    /// Assignments correspond to the request writes in input order.
    pub assignments: Vec<SyncWriteAssignment>,
}

impl SyncWriteBatchResponse {
    /// Validate assignment count, object uniqueness, and sequence ordering.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or oversized response, duplicate ids, invalid UUIDs, or
    /// non-increasing sequence numbers.
    pub fn validate(&self) -> Result<(), SyncCodecError> {
        if self.assignments.is_empty() {
            return Err(invalid("write response must not be empty"));
        }
        if self.assignments.len() > MAX_SYNC_BATCH_OBJECTS {
            return Err(invalid("write response exceeds 500 assignments"));
        }
        let mut ids = BTreeSet::new();
        let mut previous_seq = 0;
        for assignment in &self.assignments {
            assignment.validate()?;
            if !ids.insert(assignment.object_id) {
                return Err(invalid("duplicate assignment object id"));
            }
            if assignment.seq <= previous_seq {
                return Err(invalid("assignments must have strictly increasing sequences"));
            }
            previous_seq = assignment.seq;
        }
        Ok(())
    }

    /// Validate that assignments correspond to a request in input order.
    ///
    /// # Errors
    ///
    /// Returns an error when either value is invalid or the assignment count/order differs.
    pub fn validate_for_batch(&self, batch: &SyncWriteBatch) -> Result<(), SyncCodecError> {
        batch.validate()?;
        self.validate()?;
        if self.assignments.len() != batch.writes.len() {
            return Err(invalid("assignment count does not match write batch"));
        }
        for (assignment, write) in self.assignments.iter().zip(&batch.writes) {
            if assignment.object_id != write.object_id {
                return Err(invalid("assignment order does not match write batch"));
            }
        }
        Ok(())
    }

    /// Encode the assignments as a direct deterministic CBOR array.
    ///
    /// # Errors
    ///
    /// Returns an error when the response is invalid or cannot be encoded.
    pub fn to_cbor(&self) -> Result<Vec<u8>, SyncCodecError> {
        self.validate()?;
        cbor::encode(&Value::Array(
            self.assignments.iter().cloned().map(SyncWriteAssignment::into_value).collect(),
        ))
        .map_err(Into::into)
    }

    /// Decode a direct deterministic CBOR assignment array.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or non-canonical CBOR, invalid entries, or response limits.
    pub fn from_cbor(input: &[u8]) -> Result<Self, SyncCodecError> {
        let Value::Array(values) = cbor::decode(input)? else {
            return Err(invalid("write response must be an array"));
        };
        if values.len() > MAX_SYNC_BATCH_OBJECTS {
            return Err(invalid("write response exceeds 500 assignments"));
        }
        let response = Self {
            assignments: values
                .into_iter()
                .map(SyncWriteAssignment::from_value)
                .collect::<Result<Vec<_>, _>>()?,
        };
        response.validate()?;
        Ok(response)
    }
}

/// Alias matching the endpoint's request terminology.
pub type SyncWriteRequest = SyncWriteBatch;
/// Alias matching the endpoint's response terminology.
pub type SyncWriteResponse = SyncWriteBatchResponse;

/// A device cursor acknowledgement request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncAckRequest {
    pub cursor: u64,
}

impl SyncAckRequest {
    /// Encode the acknowledgement as `{cursor}`.
    ///
    /// # Errors
    ///
    /// Returns an error if deterministic CBOR encoding fails.
    pub fn to_cbor(self) -> Result<Vec<u8>, SyncCodecError> {
        encode_map(vec![("cursor", Value::UInt(self.cursor))])
    }

    /// Decode a strict acknowledgement request.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed CBOR, a missing cursor, or an unknown field.
    pub fn from_cbor(input: &[u8]) -> Result<Self, SyncCodecError> {
        let mut fields = decode_map(input)?;
        let request = Self { cursor: take_uint(&mut fields, "cursor")? };
        if !fields.is_empty() {
            return Err(invalid("unknown acknowledgement request field"));
        }
        Ok(request)
    }
}

/// The stored maximum cursor returned by an acknowledgement endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncAckResponse {
    pub cursor: u64,
}

impl SyncAckResponse {
    /// Encode the acknowledgement response as `{cursor}`.
    ///
    /// # Errors
    ///
    /// Returns an error if deterministic CBOR encoding fails.
    pub fn to_cbor(self) -> Result<Vec<u8>, SyncCodecError> {
        encode_map(vec![("cursor", Value::UInt(self.cursor))])
    }

    /// Decode an acknowledgement response, ignoring additive response fields.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed CBOR, a missing cursor, or a wrong cursor type.
    pub fn from_cbor(input: &[u8]) -> Result<Self, SyncCodecError> {
        let mut fields = decode_map(input)?;
        Ok(Self { cursor: take_uint(&mut fields, "cursor")? })
    }
}

/// Alias for callers that use the short endpoint name.
pub type SyncAck = SyncAckRequest;

/// A full-reconciliation page returned by `GET /sync/v1/vaults/{vault}/snapshot`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncSnapshotResponse {
    pub objects: Vec<SyncChange>,
    pub next_cursor: u64,
    pub more: bool,
}

impl SyncSnapshotResponse {
    /// Validate object ordering, uniqueness, and cursor invariants.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid entries, ordering, duplicates, or cursor rules.
    pub fn validate(&self) -> Result<(), SyncCodecError> {
        validate_page(&self.objects, self.next_cursor, self.more, "snapshot objects")
    }

    /// Validate a snapshot page against its canonical query parameters.
    ///
    /// # Errors
    ///
    /// Returns an error when the query or page violates the pagination contract.
    pub fn validate_for_query(&self, query: &SyncChangesQuery) -> Result<(), SyncCodecError> {
        query.validate()?;
        self.validate()?;
        if self.objects.len() > usize::from(query.limit) {
            return Err(invalid("snapshot exceeds requested limit"));
        }
        if self.next_cursor < query.after
            || self.objects.first().is_some_and(|object| object.seq <= query.after)
        {
            return Err(invalid("snapshot precedes after cursor"));
        }
        Ok(())
    }

    /// Encode the snapshot page as `{objects, next_cursor, more}`.
    ///
    /// # Errors
    ///
    /// Returns an error when validation fails or deterministic CBOR encoding fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, SyncCodecError> {
        self.validate()?;
        encode_map(vec![
            (
                "objects",
                Value::Array(self.objects.iter().cloned().map(SyncChange::into_value).collect()),
            ),
            ("next_cursor", Value::UInt(self.next_cursor)),
            ("more", Value::Bool(self.more)),
        ])
    }

    /// Decode a snapshot page, ignoring additive response fields.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed CBOR, missing fields, invalid entries, or cursor rules.
    pub fn from_cbor(input: &[u8]) -> Result<Self, SyncCodecError> {
        let mut fields = decode_map(input)?;
        let objects = match fields.remove("objects") {
            Some(Value::Array(values)) => {
                values.into_iter().map(SyncChange::from_value).collect::<Result<Vec<_>, _>>()?
            }
            _ => return Err(invalid("objects must be an array")),
        };
        let response = Self {
            objects,
            next_cursor: take_uint(&mut fields, "next_cursor")?,
            more: take_bool(&mut fields, "more")?,
        };
        response.validate()?;
        Ok(response)
    }
}

/// A bounded current-and-history response for one object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncVersionsResponse {
    pub versions: Vec<SyncChange>,
}

impl SyncVersionsResponse {
    /// Validate the bounded ascending version list.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, mixed-object, or non-ascending history.
    pub fn validate(&self) -> Result<(), SyncCodecError> {
        if self.versions.is_empty() {
            return Err(invalid("versions must not be empty"));
        }
        if self.versions.len() > MAX_SYNC_RETAINED_VERSIONS + 1 {
            return Err(invalid("versions exceeds current plus 20 retained entries"));
        }
        let object_id = self.versions[0].object_id;
        let mut previous_seq = 0;
        for version in &self.versions {
            version.validate()?;
            if version.object_id != object_id {
                return Err(invalid("versions must contain one object id"));
            }
            if version.seq <= previous_seq {
                return Err(invalid("versions must have strictly increasing sequences"));
            }
            previous_seq = version.seq;
        }
        Ok(())
    }

    /// Validate that every history entry belongs to the path object.
    ///
    /// # Errors
    ///
    /// Returns an error when the path id is invalid or an entry has a different object id.
    pub fn validate_for_object(&self, object_id: Uuid) -> Result<(), SyncCodecError> {
        valid_uuid(object_id, "version object id")?;
        self.validate()?;
        if self.versions.iter().any(|version| version.object_id != object_id) {
            return Err(invalid("version object id does not match path"));
        }
        Ok(())
    }

    /// Encode the history as `{versions}`.
    ///
    /// # Errors
    ///
    /// Returns an error when validation fails or deterministic CBOR encoding fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, SyncCodecError> {
        self.validate()?;
        encode_map(vec![(
            "versions",
            Value::Array(self.versions.iter().cloned().map(SyncChange::into_value).collect()),
        )])
    }

    /// Decode a history response, ignoring additive response fields.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed CBOR, missing fields, invalid entries, or history limits.
    pub fn from_cbor(input: &[u8]) -> Result<Self, SyncCodecError> {
        let mut fields = decode_map(input)?;
        let versions = match fields.remove("versions") {
            Some(Value::Array(values)) => {
                values.into_iter().map(SyncChange::from_value).collect::<Result<Vec<_>, _>>()?
            }
            _ => return Err(invalid("versions must be an array")),
        };
        let response = Self { versions };
        response.validate()?;
        Ok(response)
    }

    /// Decode and validate a history response against its path object id.
    ///
    /// # Errors
    ///
    /// Returns an error when decoding fails or an entry does not match the path id.
    pub fn from_cbor_for_object(input: &[u8], object_id: Uuid) -> Result<Self, SyncCodecError> {
        let response = Self::from_cbor(input)?;
        response.validate_for_object(object_id)?;
        Ok(response)
    }
}

/// The account key bundle returned by `GET /sync/v1/keys`.
///
/// Key artifacts are intentionally opaque to K-4. Their cryptographic structure is owned by
/// `scoplen-crypto`; this codec enforces only the transport limits and ordering rules from
/// `07-sync-protocol.md` §8.1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncAccountKeyBundle {
    /// Positive monotonic bundle revision.
    pub revision: u64,
    /// The authenticated device's ARK wrapping.
    pub wrapped_ark: Vec<u8>,
    /// ARK-encrypted account Ed25519 private key.
    pub account_signing_key: Vec<u8>,
    /// ARK-encrypted account X25519 private key.
    pub account_kem_key: Vec<u8>,
    /// Versioned recovery-wrapped ARK blob.
    pub recovery_blob: Vec<u8>,
    /// Signed device certificates, sorted lexicographically by opaque bytes.
    pub certificates: Vec<Vec<u8>>,
    /// Signed device revocation statements, sorted lexicographically by opaque bytes.
    pub revocations: Vec<Vec<u8>>,
}

impl SyncAccountKeyBundle {
    /// Validate the bundle fields, artifact limits, and certificate ordering.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero revision, empty or oversized artifacts, or unsorted arrays.
    pub fn validate(&self) -> Result<(), SyncCodecError> {
        positive(self.revision, "key bundle revision")?;
        validate_key_artifact(&self.wrapped_ark, "wrapped_ark")?;
        validate_key_artifact(&self.account_signing_key, "account_signing_key")?;
        validate_key_artifact(&self.account_kem_key, "account_kem_key")?;
        validate_key_artifact(&self.recovery_blob, "recovery_blob")?;
        validate_sorted_artifacts(&self.certificates, "certificates")?;
        validate_sorted_artifacts(&self.revocations, "revocations")?;
        Ok(())
    }

    /// Encode the bundle as a deterministic CBOR response map.
    ///
    /// # Errors
    ///
    /// Returns an error when validation fails, the encoded body exceeds the K-4 limit, or CBOR
    /// encoding fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, SyncCodecError> {
        self.validate()?;
        let encoded = encode_map(vec![
            ("revision", Value::UInt(self.revision)),
            ("wrapped_ark", Value::Bytes(self.wrapped_ark.clone())),
            ("account_signing_key", Value::Bytes(self.account_signing_key.clone())),
            ("account_kem_key", Value::Bytes(self.account_kem_key.clone())),
            ("recovery_blob", Value::Bytes(self.recovery_blob.clone())),
            (
                "certificates",
                Value::Array(self.certificates.iter().cloned().map(Value::Bytes).collect()),
            ),
            (
                "revocations",
                Value::Array(self.revocations.iter().cloned().map(Value::Bytes).collect()),
            ),
        ])?;
        enforce_key_body_limit(&encoded)?;
        Ok(encoded)
    }

    /// Decode a deterministic CBOR response map.
    ///
    /// Unknown response fields are ignored for forward compatibility. Known fields with the
    /// wrong type, missing fields, invalid artifacts, or invalid ordering are rejected.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, oversized, or invalid CBOR.
    pub fn from_cbor(input: &[u8]) -> Result<Self, SyncCodecError> {
        enforce_key_body_limit(input)?;
        let mut fields = decode_map(input)?;
        let certificates = take_key_artifacts(&mut fields, "certificates")?;
        let revocations = take_key_artifacts(&mut fields, "revocations")?;
        let bundle = Self {
            revision: take_uint(&mut fields, "revision")?,
            wrapped_ark: take_key_artifact(&mut fields, "wrapped_ark")?,
            account_signing_key: take_key_artifact(&mut fields, "account_signing_key")?,
            account_kem_key: take_key_artifact(&mut fields, "account_kem_key")?,
            recovery_blob: take_key_artifact(&mut fields, "recovery_blob")?,
            certificates,
            revocations,
        };
        bundle.validate()?;
        Ok(bundle)
    }
}

/// One device-specific ARK wrapping in a `PUT /sync/v1/keys` update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncAccountDeviceWrap {
    /// Enrolled device receiving this wrapping.
    pub device_id: Uuid,
    /// Opaque ARK wrapping for the device.
    pub wrapped_ark: Vec<u8>,
}

impl SyncAccountDeviceWrap {
    fn validate(&self) -> Result<(), SyncCodecError> {
        valid_uuid(self.device_id, "device wrap device id")?;
        validate_key_artifact(&self.wrapped_ark, "device wrap wrapped_ark")
    }

    fn into_value(self) -> Value {
        map(vec![
            ("device_id", Value::Bytes(self.device_id.as_bytes().to_vec())),
            ("wrapped_ark", Value::Bytes(self.wrapped_ark)),
        ])
    }

    fn from_value(value: Value) -> Result<Self, SyncCodecError> {
        let mut fields = expect_map(value)?;
        let wrap = Self {
            device_id: take_uuid(&mut fields, "device_id")?,
            wrapped_ark: take_key_artifact(&mut fields, "wrapped_ark")?,
        };
        if !fields.is_empty() {
            return Err(invalid("unknown device wrap field"));
        }
        wrap.validate()?;
        Ok(wrap)
    }
}

/// A signed account-key rotation published with `PUT /sync/v1/keys`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncAccountKeyBundleUpdate {
    /// Positive monotonic bundle revision.
    pub revision: u64,
    /// One ARK wrapping for every enrolled, unrevoked device.
    pub device_wraps: Vec<SyncAccountDeviceWrap>,
    /// ARK-encrypted account Ed25519 private key.
    pub account_signing_key: Vec<u8>,
    /// ARK-encrypted account X25519 private key.
    pub account_kem_key: Vec<u8>,
    /// Versioned recovery-wrapped ARK blob.
    pub recovery_blob: Vec<u8>,
    /// Fixed-width Ed25519 signature over [`Self::signature_input`].
    pub signature: Vec<u8>,
}

impl SyncAccountKeyBundleUpdate {
    /// Validate fields other than the signature itself.
    fn validate_unsigned(&self) -> Result<(), SyncCodecError> {
        positive(self.revision, "key bundle revision")?;
        if self.device_wraps.is_empty() {
            return Err(invalid("device_wraps must not be empty"));
        }
        if self.device_wraps.len() > MAX_SYNC_KEY_DEVICE_WRAPS {
            return Err(invalid("device_wraps exceeds 1000 entries"));
        }
        for wrap in &self.device_wraps {
            wrap.validate()?;
        }
        for pair in self.device_wraps.windows(2) {
            if pair[0].device_id.as_bytes() >= pair[1].device_id.as_bytes() {
                return Err(invalid("device_wraps must be strictly sorted by device id"));
            }
        }
        validate_key_artifact(&self.account_signing_key, "account_signing_key")?;
        validate_key_artifact(&self.account_kem_key, "account_kem_key")?;
        validate_key_artifact(&self.recovery_blob, "recovery_blob")?;
        Ok(())
    }

    /// Validate every request field, including the fixed-width Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, empty, oversized, unsorted, or malformed fields.
    pub fn validate(&self) -> Result<(), SyncCodecError> {
        self.validate_unsigned()?;
        if self.signature.len() != SYNC_KEY_SIGNATURE_BYTES {
            return Err(invalid("signature must be exactly 64 bytes"));
        }
        Ok(())
    }

    /// Validate that this update is the next revision after `current`.
    ///
    /// This helper covers the monotonic part of the endpoint contract; the server separately
    /// handles exact replay by comparing all fields and signature bytes with its stored revision.
    ///
    /// # Errors
    ///
    /// Returns an error when the update is not exactly `current + 1` or the current revision is
    /// already at the unsigned-integer maximum.
    pub fn validate_next_revision(&self, current: u64) -> Result<(), SyncCodecError> {
        self.validate()?;
        let expected = current.checked_add(1).ok_or_else(|| invalid("revision cannot advance"))?;
        if self.revision != expected {
            return Err(invalid("revision must be exactly one greater than current"));
        }
        Ok(())
    }

    /// Encode the request without its signature field for signing and verification.
    ///
    /// The returned bytes are the deterministic CBOR representation of every request field
    /// except `signature`.
    ///
    /// # Errors
    ///
    /// Returns an error when unsigned fields are invalid or CBOR encoding fails.
    pub fn unsigned_cbor(&self) -> Result<Vec<u8>, SyncCodecError> {
        self.validate_unsigned()?;
        let encoded = encode_key_bundle_update(self, false)?;
        enforce_key_body_limit(&encoded)?;
        Ok(encoded)
    }

    /// Return the exact bytes covered by the account signing key.
    ///
    /// The format is `ASCII("spl-sync-keys-v1") || unsigned_cbor()` with no length prefix.
    ///
    /// # Errors
    ///
    /// Returns an error when unsigned fields are invalid or CBOR encoding fails.
    pub fn signature_input(&self) -> Result<Vec<u8>, SyncCodecError> {
        let unsigned = self.unsigned_cbor()?;
        let mut input = Vec::with_capacity(SYNC_KEYS_SIGNATURE_DOMAIN.len() + unsigned.len());
        input.extend_from_slice(SYNC_KEYS_SIGNATURE_DOMAIN);
        input.extend_from_slice(&unsigned);
        Ok(input)
    }

    /// Encode the complete signed update as a deterministic CBOR request map.
    ///
    /// # Errors
    ///
    /// Returns an error when validation fails, the encoded body exceeds 4 MiB, or CBOR encoding
    /// fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, SyncCodecError> {
        self.validate()?;
        let encoded = encode_key_bundle_update(self, true)?;
        enforce_key_body_limit(&encoded)?;
        Ok(encoded)
    }

    /// Decode a strict deterministic CBOR update request. Unknown fields are rejected.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, oversized, or invalid CBOR.
    pub fn from_cbor(input: &[u8]) -> Result<Self, SyncCodecError> {
        enforce_key_body_limit(input)?;
        let mut fields = decode_map(input)?;
        let device_wraps = match fields.remove("device_wraps") {
            Some(Value::Array(values)) => values
                .into_iter()
                .map(SyncAccountDeviceWrap::from_value)
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err(invalid("device_wraps must be an array")),
        };
        let update = Self {
            revision: take_uint(&mut fields, "revision")?,
            device_wraps,
            account_signing_key: take_key_artifact(&mut fields, "account_signing_key")?,
            account_kem_key: take_key_artifact(&mut fields, "account_kem_key")?,
            recovery_blob: take_key_artifact(&mut fields, "recovery_blob")?,
            signature: take_exact_bytes(&mut fields, "signature", SYNC_KEY_SIGNATURE_BYTES)?,
        };
        if !fields.is_empty() {
            return Err(invalid("unknown account key update field"));
        }
        update.validate()?;
        Ok(update)
    }
}

/// Successful response from `PUT /sync/v1/keys`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncAccountKeyBundlePutResponse {
    /// Revision stored by the server.
    pub revision: u64,
}

impl SyncAccountKeyBundlePutResponse {
    /// Validate the returned revision.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero revision.
    pub fn validate(self) -> Result<(), SyncCodecError> {
        positive(self.revision, "key bundle revision")
    }

    /// Encode the successful response as `{revision}`.
    ///
    /// # Errors
    ///
    /// Returns an error when the revision is invalid or CBOR encoding fails.
    pub fn to_cbor(self) -> Result<Vec<u8>, SyncCodecError> {
        self.validate()?;
        let encoded = encode_map(vec![("revision", Value::UInt(self.revision))])?;
        enforce_key_body_limit(&encoded)?;
        Ok(encoded)
    }

    /// Decode the response, ignoring additive extension fields.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or invalid CBOR.
    pub fn from_cbor(input: &[u8]) -> Result<Self, SyncCodecError> {
        enforce_key_body_limit(input)?;
        let mut fields = decode_map(input)?;
        let response = Self { revision: take_uint(&mut fields, "revision")? };
        response.validate()?;
        Ok(response)
    }
}

/// Endpoint-oriented aliases for consumers that call the resource simply `keys`.
pub type SyncKeysResponse = SyncAccountKeyBundle;
/// Endpoint-oriented alias for a key-bundle update request.
pub type SyncKeysUpdate = SyncAccountKeyBundleUpdate;
/// Endpoint-oriented alias for a successful key-bundle update response.
pub type SyncKeysUpdateResponse = SyncAccountKeyBundlePutResponse;
/// Alias for the nested device wrap type.
pub type SyncKeysDeviceWrap = SyncAccountDeviceWrap;

/// Build the account-key signature input from a signed update.
///
/// This free function mirrors [`SyncAccountKeyBundleUpdate::signature_input`] for consumers that
/// prefer a functional helper at the HTTP adapter boundary.
///
/// # Errors
///
/// Returns an error when the update's unsigned fields are invalid or cannot be encoded.
pub fn sync_keys_signature_input(
    update: &SyncAccountKeyBundleUpdate,
) -> Result<Vec<u8>, SyncCodecError> {
    update.signature_input()
}

fn validate_page(
    entries: &[SyncChange],
    next_cursor: u64,
    more: bool,
    label: &str,
) -> Result<(), SyncCodecError> {
    if entries.len() > 1_000 {
        return Err(invalid(format!("{label} exceeds 1000 entries")));
    }
    let mut ids = BTreeSet::new();
    let mut previous_seq = 0;
    for entry in entries {
        entry.validate()?;
        if entry.seq <= previous_seq {
            return Err(invalid(format!("{label} must have strictly increasing sequence numbers")));
        }
        if !ids.insert(entry.object_id) {
            return Err(invalid(format!("duplicate {label} object id")));
        }
        previous_seq = entry.seq;
    }
    if next_cursor < previous_seq {
        return Err(invalid(format!("{label} cursor precedes a returned entry")));
    }
    if more && (entries.is_empty() || next_cursor != previous_seq) {
        return Err(invalid(format!("non-final {label} cursor must equal its last entry")));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> SyncCodecError {
    SyncCodecError::Invalid(message.into())
}

fn validate_key_artifact(value: &[u8], key: &str) -> Result<(), SyncCodecError> {
    if value.is_empty() {
        return Err(invalid(format!("{key} must not be empty")));
    }
    if value.len() > MAX_SYNC_KEY_ARTIFACT_BYTES {
        return Err(invalid(format!("{key} exceeds {MAX_SYNC_KEY_ARTIFACT_BYTES} bytes")));
    }
    Ok(())
}

fn validate_sorted_artifacts(values: &[Vec<u8>], key: &str) -> Result<(), SyncCodecError> {
    if values.windows(2).any(|pair| pair[0].as_slice() > pair[1].as_slice()) {
        return Err(invalid(format!("{key} must be sorted lexicographically")));
    }
    for value in values {
        validate_key_artifact(value, key)?;
    }
    Ok(())
}

fn enforce_key_body_limit(input: &[u8]) -> Result<(), SyncCodecError> {
    if input.len() > MAX_SYNC_KEY_BODY_BYTES {
        return Err(invalid(format!("key bundle body exceeds {MAX_SYNC_KEY_BODY_BYTES} bytes")));
    }
    Ok(())
}

fn take_key_artifact(
    fields: &mut BTreeMap<String, Value>,
    key: &str,
) -> Result<Vec<u8>, SyncCodecError> {
    let value = match fields.remove(key) {
        Some(Value::Bytes(value)) => value,
        Some(_) => return Err(invalid(format!("{key} must be a byte string"))),
        None => return Err(invalid(format!("missing {key}"))),
    };
    validate_key_artifact(&value, key)?;
    Ok(value)
}

fn take_exact_bytes(
    fields: &mut BTreeMap<String, Value>,
    key: &str,
    expected: usize,
) -> Result<Vec<u8>, SyncCodecError> {
    let value = match fields.remove(key) {
        Some(Value::Bytes(value)) => value,
        Some(_) => return Err(invalid(format!("{key} must be a byte string"))),
        None => return Err(invalid(format!("missing {key}"))),
    };
    if value.len() != expected {
        return Err(invalid(format!("{key} must be exactly {expected} bytes")));
    }
    Ok(value)
}

fn take_key_artifacts(
    fields: &mut BTreeMap<String, Value>,
    key: &str,
) -> Result<Vec<Vec<u8>>, SyncCodecError> {
    let values = match fields.remove(key) {
        Some(Value::Array(values)) => values,
        Some(_) => return Err(invalid(format!("{key} must be an array"))),
        None => return Err(invalid(format!("missing {key}"))),
    };
    let artifacts = values
        .into_iter()
        .map(|value| match value {
            Value::Bytes(value) => {
                validate_key_artifact(&value, key)?;
                Ok(value)
            }
            _ => Err(invalid(format!("{key} entries must be byte strings"))),
        })
        .collect::<Result<Vec<_>, SyncCodecError>>()?;
    validate_sorted_artifacts(&artifacts, key)?;
    Ok(artifacts)
}

fn encode_key_bundle_update(
    update: &SyncAccountKeyBundleUpdate,
    include_signature: bool,
) -> Result<Vec<u8>, SyncCodecError> {
    let mut entries = vec![
        ("revision", Value::UInt(update.revision)),
        (
            "device_wraps",
            Value::Array(
                update
                    .device_wraps
                    .iter()
                    .cloned()
                    .map(SyncAccountDeviceWrap::into_value)
                    .collect(),
            ),
        ),
        ("account_signing_key", Value::Bytes(update.account_signing_key.clone())),
        ("account_kem_key", Value::Bytes(update.account_kem_key.clone())),
        ("recovery_blob", Value::Bytes(update.recovery_blob.clone())),
    ];
    if include_signature {
        entries.push(("signature", Value::Bytes(update.signature.clone())));
    }
    encode_map(entries)
}

fn canonical_decimal(value: &str, key: &str) -> Result<u64, SyncCodecError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid(format!("{key} must be canonical decimal")));
    }
    value.parse().map_err(|_| invalid(format!("{key} is out of range")))
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

fn expect_integer_map(value: Value) -> Result<BTreeMap<u64, Value>, SyncCodecError> {
    expect_integer_map_with(value, "change")
}

fn expect_integer_map_with(
    value: Value,
    label: &str,
) -> Result<BTreeMap<u64, Value>, SyncCodecError> {
    let Value::Map(entries) = value else {
        return Err(invalid(format!("{label} must be a map")));
    };
    let mut fields = BTreeMap::new();
    for (key, value) in entries {
        let Value::UInt(key) = key else {
            return Err(invalid(format!("{label} map keys must be unsigned integers")));
        };
        fields.insert(key, value);
    }
    Ok(fields)
}

fn reject_unknown_integer_fields(
    fields: &BTreeMap<u64, Value>,
    allowed: &[u64],
    label: &str,
) -> Result<(), SyncCodecError> {
    if fields.keys().any(|key| !allowed.contains(key)) {
        return Err(invalid(format!("unknown {label} field")));
    }
    Ok(())
}

fn take_integer(fields: &mut BTreeMap<u64, Value>, key: u64) -> Result<Value, SyncCodecError> {
    fields.remove(&key).ok_or_else(|| invalid(format!("missing change field {key}")))
}

fn decode_uint(value: &Value, key: &str) -> Result<u64, SyncCodecError> {
    match value {
        Value::UInt(value) => Ok(*value),
        _ => Err(invalid(format!("{key} must be an unsigned integer"))),
    }
}

fn decode_bytes(value: Value, key: &str) -> Result<Vec<u8>, SyncCodecError> {
    match value {
        Value::Bytes(value) => Ok(value),
        _ => Err(invalid(format!("{key} must be a byte string"))),
    }
}

fn decode_bool(value: &Value, key: &str) -> Result<bool, SyncCodecError> {
    match value {
        Value::Bool(value) => Ok(*value),
        _ => Err(invalid(format!("{key} must be a boolean"))),
    }
}

fn decode_uuid(value: Value, key: &str) -> Result<Uuid, SyncCodecError> {
    let Value::Bytes(bytes) = value else {
        return Err(invalid(format!("{key} must be a 16-byte UUID")));
    };
    let bytes: [u8; 16] =
        bytes.try_into().map_err(|_| invalid(format!("{key} must be a 16-byte UUID")))?;
    let id = Uuid::from_bytes(bytes);
    valid_uuid(id, key)?;
    Ok(id)
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
    decode_uuid(fields.remove(key).ok_or_else(|| invalid(format!("missing {key}")))?, key)
}
