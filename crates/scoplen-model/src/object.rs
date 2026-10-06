// SPDX-License-Identifier: Apache-2.0
//! The deterministic replicated object envelope from contract K-1.

#![allow(clippy::doc_markdown, clippy::missing_errors_doc, clippy::must_use_candidate)]

use std::{collections::BTreeMap, fmt};

use thiserror::Error;
use uuid::Uuid;

use crate::{cbor, clock, clock::Hlc};

/// Maximum encoded size of one object before encryption.
pub const MAX_OBJECT_BYTES: usize = 256 * 1024;
/// Maximum number of field paths in one object or entries in one map field.
pub const MAX_MAP_ENTRIES: usize = 4_096;
/// Maximum UTF-8 byte length of an ordinary text field.
pub const MAX_TEXT_BYTES: usize = 16 * 1024;
/// Maximum number of bytes in a workspace layout field.
pub const MAX_WORKSPACE_LAYOUT_BYTES: usize = 64 * 1024;
/// Schema version implemented by every type currently in the registry.
pub const CURRENT_SCHEMA_VERSION: u64 = 1;

/// The stable type number carried in an object envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectType(u64);

impl ObjectType {
    /// Host object.
    pub const HOST: Self = Self(1);
    /// Access profile object.
    pub const ACCESS_PROFILE: Self = Self(2);
    /// Credential object.
    pub const CREDENTIAL: Self = Self(3);
    /// Route object.
    pub const ROUTE: Self = Self(4);
    /// Host group object.
    pub const HOST_GROUP: Self = Self(5);
    /// Trust record object.
    pub const TRUST_RECORD: Self = Self(6);
    /// Snippet object.
    pub const SNIPPET: Self = Self(7);
    /// Forward object.
    pub const FORWARD: Self = Self(8);
    /// Workspace object.
    pub const WORKSPACE: Self = Self(9);
    /// Preference object.
    pub const PREFERENCE: Self = Self(10);
    /// Gateway network object.
    pub const GATEWAY_NETWORK: Self = Self(11);

    /// Create a type from its wire number. Zero is reserved and rejected.
    pub const fn from_wire(value: u64) -> Result<Self, ModelError> {
        if value == 0 { Err(ModelError::InvalidType(value)) } else { Ok(Self(value)) }
    }

    /// Return the type number written to CBOR.
    pub const fn to_wire(self) -> u64 {
        self.0
    }

    /// Return whether this number is in the registry known by this crate.
    pub const fn is_known(self) -> bool {
        self.0 >= Self::HOST.0 && self.0 <= Self::GATEWAY_NETWORK.0
    }
}

impl fmt::Display for ObjectType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match *self {
            Self::HOST => "Host",
            Self::ACCESS_PROFILE => "AccessProfile",
            Self::CREDENTIAL => "Credential",
            Self::ROUTE => "Route",
            Self::HOST_GROUP => "HostGroup",
            Self::TRUST_RECORD => "TrustRecord",
            Self::SNIPPET => "Snippet",
            Self::FORWARD => "Forward",
            Self::WORKSPACE => "Workspace",
            Self::PREFERENCE => "Preference",
            Self::GATEWAY_NETWORK => "GatewayNetwork",
            _ => "Unknown",
        })
    }
}

/// A field path, either a scalar field number or one decomposed map entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FieldPath {
    /// A scalar field.
    Field(u64),
    /// A single entry of a map-valued field.
    MapEntry { field: u64, key: MapKey },
}

impl FieldPath {
    /// Construct a scalar path and reject field number zero.
    pub const fn field(field: u64) -> Result<Self, ModelError> {
        if field == 0 { Err(ModelError::InvalidFieldPath) } else { Ok(Self::Field(field)) }
    }

    /// Construct a map-entry path and reject field number zero.
    pub fn map_entry(field: u64, key: MapKey) -> Result<Self, ModelError> {
        if field == 0 {
            return Err(ModelError::InvalidFieldPath);
        }
        validate_map_key(&key)?;
        Ok(Self::MapEntry { field, key })
    }

    /// Return the numeric field number.
    pub const fn field_number(&self) -> u64 {
        match self {
            Self::Field(field) | Self::MapEntry { field, .. } => *field,
        }
    }
}

/// The bytes or NFC text used as a decomposed map key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MapKey {
    /// A byte-string map key.
    Bytes(Vec<u8>),
    /// A text-string map key.
    Text(String),
}

/// One field value together with the clock and device that wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldEntry {
    /// The field value. A decomposed map deletion is represented by [`cbor::Value::Null`].
    pub value: cbor::Value,
    /// Hybrid logical clock assigned to the write.
    pub clock: Hlc,
    /// UUIDv7 device identifier that authored the write.
    pub origin: Uuid,
}

impl FieldEntry {
    /// Construct and validate a field entry.
    pub fn new(value: cbor::Value, clock: Hlc, origin: Uuid) -> Result<Self, ModelError> {
        clock::validate_uuid_v7(origin).map_err(ModelError::Clock)?;
        validate_value(&value, 0, None)?;
        Ok(Self { value, clock, origin })
    }
}

/// A deletion marker for an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tombstone {
    /// Clock assigned to the deletion.
    pub clock: Hlc,
    /// Device that authored the deletion.
    pub origin: Uuid,
}

impl Tombstone {
    /// Construct and validate a tombstone.
    pub fn new(clock: Hlc, origin: Uuid) -> Result<Self, ModelError> {
        clock::validate_uuid_v7(origin).map_err(ModelError::Clock)?;
        Ok(Self { clock, origin })
    }
}

/// A replicated object before encryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    /// UUIDv7 object identifier.
    pub id: Uuid,
    /// Registry type number (unknown future numbers are preserved).
    pub object_type: ObjectType,
    /// Type-specific schema version.
    pub schema: u64,
    /// Field entries keyed by scalar or decomposed map paths.
    pub fields: BTreeMap<FieldPath, FieldEntry>,
    /// Optional object deletion marker.
    pub tombstone: Option<Tombstone>,
}

impl Object {
    /// Create an empty object envelope.
    pub fn new(id: Uuid, object_type: ObjectType, schema: u64) -> Result<Self, ModelError> {
        clock::validate_uuid_v7(id).map_err(ModelError::Clock)?;
        validate_schema(object_type, schema)?;
        Ok(Self { id, object_type, schema, fields: BTreeMap::new(), tombstone: None })
    }

    /// Insert or replace one field entry after validating its local limits.
    pub fn insert(&mut self, path: FieldPath, entry: FieldEntry) -> Result<(), ModelError> {
        validate_field_path(&path)?;
        if !self.fields.contains_key(&path) && self.fields.len() >= MAX_MAP_ENTRIES {
            return Err(ModelError::MapLimit);
        }
        self.fields.insert(path, entry);
        Ok(())
    }

    /// Set or clear the object tombstone.
    pub fn set_tombstone(&mut self, tombstone: Option<Tombstone>) {
        self.tombstone = tombstone;
    }

    /// Return the scalar field entry, ignoring decomposed map entries.
    pub fn field(&self, field: u64) -> Option<&FieldEntry> {
        self.fields.get(&FieldPath::Field(field))
    }

    /// Return all entries belonging to one field number.
    pub fn field_entries(&self, field: u64) -> impl Iterator<Item = (&FieldPath, &FieldEntry)> {
        self.fields.iter().filter(move |(path, _)| path.field_number() == field)
    }

    /// Return whether the tombstone currently hides the object.
    pub fn is_tombstoned(&self) -> bool {
        self.tombstone.is_some_and(|tombstone| {
            !self.fields.values().any(|entry| entry.clock > tombstone.clock)
        })
    }

    /// Return whether a newer field write has resurrected a tombstoned object.
    pub fn is_resurrected(&self) -> bool {
        self.tombstone.is_some_and(|tombstone| {
            self.fields.values().any(|entry| entry.clock > tombstone.clock)
        })
    }

    /// Validate the registry-specific required fields and all model limits.
    pub fn validate(&self) -> Result<(), ModelError> {
        clock::validate_uuid_v7(self.id).map_err(ModelError::Clock)?;
        validate_schema(self.object_type, self.schema)?;
        for (path, entry) in &self.fields {
            validate_field_path(path)?;
            validate_value(&entry.value, 0, None)?;
            clock::validate_uuid_v7(entry.origin).map_err(ModelError::Clock)?;
        }
        if !self.object_type.is_known() {
            return Ok(());
        }
        validate_type_fields(self)
    }

    /// Encode this object as a canonical deterministic CBOR envelope.
    pub fn encode(&self) -> Result<Vec<u8>, ModelError> {
        self.validate()?;
        let bytes = cbor::encode(&self.to_value()?)?;
        if bytes.len() > MAX_OBJECT_BYTES {
            return Err(ModelError::ObjectLimit);
        }
        Ok(bytes)
    }

    /// Decode one canonical deterministic CBOR envelope.
    pub fn decode(bytes: &[u8]) -> Result<Self, ModelError> {
        if bytes.len() > MAX_OBJECT_BYTES {
            return Err(ModelError::ObjectLimit);
        }
        let value = cbor::decode(bytes)?;
        let object = Self::from_value(value)?;
        object.validate()?;
        Ok(object)
    }

    /// Convert to the generic CBOR value used by the codec.
    pub fn to_value(&self) -> Result<cbor::Value, ModelError> {
        self.validate()?;
        let mut fields = Vec::with_capacity(self.fields.len());
        for (path, entry) in &self.fields {
            fields.push((path_to_value(path), entry_to_value(entry)));
        }
        let mut envelope = vec![
            (cbor::Value::UInt(1), cbor::Value::Bytes(self.id.into_bytes().to_vec())),
            (cbor::Value::UInt(2), cbor::Value::UInt(self.object_type.to_wire())),
            (cbor::Value::UInt(3), cbor::Value::UInt(self.schema)),
            (cbor::Value::UInt(4), cbor::Value::Map(fields)),
        ];
        if let Some(tombstone) = self.tombstone {
            envelope.push((cbor::Value::UInt(5), tombstone_to_value(tombstone)));
        }
        Ok(cbor::Value::Map(envelope))
    }

    /// Parse an object from an already decoded canonical CBOR value.
    pub fn from_value(value: cbor::Value) -> Result<Self, ModelError> {
        let cbor::Value::Map(entries) = value else {
            return Err(ModelError::InvalidEnvelope);
        };
        let mut id = None;
        let mut object_type = None;
        let mut schema = None;
        let mut fields = None;
        let mut tombstone = None;
        for (key, value) in entries {
            let cbor::Value::UInt(key) = key else {
                return Err(ModelError::InvalidEnvelope);
            };
            match key {
                1 => id = Some(parse_uuid(value)?),
                2 => {
                    let cbor::Value::UInt(value) = value else {
                        return Err(ModelError::InvalidEnvelope);
                    };
                    object_type = Some(ObjectType::from_wire(value)?);
                }
                3 => {
                    let cbor::Value::UInt(value) = value else {
                        return Err(ModelError::InvalidEnvelope);
                    };
                    schema = Some(value);
                }
                4 => fields = Some(parse_fields(value)?),
                5 => tombstone = Some(parse_tombstone(value)?),
                _ => return Err(ModelError::UnknownEnvelopeField(key)),
            }
        }
        let object = Self {
            id: id.ok_or(ModelError::MissingEnvelopeField(1))?,
            object_type: object_type.ok_or(ModelError::MissingEnvelopeField(2))?,
            schema: schema.ok_or(ModelError::MissingEnvelopeField(3))?,
            fields: fields.ok_or(ModelError::MissingEnvelopeField(4))?,
            tombstone,
        };
        object.validate()?;
        Ok(object)
    }

    /// Read a required text field from a scalar path.
    pub fn required_text(&self, field: u64) -> Result<&str, AccessError> {
        match self.field(field).map(|entry| &entry.value) {
            Some(cbor::Value::Text(value)) => Ok(value),
            Some(_) => Err(AccessError::WrongKind(field, "text")),
            None => Err(AccessError::Missing(field)),
        }
    }

    /// Read an optional text field from a scalar path.
    pub fn optional_text(&self, field: u64) -> Result<Option<&str>, AccessError> {
        match self.field(field).map(|entry| &entry.value) {
            Some(cbor::Value::Text(value)) => Ok(Some(value)),
            Some(_) => Err(AccessError::WrongKind(field, "text")),
            None => Ok(None),
        }
    }

    /// Read a required unsigned integer field.
    pub fn required_uint(&self, field: u64) -> Result<u64, AccessError> {
        match self.field(field).map(|entry| &entry.value) {
            Some(cbor::Value::UInt(value)) => Ok(*value),
            Some(_) => Err(AccessError::WrongKind(field, "unsigned integer")),
            None => Err(AccessError::Missing(field)),
        }
    }

    /// Read a required boolean field.
    pub fn required_bool(&self, field: u64) -> Result<bool, AccessError> {
        match self.field(field).map(|entry| &entry.value) {
            Some(cbor::Value::Bool(value)) => Ok(*value),
            Some(_) => Err(AccessError::WrongKind(field, "boolean")),
            None => Err(AccessError::Missing(field)),
        }
    }

    /// Read a required UUID field encoded as a 16-byte CBOR byte string.
    pub fn required_uuid(&self, field: u64) -> Result<Uuid, AccessError> {
        match self.field(field).map(|entry| &entry.value) {
            Some(cbor::Value::Bytes(value)) => parse_uuid_bytes(value)
                .map_err(|_| AccessError::WrongKind(field, "UUIDv7 byte string")),
            Some(_) => Err(AccessError::WrongKind(field, "UUIDv7 byte string")),
            None => Err(AccessError::Missing(field)),
        }
    }

    /// Read a required byte string field.
    pub fn required_bytes(&self, field: u64) -> Result<&[u8], AccessError> {
        match self.field(field).map(|entry| &entry.value) {
            Some(cbor::Value::Bytes(value)) => Ok(value),
            Some(_) => Err(AccessError::WrongKind(field, "byte string")),
            None => Err(AccessError::Missing(field)),
        }
    }

    /// Read a required array field.
    pub fn required_array(&self, field: u64) -> Result<&[cbor::Value], AccessError> {
        match self.field(field).map(|entry| &entry.value) {
            Some(cbor::Value::Array(value)) => Ok(value),
            Some(_) => Err(AccessError::WrongKind(field, "array")),
            None => Err(AccessError::Missing(field)),
        }
    }

    /// Read a required map field.
    pub fn required_map(&self, field: u64) -> Result<&[(cbor::Value, cbor::Value)], AccessError> {
        match self.field(field).map(|entry| &entry.value) {
            Some(cbor::Value::Map(value)) => Ok(value),
            Some(_) => Err(AccessError::WrongKind(field, "map")),
            None => Err(AccessError::Missing(field)),
        }
    }
}

/// Errors returned by typed scalar accessors.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum AccessError {
    /// The field was absent.
    #[error("required field {0} is missing")]
    Missing(u64),
    /// The field had a different CBOR value kind.
    #[error("field {0} is not a {1}")]
    WrongKind(u64, &'static str),
}

/// Errors returned by object construction, validation, and encoding.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ModelError {
    /// A nested deterministic CBOR operation failed.
    #[error("CBOR error: {0}")]
    Cbor(#[from] cbor::Error),
    /// A clock or UUID invariant failed.
    #[error("clock error: {0}")]
    Clock(#[from] clock::ClockError),
    /// A wire type number is reserved.
    #[error("object type {0} is reserved")]
    InvalidType(u64),
    /// A field path has a zero field number or invalid key.
    #[error("invalid field path")]
    InvalidFieldPath,
    /// The object envelope had the wrong CBOR shape.
    #[error("invalid object envelope")]
    InvalidEnvelope,
    /// A top-level envelope key was not defined by K-1.
    #[error("unknown object envelope field {0}")]
    UnknownEnvelopeField(u64),
    /// A required top-level envelope key was absent.
    #[error("object envelope field {0} is missing")]
    MissingEnvelopeField(u64),
    /// An object exceeded the encoded size limit.
    #[error("object exceeds the 256 KiB encoded size limit")]
    ObjectLimit,
    /// A field map exceeded its entry limit.
    #[error("object field map exceeds the entry limit")]
    MapLimit,
    /// A schema version of zero is reserved and cannot be used.
    #[error("schema version {schema} for {object_type} is invalid")]
    InvalidSchemaVersion {
        /// The affected object type.
        object_type: ObjectType,
        /// The invalid version.
        schema: u64,
    },
    /// A known type was encoded with a schema newer than this implementation understands.
    #[error("schema version {schema} for {object_type} is newer than supported version {current}")]
    UnsupportedSchemaVersion {
        /// The affected object type.
        object_type: ObjectType,
        /// The version received on the wire.
        schema: u64,
        /// The newest version implemented by this crate.
        current: u64,
    },
    /// A value used a text size larger than the model permits.
    #[error("text value exceeds the 16 KiB limit")]
    TextLimit,
    /// A workspace layout exceeded its special limit.
    #[error("workspace layout exceeds the 64 KiB limit")]
    WorkspaceLayoutLimit,
    /// A registry-specific required field or value constraint failed.
    #[error("invalid {object_type} object: {reason}")]
    InvalidFields {
        /// The affected object type.
        object_type: ObjectType,
        /// A stable human-readable validation reason.
        reason: &'static str,
    },
}

fn validate_schema(object_type: ObjectType, schema: u64) -> Result<(), ModelError> {
    if schema == 0 {
        return Err(ModelError::InvalidSchemaVersion { object_type, schema });
    }
    if object_type.is_known() && schema > CURRENT_SCHEMA_VERSION {
        return Err(ModelError::UnsupportedSchemaVersion {
            object_type,
            schema,
            current: CURRENT_SCHEMA_VERSION,
        });
    }
    Ok(())
}

fn validate_field_path(path: &FieldPath) -> Result<(), ModelError> {
    if path.field_number() == 0 {
        return Err(ModelError::InvalidFieldPath);
    }
    if let FieldPath::MapEntry { key, .. } = path {
        validate_map_key(key)?;
    }
    Ok(())
}

fn validate_map_key(key: &MapKey) -> Result<(), ModelError> {
    match key {
        MapKey::Bytes(_) => Ok(()),
        MapKey::Text(value) => {
            if value.len() > MAX_TEXT_BYTES {
                return Err(ModelError::TextLimit);
            }
            if !crate::cbor::is_nfc(value) {
                return Err(ModelError::Cbor(cbor::Error::NonNormalizedText));
            }
            Ok(())
        }
    }
}

fn validate_value(
    value: &cbor::Value,
    depth: usize,
    workspace_layout_limit: Option<usize>,
) -> Result<(), ModelError> {
    if depth > 128 {
        return Err(ModelError::Cbor(cbor::Error::DepthLimit));
    }
    match value {
        cbor::Value::Text(value) => {
            if value.len() > workspace_layout_limit.unwrap_or(MAX_TEXT_BYTES) {
                return if workspace_layout_limit.is_some() {
                    Err(ModelError::WorkspaceLayoutLimit)
                } else {
                    Err(ModelError::TextLimit)
                };
            }
            if !crate::cbor::is_nfc(value) {
                return Err(ModelError::Cbor(cbor::Error::NonNormalizedText));
            }
        }
        cbor::Value::Array(values) => {
            for value in values {
                validate_value(value, depth + 1, None)?;
            }
        }
        cbor::Value::Map(entries) => {
            if entries.len() > MAX_MAP_ENTRIES {
                return Err(ModelError::MapLimit);
            }
            for (key, value) in entries {
                validate_value(key, depth + 1, None)?;
                validate_value(value, depth + 1, None)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ValueKind {
    Any,
    Text,
    UInt,
    Bool,
    Bytes,
    Uuid,
    ArrayOfUuid,
    CredentialDeviceBinding,
    SessionSpec,
    RouteReference,
    VariableSpec,
}

#[derive(Clone, Copy)]
enum FieldKind {
    Scalar(ValueKind),
    Map { key: MapKeyKind, value: ValueKind },
}

#[derive(Clone, Copy)]
enum MapKeyKind {
    Text,
    Uuid,
}

fn validate_field_shapes(object: &Object) -> Result<(), ModelError> {
    for (path, entry) in &object.fields {
        let Some(kind) = field_kind(object.object_type, path.field_number()) else {
            continue;
        };
        match (path, kind) {
            (FieldPath::Field(_), FieldKind::Scalar(kind)) => {
                validate_value_kind(object, path, &entry.value, kind)?;
            }
            (FieldPath::MapEntry { key, .. }, FieldKind::Map { key: key_kind, value }) => {
                validate_map_key_kind(object, key, key_kind)?;
                if !matches!(entry.value, cbor::Value::Null) {
                    validate_value_kind(object, path, &entry.value, value)?;
                }
            }
            (FieldPath::Field(_), FieldKind::Map { .. }) => {
                return Err(invalid_field(
                    object,
                    "map fields must use decomposed map-entry paths",
                ));
            }
            (FieldPath::MapEntry { .. }, FieldKind::Scalar(_)) => {
                return Err(invalid_field(object, "scalar fields cannot use map-entry paths"));
            }
        }
    }
    Ok(())
}

fn field_kind(object_type: ObjectType, field: u64) -> Option<FieldKind> {
    use FieldKind::{Map, Scalar};
    use MapKeyKind::{Text, Uuid};
    use ValueKind::{
        ArrayOfUuid, Bool, Bytes, CredentialDeviceBinding, RouteReference, SessionSpec,
        Text as TextValue, UInt, VariableSpec,
    };
    Some(match object_type {
        ObjectType::HOST => match field {
            1 | 2 | 7 => Scalar(TextValue),
            3 => Scalar(UInt),
            4 | 9 | 10 => Map { key: Text, value: TextValue },
            5 => Map { key: Uuid, value: Bool },
            6 => Scalar(Bool),
            8 => Scalar(ValueKind::Uuid),
            _ => return None,
        },
        ObjectType::ACCESS_PROFILE => match field {
            1 | 4 => Scalar(ValueKind::Uuid),
            2 | 3 | 6 | 7 => Scalar(TextValue),
            5 => Scalar(RouteReference),
            8 => Map { key: Uuid, value: Bool },
            9 => Scalar(Bool),
            _ => return None,
        },
        ObjectType::CREDENTIAL => match field {
            1 | 6 => Scalar(TextValue),
            2 | 3 => Scalar(UInt),
            4 => Scalar(Bytes),
            5 => Map { key: Uuid, value: CredentialDeviceBinding },
            7 => Map { key: Text, value: TextValue },
            8 => Scalar(ValueKind::Uuid),
            _ => return None,
        },
        ObjectType::ROUTE => match field {
            1 | 4 | 6 => Scalar(TextValue),
            2 => Scalar(UInt),
            3 => Scalar(ArrayOfUuid),
            5 | 7 => Scalar(ValueKind::Uuid),
            _ => return None,
        },
        ObjectType::HOST_GROUP => match field {
            1 | 3 => Scalar(TextValue),
            2 => Scalar(ValueKind::Uuid),
            4 => Map { key: Text, value: TextValue },
            _ => return None,
        },
        ObjectType::TRUST_RECORD => match field {
            1 | 7 | 8 => Scalar(ValueKind::Uuid),
            2..=4 => Scalar(TextValue),
            5 | 6 => Scalar(UInt),
            9 | 10 => Scalar(Bool),
            _ => return None,
        },
        ObjectType::SNIPPET => match field {
            1 | 2 | 5 => Scalar(TextValue),
            3 => Map { key: Text, value: VariableSpec },
            4 => Map { key: Text, value: Bool },
            _ => return None,
        },
        ObjectType::FORWARD => match field {
            1 | 3 | 5 => Scalar(TextValue),
            2 | 4 | 6 => Scalar(UInt),
            7 => Scalar(ValueKind::Uuid),
            _ => return None,
        },
        ObjectType::WORKSPACE => match field {
            1 => Scalar(TextValue),
            2 => Scalar(Bytes),
            3 => Map { key: Uuid, value: SessionSpec },
            _ => return None,
        },
        ObjectType::PREFERENCE => match field {
            1 => Scalar(TextValue),
            2 => Scalar(ValueKind::Any),
            _ => return None,
        },
        ObjectType::GATEWAY_NETWORK => match field {
            1 | 2 => Scalar(TextValue),
            _ => return None,
        },
        _ => return None,
    })
}

fn validate_map_key_kind(
    object: &Object,
    key: &MapKey,
    kind: MapKeyKind,
) -> Result<(), ModelError> {
    let valid = match (kind, key) {
        (MapKeyKind::Text, MapKey::Text(_)) => true,
        (MapKeyKind::Uuid, MapKey::Bytes(bytes)) => parse_uuid_bytes(bytes).is_ok(),
        _ => false,
    };
    if valid { Ok(()) } else { Err(invalid_field(object, "map key has the wrong type")) }
}

fn validate_value_kind(
    object: &Object,
    path: &FieldPath,
    value: &cbor::Value,
    kind: ValueKind,
) -> Result<(), ModelError> {
    let valid = match kind {
        ValueKind::Any => true,
        ValueKind::Text => matches!(value, cbor::Value::Text(_)),
        ValueKind::UInt => matches!(value, cbor::Value::UInt(_)),
        ValueKind::Bool => matches!(value, cbor::Value::Bool(_)),
        ValueKind::Bytes => matches!(value, cbor::Value::Bytes(_)),
        ValueKind::Uuid => {
            matches!(value, cbor::Value::Bytes(bytes) if parse_uuid_bytes(bytes).is_ok())
        }
        ValueKind::ArrayOfUuid => {
            matches!(value, cbor::Value::Array(values) if values.iter().all(|value| matches!(value, cbor::Value::Bytes(bytes) if parse_uuid_bytes(bytes).is_ok())))
        }
        ValueKind::CredentialDeviceBinding => validate_device_binding(value),
        ValueKind::SessionSpec => validate_session_spec(value),
        ValueKind::RouteReference => match value {
            cbor::Value::UInt(0) => true,
            cbor::Value::Bytes(bytes) => parse_uuid_bytes(bytes).is_ok(),
            _ => false,
        },
        ValueKind::VariableSpec => validate_variable_spec(value),
    };
    if valid {
        Ok(())
    } else {
        let _ = path;
        Err(invalid_field(object, "field has the wrong value kind"))
    }
}

fn invalid_field(object: &Object, reason: &'static str) -> ModelError {
    ModelError::InvalidFields { object_type: object.object_type, reason }
}

fn validate_device_binding(value: &cbor::Value) -> bool {
    let cbor::Value::Map(entries) = value else {
        return false;
    };
    let mut public_key = false;
    let mut label = false;
    for (key, value) in entries {
        let cbor::Value::UInt(key) = key else {
            return false;
        };
        match (*key, value) {
            (1, cbor::Value::Text(_)) => public_key = true,
            (2, cbor::Value::Text(_)) => label = true,
            (1 | 2, _) => return false,
            _ => {}
        }
    }
    public_key && label
}

fn validate_variable_spec(value: &cbor::Value) -> bool {
    let cbor::Value::Map(entries) = value else {
        return false;
    };
    let mut kind = None;
    for (key, value) in entries {
        let cbor::Value::UInt(key) = key else {
            return false;
        };
        match *key {
            1 => match value {
                cbor::Value::UInt(value @ 1..=4) => kind = Some(*value),
                _ => return false,
            },
            3 if matches!(value, cbor::Value::Array(_)) => {}
            3 => return false,
            _ => {}
        }
    }
    kind.is_some()
}

fn validate_session_spec(value: &cbor::Value) -> bool {
    let cbor::Value::Map(entries) = value else {
        return false;
    };
    let mut profile = false;
    let mut kind = None;
    let mut forward = false;
    for (key, value) in entries {
        let cbor::Value::UInt(key) = key else {
            return false;
        };
        match *key {
            1 if matches!(value, cbor::Value::Bytes(bytes) if parse_uuid_bytes(bytes).is_ok()) => {
                profile = true;
            }
            1 => return false,
            2 => match value {
                cbor::Value::UInt(value @ 1..=3) => kind = Some(*value),
                _ => return false,
            },
            3 => {
                if !matches!(value, cbor::Value::Bytes(bytes) if parse_uuid_bytes(bytes).is_ok()) {
                    return false;
                }
                forward = true;
            }
            4 => {
                if !matches!(value, cbor::Value::Text(_)) {
                    return false;
                }
            }
            _ => {}
        }
    }
    match kind {
        Some(3) => profile && forward,
        Some(1 | 2) => profile && !forward,
        _ => false,
    }
}

fn validate_type_fields(object: &Object) -> Result<(), ModelError> {
    validate_field_shapes(object)?;
    match object.object_type {
        ObjectType::HOST => {
            object.required_text(1).map_err(|_| invalid_field(object, "name is required"))?;
            object.required_text(2).map_err(|_| invalid_field(object, "address is required"))?;
            if let Some(entry) = object.field(3) {
                if !matches!(entry.value, cbor::Value::UInt(_)) {
                    return Err(invalid_field(object, "port must be unsigned"));
                }
            }
        }
        ObjectType::ACCESS_PROFILE => {
            object.required_uuid(1).map_err(|_| invalid_field(object, "host is required"))?;
            object.required_text(3).map_err(|_| invalid_field(object, "username is required"))?;
        }
        ObjectType::CREDENTIAL => validate_credential_fields(object)?,
        ObjectType::ROUTE => validate_route_fields(object)?,
        ObjectType::HOST_GROUP => {
            object.required_text(1).map_err(|_| invalid_field(object, "name is required"))?;
        }
        ObjectType::SNIPPET => {
            object.required_text(1).map_err(|_| invalid_field(object, "name is required"))?;
            object.required_text(2).map_err(|_| invalid_field(object, "template is required"))?;
        }
        ObjectType::FORWARD => {
            object.required_text(1).map_err(|_| invalid_field(object, "name is required"))?;
            let kind =
                object.required_uint(2).map_err(|_| invalid_field(object, "kind is required"))?;
            if !(1..=3).contains(&kind) {
                return Err(invalid_field(object, "kind is outside the registry"));
            }
        }
        ObjectType::TRUST_RECORD => validate_trust_record_fields(object)?,
        ObjectType::WORKSPACE => {
            object.required_text(1).map_err(|_| invalid_field(object, "name is required"))?;
            if let Some(entry) = object.field(2) {
                match &entry.value {
                    cbor::Value::Bytes(value) if value.len() <= MAX_WORKSPACE_LAYOUT_BYTES => {}
                    cbor::Value::Bytes(_) => return Err(ModelError::WorkspaceLayoutLimit),
                    _ => return Err(invalid_field(object, "layout must be bytes")),
                }
            }
        }
        ObjectType::PREFERENCE => {
            object.required_text(1).map_err(|_| invalid_field(object, "key is required"))?;
        }
        _ => {}
    }
    Ok(())
}

fn validate_credential_fields(object: &Object) -> Result<(), ModelError> {
    let kind = object.required_uint(2).map_err(|_| invalid_field(object, "kind is required"))?;
    let binding =
        object.required_uint(3).map_err(|_| invalid_field(object, "binding is required"))?;
    if !(1..=7).contains(&kind) || !(1..=3).contains(&binding) {
        return Err(invalid_field(object, "kind or binding is outside the registry"));
    }
    if [3, 5, 6].contains(&kind) && binding == 1 {
        return Err(invalid_field(object, "this credential kind cannot use shared binding"));
    }
    let has_secret = object.field(4).is_some();
    if (binding == 1) != has_secret {
        return Err(invalid_field(object, "shared credentials require exactly one secret field"));
    }
    if object.field(6).is_some() && ![2, 4].contains(&kind) {
        return Err(invalid_field(
            object,
            "public key is only valid for key and agent credentials",
        ));
    }
    if object.field(7).is_some() && kind != 7 {
        return Err(invalid_field(object, "provider is only valid for external credentials"));
    }
    if object.field(8).is_some() && kind != 3 {
        return Err(invalid_field(
            object,
            "certificate scope is only valid for certificate credentials",
        ));
    }
    if kind == 3 && object.field(8).is_none() {
        return Err(invalid_field(object, "certificate credentials require a certificate scope"));
    }
    Ok(())
}

fn validate_route_fields(object: &Object) -> Result<(), ModelError> {
    object.required_text(1).map_err(|_| invalid_field(object, "name is required"))?;
    let kind = object.required_uint(2).map_err(|_| invalid_field(object, "kind is required"))?;
    if !(1..=5).contains(&kind) {
        return Err(invalid_field(object, "kind is outside the registry"));
    }
    let field_present = |field| object.field(field).is_some();
    match kind {
        1 => {
            if !field_present(3) {
                return Err(invalid_field(object, "jump routes require hops"));
            }
            if [4, 5, 6, 7].into_iter().any(field_present) {
                return Err(invalid_field(
                    object,
                    "jump routes cannot contain proxy, command, or gateway fields",
                ));
            }
        }
        2 | 3 => {
            if !field_present(4) {
                return Err(invalid_field(object, "proxy routes require a proxy"));
            }
            if [3, 6, 7].into_iter().any(field_present) {
                return Err(invalid_field(
                    object,
                    "proxy routes cannot contain jump, command, or gateway fields",
                ));
            }
        }
        4 => {
            if !field_present(6) {
                return Err(invalid_field(object, "command routes require a command"));
            }
            if [3, 4, 5, 7].into_iter().any(field_present) {
                return Err(invalid_field(
                    object,
                    "command routes cannot contain jump, proxy, or gateway fields",
                ));
            }
        }
        5 => {
            if !field_present(7) {
                return Err(invalid_field(object, "managed routes require a gateway network"));
            }
            if [3, 4, 5, 6].into_iter().any(field_present) {
                return Err(invalid_field(
                    object,
                    "managed routes cannot contain jump, proxy, or command fields",
                ));
            }
        }
        _ => unreachable!("route kind was range-checked"),
    }
    Ok(())
}

fn validate_trust_record_fields(object: &Object) -> Result<(), ModelError> {
    if object.field(1).is_none() && object.field(2).is_none() {
        return Err(invalid_field(object, "trust records require a host or pattern"));
    }
    if let Some(provenance) = object.field(5) {
        if !matches!(provenance.value, cbor::Value::UInt(1..=4)) {
            return Err(invalid_field(object, "provenance is outside the registry"));
        }
    }
    Ok(())
}

fn path_to_value(path: &FieldPath) -> cbor::Value {
    match path {
        FieldPath::Field(field) => cbor::Value::UInt(*field),
        FieldPath::MapEntry { field, key } => {
            cbor::Value::Array(vec![cbor::Value::UInt(*field), map_key_to_value(key)])
        }
    }
}

fn map_key_to_value(key: &MapKey) -> cbor::Value {
    match key {
        MapKey::Bytes(value) => cbor::Value::Bytes(value.clone()),
        MapKey::Text(value) => cbor::Value::Text(value.clone()),
    }
}

fn parse_field_path(value: cbor::Value) -> Result<FieldPath, ModelError> {
    match value {
        cbor::Value::UInt(field) => FieldPath::field(field),
        cbor::Value::Array(mut values) if values.len() == 2 => {
            let key = values.pop().ok_or(ModelError::InvalidFieldPath)?;
            let field = values.pop().ok_or(ModelError::InvalidFieldPath)?;
            let cbor::Value::UInt(field) = field else {
                return Err(ModelError::InvalidFieldPath);
            };
            let key = match key {
                cbor::Value::Bytes(value) => MapKey::Bytes(value),
                cbor::Value::Text(value) => MapKey::Text(value),
                _ => return Err(ModelError::InvalidFieldPath),
            };
            FieldPath::map_entry(field, key)
        }
        _ => Err(ModelError::InvalidFieldPath),
    }
}

fn entry_to_value(entry: &FieldEntry) -> cbor::Value {
    cbor::Value::Array(vec![
        entry.value.clone(),
        cbor::Value::UInt(entry.clock.to_wire()),
        cbor::Value::Bytes(entry.origin.into_bytes().to_vec()),
    ])
}

fn parse_entry(value: cbor::Value) -> Result<FieldEntry, ModelError> {
    let cbor::Value::Array(mut values) = value else {
        return Err(ModelError::InvalidEnvelope);
    };
    if values.len() != 3 {
        return Err(ModelError::InvalidEnvelope);
    }
    let origin = values.pop().ok_or(ModelError::InvalidEnvelope)?;
    let clock = values.pop().ok_or(ModelError::InvalidEnvelope)?;
    let value = values.pop().ok_or(ModelError::InvalidEnvelope)?;
    let cbor::Value::UInt(clock) = clock else {
        return Err(ModelError::InvalidEnvelope);
    };
    let clock = Hlc::from_wire(clock).map_err(ModelError::Clock)?;
    let origin = parse_uuid(origin)?;
    FieldEntry::new(value, clock, origin)
}

fn parse_fields(value: cbor::Value) -> Result<BTreeMap<FieldPath, FieldEntry>, ModelError> {
    let cbor::Value::Map(entries) = value else {
        return Err(ModelError::InvalidEnvelope);
    };
    if entries.len() > MAX_MAP_ENTRIES {
        return Err(ModelError::MapLimit);
    }
    let mut fields = BTreeMap::new();
    for (path, entry) in entries {
        let path = parse_field_path(path)?;
        let entry = parse_entry(entry)?;
        if fields.insert(path, entry).is_some() {
            return Err(ModelError::InvalidEnvelope);
        }
    }
    Ok(fields)
}

fn tombstone_to_value(tombstone: Tombstone) -> cbor::Value {
    cbor::Value::Array(vec![
        cbor::Value::UInt(tombstone.clock.to_wire()),
        cbor::Value::Bytes(tombstone.origin.into_bytes().to_vec()),
    ])
}

fn parse_tombstone(value: cbor::Value) -> Result<Tombstone, ModelError> {
    let cbor::Value::Array(mut values) = value else {
        return Err(ModelError::InvalidEnvelope);
    };
    if values.len() != 2 {
        return Err(ModelError::InvalidEnvelope);
    }
    let origin = values.pop().ok_or(ModelError::InvalidEnvelope)?;
    let clock = values.pop().ok_or(ModelError::InvalidEnvelope)?;
    let cbor::Value::UInt(clock) = clock else {
        return Err(ModelError::InvalidEnvelope);
    };
    Tombstone::new(Hlc::from_wire(clock).map_err(ModelError::Clock)?, parse_uuid(origin)?)
}

fn parse_uuid(value: cbor::Value) -> Result<Uuid, ModelError> {
    let cbor::Value::Bytes(value) = value else {
        return Err(ModelError::InvalidEnvelope);
    };
    parse_uuid_bytes(&value)
}

fn parse_uuid_bytes(value: &[u8]) -> Result<Uuid, ModelError> {
    let bytes: [u8; 16] = value.try_into().map_err(|_| ModelError::InvalidEnvelope)?;
    let id = Uuid::from_bytes(bytes);
    clock::validate_uuid_v7(id).map_err(ModelError::Clock)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> Uuid {
        let mut bytes = [0; 16];
        bytes[0] = seed;
        bytes[6] = 0x70;
        bytes[8] = 0x80;
        Uuid::from_bytes(bytes)
    }

    fn host() -> Object {
        let mut object = Object::new(id(1), ObjectType::HOST, 1).expect("object");
        object
            .insert(
                FieldPath::field(1).expect("path"),
                FieldEntry::new(
                    cbor::Value::Text("example".into()),
                    Hlc::at(1).expect("clock"),
                    id(2),
                )
                .expect("entry"),
            )
            .expect("insert");
        object
            .insert(
                FieldPath::field(2).expect("path"),
                FieldEntry::new(
                    cbor::Value::Text("host.example".into()),
                    Hlc::at(2).expect("clock"),
                    id(2),
                )
                .expect("entry"),
            )
            .expect("insert");
        object
    }

    fn put_field(object: &mut Object, field: u64, value: cbor::Value, clock: u64) {
        object
            .insert(
                FieldPath::field(field).expect("path"),
                FieldEntry::new(value, Hlc::at(clock).expect("clock"), id(2)).expect("entry"),
            )
            .expect("insert");
    }

    fn put_map_entry(object: &mut Object, field: u64, key: MapKey, value: cbor::Value, clock: u64) {
        object
            .insert(
                FieldPath::map_entry(field, key).expect("path"),
                FieldEntry::new(value, Hlc::at(clock).expect("clock"), id(2)).expect("entry"),
            )
            .expect("insert");
    }

    #[test]
    fn object_round_trips_with_unknown_fields() {
        let mut object = host();
        object
            .insert(
                FieldPath::field(99).expect("path"),
                FieldEntry::new(cbor::Value::Bool(true), Hlc::at(3).expect("clock"), id(2))
                    .expect("entry"),
            )
            .expect("insert");
        let bytes = object.encode().expect("encode");
        assert_eq!(Object::decode(&bytes).expect("decode"), object);
    }

    #[test]
    fn object_round_trips_tombstones_and_binary_map_keys() {
        let mut object = host();
        object
            .insert(
                FieldPath::map_entry(99, MapKey::Bytes(vec![1, 2, 3])).expect("path"),
                FieldEntry::new(cbor::Value::Null, Hlc::at(3).expect("clock"), id(2))
                    .expect("entry"),
            )
            .expect("insert");
        object.set_tombstone(Some(
            Tombstone::new(Hlc::at(4).expect("clock"), id(3)).expect("tombstone"),
        ));

        let bytes = object.encode().expect("encode");
        assert_eq!(Object::decode(&bytes).expect("decode"), object);
    }

    #[test]
    fn typed_accessors_cover_scalar_and_container_values() {
        let object = host();
        assert_eq!(object.required_text(1).expect("name"), "example");
        assert_eq!(object.required_uint(3), Err(AccessError::Missing(3)));
        assert_eq!(object.required_bytes(1), Err(AccessError::WrongKind(1, "byte string")));

        let mut route = Object::new(id(4), ObjectType::ROUTE, 1).expect("route");
        put_field(&mut route, 1, cbor::Value::Text("jump".into()), 1);
        put_field(&mut route, 2, cbor::Value::UInt(1), 2);
        put_field(&mut route, 3, cbor::Value::Array(vec![]), 3);
        assert!(route.required_array(3).expect("hops").is_empty());

        let mut workspace = Object::new(id(5), ObjectType::WORKSPACE, 1).expect("workspace");
        put_field(&mut workspace, 1, cbor::Value::Text("workspace".into()), 1);
        put_field(&mut workspace, 2, cbor::Value::Bytes(vec![1, 2]), 2);
        assert_eq!(workspace.required_bytes(2).expect("layout"), [1, 2]);

        let mut preference = Object::new(id(6), ObjectType::PREFERENCE, 1).expect("preference");
        put_field(&mut preference, 1, cbor::Value::Text("theme".into()), 1);
        put_field(
            &mut preference,
            2,
            cbor::Value::Map(vec![(cbor::Value::Text("dark".into()), cbor::Value::Bool(true))]),
            2,
        );
        assert_eq!(preference.required_map(2).expect("value").len(), 1);
    }

    #[test]
    fn map_entries_encode_as_distinct_paths() {
        let mut object = host();
        for (key, clock) in [("a", 3), ("b", 4)] {
            object
                .insert(
                    FieldPath::map_entry(4, MapKey::Text(key.into())).expect("path"),
                    FieldEntry::new(
                        cbor::Value::Text("tag".into()),
                        Hlc::at(clock).expect("clock"),
                        id(2),
                    )
                    .expect("entry"),
                )
                .expect("insert");
        }
        object
            .insert(
                FieldPath::map_entry(4, MapKey::Text("removed".into())).expect("path"),
                FieldEntry::new(cbor::Value::Null, Hlc::at(5).expect("clock"), id(2))
                    .expect("entry"),
            )
            .expect("insert tombstone entry");
        let decoded = Object::decode(&object.encode().expect("encode")).expect("decode");
        assert_eq!(decoded.fields.len(), 5);
    }

    #[test]
    fn rejects_non_v7_identifiers() {
        let id = Uuid::from_bytes([0; 16]);
        assert!(matches!(
            Object::new(id, ObjectType::HOST, 1),
            Err(ModelError::Clock(clock::ClockError::NotUuidV7))
        ));
    }

    #[test]
    fn enforces_known_schema_versions_and_round_trips_future_types() {
        assert_eq!(
            Object::new(id(11), ObjectType::HOST, 0),
            Err(ModelError::InvalidSchemaVersion { object_type: ObjectType::HOST, schema: 0 })
        );

        let mut too_new = host();
        too_new.schema = CURRENT_SCHEMA_VERSION + 1;
        assert_eq!(
            too_new.validate(),
            Err(ModelError::UnsupportedSchemaVersion {
                object_type: ObjectType::HOST,
                schema: CURRENT_SCHEMA_VERSION + 1,
                current: CURRENT_SCHEMA_VERSION,
            })
        );

        let future_type = ObjectType::from_wire(99).expect("future type");
        let mut future = Object::new(id(12), future_type, 7).expect("future object");
        future
            .insert(
                FieldPath::field(99).expect("path"),
                FieldEntry::new(cbor::Value::Bool(true), Hlc::at(1).expect("clock"), id(2))
                    .expect("entry"),
            )
            .expect("insert");
        assert_eq!(Object::decode(&future.encode().expect("encode")).expect("decode"), future);
    }

    #[test]
    fn rejects_malformed_envelope_shapes() {
        let entry = || {
            cbor::Value::Array(vec![
                cbor::Value::Bool(true),
                cbor::Value::UInt(Hlc::at(1).expect("clock").to_wire()),
                cbor::Value::Bytes(id(2).into_bytes().to_vec()),
            ])
        };
        let envelope = |fields| {
            cbor::Value::Map(vec![
                (cbor::Value::UInt(1), cbor::Value::Bytes(id(1).into_bytes().to_vec())),
                (cbor::Value::UInt(2), cbor::Value::UInt(99)),
                (cbor::Value::UInt(3), cbor::Value::UInt(1)),
                (cbor::Value::UInt(4), cbor::Value::Map(fields)),
            ])
        };

        assert_eq!(
            Object::from_value(cbor::Value::Array(vec![])),
            Err(ModelError::InvalidEnvelope)
        );
        assert_eq!(
            Object::from_value(cbor::Value::Map(vec![])),
            Err(ModelError::MissingEnvelopeField(1))
        );
        assert_eq!(
            Object::from_value(envelope(vec![(cbor::Value::UInt(0), entry(),)])),
            Err(ModelError::InvalidFieldPath)
        );
        assert_eq!(
            Object::from_value(envelope(vec![(
                cbor::Value::UInt(1),
                cbor::Value::Array(vec![cbor::Value::Bool(true)]),
            )])),
            Err(ModelError::InvalidEnvelope)
        );
        assert_eq!(
            Object::from_value(cbor::Value::Map(vec![
                (cbor::Value::UInt(1), cbor::Value::Bytes(id(1).into_bytes().to_vec())),
                (cbor::Value::UInt(2), cbor::Value::UInt(99)),
                (cbor::Value::UInt(3), cbor::Value::UInt(1)),
                (cbor::Value::UInt(4), cbor::Value::Map(vec![])),
                (cbor::Value::UInt(6), cbor::Value::Null),
            ])),
            Err(ModelError::UnknownEnvelopeField(6))
        );
    }

    #[test]
    fn tombstone_and_resurrection_are_visible() {
        let mut object = host();
        object.set_tombstone(Some(
            Tombstone::new(Hlc::at(10).expect("clock"), id(3)).expect("tombstone"),
        ));
        assert!(object.is_tombstoned());
        object
            .insert(
                FieldPath::field(1).expect("path"),
                FieldEntry::new(
                    cbor::Value::Text("restored".into()),
                    Hlc::at(11).expect("clock"),
                    id(2),
                )
                .expect("entry"),
            )
            .expect("insert");
        assert!(object.is_resurrected());
        assert!(!object.is_tombstoned());
    }

    #[test]
    fn enforces_text_map_and_workspace_limits() {
        let exactly_text = cbor::Value::Text("x".repeat(MAX_TEXT_BYTES));
        FieldEntry::new(exactly_text, Hlc::at(1).expect("clock"), id(2))
            .expect("the text limit is inclusive");
        let too_long = cbor::Value::Text("x".repeat(MAX_TEXT_BYTES + 1));
        assert_eq!(
            FieldEntry::new(too_long, Hlc::at(1).expect("clock"), id(2))
                .expect_err("text limit")
                .to_string(),
            "text value exceeds the 16 KiB limit"
        );

        let mut object = host();
        object
            .insert(
                FieldPath::field(4).expect("path"),
                FieldEntry::new(
                    cbor::Value::Text("not a map entry".into()),
                    Hlc::at(3).expect("clock"),
                    id(2),
                )
                .expect("entry"),
            )
            .expect("insert");
        assert!(object.validate().is_err());

        let mut workspace = Object::new(id(4), ObjectType::WORKSPACE, 1).expect("workspace");
        workspace
            .insert(
                FieldPath::field(1).expect("path"),
                FieldEntry::new(
                    cbor::Value::Text("workspace".into()),
                    Hlc::at(1).expect("clock"),
                    id(2),
                )
                .expect("entry"),
            )
            .expect("insert");
        workspace
            .insert(
                FieldPath::field(2).expect("path"),
                FieldEntry::new(
                    cbor::Value::Bytes(vec![0; MAX_WORKSPACE_LAYOUT_BYTES]),
                    Hlc::at(2).expect("clock"),
                    id(2),
                )
                .expect("entry"),
            )
            .expect("insert");
        workspace.encode().expect("the workspace layout limit is inclusive");
        workspace
            .insert(
                FieldPath::field(2).expect("path"),
                FieldEntry::new(
                    cbor::Value::Bytes(vec![0; MAX_WORKSPACE_LAYOUT_BYTES + 1]),
                    Hlc::at(3).expect("clock"),
                    id(2),
                )
                .expect("entry"),
            )
            .expect("replace layout");
        assert_eq!(workspace.encode(), Err(ModelError::WorkspaceLayoutLimit));
    }

    #[test]
    fn enforces_field_map_and_nested_map_limits_at_the_boundary() {
        let mut object = Object::new(
            id(13),
            ObjectType::from_wire(99).expect("future type"),
            CURRENT_SCHEMA_VERSION,
        )
        .expect("object");
        for field in 1..=MAX_MAP_ENTRIES as u64 {
            object
                .insert(
                    FieldPath::field(field).expect("path"),
                    FieldEntry::new(cbor::Value::Null, Hlc::at(field).expect("clock"), id(2))
                        .expect("entry"),
                )
                .expect("the field-map limit is inclusive");
        }
        assert_eq!(object.fields.len(), MAX_MAP_ENTRIES);
        assert_eq!(
            object.insert(
                FieldPath::field(MAX_MAP_ENTRIES as u64 + 1).expect("path"),
                FieldEntry::new(cbor::Value::Null, Hlc::at(5_000).expect("clock"), id(2))
                    .expect("entry"),
            ),
            Err(ModelError::MapLimit)
        );

        let at_limit = cbor::Value::Map(
            (0..MAX_MAP_ENTRIES)
                .map(|key| (cbor::Value::UInt(key as u64), cbor::Value::Null))
                .collect(),
        );
        FieldEntry::new(at_limit, Hlc::at(1).expect("clock"), id(2))
            .expect("the nested map limit is inclusive");
        let over_limit = cbor::Value::Map(
            (0..=MAX_MAP_ENTRIES)
                .map(|key| (cbor::Value::UInt(key as u64), cbor::Value::Null))
                .collect(),
        );
        assert_eq!(
            FieldEntry::new(over_limit, Hlc::at(1).expect("clock"), id(2)),
            Err(ModelError::MapLimit)
        );
    }

    #[test]
    fn enforces_encoded_object_limit_at_the_boundary() {
        fn object_with_payload(length: usize) -> Object {
            let mut object = Object::new(
                id(14),
                ObjectType::from_wire(99).expect("future type"),
                CURRENT_SCHEMA_VERSION,
            )
            .expect("object");
            object
                .insert(
                    FieldPath::field(1).expect("path"),
                    FieldEntry::new(
                        cbor::Value::Bytes(vec![0; length]),
                        Hlc::at(1).expect("clock"),
                        id(2),
                    )
                    .expect("entry"),
                )
                .expect("insert");
            object
        }

        let mut lower = 0;
        let mut upper = MAX_OBJECT_BYTES + 1;
        while upper - lower > 1 {
            let middle = lower + (upper - lower) / 2;
            if object_with_payload(middle).encode().is_ok() {
                lower = middle;
            } else {
                upper = middle;
            }
        }
        let encoded = object_with_payload(lower).encode().expect("largest valid object");
        assert_eq!(encoded.len(), MAX_OBJECT_BYTES);
        assert_eq!(object_with_payload(upper).encode(), Err(ModelError::ObjectLimit));
        assert_eq!(Object::decode(&vec![0; MAX_OBJECT_BYTES + 1]), Err(ModelError::ObjectLimit));
    }

    #[test]
    fn rejects_shared_binding_for_device_credentials() {
        let mut credential = Object::new(id(5), ObjectType::CREDENTIAL, 1).expect("credential");
        for (field, value) in
            [(2, cbor::Value::UInt(5)), (3, cbor::Value::UInt(1)), (4, cbor::Value::Bytes(vec![1]))]
        {
            credential
                .insert(
                    FieldPath::field(field).expect("path"),
                    FieldEntry::new(value, Hlc::at(field).expect("clock"), id(2)).expect("entry"),
                )
                .expect("insert");
        }
        assert!(matches!(credential.validate(), Err(ModelError::InvalidFields { .. })));
    }

    #[test]
    fn validates_nested_specs_and_conditional_registry_fields() {
        let mut credential = Object::new(id(6), ObjectType::CREDENTIAL, 1).expect("credential");
        put_field(&mut credential, 2, cbor::Value::UInt(6), 1);
        put_field(&mut credential, 3, cbor::Value::UInt(2), 2);
        put_map_entry(
            &mut credential,
            5,
            MapKey::Bytes(id(3).into_bytes().to_vec()),
            cbor::Value::Map(vec![(cbor::Value::UInt(1), cbor::Value::Text("key".into()))]),
            3,
        );
        assert!(credential.validate().is_err());
        put_map_entry(
            &mut credential,
            5,
            MapKey::Bytes(id(3).into_bytes().to_vec()),
            cbor::Value::Map(vec![
                (cbor::Value::UInt(1), cbor::Value::Text("key".into())),
                (cbor::Value::UInt(2), cbor::Value::Text("laptop".into())),
            ]),
            4,
        );
        credential.validate().expect("valid device binding");

        let mut snippet = Object::new(id(7), ObjectType::SNIPPET, 1).expect("snippet");
        put_field(&mut snippet, 1, cbor::Value::Text("snippet".into()), 1);
        put_field(&mut snippet, 2, cbor::Value::Text("{{name}}".into()), 2);
        put_map_entry(
            &mut snippet,
            3,
            MapKey::Text("name".into()),
            cbor::Value::Map(vec![(cbor::Value::UInt(1), cbor::Value::UInt(5))]),
            3,
        );
        assert!(snippet.validate().is_err());
        put_map_entry(
            &mut snippet,
            3,
            MapKey::Text("name".into()),
            cbor::Value::Map(vec![
                (cbor::Value::UInt(1), cbor::Value::UInt(3)),
                (cbor::Value::UInt(3), cbor::Value::Array(vec![cbor::Value::Text("admin".into())])),
            ]),
            4,
        );
        snippet.validate().expect("valid variable spec");

        let mut workspace = Object::new(id(8), ObjectType::WORKSPACE, 1).expect("workspace");
        put_field(&mut workspace, 1, cbor::Value::Text("workspace".into()), 1);
        put_map_entry(
            &mut workspace,
            3,
            MapKey::Bytes(id(4).into_bytes().to_vec()),
            cbor::Value::Map(vec![
                (cbor::Value::UInt(1), cbor::Value::Bytes(id(4).into_bytes().to_vec())),
                (cbor::Value::UInt(2), cbor::Value::UInt(3)),
            ]),
            2,
        );
        assert!(workspace.validate().is_err());
        put_map_entry(
            &mut workspace,
            3,
            MapKey::Bytes(id(4).into_bytes().to_vec()),
            cbor::Value::Map(vec![
                (cbor::Value::UInt(1), cbor::Value::Bytes(id(4).into_bytes().to_vec())),
                (cbor::Value::UInt(2), cbor::Value::UInt(3)),
                (cbor::Value::UInt(3), cbor::Value::Bytes(id(5).into_bytes().to_vec())),
                (cbor::Value::UInt(4), cbor::Value::Text("/tmp".into())),
            ]),
            3,
        );
        workspace.validate().expect("valid session spec");

        let mut route = Object::new(id(9), ObjectType::ROUTE, 1).expect("route");
        put_field(&mut route, 1, cbor::Value::Text("jump".into()), 1);
        put_field(&mut route, 2, cbor::Value::UInt(1), 2);
        assert!(route.validate().is_err());
        put_field(&mut route, 3, cbor::Value::Array(vec![]), 3);
        route.validate().expect("valid jump route");

        let mut trust = Object::new(id(10), ObjectType::TRUST_RECORD, 1).expect("trust record");
        assert!(trust.validate().is_err());
        put_field(&mut trust, 2, cbor::Value::Text("*.example.com".into()), 1);
        trust.validate().expect("pattern trust record");
    }
}
