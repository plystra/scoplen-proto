// SPDX-License-Identifier: Apache-2.0
//! Pure merge and referential-integrity helpers for K-1 objects.

#![allow(clippy::doc_markdown, clippy::missing_errors_doc)]

use std::{collections::HashSet, hash::BuildHasher};

use thiserror::Error;
use uuid::Uuid;

use crate::{FieldEntry, ModelError, Object, Tombstone, cbor::Value, object::FieldPath};

/// Merge two objects with the same identifier.
///
/// Field clocks are compared first and the bytewise UUID of the origin breaks ties. Equal
/// clocks and origins with different values are a protocol violation rather than an arbitrary
/// conflict. Unknown fields and future type numbers are preserved.
pub fn merge(local: &Object, remote: &Object) -> Result<Object, MergeError> {
    local.validate().map_err(MergeError::Model)?;
    remote.validate().map_err(MergeError::Model)?;
    if local.id != remote.id {
        return Err(MergeError::IdentityMismatch { local: local.id, remote: remote.id });
    }
    if local.object_type != remote.object_type {
        return Err(MergeError::TypeMismatch {
            local: local.object_type,
            remote: remote.object_type,
        });
    }

    let mut merged = local.clone();
    merged.schema = local.schema.max(remote.schema);
    merged.fields.clear();
    let mut paths = local.fields.keys().cloned().collect::<Vec<_>>();
    paths.extend(remote.fields.keys().filter(|path| !local.fields.contains_key(path)).cloned());
    paths.sort();
    for path in paths {
        let entry = match (local.fields.get(&path), remote.fields.get(&path)) {
            (Some(left), Some(right)) => choose_entry(&path, left, right)?,
            (Some(left), None) => left.clone(),
            (None, Some(right)) => right.clone(),
            (None, None) => unreachable!("path came from one of the two field maps"),
        };
        merged.fields.insert(path, entry);
    }
    merged.tombstone = choose_tombstone(local.tombstone, remote.tombstone);
    Ok(merged)
}

/// Return the object references that must resolve before an object can be shown.
#[must_use]
pub fn references(object: &Object) -> Vec<Uuid> {
    let mut references = Vec::new();
    let mut add_scalar = |field| {
        if let Some(entry) = object.field(field) {
            if let Value::Bytes(bytes) = &entry.value {
                if let Ok(id) = uuid(bytes) {
                    references.push(id);
                }
            }
        }
    };
    match object.object_type {
        crate::ObjectType::ACCESS_PROFILE => {
            add_scalar(1);
            add_scalar(4);
            if let Some(entry) = object.field(5) {
                if let Value::Bytes(bytes) = &entry.value {
                    if let Ok(id) = uuid(bytes) {
                        references.push(id);
                    }
                }
            }
        }
        crate::ObjectType::HOST => {
            for (path, _) in object.field_entries(5) {
                if let FieldPath::MapEntry { key: crate::MapKey::Bytes(bytes), .. } = path {
                    if let Ok(id) = uuid(bytes) {
                        references.push(id);
                    }
                }
            }
        }
        crate::ObjectType::ROUTE => {
            add_scalar(5);
            add_scalar(7);
            if let Some(entry) = object.field(3) {
                if let Value::Array(values) = &entry.value {
                    for value in values {
                        if let Value::Bytes(bytes) = value {
                            if let Ok(id) = uuid(bytes) {
                                references.push(id);
                            }
                        }
                    }
                }
            }
        }
        crate::ObjectType::TRUST_RECORD => {
            add_scalar(1);
            add_scalar(7);
            add_scalar(8);
        }
        crate::ObjectType::FORWARD => {
            add_scalar(5);
            add_scalar(7);
        }
        crate::ObjectType::WORKSPACE => {
            for (path, entry) in object.field_entries(3) {
                if let FieldPath::MapEntry { .. } = path {
                    if let Value::Array(values) = &entry.value {
                        for value in values {
                            if let Value::Bytes(bytes) = value {
                                if let Ok(id) = uuid(bytes) {
                                    references.push(id);
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    references.sort_unstable();
    references.dedup();
    references
}

/// Return whether any reference in an object points to a missing live object.
pub fn is_orphaned<S: BuildHasher>(object: &Object, live_ids: &HashSet<Uuid, S>) -> bool {
    !object.is_tombstoned() && references(object).iter().any(|id| !live_ids.contains(id))
}

/// Errors returned by a merge operation.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum MergeError {
    /// The two objects do not have the same identifier.
    #[error("cannot merge object {local} with object {remote}")]
    IdentityMismatch { local: Uuid, remote: Uuid },
    /// The two objects have the same ID but different immutable type numbers.
    #[error("object type mismatch: {local} versus {remote}")]
    TypeMismatch {
        /// Local object type.
        local: crate::ObjectType,
        /// Remote object type.
        remote: crate::ObjectType,
    },
    /// Equal clock and origin carried different values.
    #[error("field {path:?} has conflicting values at the same clock and origin")]
    Conflict { path: FieldPath },
    /// One input was not a valid object.
    #[error("invalid object: {0}")]
    Model(ModelError),
}

fn choose_entry(
    path: &FieldPath,
    left: &FieldEntry,
    right: &FieldEntry,
) -> Result<FieldEntry, MergeError> {
    match left.clock.cmp(&right.clock) {
        std::cmp::Ordering::Greater => Ok(left.clone()),
        std::cmp::Ordering::Less => Ok(right.clone()),
        std::cmp::Ordering::Equal => match left.origin.as_bytes().cmp(right.origin.as_bytes()) {
            std::cmp::Ordering::Greater => Ok(left.clone()),
            std::cmp::Ordering::Less => Ok(right.clone()),
            std::cmp::Ordering::Equal if left.value == right.value => Ok(left.clone()),
            std::cmp::Ordering::Equal => Err(MergeError::Conflict { path: path.clone() }),
        },
    }
}

fn choose_tombstone(left: Option<Tombstone>, right: Option<Tombstone>) -> Option<Tombstone> {
    match (left, right) {
        (None, value) | (value, None) => value,
        (Some(left), Some(right)) => match left.clock.cmp(&right.clock) {
            std::cmp::Ordering::Greater => Some(left),
            std::cmp::Ordering::Less => Some(right),
            std::cmp::Ordering::Equal => {
                match left.origin.as_bytes().cmp(right.origin.as_bytes()) {
                    std::cmp::Ordering::Greater | std::cmp::Ordering::Equal => Some(left),
                    std::cmp::Ordering::Less => Some(right),
                }
            }
        },
    }
}

fn uuid(bytes: &[u8]) -> Result<Uuid, ()> {
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| ())?;
    let id = Uuid::from_bytes(bytes);
    crate::clock::validate_uuid_v7(id).map_err(|_| ())?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FieldEntry, ObjectType, cbor::Value, clock::Hlc};

    fn id(seed: u8) -> Uuid {
        let mut bytes = [0; 16];
        bytes[0] = seed;
        bytes[6] = 0x70;
        bytes[8] = 0x80;
        Uuid::from_bytes(bytes)
    }

    fn object(value: &str, clock: u64, origin: u8) -> Object {
        let mut object = Object::new(id(1), ObjectType::HOST, 1).expect("object");
        object
            .insert(
                FieldPath::field(1).expect("path"),
                FieldEntry::new(
                    Value::Text(value.into()),
                    Hlc::at(clock).expect("clock"),
                    id(origin),
                )
                .expect("entry"),
            )
            .expect("insert");
        object
            .insert(
                FieldPath::field(2).expect("path"),
                FieldEntry::new(Value::Text("host".into()), Hlc::at(1).expect("clock"), id(origin))
                    .expect("entry"),
            )
            .expect("insert");
        object
    }

    #[test]
    fn merge_is_commutative_associative_and_idempotent() {
        let left = object("left", 1, 2);
        let mut middle = object("middle", 2, 3);
        middle.schema = 2;
        let right = object("right", 3, 4);
        let lm = merge(&left, &middle).expect("merge");
        let ml = merge(&middle, &left).expect("merge");
        assert_eq!(lm, ml);
        assert_eq!(lm.schema, 2);
        assert_eq!(merge(&left, &left).expect("idempotent"), left);
        assert_eq!(
            merge(&merge(&left, &middle).expect("left-middle"), &right).expect("associative"),
            merge(&left, &merge(&middle, &right).expect("middle-right")).expect("associative")
        );
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/baseline.json");
        let vector = scoplen_test_vectors::VectorDocument::from_path(path)
            .expect("vectors")
            .vectors
            .into_iter()
            .find(|vector| vector.kind == "model.merge")
            .expect("merge vector");
        assert_eq!(vector.expected, "higher-clock");
        assert_eq!(
            merge(&left, &middle).expect("higher clock").required_text(1).expect("merged name"),
            "middle"
        );
    }

    #[test]
    fn equal_clock_and_origin_with_different_values_is_a_conflict() {
        let left = object("left", 1, 2);
        let right = object("right", 1, 2);
        assert!(matches!(
            merge(&left, &right),
            Err(MergeError::Conflict { path: FieldPath::Field(1) })
        ));
    }

    #[test]
    fn newer_field_resurrects_object_and_missing_reference_is_orphaned() {
        let mut deleted = object("old", 1, 2);
        deleted.set_tombstone(Some(
            Tombstone::new(Hlc::at(3).expect("clock"), id(3)).expect("tombstone"),
        ));
        let mut restored = object("new", 4, 2);
        restored.set_tombstone(deleted.tombstone);
        let merged = merge(&deleted, &restored).expect("merge");
        assert!(merged.is_resurrected());
        assert!(!merged.is_tombstoned());

        let mut profile = Object::new(id(5), ObjectType::ACCESS_PROFILE, 1).expect("profile");
        for (field, value) in
            [(1, Value::Bytes(id(99).into_bytes().to_vec())), (3, Value::Text("user".into()))]
        {
            profile
                .insert(
                    FieldPath::field(field).expect("path"),
                    FieldEntry::new(value, Hlc::at(field).expect("clock"), id(2)).expect("entry"),
                )
                .expect("insert");
        }
        let live = HashSet::from([profile.id]);
        assert!(is_orphaned(&profile, &live));
    }
}
