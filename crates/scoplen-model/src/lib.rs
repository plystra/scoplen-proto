// SPDX-License-Identifier: Apache-2.0
//! Deterministic object model shared by Scoplen clients and services.

#![forbid(unsafe_code)]

pub mod cbor;
pub mod clock;
pub mod merge;
pub mod object;

pub use clock::{Hlc, ensure_write_clock, new_uuid_v7, system_time_millis, validate_uuid_v7};
pub use merge::{MergeError, is_orphaned, merge, references};
pub use object::{
    AccessError, FieldEntry, FieldPath, MAX_MAP_ENTRIES, MAX_OBJECT_BYTES, MAX_TEXT_BYTES,
    MAX_WORKSPACE_LAYOUT_BYTES, MapKey, ModelError, Object, ObjectType, Tombstone,
};

/// The contract identifier implemented by this crate.
pub const CONTRACT: &str = "K-1";
