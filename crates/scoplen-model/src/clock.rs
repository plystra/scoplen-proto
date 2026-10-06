// SPDX-License-Identifier: Apache-2.0
//! `UUIDv7` identifiers and hybrid logical clocks for replicated objects.

#![allow(clippy::cast_possible_truncation, clippy::doc_markdown, clippy::missing_errors_doc)]

use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;
use uuid::Uuid;

/// The largest physical timestamp representable in the 48-bit HLC prefix.
pub const MAX_PHYSICAL_MILLIS: u64 = (1 << 48) - 1;
/// The maximum permitted wall-clock lead over the server clock.
pub const MAX_FORWARD_SKEW_MILLIS: u64 = 24 * 60 * 60 * 1_000;

/// Errors produced while creating or advancing clock values.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum ClockError {
    /// The physical component does not fit in the wire format.
    #[error("physical clock value is outside the 48-bit range")]
    PhysicalOverflow,
    /// The logical counter cannot be advanced without moving physical time.
    #[error("logical clock value overflowed")]
    CounterOverflow,
    /// A local wall clock is more than 24 hours ahead of the server.
    #[error("local clock is more than 24 hours ahead of the server")]
    ForwardSkew,
    /// A UUID used in the object model was not generated as `UUIDv7`.
    #[error("identifier is not a UUIDv7")]
    NotUuidV7,
    /// The system clock is before the Unix epoch.
    #[error("system clock is before the Unix epoch")]
    SystemTime,
}

/// A hybrid logical clock encoded as physical milliseconds followed by a 16-bit counter.
///
/// The wire representation is an unsigned integer: `physical_millis << 16 | counter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hlc(u64);

impl Hlc {
    /// Construct a clock from its two wire components.
    pub const fn new(physical_millis: u64, counter: u16) -> Result<Self, ClockError> {
        if physical_millis > MAX_PHYSICAL_MILLIS {
            return Err(ClockError::PhysicalOverflow);
        }
        Ok(Self((physical_millis << 16) | counter as u64))
    }

    /// Construct a clock directly from its wire value.
    pub const fn from_wire(value: u64) -> Result<Self, ClockError> {
        if value >> 16 > MAX_PHYSICAL_MILLIS {
            return Err(ClockError::PhysicalOverflow);
        }
        Ok(Self(value))
    }

    /// Return the wire representation used by the object envelope.
    #[must_use]
    pub const fn to_wire(self) -> u64 {
        self.0
    }

    /// Return the physical millisecond component.
    #[must_use]
    pub const fn physical_millis(self) -> u64 {
        self.0 >> 16
    }

    /// Return the logical counter component.
    #[must_use]
    pub const fn counter(self) -> u16 {
        self.0 as u16
    }

    /// Return the first local clock at a wall-clock instant.
    pub const fn at(physical_millis: u64) -> Result<Self, ClockError> {
        Self::new(physical_millis, 0)
    }

    /// Advance a local clock for a write at `now_millis`.
    pub fn tick(previous: Option<Self>, now_millis: u64) -> Result<Self, ClockError> {
        let Some(previous) = previous else {
            return Self::at(now_millis);
        };
        let physical = previous.physical_millis().max(now_millis);
        if physical > MAX_PHYSICAL_MILLIS {
            return Err(ClockError::PhysicalOverflow);
        }
        if physical > previous.physical_millis() {
            return Self::at(physical);
        }
        if previous.counter() == u16::MAX {
            return Self::new(physical.checked_add(1).ok_or(ClockError::PhysicalOverflow)?, 0);
        }
        Self::new(physical, previous.counter() + 1)
    }

    /// Advance a local clock after observing a remote clock during merge.
    pub fn observe(
        previous: Option<Self>,
        remote: Self,
        now_millis: u64,
    ) -> Result<Self, ClockError> {
        let physical =
            now_millis.max(previous.map_or(0, Self::physical_millis)).max(remote.physical_millis());
        if physical > MAX_PHYSICAL_MILLIS {
            return Err(ClockError::PhysicalOverflow);
        }

        let counter = match (
            previous.filter(|clock| clock.physical_millis() == physical),
            (remote.physical_millis() == physical).then_some(remote),
        ) {
            (Some(local), Some(remote)) => local.counter().max(remote.counter()),
            (Some(local), None) => local.counter(),
            (None, Some(remote)) => remote.counter(),
            (None, None) => 0,
        };
        if counter == u16::MAX {
            return Self::new(physical.checked_add(1).ok_or(ClockError::PhysicalOverflow)?, 0);
        }
        Self::new(physical, counter + 1)
    }
}

/// Return the current Unix time in milliseconds.
pub fn system_time_millis() -> Result<u64, ClockError> {
    let duration =
        SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| ClockError::SystemTime)?;
    u64::try_from(duration.as_millis()).map_err(|_| ClockError::PhysicalOverflow)
}

/// Create a UUIDv7 using the system clock.
pub fn new_uuid_v7() -> Result<Uuid, ClockError> {
    let id = Uuid::now_v7();
    validate_uuid_v7(id)?;
    Ok(id)
}

/// Ensure an identifier is a UUIDv7 value before it enters the object model.
pub fn validate_uuid_v7(id: Uuid) -> Result<(), ClockError> {
    if id.get_version_num() == 7 { Ok(()) } else { Err(ClockError::NotUuidV7) }
}

/// Reject a local write when the wall clock leads the server by more than 24 hours.
pub fn ensure_write_clock(local_millis: u64, server_millis: u64) -> Result<(), ClockError> {
    if local_millis.saturating_sub(server_millis) > MAX_FORWARD_SKEW_MILLIS {
        Err(ClockError::ForwardSkew)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_logical_counter_when_wall_clock_does_not_move() {
        let first = Hlc::tick(None, 100).expect("first clock");
        let second = Hlc::tick(Some(first), 100).expect("second clock");
        assert_eq!(first.physical_millis(), 100);
        assert_eq!(first.counter(), 0);
        assert_eq!(second.counter(), 1);
    }

    #[test]
    fn counter_rollover_moves_physical_time() {
        let first = Hlc::new(100, u16::MAX).expect("clock");
        let next = Hlc::tick(Some(first), 100).expect("clock after rollover");
        assert_eq!(next, Hlc::new(101, 0).expect("rolled clock"));
    }

    #[test]
    fn observe_is_after_remote_and_local() {
        let local = Hlc::new(100, 4).expect("local");
        let remote = Hlc::new(100, 9).expect("remote");
        let merged = Hlc::observe(Some(local), remote, 100).expect("merged");
        assert_eq!(merged, Hlc::new(100, 10).expect("next clock"));
    }

    #[test]
    fn rejects_more_than_one_day_of_forward_skew() {
        assert_eq!(
            ensure_write_clock(MAX_FORWARD_SKEW_MILLIS + 1, 0),
            Err(ClockError::ForwardSkew)
        );
        ensure_write_clock(MAX_FORWARD_SKEW_MILLIS, 0).expect("boundary is accepted");
    }

    #[test]
    fn generated_identifier_is_uuidv7() {
        validate_uuid_v7(new_uuid_v7().expect("UUIDv7")).expect("UUIDv7 validation");
    }
}
