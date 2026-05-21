//! Channel layer over the substrate. Spec:
//! docs/superpowers/specs/2026-05-21-wires-channels-design.md

pub mod types;

/// Version stamp for the channel-layer wire vocabulary. Bumped only when
/// breaking schema changes ship.
pub const MODULE_VERSION: u32 = 1;
