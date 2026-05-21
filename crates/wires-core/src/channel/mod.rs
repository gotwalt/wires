//! Channel layer over the substrate. Spec:
//! docs/superpowers/specs/2026-05-21-wires-channels-design.md

pub mod schemas;
pub mod types;

pub use schemas::{
    ChannelCreate, ChannelInvite, ChannelMemberMeta, TYPE_CREATE, TYPE_INVITE, TYPE_MEMBER_META,
};
pub use types::{ChannelVariant, ChannelView, MemberKind, MemberMeta};

/// Version stamp for the channel-layer wire vocabulary. Bumped only when
/// breaking schema changes ship.
pub const MODULE_VERSION: u32 = 1;
