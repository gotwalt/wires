//! The admin-signed policy on this node: where it is kept, and how it moves
//! between nodes (card 36).
//!
//! Every role reads it: the caller lists and resolves services from it, the
//! host authorizes calls with it, the admin writes it. Everything else
//! calls [`store::read`] and [`store::adopt_if_newer`].
//!
//! - [`store`] — `$WIRES_HOME/policy.json`: read, and adopt a newer verified
//!   copy under a lock (never an older one).
//! - [`fetch`] — publish to the directories after an admin edit; fetch from
//!   a directory at a host's start, on its timer, and when a caller's copy
//!   is stale. The directory itself is [`crate::directory`].

pub mod fetch;
pub mod store;
