//! The admin-signed policy on a node that holds it whole: the admin, the
//! hosts and the directories (card 36). A caller holds only its view
//! ([`crate::caller::view`], card 37).
//!
//! The host authorizes calls with it, the admin writes it, a directory
//! serves it. Everything else calls [`store::read`] and
//! [`store::adopt_if_newer`].
//!
//! - [`store`] — `$WIRES_HOME/policy.json`: read, and adopt a newer verified
//!   copy under a lock (never an older one).
//! - [`fetch`] — publish to the directories after an admin edit; fetch from
//!   a directory at a host's start. The directory itself is
//!   [`crate::directory`].

pub mod fetch;
pub mod store;
