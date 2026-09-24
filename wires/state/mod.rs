//! The admin-signed state on this node: where it is kept, and how it moves
//! between nodes.
//!
//! Every role reads it: the caller lists and resolves services from it, the
//! host authorizes calls with it, the admin writes it. Everything else
//! calls [`store::read`] and
//! [`store::adopt_if_newer`].
//!
//! - [`store`] — `$WIRES_HOME/state.json`: read, and adopt a newer verified
//!   copy under a lock (never an older one).
//! - [`sync`] — push to the hosts after an admin change; pull from a host
//!   (then the admin) when the local copy is stale; the responder side.

pub mod store;
pub mod sync;
