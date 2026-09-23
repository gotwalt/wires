//! The admin-signed state on this node (card 27, lane **27a**): where it is
//! kept, and how it moves between nodes.
//!
//! Every role reads it: the caller lists and resolves services from it, the
//! host authorizes calls with it, the admin writes it. Only lane 27a writes
//! these files; the other lanes call [`store::read`] and
//! [`store::adopt_if_newer`].
//!
//! - [`store`] — `$WIRES_HOME/state.json`: read, and adopt a newer verified
//!   copy under a lock (never an older one).
//! - [`sync`] — push to members after an admin change; pull from the admin
//!   or any host when the local copy is stale; the responder side.

pub mod store;
pub mod sync;
