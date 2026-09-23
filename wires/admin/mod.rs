//! The **admin** role: holds the root key and decides who is in.
//!
//! Today that is the offline plumbing under `wires advanced` — keys, grants,
//! memberships, the committed roster, the CRL, and installing what the admin
//! hands out. `wires init` / `invite` / `remove` (card 14) will be built on
//! these and live in this folder.
//!
//! - [`keystore`] — the on-disk home: keys, credentials, the keyring, and the
//!   flag → env → file → keystore resolution every command uses.

pub mod keystore;
