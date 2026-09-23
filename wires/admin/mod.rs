//! The **admin** role: holds the root key and decides who is in.
//!
//! `wires init` / `invite` / `remove` (card 14) are the whole job: start a
//! fabric, admit a node with one token, drop one — each commit published on
//! the channel as a re-key, so no member imports anything by hand. Under them
//! is the offline plumbing of `wires advanced` — memberships, the committed
//! roster, and installing what the admin hands out.
//!
//! - [`init`] — `wires init`: root key, node key, first commit, channel.
//! - [`invite`] — `wires invite` (one token per joiner) and `wires remove`.
//! - [`commit`] — the commit both run: sign, publish the re-key, install.
//! - [`keystore`] — the on-disk home: keys, credentials, the keyring, and the
//!   flag → env → file → keystore resolution every command uses.
//! - [`keys`] — `member`.
//! - [`roster`] — `roster add | remove | commit | head`.
//! - [`import`] — installing the credentials the admin hands out.

pub mod commit;
pub mod import;
pub mod init;
pub mod invite;
pub mod keys;
pub mod keystore;
pub mod roster;

/// Render any error as a string for the admin-command error channel.
pub(crate) fn stringify<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}
