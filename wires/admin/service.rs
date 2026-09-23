//! `wires service add | rm | set` (card 27, lane **27a**): the admin edits
//! the registry, signs a new state version, and pushes it (hosts first).
//!
//! ```text
//! wires service add orders-db --host workbench --allow analyst --description "Read-only SQL"
//! wires service set orders-db --host workbench --host spare     # failover
//! wires service rm  orders-db
//! ```

// Nothing calls these until lane 27a adds the subcommand to `main.rs`.
#![allow(dead_code)]

use anyhow::Result;
use library::{NodeId, RoleName, ServiceName};

use crate::admin::keystore::Keystore;

/// A change to one registry entry. `None` fields keep the current value
/// (`set`); `add` requires the service not to exist, `set` requires it to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ServiceEdit {
    /// The service's description.
    pub(crate) description: Option<String>,
    /// Its `allow` roles, replacing the list.
    pub(crate) allow: Option<Vec<RoleName>>,
    /// Its hosts, replacing the list (each must be a host member).
    pub(crate) hosts: Option<Vec<NodeId>>,
    /// Its record readers, replacing the list.
    pub(crate) readers: Option<Vec<RoleName>>,
}

/// `wires service add <name>`: register a new service, sign, push.
pub(crate) async fn add(ks: &Keystore, name: ServiceName, edit: ServiceEdit) -> Result<()> {
    let _ = (ks, name, edit);
    todo!("27a: service add")
}

/// `wires service set <name>`: change an existing service, sign, push.
pub(crate) async fn set(ks: &Keystore, name: ServiceName, edit: ServiceEdit) -> Result<()> {
    let _ = (ks, name, edit);
    todo!("27a: service set")
}

/// `wires service rm <name>`: drop a service, sign, push.
pub(crate) async fn rm(ks: &Keystore, name: ServiceName) -> Result<()> {
    let _ = (ks, name);
    todo!("27a: service rm")
}
