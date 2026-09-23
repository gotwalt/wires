//! `wires services` (card 27, lane **27b**): the services this caller may
//! call, evaluated **locally** against its signed state and its own verified
//! identity; no network, no broadcast. Services it can't call are not shown.
//!
//! ```text
//! $ wires services
//! orders-db   Read-only SQL against the orders database   (analyst)
//! status      Build and deploy status                     (member)
//! ```

// Nothing calls this until lane 27b adds the subcommand to `main.rs`.
#![allow(dead_code)]

use anyhow::Result;
use library::{Grant, State};

/// Run `wires services` (`--json`: one object per service).
pub(crate) fn run(json: bool) -> Result<()> {
    let _ = json;
    todo!("27b: wires services")
}

/// The listing: one line per grant, `name  description  (role)`, columns
/// aligned, in name order.
pub(crate) fn render(state: &State, grants: &[Grant]) -> String {
    let _ = (state, grants);
    todo!("27b: render the listing")
}
