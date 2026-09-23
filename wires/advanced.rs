//! `wires advanced`: the plumbing under the four role commands.
//!
//! Everything here worked before the CLI was organized by role and works the
//! same now, one level down: the admin's offline minting and roster commands
//! ([`crate::admin`]), credential import, and publishing to a channel by hand
//! ([`crate::channel::publish`]). `tail` is kept, hidden, as an alias of the
//! observer's `wires watch`.

use clap::{Args, Subcommand};

use crate::admin::{import, keys, roster, stringify};
use crate::channel::{publish, watch};
use crate::{exit_with, runtime};

/// `wires advanced <command>`.
#[derive(Args)]
pub(crate) struct AdvancedArgs {
    #[command(subcommand)]
    pub(crate) cmd: Advanced,
}

/// The plumbing commands.
#[derive(Subcommand)]
pub(crate) enum Advanced {
    /// Generate (or re-derive) the node + root keys and print their seeds + ids.
    Keygen(keys::KeygenArgs),
    /// Mint a capability grant and print its base64 ticket.
    Grant(keys::GrantArgs),
    /// Mint a fabric membership and print its base64 token.
    Member(keys::MemberArgs),
    /// Author the fabric roster (add/remove members, sign a committed head).
    Roster(roster::RosterArgs),
    /// Add a subject to the CRL (keystore by default) and print the result.
    Revoke(keys::RevokeArgs),
    /// Install credentials (membership, inclusion proof, roster head, sealed
    /// fabric key) into the keystore.
    Import(import::ImportArgs),
    /// Publish a message to a topic (through a resident `wires watch`, or
    /// one-shot when none is running).
    Publish(publish::PublishArgs),
    /// The old name of `wires watch`.
    #[command(hide = true)]
    Tail(watch::WatchArgs),
}

/// Run one plumbing command and exit the way it always has: offline commands
/// print to stdout or fail with `wires: <message>` and exit 1; the channel
/// commands exit 77 on a refusal.
pub(crate) fn run(a: AdvancedArgs) {
    match a.cmd {
        Advanced::Publish(a) => {
            if let Err(e) = runtime().block_on(publish::publish_cmd(a)) {
                exit_with(e);
            }
        }
        Advanced::Tail(a) => {
            if let Err(e) = runtime().block_on(watch::watch_cmd(a)) {
                exit_with(e);
            }
        }
        offline => match run_offline(offline) {
            Ok(out) => println!("{out}"),
            Err(e) => {
                eprintln!("wires: {e}");
                std::process::exit(1);
            }
        },
    }
}

/// Run an offline admin subcommand, returning its stdout text.
fn run_offline(command: Advanced) -> Result<String, String> {
    match command {
        Advanced::Keygen(a) => keys::run_keygen_cmd(a).map_err(stringify),
        Advanced::Grant(a) => keys::run_grant_cmd(a),
        Advanced::Member(a) => keys::run_member_cmd(a),
        Advanced::Roster(a) => roster::run_roster_cmd(a),
        Advanced::Revoke(a) => keys::run_revoke_cmd(a).map_err(stringify),
        Advanced::Import(a) => import::run_import_cmd(a).map_err(|e| format!("{e:#}")),
        Advanced::Publish(_) | Advanced::Tail(_) => unreachable!("handled in run"),
    }
}
