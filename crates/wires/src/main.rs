//! `wires` — the multi-call CLI for the session layer.
//!
//! Scaffold: every subcommand parses but is not yet implemented. Bodies land
//! in later steps (see `docs/new_plan.md`).

use clap::{Parser, Subcommand};

/// wires: a capability-addressed stdio/MCP session layer.
#[derive(Parser)]
#[command(name = "wires", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate node + root keys.
    Keygen,
    /// Mint a capability grant.
    Grant,
    /// Revoke a grant (append to the CRL).
    Revoke,
    /// Operator side of pairing.
    Pair,
    /// Responder: verify a grant, exec a command, bridge its stdio.
    Serve,
    /// Dial a capability and pipe local stdio over the session.
    Connect,
}

fn main() {
    let cli = Cli::parse();
    let name = match cli.command {
        Command::Keygen => "keygen",
        Command::Grant => "grant",
        Command::Revoke => "revoke",
        Command::Pair => "pair",
        Command::Serve => "serve",
        Command::Connect => "connect",
    };
    eprintln!("wires {name} (core {}): not implemented", wires_core::version());
}
