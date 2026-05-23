//! `wires-relay` — self-hosted iroh rendezvous (scaffold).
//!
//! Lets two egress-only nodes with no inbound reachability find a path. The
//! relay loop lands in a later step.

use clap::Parser;

/// wires-relay: self-hosted rendezvous for egress-only nodes.
#[derive(Parser)]
#[command(name = "wires-relay", version, about)]
struct Cli {
    /// Address to listen on (placeholder).
    #[arg(long, default_value = "0.0.0.0:0")]
    listen: String,
}

fn main() {
    let cli = Cli::parse();
    eprintln!(
        "wires-relay (library {}): not implemented (listen={})",
        library::version(),
        cli.listen
    );
}
