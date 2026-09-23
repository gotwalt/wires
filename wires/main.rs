//! `wires` — run a CLI on another machine from your agent.
//!
//! The binary is organized by the four roles in `docs/board/README.md`, one
//! folder each, and this file is only argument parsing and dispatch:
//!
//! - **admin** ([`admin`]) — holds the root key and decides who is in. Its
//!   offline plumbing sits under `wires advanced` ([`advanced`]).
//! - **host** ([`host`]) — `wires serve`: runs CLIs, decides what is exposed
//!   and who may call, and records every call on the channel.
//! - **caller** ([`caller`]) — `wires login | call | tools | mcp`: runs remote
//!   CLIs (`mcp` is the adapter for clients that only speak MCP).
//! - **observer** — `wires watch`: streams the channel ([`channel`], which
//!   every role meets on).
//!
//! Secrets resolve through flag → env → `--…-file` → on-disk
//! keystore ([`admin::keystore`]), so once the admin's credentials are
//! installed, `wires call <tool>` and `wires mcp` need no other flags — which
//! is what lets `wires mcp` drop straight into an MCP client's config as
//! `"command": "wires"`.
//!
//! `call` keeps stdout **byte-pure** (only the remote CLI's bytes): every
//! diagnostic goes to stderr, and the exit code carries the outcome — the
//! child's own code on success, [`EXIT_DENIED`] when the responder refused the
//! credentials, `1` for any local or transport failure.

mod admin;
mod advanced;
mod caller;
mod channel;
mod host;
mod state;

/// The money-shot integration tests of spec §9 — the whole stack over
/// hermetic loopback, in one place because none of them belongs to a single
/// module's seam.
///
/// Declared `#[cfg(test)]` rather than carrying an inner `#![cfg(test)]`: the
/// `srcs = glob(["**/*.rs"])` in `BUILD` hands `e2e/` to both the binary and
/// the test target, and gating the `mod` item is what keeps it out of the
/// shipped binary entirely instead of compiling to an empty module.
#[cfg(test)]
mod e2e;

/// Fixtures shared by more than one role's unit tests.
#[cfg(test)]
mod testutil;

#[cfg(feature = "dev-mock-idp")]
use std::io::Write as _;

#[cfg(feature = "dev-mock-idp")]
use clap::Args;
use clap::{Parser, Subcommand};

/// The top-level help, grouped by role.
///
/// Hand-written because clap cannot put subcommands under more than one
/// heading; `tests::help_lists_every_visible_command` keeps it in step with
/// [`Command`].
const HELP_TEMPLATE: &str = "\
{about-with-newline}
{usage-heading} {usage}

Admin — decides who's in (holds the root key):
  init      Start a fabric: root key, this node, the first commit, a channel
  invite    Add a node and print its one join token; re-key the channel
  remove    Drop a node; re-key the channel so the rest carry on untouched
  service   Register services: add / set / rm (name, allowed roles, hosts)
  role      Define roles from IdP identity: set / rm
  advanced  Plumbing: memberships, roster, import, publish

Host — decides what runs and who may run it:
  serve     Expose CLIs as named tools; verify every caller; record every call
  push      Send a caller a message by key (to its inbox); recorded on the channel

Caller — runs remote CLIs (every role joins the same way):
  id        Print this node's id: what you send the admin
  join      Install the admin's invite token: credentials, channel, peers
  login     Sign in with your IdP, binding this node's key to your identity
  services  List the services you may call, and the role that lets you
  call      Run a service by name: stdio passes through, its exit code is ours
  mcp       Serve those services as MCP tools over stdio (compatibility)
  inbox     Read what hosts pushed to you; --wait blocks until something arrives

Observer — watches calls:
  watch     Stream a channel: every call, refusal and identity as it happens

Options:
{options}";

/// wires: run a CLI on another machine, reached by key, with every call on an
/// encrypted channel.
#[derive(Parser)]
#[command(name = "wires", version, about, help_template = HELP_TEMPLATE)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Every top-level command. The doc comments are each command's own `--help`
/// summary; the top-level listing is [`HELP_TEMPLATE`].
#[derive(Subcommand)]
enum Command {
    // --- admin ---
    /// Start a fabric: create the root key and this machine's node key, add
    /// this node to the roster, commit, and record the channel.
    Init(admin::init::InitArgs),
    /// Add a node to the roster and print its join token (stdout); the
    /// commit is published on the channel so current members adopt it.
    Invite(admin::invite::InviteArgs),
    /// Remove a node (by `--name` label or id); the commit is published on the
    /// channel, and every host that adopts it refuses the node's next call.
    Remove(admin::invite::RemoveArgs),
    /// Edit the service registry in the signed state, and push it.
    Service(admin::service::ServiceArgs),
    /// Edit the role definitions in the signed state, and push them.
    Role(admin::service::RoleArgs),
    /// Plumbing for every role: memberships, the roster, credential import,
    /// and publishing to a channel.
    Advanced(advanced::AdvancedArgs),

    // --- host ---
    /// Expose CLIs as named tools, verify every caller, exec the tool, bridge
    /// its stdio — and, with a `channel` in host.json, record every call.
    Serve(host::serve::ServeArgs),
    /// Send a caller a message, addressed by its key (a tool's
    /// `$WIRES_CALLER_NODE`) or a role: through this machine's running
    /// `wires serve`, to the caller's inbox; recorded on the channel.
    Push(host::push::PushArgs),

    // --- caller (and every joiner) ---
    /// Print this node's id (creating its key on first use): what a joiner
    /// sends the admin.
    Id,
    /// Install an invite token from `wires invite`: membership, proof, head,
    /// fabric key, the channel and its bootstrap peers. Without a token,
    /// print this node's id.
    Join(caller::join::JoinArgs),
    /// Sign in with your IdP (OIDC), binding this node's key to your identity;
    /// the token is stored locally and presented when you call.
    Login(caller::login::LoginArgs),
    /// List the services you may call (evaluated locally against the signed
    /// state), with what each does and the role that admits you.
    Services(caller::services::ServicesArgs),
    /// Run a service by name (or a `tools.json` alias): stdio passes through,
    /// its exit code becomes ours, a refusal exits 77.
    Call(caller::call::CallArgs),
    /// The old name of `wires services`; `add` / `list` / `rm` edit the local
    /// aliases in `tools.json`.
    #[command(hide = true)]
    Tools(caller::tools::ToolsArgs),
    /// Serve the services you may call (plus aliases) as MCP tools over stdio
    /// (for clients that only speak MCP).
    Mcp(caller::mcp::McpArgs),
    /// Print what hosts pushed to you (verified sender first), and mark it
    /// read; `--wait` blocks until something arrives (exit 124 on
    /// `--timeout`).
    Inbox(caller::inbox::InboxArgs),

    // --- observer ---
    /// Join a channel and stream it: every call record, refusal and identity
    /// claim, as it happens.
    Watch(channel::watch::WatchArgs),

    /// Dev build only: run the hermetic mock OIDC issuer on a loopback port
    /// until killed. Prints `issuer <url>` and `client_id <id>` on stdout.
    #[cfg(feature = "dev-mock-idp")]
    #[command(hide = true)]
    DevMockIdp(DevMockIdpArgs),
}

/// `dev-mock-idp` arguments (dev build only).
#[cfg(feature = "dev-mock-idp")]
#[derive(Args)]
struct DevMockIdpArgs {
    /// The email every sign-in resolves to.
    #[arg(long)]
    email: String,
}

/// `dev-mock-idp`: serve [`caller::mock_idp::MockIdp`] until the process is
/// killed.
#[cfg(feature = "dev-mock-idp")]
async fn dev_mock_idp_cmd(a: DevMockIdpArgs) -> anyhow::Result<()> {
    let idp = caller::mock_idp::MockIdp::start(&a.email).await;
    println!("issuer {}", idp.issuer.as_str());
    println!("client_id {}", idp.client_id);
    std::io::stdout().flush()?;
    std::future::pending::<()>().await;
    Ok(())
}

/// Exit code for an authorization refusal by the responder (sysexits
/// `EX_NOPERM`), distinct from 1 = local/transport failure. An agent running
/// `wires call` can tell "you are not allowed" apart from "the network is
/// down" without parsing text.
const EXIT_DENIED: i32 = 77;

/// Current unix time in seconds.
pub(crate) fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Build a multi-threaded tokio runtime for the network subcommands.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("building tokio runtime")
}

/// Initialize tracing for the network subcommands, writing to **stderr** so it
/// never corrupts a command's piped stdout.
///
/// The default filter is [`LOG_FILTER`]: wires' own startup / accept /
/// reject lines print, while iroh's relay and discovery chatter stays out of an
/// MCP client's server-log pane. `$RUST_LOG` overrides it entirely (e.g.
/// `RUST_LOG=iroh=debug`).
fn init_logging() {
    init_logging_with(LOG_FILTER);
}

/// [`init_logging`] for the dialing commands (`call`, `tools`, `mcp`), whose
/// stderr belongs to the remote CLI, and the admin's one-shot commands
/// (`init`, `invite`, `remove`), whose brief channel node would otherwise
/// print mesh admission WARNs: [`QUIET_LOG_FILTER`] by default, so a
/// successful run leaves nothing of wires' own on stderr but its notes.
fn init_quiet_logging() {
    init_logging_with(QUIET_LOG_FILTER);
}

/// The default log filter of the long-running commands.
const LOG_FILTER: &str = "warn,wires=info";

/// The default log filter of the dialing commands: only warnings from wires
/// itself, and iroh (plus `iroh_*`, which the target prefix also matches)
/// entirely off — its endpoint teardown logs `ERROR … relay_recv_channel
/// closed` at the end of every perfectly normal call. The channel node a cold
/// call joins to read the directory (card 15) keeps only its errors: its mesh
/// chatter is not the remote CLI's stderr.
const QUIET_LOG_FILTER: &str = "warn,iroh=off,wires::channel=error";

/// Install the stderr subscriber with `default` unless `$RUST_LOG` is set.
fn init_logging_with(default: &str) {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default)),
        )
        .with_writer(std::io::stderr)
        .try_init();
}

fn main() {
    match Cli::parse().command {
        Command::Init(a) => {
            init_quiet_logging();
            print_or_exit(admin::init::init_cmd(a))
        }
        Command::Invite(a) => {
            init_quiet_logging();
            match runtime().block_on(admin::invite::invite_cmd(a)) {
                Ok(report) => print_report(report),
                Err(e) => exit_with(e),
            }
        }
        Command::Remove(a) => {
            init_quiet_logging();
            match runtime().block_on(admin::invite::remove_cmd(a)) {
                Ok(report) => print_report(report),
                Err(e) => exit_with(e),
            }
        }
        Command::Service(a) => {
            init_quiet_logging();
            match runtime().block_on(admin::service::service_cmd(a)) {
                Ok(report) => print_report(report),
                Err(e) => exit_with(e),
            }
        }
        Command::Role(a) => {
            init_quiet_logging();
            match runtime().block_on(admin::service::role_cmd(a)) {
                Ok(report) => print_report(report),
                Err(e) => exit_with(e),
            }
        }
        Command::Id => print_or_exit(caller::join::id_cmd()),
        Command::Join(a) => print_or_exit(caller::join::join_cmd(a)),
        Command::Advanced(a) => advanced::run(a),
        Command::Serve(a) => {
            if let Err(e) = runtime().block_on(host::serve::serve_cmd(a)) {
                eprintln!("wires: {e:#}");
                std::process::exit(1);
            }
        }
        Command::Push(a) => {
            init_quiet_logging();
            match runtime().block_on(host::push::push_cmd(a)) {
                Ok(code) => std::process::exit(code),
                Err(e) => exit_with(e),
            }
        }
        Command::Inbox(a) => {
            init_quiet_logging();
            runtime().block_on(state::sync::refresh_cold());
            match runtime().block_on(caller::inbox::inbox_cmd(a)) {
                Ok(code) => std::process::exit(code),
                Err(e) => exit_with(e),
            }
        }
        Command::Login(a) => {
            if let Err(e) = runtime().block_on(caller::login::login_cmd(a)) {
                exit_with(e);
            }
        }
        Command::Call(a) => {
            init_quiet_logging();
            runtime().block_on(state::sync::refresh_cold());
            match runtime().block_on(caller::call::call_cmd(a)) {
                Ok(code) => std::process::exit(code),
                Err(e) => exit_with(e),
            }
        }
        Command::Services(a) => {
            init_quiet_logging();
            match runtime().block_on(caller::services::run(&a)) {
                Ok(out) if out.is_empty() => {}
                Ok(out) => println!("{out}"),
                Err(e) => exit_with(e),
            }
        }
        Command::Tools(a) => {
            init_quiet_logging();
            runtime().block_on(state::sync::refresh_cold());
            match runtime().block_on(caller::tools::tools_cmd(a)) {
                Ok(out) if out.is_empty() => {}
                Ok(out) => println!("{out}"),
                Err(e) => {
                    eprintln!("wires: {e:#}");
                    std::process::exit(1);
                }
            }
        }
        Command::Mcp(a) => {
            init_quiet_logging();
            runtime().block_on(state::sync::refresh_cold());
            if let Err(e) = runtime().block_on(caller::mcp::mcp_cmd(a)) {
                eprintln!("wires: {e:#}");
                std::process::exit(1);
            }
        }
        // Keeps stdout for messages and reports the same way `call` does —
        // including exit 77 when the refusal came from the roster rather than
        // from the network.
        Command::Watch(a) => {
            if let Err(e) = runtime().block_on(channel::watch::watch_cmd(a)) {
                exit_with(e);
            }
        }
        #[cfg(feature = "dev-mock-idp")]
        Command::DevMockIdp(a) => {
            if let Err(e) = runtime().block_on(dev_mock_idp_cmd(a)) {
                exit_with(e);
            }
        }
    }
}

/// Print an offline command's result on stdout, or its error and exit 1.
fn print_or_exit(result: anyhow::Result<String>) {
    match result {
        Ok(out) => println!("{out}"),
        Err(e) => {
            eprintln!("wires: {e:#}");
            std::process::exit(1);
        }
    }
}

/// Print an admin command's notes on stderr and its result on stdout (the
/// token, for `invite` — so `$(wires invite …)` is the token alone).
fn print_report(report: admin::invite::Report) {
    for note in &report.notes {
        eprintln!("wires: {note}");
    }
    println!("{}", report.stdout);
}

/// Report a network-command failure and exit.
///
/// An authorization refusal is its own outcome: print the responder's own
/// words and exit [`EXIT_DENIED`], not the generic 1. The downcast walks
/// anyhow's context chain, so a `Denied` wrapped in "peer X refused this node's
/// admission" still lands here.
fn exit_with(e: anyhow::Error) -> ! {
    if let Some(d) = e.downcast_ref::<host::transport::Denied>() {
        eprintln!("wires: denied by responder: {}", d.reason());
        std::process::exit(EXIT_DENIED);
    }
    eprintln!("wires: {e:#}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;
    use clap::error::ErrorKind;

    use super::*;

    /// Every command a user can see is listed, under a role, in the
    /// hand-written top-level help — and nothing else is.
    #[test]
    fn help_lists_every_visible_command() {
        let cli = Cli::command();
        let mut visible: Vec<&str> = cli
            .get_subcommands()
            .filter(|c| !c.is_hide_set())
            .map(|c| c.get_name())
            .collect();
        let mut listed: Vec<&str> = HELP_TEMPLATE
            .lines()
            .filter_map(|l| l.strip_prefix("  "))
            .filter_map(|l| l.split_whitespace().next())
            .collect();
        visible.sort_unstable();
        listed.sort_unstable();
        assert_eq!(
            visible, listed,
            "HELP_TEMPLATE is out of step with `Command`"
        );
    }

    /// The top-level help names the four roles and fits on one screen.
    #[test]
    fn help_shows_the_four_roles_on_one_screen() {
        let help = Cli::command().render_help().to_string();
        for role in ["Admin", "Host", "Caller", "Observer"] {
            assert!(help.contains(&format!("{role} — ")), "{help}");
        }
        let lines = help.lines().count();
        assert!(lines <= 32, "{lines} lines:\n{help}");
        // The plumbing is not on it.
        for plumbing in ["member", "roster", "import", "tail"] {
            assert!(
                !help.contains(&format!("  {plumbing} ")),
                "{plumbing} is listed:\n{help}"
            );
        }
    }

    /// Card 14's onboarding commands parse as documented.
    #[test]
    fn onboarding_commands_parse() {
        let id = "ab".repeat(32);
        assert!(Cli::try_parse_from(["wires", "init"]).is_ok());
        assert!(Cli::try_parse_from(["wires", "init", "--channel", "eng", "--ttl", "7d"]).is_ok());
        assert!(Cli::try_parse_from(["wires", "init", "--ttl", "soon"]).is_err());
        assert!(Cli::try_parse_from(["wires", "invite", &id, "--name", "alice"]).is_ok());
        assert!(
            Cli::try_parse_from(["wires", "invite", &id, "--peer", "t1", "--peer", "t2"]).is_ok()
        );
        assert!(Cli::try_parse_from(["wires", "invite"]).is_err());
        assert!(Cli::try_parse_from(["wires", "remove", "alice"]).is_ok());
        assert!(Cli::try_parse_from(["wires", "id"]).is_ok());
        assert!(Cli::try_parse_from(["wires", "join"]).is_ok());
        assert!(Cli::try_parse_from(["wires", "join", "tok"]).is_ok());
        // `watch` needs no topic once a channel is joined.
        assert!(Cli::try_parse_from(["wires", "watch"]).is_ok());
    }

    #[test]
    fn connect_is_gone() {
        assert!(Cli::try_parse_from(["wires", "connect", "--target", "00"]).is_err());
    }

    /// The plumbing that used to be top-level now lives under `advanced`, and
    /// `tail` is `watch` (with `advanced tail` kept as a hidden alias).
    #[test]
    fn plumbing_is_under_advanced() {
        for old in ["member", "roster", "import", "publish", "tail"] {
            assert!(
                Cli::try_parse_from(["wires", old, "--help"])
                    .is_err_and(|e| e.kind() == ErrorKind::InvalidSubcommand),
                "`wires {old}` still parses at top level"
            );
            assert!(
                Cli::try_parse_from(["wires", "advanced", old, "--help"])
                    .is_err_and(|e| e.kind() == ErrorKind::DisplayHelp),
                "`wires advanced {old}` is missing"
            );
        }
        assert!(Cli::try_parse_from(["wires", "watch", "ops"]).is_ok());
    }

    /// Card 25: grants, the CRL and loose key generation are gone (`wires
    /// id` / `init` make keys; roster removal replaces revocation).
    #[test]
    fn removed_plumbing_is_gone() {
        for gone in ["keygen", "grant", "revoke"] {
            assert!(
                Cli::try_parse_from(["wires", "advanced", gone, "--help"])
                    .is_err_and(|e| e.kind() == ErrorKind::InvalidSubcommand),
                "`wires advanced {gone}` still parses"
            );
        }
    }
}
