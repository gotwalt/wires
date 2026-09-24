//! `wires` — run a CLI on another machine from your agent.
//!
//! The crate is organized by role, one folder each. This file is argument
//! parsing and dispatch ([`run`], which `main.rs` calls), plus the public
//! surface an app embeds to serve wires calls in-process (card 33):
//!
//! - **admin** (`admin/`) — holds the root key, mints badges and signs the
//!   policy: which IdPs are trusted, which roles exist, which services run
//!   where and who may call them, who is banned, which nodes are directories.
//! - **directory** (`directory/`) — holds the newest policy and vouches for
//!   its freshness; hosts fetch it whole, and each caller its view (the
//!   services it may use, card 37). It never decides a call (card 36).
//! - **host** (`host/`) — `wires serve`: implements the services the signed
//!   policy assigns to it, checks every caller against that policy, and keeps
//!   its own log of every call.
//! - **caller** (`caller/`) — `wires login | services | call | mcp | inbox`:
//!   holds only its view, and runs remote CLIs by service name (`mcp` serves them as MCP over stdio,
//!   for the MCP clients people already use).
//! - **gateway** (`gateway/`) — `wires gateway`: those services as a
//!   remote MCP server with OAuth, for web clients (Claude.ai), each call
//!   made with the signed-in user's own ID token.
//! - **observer** — `wires watch`: streams call records from the hosts' own
//!   logs, to readers the registry names (card 26b, `caller/watch_records.rs`).
//!
//! `policy/` is where the signed policy lives on every node and how it moves.
//!
//! **Embedding** (card 33): an app serves wires calls in-process by
//! implementing [`Service`] and serving a [`Host`] built from its keystore.
//! To callers, a native service is a CLI like any other. The Python and
//! TypeScript bindings (`bindings/`) are built on the same API, sharing a
//! call's stdio through [`SharedIo`].
//!
//! Secrets resolve through flag → env → `--…-file` → on-disk
//! keystore (`admin/keystore.rs`), so once the admin's credentials are
//! installed, `wires call <service>` and `wires mcp` need no other flags — which
//! is what lets `wires mcp` drop straight into an MCP client's config as
//! `"command": "wires"`.
//!
//! `call` keeps stdout **byte-pure** (only the remote CLI's bytes): every
//! diagnostic goes to stderr, and the exit code carries the outcome — the
//! child's own code on success (a remote `77` is reported as `1`), and
//! `77` (`EXIT_DENIED`) only when the host refused the call, `1` for any local or
//! transport failure.

// The crate calls itself `wires` too, so code written against the public API
// (`examples/kv/store.rs`, which the e2e tests include) compiles inside it.
extern crate self as wires;

mod admin;
mod caller;
mod clock;
mod directory;
mod gateway;
mod help;
mod host;
mod net;
mod policy;

pub use host::embed::{Host, HostBuilder};
pub use host::native::{Call, CallIo, Service, SharedIo};
/// The types a [`Call`] is described in.
pub use library::{CallId, NodeId, Principal, RoleName, ServiceName, StateVersion};

/// The integration tests — the whole stack over hermetic loopback, in one
/// place because none of them belongs to a single module's seam.
///
/// Declared `#[cfg(test)]` so it is out of the shipped binary entirely.
#[cfg(test)]
mod e2e;

/// Fixtures shared by more than one role's unit tests.
#[cfg(test)]
mod testutil;

/// Snapshots of the help text, MCP instructions and key errors (card 38).
#[cfg(test)]
mod help_snapshots;

#[cfg(feature = "dev-mock-idp")]
use std::io::Write as _;

#[cfg(feature = "dev-mock-idp")]
use clap::Args;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

/// The `wires` command line. Its help text is [`help`]'s: the premise, the
/// commands a caller runs, and `--help-all` for the rest.
#[derive(Parser)]
#[command(
    name = "wires",
    version,
    about = "Run a command-line program on another machine, by service name",
    help_template = help::HELP_TEMPLATE
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Every top-level command. Each doc comment is that command's first help
/// line (verb first, under 80 characters); the top-level listings are
/// [`help::HELP_TEMPLATE`] and [`help::HELP_ALL_TEMPLATE`].
#[derive(Subcommand)]
enum Command {
    // --- admin ---
    /// Create the network: the root key, this node's key and badge, the first policy
    #[command(after_help = help::INIT_AFTER)]
    Init(admin::init::InitArgs),
    /// Admit a node: mint its badge and print its join token (edits no policy)
    #[command(after_help = help::INVITE_AFTER)]
    Invite(admin::invite::InviteArgs),
    /// Ban a node until its badge expires; hosts refuse its next call
    #[command(after_help = help::REMOVE_AFTER)]
    Remove(admin::invite::RemoveArgs),
    /// Register services: add, set, rm (who may call and read, which hosts)
    #[command(after_help = help::SERVICE_AFTER)]
    Service(admin::service::ServiceArgs),
    /// Define roles from IdP identities: set, rm
    #[command(after_help = help::ROLE_AFTER)]
    Role(admin::service::RoleArgs),
    /// Trust an IdP: set, rm
    #[command(after_help = help::ISSUER_AFTER)]
    Issuer(admin::service::IssuerArgs),
    /// Name the network's directories (add, rm), or run this node's (serve)
    #[command(after_help = help::DIRECTORY_AFTER)]
    Directory(directory::DirectoryArgs),
    /// Re-publish the signed policy (push), or print or change its settings
    #[command(after_help = help::POLICY_AFTER)]
    Policy(admin::propagate::PolicyArgs),

    // --- host ---
    /// Run host.json's services: check every caller, run the call, log it
    #[command(after_help = help::SERVE_AFTER)]
    Serve(host::serve::ServeArgs),
    /// Send a caller a message by node id or role, to its inbox (logged)
    #[command(after_help = help::PUSH_AFTER)]
    Push(host::push::PushArgs),

    // --- caller (and every joiner) ---
    /// Print this node's id (making its key on first use), for your admin
    #[command(after_help = help::ID_AFTER)]
    Id,
    /// Install the invite token your admin sent (without one, print this node's id)
    #[command(after_help = help::JOIN_AFTER)]
    Join(caller::join::JoinArgs),
    /// Sign in with your IdP, binding your identity to this node's key
    #[command(after_help = help::LOGIN_AFTER)]
    Login(caller::login::LoginArgs),
    /// List the services you may call, one per line (a query searches them)
    #[command(after_help = help::SERVICES_AFTER)]
    Services(caller::services::ServicesArgs),
    /// Run a service by name: its stdin, stdout, stderr and exit code are yours
    #[command(
        after_help = help::CALL_AFTER,
        override_usage = "wires call [OPTIONS] <SERVICE> [-- <ARGS>...]"
    )]
    Call(caller::call::CallArgs),
    /// Edit the local aliases in `tools.json`: add, list, rm
    #[command(
        hide = true,
        subcommand_required = true,
        after_help = "Example:\n  wires tools list"
    )]
    Tools(caller::tools::ToolsArgs),
    /// Serve the services you may call as MCP tools over stdio
    #[command(after_help = help::MCP_AFTER)]
    Mcp(caller::mcp::McpArgs),
    /// Print the messages hosts pushed to you, and mark them read
    #[command(after_help = help::INBOX_AFTER)]
    Inbox(caller::inbox::InboxArgs),

    /// Serve each signed-in user's services as a remote MCP server (HTTP + OAuth)
    #[command(after_help = help::GATEWAY_AFTER)]
    Gateway(gateway::GatewayArgs),

    // --- reader ---
    /// Stream the call records you may read, verified, from the services' hosts
    #[command(after_help = help::WATCH_AFTER)]
    Watch(caller::watch_records::WatchArgs),

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

/// [`init_logging`] for the dialing commands (`call`, `services`, `mcp`),
/// whose stderr belongs to the remote CLI, and the admin's one-shot commands:
/// [`QUIET_LOG_FILTER`] by default, so a successful run leaves nothing of
/// wires' own on stderr but its notes.
fn init_quiet_logging() {
    init_logging_with(QUIET_LOG_FILTER);
}

/// The default log filter of the long-running commands.
const LOG_FILTER: &str = "warn,wires=info";

/// The default log filter of the dialing commands: only warnings from wires
/// itself, and iroh (plus `iroh_*`, which the target prefix also matches)
/// entirely off — its endpoint teardown logs `ERROR … relay_recv_channel
/// closed` at the end of every perfectly normal call.
const QUIET_LOG_FILTER: &str = "warn,iroh=off";

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

/// The `wires` command line: parse the arguments, run the command, exit.
pub fn run() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let cmd = help::with_help_all(Cli::command());
    if let Some(text) = help::help_all(cmd.clone(), &args) {
        print!("{text}");
        std::process::exit(0);
    }
    let matches = cmd.get_matches_from(args);
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    match cli.command {
        Command::Init(a) => {
            init_quiet_logging();
            print_or_exit(admin::init::init_cmd(a))
        }
        Command::Invite(a) => {
            init_quiet_logging();
            print_report(runtime().block_on(admin::invite::invite_cmd(a)))
        }
        Command::Remove(a) => {
            init_quiet_logging();
            print_report(runtime().block_on(admin::invite::remove_cmd(a)))
        }
        Command::Service(a) => {
            init_quiet_logging();
            print_report(runtime().block_on(admin::service::service_cmd(a)))
        }
        Command::Role(a) => {
            init_quiet_logging();
            print_report(runtime().block_on(admin::service::role_cmd(a)))
        }
        Command::Issuer(a) => {
            init_quiet_logging();
            print_report(runtime().block_on(admin::service::issuer_cmd(a)))
        }
        Command::Directory(a) if directory::is_edit(&a) => {
            init_quiet_logging();
            print_report(runtime().block_on(directory::edit_cmd(a)))
        }
        Command::Directory(a) => {
            let directory::DirectoryCmd::Serve(serve) = a.cmd else {
                unreachable!("an edit is dispatched above");
            };
            if let Err(e) = runtime().block_on(directory::serve::serve_cmd(serve)) {
                exit_with(e);
            }
        }
        Command::Policy(a) => {
            init_quiet_logging();
            print_report(runtime().block_on(admin::propagate::policy_cmd(a)))
        }
        Command::Id => print_or_exit(caller::join::id_cmd()),
        Command::Join(a) => {
            init_quiet_logging();
            print_or_exit(runtime().block_on(caller::join::join_cmd(a)))
        }
        Command::Serve(a) => {
            if let Err(e) = runtime().block_on(host::serve::serve_cmd(a)) {
                exit_with(e);
            }
        }
        Command::Push(a) => {
            init_quiet_logging();
            exit_with_code(runtime().block_on(host::push::push_cmd(a)))
        }
        Command::Inbox(a) => {
            init_quiet_logging();
            exit_with_code(runtime().block_on(caller::inbox::inbox_cmd(a)))
        }
        Command::Login(a) => {
            if let Err(e) = runtime().block_on(caller::login::login_cmd(a)) {
                exit_with(e);
            }
        }
        Command::Call(a) => {
            init_quiet_logging();
            set_verbose(a.verbose);
            exit_with_code(runtime().block_on(caller::call::call_cmd(a)))
        }
        Command::Services(a) => {
            init_quiet_logging();
            set_verbose(a.verbose);
            print_or_exit(runtime().block_on(caller::services::run(&a)))
        }
        Command::Tools(a) => print_or_exit(caller::tools::run_tools_cmd(a)),
        Command::Mcp(a) => {
            init_quiet_logging();
            let served = runtime().block_on(caller::mcp::mcp_cmd(a));
            if let Err(e) = served {
                exit_with(e);
            }
        }
        Command::Gateway(a) => {
            init_logging();
            let served = runtime().block_on(gateway::gateway_cmd(a));
            if let Err(e) = served {
                exit_with(e);
            }
        }
        // Exit 77 when every host refused the stream.
        Command::Watch(a) => {
            init_quiet_logging();
            exit_with_code(runtime().block_on(caller::watch_records::watch_cmd(a)))
        }
        #[cfg(feature = "dev-mock-idp")]
        Command::DevMockIdp(a) => {
            if let Err(e) = runtime().block_on(dev_mock_idp_cmd(a)) {
                exit_with(e);
            }
        }
    }
}

/// Print a command's result on stdout (nothing when it is empty), or
/// [`exit_with`] its error.
fn print_or_exit(result: anyhow::Result<String>) {
    match result {
        Ok(out) if out.is_empty() => {}
        Ok(out) => println!("{out}"),
        Err(e) => exit_with(e),
    }
}

/// Exit with a command's own exit code, or [`exit_with`] its error.
fn exit_with_code(result: anyhow::Result<i32>) -> ! {
    match result {
        Ok(code) => std::process::exit(code),
        Err(e) => exit_with(e),
    }
}

/// Print an admin command's notes on stderr and its result on stdout (the
/// token, for `invite` — so `$(wires invite …)` is the token alone). A
/// failure (the new policy reached no directory) is printed last and exits
/// 1: the work is done and stored, but not in force. An error is
/// [`exit_with`].
fn print_report(result: anyhow::Result<admin::Report>) {
    let report = match result {
        Ok(report) => report,
        Err(e) => exit_with(e),
    };
    for note in report.notes.iter().chain(&report.hint) {
        eprintln!("wires: {note}");
    }
    if !report.stdout.is_empty() {
        println!("{}", report.stdout);
    }
    if let Some(failure) = report.failure {
        eprintln!("wires: {failure}");
        std::process::exit(1);
    }
}

/// Report a network-command failure and exit.
///
/// An authorization refusal is its own outcome: print the responder's own
/// words and exit [`EXIT_DENIED`], not the generic 1. The downcast walks
/// anyhow's context chain, so a `Denied` wrapped in "peer X refused this node's
/// admission" still lands here.
fn exit_with(e: anyhow::Error) -> ! {
    if let Some(d) = e.downcast_ref::<host::transport::Denied>() {
        eprintln!("wires: {}", help::refusal(d.reason()));
        std::process::exit(EXIT_DENIED);
    }
    if VERBOSE.load(std::sync::atomic::Ordering::Relaxed) {
        eprintln!("wires: {e:#}");
    } else {
        eprintln!("wires: {}", help::brief(&e));
    }
    std::process::exit(1);
}

/// Set by a command's `--verbose`: [`exit_with`] prints an error's every
/// cause, not just [`help::brief`].
static VERBOSE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Record a command's `--verbose` for [`exit_with`].
fn set_verbose(on: bool) {
    VERBOSE.store(on, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Card 14's onboarding commands parse as documented.
    #[test]
    fn onboarding_commands_parse() {
        let id = "ab".repeat(32);
        assert!(Cli::try_parse_from(["wires", "init"]).is_ok());
        assert!(Cli::try_parse_from(["wires", "init", "--ttl", "7d"]).is_ok());
        assert!(Cli::try_parse_from(["wires", "init", "--ttl", "soon"]).is_err());
        assert!(Cli::try_parse_from(["wires", "invite", &id, "--name", "alice"]).is_ok());
        assert!(Cli::try_parse_from(["wires", "invite"]).is_err());
        assert!(Cli::try_parse_from(["wires", "remove", "alice"]).is_ok());
        // Card 28: `--ttl` is a membership's lifetime, `--policy-ttl` the
        // signed policy's.
        assert!(
            Cli::try_parse_from(["wires", "invite", &id, "--ttl", "1h", "--policy-ttl", "30d"])
                .is_ok()
        );
        assert!(Cli::try_parse_from(["wires", "init", "--policy-ttl", "7d"]).is_ok());
        assert!(Cli::try_parse_from(["wires", "remove", "alice", "--policy-ttl", "7d"]).is_ok());
        assert!(Cli::try_parse_from(["wires", "remove", "alice", "--ttl", "7d"]).is_err());
        assert!(
            Cli::try_parse_from(["wires", "service", "rm", "db", "--policy-ttl", "7d"]).is_ok()
        );
        assert!(Cli::try_parse_from(["wires", "service", "rm", "db", "--ttl", "7d"]).is_err());
        assert!(Cli::try_parse_from(["wires", "policy", "push"]).is_ok());
        assert!(
            Cli::try_parse_from(["wires", "init", "--issuer", "https://i", "--client-id", "c"])
                .is_ok()
        );
        assert!(Cli::try_parse_from(["wires", "directory", "add", "workbench"]).is_ok());
        assert!(Cli::try_parse_from(["wires", "directory", "rm", "workbench"]).is_ok());
        assert!(Cli::try_parse_from(["wires", "directory", "serve"]).is_ok());
        assert!(
            Cli::try_parse_from(["wires", "directory", "serve", "--max-subscribers", "8"]).is_ok()
        );
        assert!(Cli::try_parse_from(["wires", "directory"]).is_err());
        assert!(Cli::try_parse_from(["wires", "id"]).is_ok());
        assert!(Cli::try_parse_from(["wires", "join"]).is_ok());
        assert!(Cli::try_parse_from(["wires", "join", "tok"]).is_ok());
    }
}
