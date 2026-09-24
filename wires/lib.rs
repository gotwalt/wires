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
//!   its freshness; hosts and callers fetch from it. It never decides a
//!   call (card 36).
//! - **host** (`host/`) — `wires serve`: implements the services the signed
//!   policy assigns to it, checks every caller against that policy, and keeps
//!   its own log of every call.
//! - **caller** (`caller/`) — `wires login | services | call | mcp | inbox`:
//!   runs remote CLIs by service name (`mcp` serves them as MCP over stdio,
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

Admin — admits nodes and signs what runs where (holds the root key):
  init      Create the root key, this node, and the first signed policy
  invite    Admit a node: mint its badge, print its one join token
  remove    Ban a node; hosts refuse its next call
  service   Register services: add / set / rm (name, allowed roles, hosts)
  role      Define roles from IdP identity: set / rm
  issuer    Trust an IdP: set / rm (its client id, accepted audiences)
  directory Name directories: add / rm; `directory serve` runs one
  state     Re-publish the signed policy to every directory (push)

Host — implements the services assigned to it:
  serve     Run host.json's services; check every caller; log every call
  push      Send a caller a message by key (to its inbox); logged

Caller — runs remote CLIs by service name (every role joins the same way):
  id        Print this node's id: what you send the admin
  join      Install the admin's invite token: membership and signed policy
  login     Sign in with your IdP, binding this node's key to your identity
  services  List the services you may call, and the role that lets you
  call      Run a service by name: stdio passes through, its exit code is ours
  mcp       Serve those services as MCP tools over stdio (Claude Desktop, IDEs)
  gateway   Serve them as a remote MCP server (HTTP + OAuth) for web users
  inbox     Read what hosts pushed to you; --wait blocks until something arrives

Reader — reads the hosts' call records:
  watch     Stream call records from your services' hosts, verified (--mine)

Options:
{options}";

/// wires: run a CLI on another machine by service name, reached by key, with
/// every caller checked against an admin-signed list.
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
    /// Create the root key and this machine's node key, mint this node's
    /// badge, and sign the first policy (trusting one IdP).
    Init(admin::init::InitArgs),
    /// Mint a node's badge and print its join token (stdout). No policy
    /// edit: nothing is published (unless it lifts the node's ban).
    Invite(admin::invite::InviteArgs),
    /// Remove a node (by `--name` label or id): a ban in the signed policy
    /// until its badge expires. It is published to the directories, and
    /// every host that fetches it refuses the node's next call.
    Remove(admin::invite::RemoveArgs),
    /// Edit the service registry in the signed policy, and publish it.
    Service(admin::service::ServiceArgs),
    /// Edit the role definitions in the signed policy, and publish them.
    Role(admin::service::RoleArgs),
    /// Edit the trusted IdPs in the signed policy, and publish them.
    Issuer(admin::service::IssuerArgs),
    /// The directories: `add` / `rm` (admin) edit the policy's list;
    /// `serve` runs this node's directory alone.
    Directory(directory::DirectoryArgs),
    /// The signed policy itself: `push` re-publishes it to every directory
    /// (after an edit that reached none).
    State(admin::propagate::StateArgs),

    // --- host ---
    /// Implement the services host.json names (and the signed policy assigns
    /// here): check every caller, exec the service, bridge its stdio, log
    /// every call. Runs the directory too when the policy lists this node.
    Serve(host::serve::ServeArgs),
    /// Send a caller a message, addressed by its key (a service's
    /// `$WIRES_CALLER_NODE`) or a role: through this machine's running
    /// `wires serve`, to the caller's inbox; logged.
    Push(host::push::PushArgs),

    // --- caller (and every joiner) ---
    /// Print this node's id (creating its key on first use): what a joiner
    /// sends the admin.
    Id,
    /// Install an invite token from `wires invite`: membership and the
    /// signed policy. Without a token, print this node's id.
    Join(caller::join::JoinArgs),
    /// Sign in with your IdP (OIDC), binding this node's key to your identity;
    /// the token is stored locally and presented when you call.
    Login(caller::login::LoginArgs),
    /// List the services you may call (evaluated locally against the signed
    /// policy), with what each does and the role that admits you.
    Services(caller::services::ServicesArgs),
    /// Run a service by name: stdio passes through,
    /// its exit code becomes ours, a refusal exits 77.
    Call(caller::call::CallArgs),
    /// Edit the local aliases in `tools.json` (`add` / `list` / `rm`): a
    /// name pinned to one host by node id.
    #[command(hide = true, subcommand_required = true)]
    Tools(caller::tools::ToolsArgs),
    /// Serve the services you may call (plus aliases) as MCP tools over stdio
    /// (Claude Desktop, IDEs, any stdio MCP client).
    Mcp(caller::mcp::McpArgs),
    /// Print what hosts pushed to you (verified sender first), and mark it
    /// read; `--wait` blocks until something arrives (exit 124 on
    /// `--timeout`).
    Inbox(caller::inbox::InboxArgs),

    /// Serve the services each signed-in user may call as a remote MCP
    /// server (Streamable HTTP + OAuth 2.1), for web clients like Claude.ai.
    Gateway(gateway::GatewayArgs),

    // --- reader ---
    /// Stream call records from the hosts of your services: every record of
    /// a service you are a reader of, otherwise your own.
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
    match Cli::parse().command {
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
        Command::State(a) => {
            init_quiet_logging();
            print_report(runtime().block_on(admin::propagate::state_cmd(a)))
        }
        Command::Id => print_or_exit(caller::join::id_cmd()),
        Command::Join(a) => print_or_exit(caller::join::join_cmd(a)),
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
            exit_with_code(runtime().block_on(async {
                policy::fetch::refresh_cold().await;
                caller::inbox::inbox_cmd(a).await
            }))
        }
        Command::Login(a) => {
            if let Err(e) = runtime().block_on(caller::login::login_cmd(a)) {
                exit_with(e);
            }
        }
        Command::Call(a) => {
            init_quiet_logging();
            exit_with_code(runtime().block_on(async {
                policy::fetch::refresh_cold().await;
                caller::call::call_cmd(a).await
            }))
        }
        Command::Services(a) => {
            init_quiet_logging();
            print_or_exit(runtime().block_on(caller::services::run(&a)))
        }
        Command::Tools(a) => print_or_exit(caller::tools::run_tools_cmd(a)),
        Command::Mcp(a) => {
            init_quiet_logging();
            let served = runtime().block_on(async {
                policy::fetch::refresh_cold().await;
                caller::mcp::mcp_cmd(a).await
            });
            if let Err(e) = served {
                exit_with(e);
            }
        }
        Command::Gateway(a) => {
            init_logging();
            let served = runtime().block_on(async {
                policy::fetch::refresh_cold().await;
                gateway::gateway_cmd(a).await
            });
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
        eprintln!("wires: denied by host: {}", d.reason());
        std::process::exit(EXIT_DENIED);
    }
    eprintln!("wires: {e:#}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

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

    /// The top-level help names the roles and fits on one screen.
    #[test]
    fn help_shows_the_roles_on_one_screen() {
        let help = Cli::command().render_help().to_string();
        for role in ["Admin", "Host", "Caller", "Reader"] {
            assert!(help.contains(&format!("{role} — ")), "{help}");
        }
        let lines = help.lines().count();
        assert!(lines <= 34, "{lines} lines:\n{help}");
    }

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
        // Card 28: `--ttl` is a membership's lifetime, `--state-ttl` the
        // signed policy's.
        assert!(
            Cli::try_parse_from(["wires", "invite", &id, "--ttl", "1h", "--state-ttl", "30d"])
                .is_ok()
        );
        assert!(Cli::try_parse_from(["wires", "init", "--state-ttl", "7d"]).is_ok());
        assert!(Cli::try_parse_from(["wires", "remove", "alice", "--state-ttl", "7d"]).is_ok());
        assert!(Cli::try_parse_from(["wires", "remove", "alice", "--ttl", "7d"]).is_err());
        assert!(Cli::try_parse_from(["wires", "service", "rm", "db", "--state-ttl", "7d"]).is_ok());
        assert!(Cli::try_parse_from(["wires", "service", "rm", "db", "--ttl", "7d"]).is_err());
        assert!(Cli::try_parse_from(["wires", "state", "push"]).is_ok());
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
