//! What a model (or a person) reads first about wires (card 38): the
//! premise paragraph, the top-level help, each command's examples and exit
//! codes, and `--help-all`, which lists the operator and credential flags
//! that plain `--help` hides.
//!
//! The rules the text is held to are card 38's: a verb-first first line
//! under 80 characters, one or two real examples, only what a caller uses
//! (the rest behind `--help-all`), exit codes and output shape stated where
//! they matter, and the same words everywhere ("network", "service", "host").
//! The snapshot tests (`help_snapshots.rs`) keep every change to this text a
//! reviewed diff.

use std::ffi::OsString;

use clap::{Arg, ArgAction, Command};

/// The premise, told once: the preamble of `wires --help`, the MCP
/// `instructions` of `wires mcp` and `wires gateway`, and what an empty
/// `wires services` says. Under 90 words; "network" and "service", never
/// how wires is built.
pub const PREMISE: &str = "\
wires is a network for authenticated remote CLI calls. Each service is a
command-line program on another machine, run by its name, never by host or
address. Every call runs as you: your sign-in is checked against an
admin-signed list of who may call what, and the machine that runs it records
the call. A refusal (\"denied by host\", exit 77) is that policy, not a fault:
don't retry or work around it; ask your admin for access.";

/// What a command that needs a membership says on a node that has none.
pub(crate) const NOT_JOINED: &str = "this node has not joined a network: run `wires id`, send the \
id to your admin, then `wires join <token>` with the token they send";

/// The caller's two commands, after [`PREMISE`] wherever a CLI is the way in
/// (`wires --help`, an empty `wires services`).
pub const CLI_NEXT: &str = "\
`wires services` lists what you may call; `wires call <service> -- <args>` runs one.";

/// `wires --help`: the premise, then only what a caller runs. The admin,
/// host and directory commands are in [`HELP_ALL_TEMPLATE`].
///
/// Hand-written because clap cannot put subcommands under more than one
/// heading; a test keeps both templates in step with the commands.
pub(crate) const HELP_TEMPLATE: &str = "\
{before-help}Usage: wires <COMMAND>

  services  List the services you may call (a word searches them; --json)
  call      Run a service by name; its output and exit code are yours
  login     Sign in with your IdP; every call needs it
  join      Install the invite token your admin sent
  id        Print this node's id, to send your admin for an invite
  watch     Stream the call records you may read
  inbox     Print the messages hosts pushed to you
  mcp       Serve the services you may call as MCP tools over stdio

Examples:
  wires services orders
  wires call orders-db -- \"select count(*) from orders\"

Admin, host and directory commands: wires --help-all";

/// `wires --help-all`: every command, grouped by role.
pub(crate) const HELP_ALL_TEMPLATE: &str = "\
{before-help}Usage: wires <COMMAND>

Caller: runs services by name (every node joins the same way)
  services  List the services you may call (a word searches them; --json)
  call      Run a service by name; its output and exit code are yours
  login     Sign in with your IdP; every call needs it
  join      Install the invite token your admin sent
  id        Print this node's id, to send your admin for an invite
  watch     Stream the call records you may read
  inbox     Print the messages hosts pushed to you
  mcp       Serve the services you may call as MCP tools over stdio
  gateway   Serve them as a remote MCP server (HTTP + OAuth) for web clients

Admin: admits nodes and signs what runs where (holds the root key)
  init      Create the network: the root key, this node, the first policy
  invite    Admit a node: print the join token for its id
  remove    Ban a node; hosts refuse its next call
  service   Register services: add, set, rm (who may call, which hosts)
  role      Define roles from IdP identities: set, rm
  issuer    Trust an IdP: set, rm
  directory Name the network's directories: add, rm; or run one: serve
  state     Re-publish the signed policy (push) or change its settings

Host: implements the services assigned to it
  serve     Run host.json's services; check every caller; log every call
  push      Send a caller a message by its node id or role, to its inbox

Every command takes --help; --help-all also lists its operator flags.";

/// `wires call`: examples and exit codes.
pub(crate) const CALL_AFTER: &str = "\
Examples:
  wires call orders-db -- \"select count(*) from orders\"
  wires call gh --jq '.[].title' -- issue list --json title

Exit: the service's own code. 77: refused by policy, nothing on stdout (don't
retry; ask your admin). 1: a local or transport failure (a service's own 77
is reported as 1). 2: a usage error (a bad --jq, a flag locked mode refuses).";

/// `wires services`: examples and the output shape.
pub(crate) const SERVICES_AFTER: &str = "\
Examples:
  wires services
  wires services orders --json

Output: one service per line, `<name>  <description>  (<roles that may call>)`;
nothing on stdout when none. --json, one object per line:
  {\"service\":\"orders-db\",\"description\":\"…\",\"allow\":[\"analyst\"],\"call\":true,\"read\":false,\"hosts\":2}";

/// `wires login`: examples.
pub(crate) const LOGIN_AFTER: &str = "\
Examples:
  wires login
  wires login --no-browser    # prints the URL to open elsewhere";

/// `wires join`: examples.
pub(crate) const JOIN_AFTER: &str = "\
Examples:
  wires id                    # send the id to your admin; they send a token
  wires join <token>          # then: wires login";

/// `wires id`: examples.
pub(crate) const ID_AFTER: &str = "\
Example:
  wires id                    # send this to your admin: `wires invite <id>`";

/// `wires watch`: examples and output.
pub(crate) const WATCH_AFTER: &str = "\
Examples:
  wires watch orders-db
  wires watch --mine --once

Readers the policy names see a service's calls in full; everyone else sees
their own. Exit 77: every host refused the stream.";

/// `wires inbox`: examples and exit codes.
pub(crate) const INBOX_AFTER: &str = "\
Examples:
  wires inbox
  wires inbox --wait --timeout 10m

Exit: 0 with messages printed (or none, without --wait); 124: --timeout ran out.";

/// `wires mcp`: examples.
pub(crate) const MCP_AFTER: &str = "\
Example, as an MCP client's server entry:
  {\"command\": \"wires\", \"args\": [\"mcp\"]}";

/// `wires gateway`: examples.
pub(crate) const GATEWAY_AFTER: &str = "\
Example:
  wires gateway --public-url https://wires.example.com --client-id <web client id>";

/// `wires init`: examples.
pub(crate) const INIT_AFTER: &str = "\
Example:
  wires init --client-id <desktop client id> --public-client-secret <its secret>";

/// `wires invite`: examples.
pub(crate) const INVITE_AFTER: &str = "\
Example:
  wires invite <node id> --name alice    # prints the token; send it to them";

/// `wires remove`: examples.
pub(crate) const REMOVE_AFTER: &str = "\
Example:
  wires remove alice";

/// `wires service`: examples.
pub(crate) const SERVICE_AFTER: &str = "\
Examples:
  wires service add orders-db --description \"Read-only SQL over the orders database\" \\
    --allow analyst --reader security --host workbench
  wires service rm orders-db";

/// `wires role`: examples.
pub(crate) const ROLE_AFTER: &str = "\
Example:
  wires role set analyst --issuer https://accounts.google.com '*@example.com'";

/// `wires issuer`: examples.
pub(crate) const ISSUER_AFTER: &str = "\
Example:
  wires issuer set https://accounts.google.com --client-id <client id>";

/// `wires directory`: examples.
pub(crate) const DIRECTORY_AFTER: &str = "\
Examples:
  wires directory add workbench
  wires directory serve";

/// `wires state`: examples.
pub(crate) const STATE_AFTER: &str = "\
Examples:
  wires state push
  wires state settings --freshness strict";

/// `wires serve`: examples.
pub(crate) const SERVE_AFTER: &str = "\
Examples:
  wires serve --check host.json
  wires serve host.json";

/// `wires push`: examples.
pub(crate) const PUSH_AFTER: &str = "\
Example:
  wires push --to \"$WIRES_CALLER_NODE\" --subject \"build 42 done\" \"all green\"";

/// The `--help-all` flag's own help line.
const HELP_ALL_HELP: &str = "Also list the operator and credential flags";

/// The command line clap parses: `cli` with the premise before the
/// top-level help, and a `--help-all` flag on the top level and on every
/// command that hides a flag.
pub(crate) fn with_help_all(cli: Command) -> Command {
    let cli = cli.before_help(premise_block());
    add_help_all(cli, true)
}

/// [`PREMISE`] and [`CLI_NEXT`], as the top-level help's preamble.
fn premise_block() -> String {
    format!("{PREMISE}\n{CLI_NEXT}")
}

/// Add `--help-all` to `cmd` (when `always`, or when it hides a flag) and,
/// recursively, to its subcommands.
fn add_help_all(cmd: Command, always: bool) -> Command {
    let hides = cmd
        .get_arguments()
        .any(|a| a.is_hide_set() && a.get_long().is_some());
    let cmd = cmd.mut_subcommands(|c| add_help_all(c, false));
    if always || hides {
        cmd.arg(
            Arg::new("help_all")
                .long("help-all")
                .action(ArgAction::SetTrue)
                .help(HELP_ALL_HELP)
                .display_order(usize::MAX),
        )
    } else {
        cmd
    }
}

/// When `args` asks for `--help-all` (before any `--`), the text to print:
/// the whole command list for `wires --help-all`, else that command's help
/// with every hidden flag shown. `None` when `args` doesn't ask.
pub(crate) fn help_all(mut cli: Command, args: &[OsString]) -> Option<String> {
    let words: Vec<&str> = args
        .iter()
        .skip(1)
        .map(|a| a.to_str().unwrap_or(""))
        .take_while(|a| *a != "--")
        .collect();
    if !words.contains(&"--help-all") {
        return None;
    }
    // The command path: each word that names a subcommand of the last.
    let mut path = Vec::new();
    {
        let mut at = &cli;
        for w in words.iter().filter(|w| !w.starts_with('-')) {
            match at.find_subcommand(w) {
                Some(sub) => {
                    path.push(sub.get_name().to_owned());
                    at = sub;
                }
                None => break,
            }
        }
    }
    if path.is_empty() {
        cli = cli.help_template(HELP_ALL_TEMPLATE);
        return Some(cli.render_help().to_string());
    }
    cli.build();
    let mut at = &mut cli;
    for name in &path {
        at = at.find_subcommand_mut(name).expect("found above");
    }
    let shown = at
        .clone()
        .mut_args(|a| {
            if a.get_id() == "help_all" {
                a
            } else {
                a.hide(false)
            }
        })
        .bin_name(format!("wires {}", path.join(" ")));
    let mut shown = shown;
    Some(shown.render_help().to_string())
}

/// Collapse `text` onto one line (for the MCP `instructions`, which a
/// client shows as one paragraph).
pub fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Whether `text` already names a next step: a command to run, the admin
/// or operator to ask, or to try again.
pub(crate) fn has_next_step(text: &str) -> bool {
    ["`wires ", "admin", "operator", "try again"]
        .iter()
        .any(|m| text.contains(m))
}

/// A host's refusal as the caller reports it (`wires call`'s stderr, an MCP
/// tool result): `denied by host: <reason>`, then the next step when the
/// reason doesn't carry one. The host's own words are never changed.
pub fn refusal(reason: &str) -> String {
    let step = if has_next_step(reason) {
        ""
    } else if reason.starts_with("unknown service") || reason.contains("not assigned to this host")
    {
        "; see `wires services`"
    } else if reason.starts_with("host configuration error") {
        "; try again later, or tell the host's operator"
    } else {
        "; don't retry: ask your admin for access"
    };
    format!("denied by host: {reason}{step}")
}

/// An error as `wires` prints it without `--verbose`: its messages up to
/// and including the first that names a next step, or else the outermost
/// and the root cause. No stack of causes (`--verbose` prints them all).
pub(crate) fn brief(e: &anyhow::Error) -> String {
    let chain: Vec<String> = e.chain().map(ToString::to_string).collect();
    if let Some(i) = chain.iter().position(|m| has_next_step(m)) {
        return chain[..=i].join(": ");
    }
    match chain.as_slice() {
        [] => String::new(),
        [only] => only.clone(),
        [top, .., root] => format!("{top}: {root}"),
    }
}
