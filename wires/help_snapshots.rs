//! Snapshots of what a model reads (card 38): every command's `--help` and
//! `--help-all`, the MCP `instructions` and tool descriptions, and the key
//! error messages, as plain text files under `wires/snapshots/`. A change
//! to any of them is a reviewed diff.
//!
//! Update them after an intended change with
//! `WIRES_BLESS=1 cargo test -p wires help_snapshots`, then read the diff.
//!
//! Also held here: the card's size rules (`wires --help` and each caller
//! command's `--help` fit in 25 lines; every command's first line is under
//! 80 characters) and the premise's (under 90 words, "network" and
//! "service", no "fabric" or "tool").

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use clap::{Command, CommandFactory};
use library::{Refusal, RoleName, ServiceName, StateVersion};

use crate::Cli;
use crate::caller::lock::Refused;
use crate::help;
use crate::host::gate::{
    GateRefusal, HOST_MISCONFIGURED, IDP_UNREACHABLE, NOT_ADMITTED, TOKEN_UNVERIFIED,
};

/// The commands a caller runs: `wires --help` lists exactly these.
const CALLER: &[&str] = &[
    "services", "call", "login", "join", "id", "watch", "inbox", "mcp",
];

/// Where the snapshots live.
fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("snapshots")
}

/// Compare `actual` with the snapshot `name` (or write it, under
/// `WIRES_BLESS`). Returns the mismatch, if any, so one run reports all.
fn check(name: &str, actual: &str) -> Option<String> {
    let path = dir().join(name);
    if std::env::var_os("WIRES_BLESS").is_some() {
        std::fs::create_dir_all(dir()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return None;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_default();
    (expected != actual).then(|| {
        format!(
            "{name} differs (WIRES_BLESS=1 to update):\n--- snapshot\n{expected}\n--- now\n{actual}"
        )
    })
}

/// The command line `wires` parses.
fn cli() -> Command {
    help::with_help_all(Cli::command())
}

/// `wires <path…> --help`, exactly as printed.
fn help_of(path: &[&str]) -> String {
    let mut args = vec!["wires"];
    args.extend_from_slice(path);
    args.push("--help");
    match cli().try_get_matches_from(args) {
        Err(e) if e.kind() == clap::error::ErrorKind::DisplayHelp => e.to_string(),
        other => panic!("`{path:?} --help` did not print help: {:?}", other.err()),
    }
}

/// `wires <path…> --help-all`, exactly as printed.
fn help_all_of(path: &[&str]) -> String {
    let mut args: Vec<OsString> = vec!["wires".into()];
    args.extend(path.iter().map(OsString::from));
    args.push("--help-all".into());
    help::help_all(cli(), &args).expect("--help-all is asked for")
}

/// Every command path (visible or not), depth first: `["call"]`,
/// `["service", "add"]`, …
fn paths() -> Vec<Vec<String>> {
    fn walk(cmd: &Command, at: &[String], out: &mut Vec<Vec<String>>) {
        for sub in cmd.get_subcommands() {
            if sub.get_name() == "help" || sub.get_name() == "dev-mock-idp" {
                continue;
            }
            let mut path = at.to_vec();
            path.push(sub.get_name().to_owned());
            out.push(path.clone());
            walk(sub, &path, out);
        }
    }
    let mut out = Vec::new();
    walk(&cli(), &[], &mut out);
    out
}

/// Whether the command at `path` hides a flag (so `--help-all` shows more).
fn hides(path: &[String]) -> bool {
    let mut cmd = cli();
    cmd.build();
    let mut at = &cmd;
    for p in path {
        at = at.find_subcommand(p).unwrap();
    }
    at.get_arguments()
        .any(|a| a.is_hide_set() && a.get_long().is_some())
}

#[test]
fn every_help_text_matches_its_snapshot() {
    let mut diffs = Vec::new();
    diffs.extend(check("wires.txt", &help_of(&[])));
    diffs.extend(check("wires.all.txt", &help_all_of(&[])));
    for path in paths() {
        let p: Vec<&str> = path.iter().map(String::as_str).collect();
        let name = p.join("-");
        diffs.extend(check(&format!("{name}.txt"), &help_of(&p)));
        if hides(&path) {
            diffs.extend(check(&format!("{name}.all.txt"), &help_all_of(&p)));
        }
    }
    assert!(diffs.is_empty(), "{}", diffs.join("\n\n"));
}

/// The MCP server's `instructions` and its fixed tool descriptions.
#[test]
fn mcp_text_matches_its_snapshot() {
    use crate::caller::mcp;
    let text = format!(
        "instructions:\n{}\n\nsearch_services / call_service: {}\n",
        mcp::instructions(),
        mcp::REFUSAL_HINT
    );
    if let Some(d) = check("mcp-server.txt", &text) {
        panic!("{d}");
    }
}

/// The key error messages: what a caller hears when it can't go on, each
/// ending with the next step.
#[test]
fn error_messages_match_their_snapshot() {
    let svc = ServiceName::new("orders-db").unwrap();
    let analyst = RoleName::new("analyst").unwrap();
    let v = StateVersion(7);
    let registry = |refusal| GateRefusal::Registry {
        refusal,
        version: v,
    };
    let refusals = [
        NOT_ADMITTED.to_owned(),
        registry(Refusal::NotInRole {
            service: svc.clone(),
            allow: vec![analyst.clone()],
            principal: Some("sec@audit.example".into()),
        })
        .to_string(),
        registry(Refusal::NotInRole {
            service: svc.clone(),
            allow: vec![analyst.clone()],
            principal: None,
        })
        .to_string(),
        registry(Refusal::UnknownService(svc.clone())).to_string(),
        registry(Refusal::NobodyAllowed(svc.clone())).to_string(),
        GateRefusal::NotAssigned {
            service: svc.clone(),
            version: v,
        }
        .to_string(),
        GateRefusal::AlsoRequire {
            service: svc.clone(),
            roles: vec![analyst.clone()],
            principal: Some("alice@example.com".into()),
        }
        .to_string(),
        GateRefusal::Unvouched { version: v }.to_string(),
        TOKEN_UNVERIFIED.to_owned(),
        IDP_UNREACHABLE.to_owned(),
        HOST_MISCONFIGURED.to_owned(),
    ];
    let mut lines: Vec<String> = refusals
        .iter()
        .map(|r| format!("wires: {} [exit 77]", help::refusal(r)))
        .collect();
    let call = crate::caller::call::not_callable;
    lines.push(format!("wires: {} [exit 1]", call(&svc, true)));
    lines.push(format!("wires: {} [exit 1]", call(&svc, false)));
    for refused in [
        Refused::Flag("--node-seed"),
        Refused::Env("WIRES_NODE_SEED"),
        Refused::Stdin,
    ] {
        lines.push(format!("wires: {refused} [exit 2]"));
    }
    lines.push(format!("wires: {} [exit 1]", help::NOT_JOINED));
    let ks = crate::admin::keystore::Keystore::at("/home/me/.wires");
    let Err(no_key) = crate::admin::keystore::node_identity_in(&ks) else {
        panic!("no key there");
    };
    lines.push(format!("wires: {} [exit 1]", help::brief(&no_key)));
    let Err(bad_token) = crate::caller::join::join_in(&ks, "not-a-token", 0) else {
        panic!("not a token");
    };
    lines.push(format!("wires: {} [exit 1]", help::brief(&bad_token)));
    use crate::caller::services::empty_note;
    lines.push(empty_note(None, false, 7));
    lines.push(empty_note(None, true, 7));
    lines.push(empty_note(Some("payroll"), true, 7));
    let text = lines.join("\n\n") + "\n";
    if let Some(d) = check("errors.txt", &text) {
        panic!("{d}");
    }
    // Every one names its next step.
    for l in &lines {
        assert!(
            help::has_next_step(l) || l.contains("drop it") || l.contains("instead"),
            "no next step: {l}"
        );
    }
}

/// `wires --help` lists exactly the caller's commands; `--help-all` lists
/// every visible one, under a role.
#[test]
fn the_listings_match_the_commands() {
    let listed = |template: &str| -> Vec<String> {
        let mut v: Vec<String> = template
            .lines()
            .filter_map(|l| l.strip_prefix("  "))
            .filter_map(|l| l.split_whitespace().next())
            .filter(|w| *w != "wires")
            .map(str::to_owned)
            .collect();
        v.sort();
        v
    };
    let mut visible: Vec<String> = Cli::command()
        .get_subcommands()
        .filter(|c| !c.is_hide_set())
        .map(|c| c.get_name().to_owned())
        .collect();
    visible.sort();
    assert_eq!(listed(help::HELP_ALL_TEMPLATE), visible);
    let mut caller: Vec<String> = CALLER.iter().map(|s| s.to_string()).collect();
    caller.sort();
    assert_eq!(listed(help::HELP_TEMPLATE), caller);
}

/// Card 38's size rules.
#[test]
fn help_is_terse() {
    let top = help_of(&[]);
    assert!(top.lines().count() <= 25, "{top}");
    for c in CALLER {
        let h = help_of(&[c]);
        assert!(h.lines().count() <= 25, "wires {c} --help:\n{h}");
    }
    for path in paths() {
        let p: Vec<&str> = path.iter().map(String::as_str).collect();
        let h = help_of(&p);
        let first = h.lines().next().unwrap();
        assert!(first.chars().count() < 80, "wires {p:?}: {first}");
        assert!(!first.ends_with('.'), "wires {p:?}: {first}");
        assert!(
            h.contains("Example"),
            "wires {p:?} --help has no example:\n{h}"
        );
    }
}

/// The premise: under 90 words, in the words agents see everywhere.
#[test]
fn the_premise_is_short_and_in_the_right_words() {
    let words = help::PREMISE.split_whitespace().count();
    assert!(words < 90, "{words} words");
    let lower = help::PREMISE.to_lowercase();
    for w in ["network", "service", "exit 77"] {
        assert!(lower.contains(w), "{w}");
    }
    for w in ["fabric", "tool", "substrate", "capability"] {
        assert!(!lower.contains(w), "{w}");
    }
    assert!(help_of(&[]).starts_with(help::PREMISE));
    assert!(crate::caller::mcp::instructions().starts_with(&help::one_line(help::PREMISE)));
    assert!(crate::caller::services::empty_note(None, true, 1).starts_with(help::PREMISE));
}

/// A refusal's next step is added only when the host's reason has none.
#[test]
fn a_refusal_gets_one_next_step() {
    assert_eq!(
        help::refusal("not a member of this network"),
        "denied by host: not a member of this network; don't retry: ask your admin for access"
    );
    let login = "your ID token could not be verified; run `wires login`";
    assert_eq!(help::refusal(login), format!("denied by host: {login}"));
    assert!(help::refusal("unknown service: x").ends_with("see `wires services`"));
}

/// Without `--verbose`, an error prints up to its first next step, or its
/// outermost message and root cause: never the whole stack.
#[test]
fn brief_errors_stop_at_the_next_step() {
    let e = anyhow::anyhow!("timed out")
        .context("dialing 0123abcd")
        .context("calling orders-db");
    assert_eq!(help::brief(&e), "calling orders-db: timed out");
    let e = anyhow::anyhow!("timed out")
        .context("no directory answered; run `wires login`")
        .context("refreshing");
    assert_eq!(
        help::brief(&e),
        "refreshing: no directory answered; run `wires login`"
    );
    assert_eq!(help::brief(&anyhow::anyhow!("one")), "one");
}
