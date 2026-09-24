//! `wires services [query]` (cards 27 and 37): the services this caller may
//! call, read from its **view** (`view.json`, [`crate::caller::view`]): the
//! root-signed entries a directory cut for its verified identity. Services
//! it may not use are not in the view at all.
//!
//! ```text
//! $ wires services
//! orders-db  Read-only SQL against the orders database  (analyst)
//! status     Build and deploy status                    (staff)
//! $ wires services orders
//! orders-db  Read-only SQL against the orders database  (analyst)
//! ```
//!
//! The roles in parentheses are those the service allows (the view names
//! no role's members). A `query` keeps the services whose name or
//! description contains it, ignoring case. Hosts are not shown: a caller
//! addresses a service, never a machine. `--verbose` adds them (`hosts:
//! 51442ef9, 0c1d2e3f`), for debugging.
//!
//! The view is refreshed from a directory first when it is older than a
//! day, its head has expired, or a host reported a newer head
//! ([`HeldView::is_stale`]); otherwise this reads the file and dials
//! nothing. The listing is advisory: the host re-checks everything on every
//! call and is the ground truth.

use anyhow::{Context, Result};
use base64::Engine as _;
use clap::Args;
use library::{Audience, IdentityClaim, Issuer, NodeId, Principal, ViewEntry};
use serde_json::Value;

use crate::admin::keystore::{self, Keystore};
use crate::caller::hello::stored_token;
use crate::caller::jwks::KeyFetcher;
use crate::caller::view::{self, HeldView};

/// `wires services [query] [--json] [--verbose]`.
#[derive(Args, Clone, Debug, Default)]
pub(crate) struct ServicesArgs {
    /// Keep the services whose name or description contains this (any case).
    pub(crate) query: Option<String>,
    /// One JSON object per line (the shape is below).
    #[arg(long)]
    pub(crate) json: bool,
    /// Also show each service's hosts; you never need them to call.
    #[arg(long, short)]
    pub(crate) verbose: bool,
}

/// Verify the ID token `wires login` stored as a claim for `me`. `Ok(None)`:
/// no token stored. The issuer and audience are the token's own (this is the
/// caller reading its own file; the host checks them against its own trust
/// settings).
pub(crate) async fn my_principal(ks: &Keystore, me: NodeId) -> Result<Option<Principal>> {
    let Some(id_token) = stored_token(ks) else {
        return Ok(None);
    };
    let issuer: Issuer = id_token.unverified_issuer()?;
    let audiences = unverified_audiences(id_token.as_str())?;
    let claim = IdentityClaim { node: me, id_token };
    let fetcher = KeyFetcher::new(Some(ks.path(crate::caller::jwks::JWKS_DIR)))?;
    let principal = fetcher
        .verify(&claim, &[issuer], &audiences, crate::clock::now_unix())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(Some(principal))
}

/// The `aud` claim of an unverified JWS (a string or an array of strings).
fn unverified_audiences(jws: &str) -> Result<Vec<Audience>> {
    let payload = jws.split('.').nth(1).context("the ID token is not a JWS")?;
    let bytes = library::B64
        .decode(payload.trim_end_matches('='))
        .context("the ID token's payload is not base64url")?;
    let json: Value = serde_json::from_slice(&bytes).context("the ID token's payload")?;
    Ok(match json.get("aud") {
        Some(Value::String(a)) => vec![Audience::new(a.clone())],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .map(Audience::new)
            .collect(),
        _ => Vec::new(),
    })
}

/// This node's view in `ks`, refreshed first when it is stale (or missing).
/// A refresh that fails leaves the held view, with a note on stderr; with
/// no view at all it is an error.
pub(crate) async fn current_view(ks: &Keystore) -> Result<HeldView> {
    let node = keystore::node_identity_in(ks)?;
    let badge = ks.read_membership()?.context(crate::help::NOT_JOINED)?;
    let held = view::read(ks, badge.fabric)?;
    if let Some(held) = &held
        && !held.is_stale(crate::clock::now_unix())
    {
        return Ok(held.clone());
    }
    match view::refresh_now(ks, &node, &badge, None, false).await {
        Ok(fresh) => Ok(fresh),
        Err(e) => match held {
            Some(held) => {
                eprintln!(
                    "wires services: could not refresh the view ({e:#}); showing policy version {}",
                    held.version().0
                );
                Ok(held)
            }
            None => Err(e),
        },
    }
}

/// Run `wires services`; returns what to print on stdout.
pub(crate) async fn run(a: &ServicesArgs) -> Result<String> {
    let ks = Keystore::resolve()?;
    let held = current_view(&ks).await?;
    let matching = a.query.as_deref().map(|q| held.view.matching(q));
    let entries: Vec<&ViewEntry> = match &matching {
        Some(found) => found.iter().copied().filter(|e| e.call).collect(),
        None => held.callable().collect(),
    };
    if entries.is_empty() {
        let signed_in = stored_token(&ks).is_some();
        eprintln!(
            "{}",
            empty_note(a.query.as_deref(), signed_in, held.version().0)
        );
    }
    if a.json {
        return render_json(&entries, a.verbose);
    }
    Ok(render(&entries, a.verbose))
}

/// What `wires services` prints on stderr when it lists nothing (stdout
/// stays empty): the premise when the whole view is empty (this is where an
/// agent new to wires lands), then why, ending with the next step.
pub(crate) fn empty_note(query: Option<&str>, signed_in: bool, version: u64) -> String {
    let why = match (query, signed_in) {
        (_, false) => {
            "wires services: nothing to list: this node is not signed in; run `wires login`"
                .to_owned()
        }
        (Some(q), true) => {
            return format!(
                "wires services: no service you may call matches {q:?}; run `wires services` \
                 for all of them"
            );
        }
        (None, true) => format!(
            "wires services: no service allows you (policy version {version}); ask your admin \
             for a role that may call one"
        ),
    };
    format!("{}\n\n{why}", crate::help::PREMISE)
}

/// The roles `e`'s service allows, comma-separated.
fn allow(e: &ViewEntry) -> String {
    e.entry
        .service
        .allow
        .iter()
        .map(|r| r.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The listing: one line per entry, `name  description  (roles)`, columns
/// aligned, in name order; `verbose` appends `hosts: …`.
pub(crate) fn render(entries: &[&ViewEntry], verbose: bool) -> String {
    let desc = |e: &ViewEntry| one_line(&e.entry.service.description);
    let name_w = entries
        .iter()
        .map(|e| e.entry.name.as_str().len())
        .max()
        .unwrap_or(0);
    let desc_w = entries
        .iter()
        .map(|e| desc(e).chars().count())
        .max()
        .unwrap_or(0);
    entries
        .iter()
        .map(|e| {
            let d = desc(e);
            let pad = desc_w - d.chars().count();
            let mut line = format!(
                "{:name_w$}  {d}{}  ({})",
                e.entry.name.as_str(),
                " ".repeat(pad),
                allow(e)
            );
            if verbose {
                let hosts: Vec<String> = e.entry.service.hosts.iter().map(NodeId::short).collect();
                line.push_str(&format!("  hosts: {}", hosts.join(", ")));
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `--json`: one object per line.
fn render_json(entries: &[&ViewEntry], verbose: bool) -> Result<String> {
    let mut lines = Vec::new();
    for e in entries {
        let svc = &e.entry.service;
        let line = JsonLine {
            service: e.entry.name.as_str(),
            description: svc.description.as_str(),
            allow: svc.allow.iter().map(|r| r.as_str()).collect(),
            call: e.call,
            read: e.read,
            hosts: svc.hosts.len(),
            host_ids: verbose.then(|| svc.hosts.iter().map(NodeId::hex).collect()),
        };
        lines.push(serde_json::to_string(&line)?);
    }
    Ok(lines.join("\n"))
}

/// One `wires services --json` line (card 38: a stable shape, in this
/// field order; `wires services --help` shows it).
#[derive(serde::Serialize)]
struct JsonLine<'a> {
    /// The service's name: what `wires call` takes.
    service: &'a str,
    /// What it does, from the registry.
    description: &'a str,
    /// The roles that may call it.
    allow: Vec<&'a str>,
    /// Whether you may call it.
    call: bool,
    /// Whether you may read its call records (`wires watch`).
    read: bool,
    /// How many hosts run it.
    hosts: usize,
    /// With `--verbose`: the hosts' node ids.
    #[serde(skip_serializing_if = "Option::is_none")]
    host_ids: Option<Vec<String>>,
}

/// A description on one line (newlines and tabs become spaces).
fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{NodeIdentity, Policy, RoleName, Service, ServiceName, StateVersion, View};

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    fn name(s: &str) -> ServiceName {
        ServiceName::new(s).unwrap()
    }

    /// A view of `orders-db` (analyst) and `status` (staff), both hosted by
    /// node 4, for someone in both roles; `locked` only for readers.
    fn view() -> View {
        let root = NodeIdentity::from_seed([1; 32]);
        let mut s = Policy::new(root.node_id());
        s.version = StateVersion(1);
        s.not_after = i64::MAX;
        let (_, anyone) = crate::testutil::staff_role();
        for role in ["analyst", "staff", "auditor"] {
            s.roles.insert(RoleName::new(role).unwrap(), anyone.clone());
        }
        let svc = |description: &str, allow: &str, readers: &[&str]| Service {
            description: description.into(),
            allow: vec![RoleName::new(allow).unwrap()],
            hosts: vec![node(4)],
            readers: readers.iter().map(|r| RoleName::new(*r).unwrap()).collect(),
        };
        s.services.insert(
            name("orders-db"),
            svc("Read-only SQL against\nthe orders database", "analyst", &[]),
        );
        s.services
            .insert(name("status"), svc("Build and deploy status", "staff", &[]));
        let principal = Principal {
            issuer: crate::testutil::test_idp().issuer.as_str().into(),
            subject: "1".into(),
            email: None,
            org: None,
            groups: vec![],
            not_after: i64::MAX,
        };
        crate::testutil::signed_policy(&root, s).view_for(Some(&principal), None)
    }

    #[test]
    fn the_listing_is_aligned_and_hides_hosts() {
        let v = view();
        let entries: Vec<&ViewEntry> = v.entries.iter().collect();
        let out = render(&entries, false);
        assert_eq!(
            out,
            "orders-db  Read-only SQL against the orders database  (analyst)\n\
             status     Build and deploy status                    (staff)"
        );
        assert!(!out.contains(&node(4).short()));
        assert_eq!(render(&[], false), "");
    }

    #[test]
    fn verbose_shows_hosts() {
        let v = view();
        let entries: Vec<&ViewEntry> = v.entries.iter().collect();
        let out = render(&entries, true);
        for line in out.lines() {
            assert!(
                line.ends_with(&format!("hosts: {}", node(4).short())),
                "{line}"
            );
        }
    }

    /// Card 37: `wires services orders` finds a service by name or by
    /// description.
    #[test]
    fn a_query_finds_a_service_by_name_or_description() {
        let v = view();
        let names = |q: &str| -> Vec<String> {
            v.matching(q)
                .iter()
                .map(|e| e.entry.name.to_string())
                .collect()
        };
        assert_eq!(names("orders"), vec!["orders-db"]);
        assert_eq!(names("DEPLOY"), vec!["status"]);
        assert!(names("payroll").is_empty());
    }

    #[test]
    fn json_is_one_object_per_line() {
        let v = view();
        let entries: Vec<&ViewEntry> = v.entries.iter().collect();
        let out = render_json(&entries, false).unwrap();
        let rows: Vec<Value> = out
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["service"], "orders-db");
        assert_eq!(rows[0]["allow"], serde_json::json!(["analyst"]));
        assert_eq!(rows[0]["call"], true);
        assert_eq!(rows[0]["hosts"], 1);
        // The shape `wires services --help` documents, in its order.
        let first = out.lines().next().unwrap();
        let at: Vec<usize> = ["service", "description", "allow", "call", "read", "hosts"]
            .iter()
            .map(|k| first.find(&format!("\"{k}\":")).unwrap())
            .collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "{first}");
        assert!(!first.contains("host_ids"), "{first}");
        let out = render_json(&entries, true).unwrap();
        assert!(out.contains(&node(4).hex()));
        assert!(out.contains("\"host_ids\""));
    }

    #[test]
    fn audiences_come_from_the_token() {
        let b64 = |v: &str| library::B64.encode(v);
        let one = format!("h.{}.s", b64(r#"{"aud":"client-1"}"#));
        assert_eq!(
            unverified_audiences(&one).unwrap(),
            vec![Audience::new("client-1")]
        );
        let many = format!("h.{}.s", b64(r#"{"aud":["a","b"]}"#));
        assert_eq!(unverified_audiences(&many).unwrap().len(), 2);
        assert!(unverified_audiences("nope").is_err());
    }
}
