//! `wires services` (card 27, lane **27b**): the services this caller may
//! call, evaluated **locally** against its signed state and its own verified
//! identity; no network, no broadcast. Services it can't call are not shown.
//!
//! ```text
//! $ wires services
//! orders-db  Read-only SQL against the orders database  (analyst)
//! status     Build and deploy status                    (staff)
//! ```
//!
//! Hosts are not shown: a caller addresses a service, never a machine.
//! `--verbose` adds them (`hosts: 51442ef9, 0c1d2e3f`), for debugging.
//!
//! The identity is the ID token `wires login` stored, verified with the same
//! JWKS path a host uses (served from the on-disk key cache `login` filled, so
//! normally no network either). The listing is advisory: the host re-checks
//! everything on every call and is the ground truth.

use anyhow::{Context, Result};
use base64::Engine as _;
use clap::Args;
use library::{
    Audience, Grant, IdentityClaim, Issuer, NodeId, Principal, SignedState, State, allowed_services,
};
use serde_json::Value;

use crate::admin::keystore::{self, Keystore};
use crate::caller::hello::stored_token;
use crate::caller::jwks::KeyFetcher;
use crate::state::store;

/// `wires services [--json] [--verbose]`.
#[derive(Args, Clone, Debug, Default)]
pub(crate) struct ServicesArgs {
    /// One JSON object per line: `{service, description, role}` (plus
    /// `hosts` with `--verbose`).
    #[arg(long)]
    pub(crate) json: bool,
    /// Also show each service's hosts (short keys). Callers don't need them.
    #[arg(long, short)]
    pub(crate) verbose: bool,
}

/// What this node may call: its verified principal (if any), the signed state,
/// and the grants that state gives it.
pub(crate) struct Allowed {
    /// The verified stored state.
    pub(crate) state: SignedState,
    /// Who this node verified as; `None`: no usable token.
    pub(crate) principal: Option<Principal>,
    /// The services it may call, in name order.
    pub(crate) grants: Vec<Grant>,
}

/// Evaluate the stored state for this node (`ks`), with its stored identity.
/// Notes on why the identity is missing go to stderr; they don't fail the
/// listing (which is then empty: every role needs a verified identity).
pub(crate) async fn allowed(ks: &Keystore) -> Result<Allowed> {
    let me = keystore::node_identity_in(ks)?.node_id();
    let (_, state) = store::require(ks)?;
    let principal = match my_principal(ks, me).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("wires: your stored identity is not usable ({e:#}); run `wires login`");
            None
        }
    };
    let grants = allowed_services(&state.state, me, principal.as_ref());
    Ok(Allowed {
        state,
        principal,
        grants,
    })
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

/// Run `wires services`; returns what to print on stdout.
pub(crate) async fn run(a: &ServicesArgs) -> Result<String> {
    let ks = Keystore::resolve()?;
    let allowed = allowed(&ks).await?;
    if allowed.grants.is_empty() {
        let who = allowed.principal.as_ref().map(Principal::name);
        eprintln!(
            "wires services: no service allows {} (state v{})",
            who.as_deref().unwrap_or("this node without a login"),
            allowed.state.state.version.0
        );
    }
    if a.json {
        return render_json(&allowed.state.state, &allowed.grants, a.verbose);
    }
    Ok(render(&allowed.state.state, &allowed.grants, a.verbose))
}

/// The listing: one line per grant, `name  description  (role)`, columns
/// aligned, in name order; `verbose` appends `hosts: …`.
pub(crate) fn render(state: &State, grants: &[Grant], verbose: bool) -> String {
    let desc = |g: &Grant| {
        state
            .service(&g.service)
            .map(|s| one_line(&s.description))
            .unwrap_or_default()
    };
    let name_w = grants
        .iter()
        .map(|g| g.service.as_str().len())
        .max()
        .unwrap_or(0);
    let desc_w = grants
        .iter()
        .map(|g| desc(g).chars().count())
        .max()
        .unwrap_or(0);
    grants
        .iter()
        .map(|g| {
            let d = desc(g);
            let pad = desc_w - d.chars().count();
            let mut line = format!(
                "{:name_w$}  {d}{}  ({})",
                g.service.as_str(),
                " ".repeat(pad),
                g.role.as_str()
            );
            if verbose {
                line.push_str(&format!("  hosts: {}", hosts(state, g).join(", ")));
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `--json`: one object per line.
fn render_json(state: &State, grants: &[Grant], verbose: bool) -> Result<String> {
    let mut lines = Vec::new();
    for g in grants {
        let mut obj = serde_json::json!({
            "service": g.service.as_str(),
            "description": state.service(&g.service).map(|s| s.description.clone()).unwrap_or_default(),
            "role": g.role.as_str(),
        });
        if verbose {
            obj["hosts"] = serde_json::json!(
                state
                    .service(&g.service)
                    .map(|s| s.hosts.iter().map(NodeId::hex).collect::<Vec<_>>())
                    .unwrap_or_default()
            );
        }
        lines.push(serde_json::to_string(&obj)?);
    }
    Ok(lines.join("\n"))
}

fn hosts(state: &State, g: &Grant) -> Vec<String> {
    state
        .service(&g.service)
        .map(|s| s.hosts.iter().map(NodeId::short).collect())
        .unwrap_or_default()
}

/// A description on one line (newlines and tabs become spaces).
fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{NodeIdentity, RoleName, Service, ServiceName, StateVersion};

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    fn name(s: &str) -> ServiceName {
        ServiceName::new(s).unwrap()
    }

    fn state() -> State {
        let mut s = State::new(node(1));
        s.version = StateVersion(1);
        let svc = |description: &str| Service {
            description: description.into(),
            allow: vec![RoleName::new("staff").unwrap()],
            hosts: vec![node(4)],
            readers: vec![],
        };
        s.services.insert(
            name("orders-db"),
            svc("Read-only SQL against\nthe orders database"),
        );
        s.services
            .insert(name("status"), svc("Build and deploy status"));
        s
    }

    fn grants() -> Vec<Grant> {
        vec![
            Grant {
                service: name("orders-db"),
                role: RoleName::new("analyst").unwrap(),
            },
            Grant {
                service: name("status"),
                role: RoleName::new("staff").unwrap(),
            },
        ]
    }

    #[test]
    fn the_listing_is_aligned_and_hides_hosts() {
        let out = render(&state(), &grants(), false);
        assert_eq!(
            out,
            "orders-db  Read-only SQL against the orders database  (analyst)\n\
             status     Build and deploy status                    (staff)"
        );
        assert!(!out.contains(&node(4).short()));
        assert_eq!(render(&state(), &[], false), "");
    }

    #[test]
    fn verbose_shows_hosts() {
        let out = render(&state(), &grants(), true);
        for line in out.lines() {
            assert!(
                line.ends_with(&format!("hosts: {}", node(4).short())),
                "{line}"
            );
        }
    }

    #[test]
    fn json_is_one_object_per_line() {
        let out = render_json(&state(), &grants(), false).unwrap();
        let rows: Vec<Value> = out
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["service"], "orders-db");
        assert_eq!(rows[0]["role"], "analyst");
        assert!(rows[0].get("hosts").is_none());
        let out = render_json(&state(), &grants(), true).unwrap();
        assert!(out.contains(&node(4).hex()));
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
