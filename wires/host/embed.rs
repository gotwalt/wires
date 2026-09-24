//! The host an app embeds (card 33): build it from a keystore, register
//! native [`Service`]s, and serve.
//!
//! An embedded host is `wires serve` running inside the app. It starts the
//! same way, keeps the same call log, and decides every call by the same
//! admin-signed state. It must be a joined node (`WIRES_HOME=<dir> wires
//! id`, the admin invites it, `WIRES_HOME=<dir> wires join <token>`), and
//! the signed state must assign each of its services to it
//! (`wires service add <name> --host <it>`), or [`Host::serve`] refuses to
//! start, naming the first that isn't.
//!
//! The host's node key is loaded from the keystore into the app's memory and
//! stays there: the API never hands it out, and it is scrubbed when the host
//! drops (see `NodeIdentity` in `library`). Native services are the operator's
//! own code, trusted as much as `wires serve` itself; nothing isolates them
//! from the key the way a CLI child is kept away from it.
//!
//! ```no_run
//! # use tokio::io::AsyncWriteExt;
//! struct Hello;
//!
//! impl wires::Service for Hello {
//!     async fn call(&self, call: wires::Call, mut io: wires::CallIo) -> i32 {
//!         let line = format!("hello, {}\n", call.role());
//!         io.stdout.write_all(line.as_bytes()).await.map_or(1, |()| 0)
//!     }
//! }
//!
//! # async fn run() -> anyhow::Result<()> {
//! wires::Host::builder("/var/lib/hello/wires")
//!     .trust_issuer("https://accounts.google.com", ["476….apps.googleusercontent.com"])
//!     .service("hello", Hello)
//!     .build()?
//!     .serve()
//!     .await
//! # }
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use library::{NodeId, RoleName, ServiceName};

use crate::admin::keystore::Keystore;
use crate::host::config_v2::{HOST_CONFIG_V2, HostConfigV2, IdentityConfig, TrustedIssuer};
use crate::host::native::{NativeServices, Service};
use crate::host::serve::{Binding, Serving, serve_until};

/// A wires host inside an app, ready to serve. Made by [`Host::builder`].
pub struct Host {
    serving: Serving,
}

/// Collects what a [`Host`] implements and trusts; [`build`](Self::build)
/// checks it and reads the keystore.
pub struct HostBuilder {
    home: PathBuf,
    host_json: Option<PathBuf>,
    issuers: Vec<TrustedIssuer>,
    native: Vec<(String, Arc<dyn crate::host::native::DynService>)>,
    push_allow: Option<Vec<String>>,
    relay_url: Option<String>,
    loopback_only: bool,
}

impl Host {
    /// Start building a host whose keystore is `home` (what `$WIRES_HOME` is
    /// for `wires`): its `node.seed`, `membership.json` and signed state.
    /// The host reads nothing from `$WIRES_HOME` or `$WIRES_NODE_SEED`.
    pub fn builder(home: impl Into<PathBuf>) -> HostBuilder {
        HostBuilder {
            home: home.into(),
            host_json: None,
            issuers: Vec::new(),
            native: Vec::new(),
            push_allow: None,
            relay_url: None,
            loopback_only: false,
        }
    }

    /// This host's node id: what the admin names in `wires service add
    /// --host`, and what callers reach it by.
    pub fn node_id(&self) -> NodeId {
        self.serving.node.node_id()
    }

    /// Serve until Ctrl-C.
    pub async fn serve(self) -> Result<()> {
        self.serve_until(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
    }

    /// Serve until `shutdown` resolves. Errors before serving if the signed
    /// state doesn't assign every service to this host (after trying to
    /// pull a newer one), or the call log can't be opened.
    pub async fn serve_until(self, shutdown: impl std::future::Future<Output = ()>) -> Result<()> {
        serve_until(self.serving, async {
            shutdown.await;
            Ok(())
        })
        .await
    }

    /// A host that serves on `endpoint` (already bound for this host's key)
    /// instead of binding its own: for hermetic tests.
    #[cfg(test)]
    pub(crate) fn on_endpoint(mut self, endpoint: iroh::Endpoint) -> Self {
        self.serving.binding = Binding::Endpoint(endpoint);
        self
    }
}

impl HostBuilder {
    /// Also read `path` as `host.json` v2: its CLI services (served beside
    /// the native ones), trusted IdPs, `push` and `audit`. Its `services`
    /// may be empty.
    pub fn host_json(mut self, path: impl Into<PathBuf>) -> Self {
        self.host_json = Some(path.into());
        self
    }

    /// Trust ID tokens from `issuer` (its `iss`, exactly) for the OAuth
    /// client ids in `audiences`, as `host.json`'s `identity.issuers` does.
    /// Every registry role names an issuer, so a host that trusts none
    /// admits nobody.
    pub fn trust_issuer<A: Into<String>>(
        mut self,
        issuer: impl Into<String>,
        audiences: impl IntoIterator<Item = A>,
    ) -> Self {
        self.issuers.push(TrustedIssuer {
            issuer: issuer.into(),
            audiences: audiences.into_iter().map(Into::into).collect(),
        });
        self
    }

    /// Implement service `name` with `service`, in-process.
    pub fn service(mut self, name: impl Into<String>, service: impl Service) -> Self {
        self.native.push((name.into(), Arc::new(service)));
        self
    }

    /// Let the host push to the members of `roles` (from the signed state),
    /// tried in order, as `host.json`'s `push.allow` does: what a native
    /// service's [`Call::push_to_caller`](crate::Call::push_to_caller) needs.
    pub fn push_allow<R: Into<String>>(mut self, roles: impl IntoIterator<Item = R>) -> Self {
        self.push_allow = Some(roles.into_iter().map(Into::into).collect());
        self
    }

    /// Accept direct connections only on this machine's loopback
    /// (`127.0.0.1`, `::1`); callers elsewhere still reach the host through
    /// its relay. For local demos and tests: the host opens no socket on the
    /// network, so the macOS firewall doesn't prompt for it.
    pub fn bind_loopback(mut self) -> Self {
        self.loopback_only = true;
        self
    }

    /// Use a self-hosted relay at `url` instead of n0's.
    pub fn relay_url(mut self, url: impl Into<String>) -> Self {
        self.relay_url = Some(url.into());
        self
    }

    /// Check the configuration and load the keystore: the node key, the
    /// membership. Errors on a bad service name, a name registered twice,
    /// no services at all, an invalid `host.json`, or a keystore that isn't
    /// a joined node's. Whether the signed state assigns the services here
    /// is checked when the host starts to serve.
    pub fn build(self) -> Result<Host> {
        let mut native = NativeServices::new();
        for (name, service) in self.native {
            let name = ServiceName::new(&name).with_context(|| format!("service name {name:?}"))?;
            if native.insert(name.clone(), service).is_some() {
                bail!("service {name} is registered twice");
            }
        }
        let mut config = match &self.host_json {
            Some(path) => HostConfigV2::load_embedded(path)?,
            None => HostConfigV2 {
                version: HOST_CONFIG_V2,
                identity: IdentityConfig::default(),
                services: Default::default(),
                push: None,
                audit: None,
            },
        };
        config.identity.issuers.extend(self.issuers);
        if let Some(roles) = self.push_allow {
            let allow = roles
                .iter()
                .map(|r| RoleName::new(r).with_context(|| format!("push role {r:?}")))
                .collect::<Result<Vec<_>>>()?;
            let push = config.push.get_or_insert_with(Default::default);
            push.allow.extend(allow);
        }
        config.validate_fields()?;
        if config.services.is_empty() && native.is_empty() {
            bail!("nothing is implemented: register a service, or give a host.json that has some");
        }
        let keystore = Keystore::at(&self.home);
        let node = keystore.read_node_identity()?.ok_or_else(|| {
            anyhow!(
                "no node key in {}: run `WIRES_HOME={} wires id`, have the admin invite it, \
                 then `wires join` there",
                self.home.display(),
                self.home.display()
            )
        })?;
        let membership = keystore.read_membership()?.ok_or_else(|| {
            anyhow!(
                "{} holds a node key but no membership: `WIRES_HOME={} wires join <token>`",
                self.home.display(),
                self.home.display()
            )
        })?;
        Ok(Host {
            serving: Serving {
                node,
                membership,
                keystore: Arc::new(keystore),
                config,
                native,
                binding: Binding::N0 {
                    relay_url: self.relay_url,
                    loopback_only: self.loopback_only,
                },
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::native::{Call, CallIo};

    struct Nop;

    impl Service for Nop {
        async fn call(&self, _call: Call, _io: CallIo) -> i32 {
            0
        }
    }

    /// A keystore holding a node key and a membership for it.
    fn joined() -> PathBuf {
        let home = crate::testutil::temp_dir();
        let ks = Keystore::at(&home);
        let root = library::NodeIdentity::from_seed([1u8; 32]);
        let node = library::NodeIdentity::from_seed([9u8; 32]);
        ks.save_node(&node, false).unwrap();
        ks.save_membership(&library::Membership::mint(&root, node.node_id(), 0, i64::MAX).unwrap())
            .unwrap();
        home
    }

    fn err(b: HostBuilder) -> String {
        format!("{:#}", b.build().err().expect("build should fail"))
    }

    #[test]
    fn a_joined_keystore_builds_and_names_its_node() {
        let host = Host::builder(joined()).service("t", Nop).build().unwrap();
        assert_eq!(
            host.node_id(),
            library::NodeIdentity::from_seed([9u8; 32]).node_id()
        );
    }

    #[test]
    fn nothing_to_serve_is_refused() {
        assert!(err(Host::builder(joined())).starts_with("nothing is implemented"));
    }

    #[test]
    fn a_name_twice_or_a_bad_name_is_refused() {
        let twice = Host::builder(joined()).service("t", Nop).service("t", Nop);
        assert_eq!(err(twice), "service t is registered twice");
        assert!(err(Host::builder(joined()).service("Not A Name", Nop)).contains("service name"));
    }

    #[test]
    fn an_unjoined_keystore_says_what_to_run() {
        let empty = crate::testutil::temp_dir();
        assert!(err(Host::builder(&empty).service("t", Nop)).contains("wires id"));
        Keystore::at(&empty)
            .save_node(&library::NodeIdentity::generate(), false)
            .unwrap();
        assert!(err(Host::builder(&empty).service("t", Nop)).contains("wires join"));
    }

    #[test]
    fn issuers_are_validated_like_host_json() {
        let b = Host::builder(joined())
            .service("t", Nop)
            .trust_issuer("https://idp.example", ["a"])
            .trust_issuer("https://idp.example", ["b"]);
        assert!(err(b).contains("listed twice"));
        let no_aud = Host::builder(joined())
            .service("t", Nop)
            .trust_issuer("https://idp.example", Vec::<String>::new());
        assert!(err(no_aud).contains("no audiences"));
    }
}
