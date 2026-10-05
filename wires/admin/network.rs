//! `wires network`: print the network string every node joins with.
//!
//! The string ([`library::Network`]) names the root key, the first two
//! directories of the policy's head and the login settings; it is the same
//! for everyone and not secret (protocol §2). On the admin it is built from
//! the stored policy and `login-client.json` each time, so it follows
//! `directory add` and `issuer set --login`; on any other node it is the one
//! `wires join` or `wires login` stored.
//!
//! ```text
//! admin$     wires network                 # one string, for everyone
//! workbench$ wires join <network>          # a host or a directory
//! laptop$    wires login <network>         # a caller: join and sign in
//! ```

use anyhow::{Result, anyhow};
use library::Network;

use super::Report;
use super::keystore::Keystore;
use super::login_client::LoginClient;

/// `network` against the resolved keystore.
pub(crate) fn network_cmd() -> Result<Report> {
    network_in(&Keystore::resolve()?)
}

/// [`network_cmd`] against an explicit keystore: the string on stdout, and
/// on the admin a note when no directory is listed yet (a node can't reach
/// the policy through it then).
pub(crate) fn network_in(ks: &Keystore) -> Result<Report> {
    if ks.read_root_identity()?.is_none() {
        let network = ks.read_network()?.ok_or_else(|| {
            anyhow!(
                "this node has joined no network: run `wires join <network>` (or `wires login \
                 <network>`) with the string your admin prints with `wires network`"
            )
        })?;
        return Ok(Report {
            stdout: network.encode()?,
            ..Report::default()
        });
    }
    let network = admin_network(ks)?;
    let mut report = Report {
        stdout: network.encode()?,
        ..Report::default()
    };
    if network.directories.is_empty() {
        report.notes.push(
            "the policy lists no directory yet, so a node that joins with this string can't \
             reach it: `wires directory add <label>=<node id>` first, then print it again"
                .to_string(),
        );
    }
    Ok(report)
}

/// The admin's network string: its root key, the stored policy's first
/// directories and the login settings ([`LoginClient::settings`]).
pub(crate) fn admin_network(ks: &Keystore) -> Result<Network> {
    let root = ks
        .read_root_identity()?
        .ok_or_else(|| anyhow!("no root key here; run `wires init` first (on the admin)"))?;
    let held = super::service::admin_policy(ks, root.node_id())?;
    let login = LoginClient::load(ks)?
        .settings(&held.policy)
        .ok_or_else(|| {
            anyhow!(
                "the policy trusts no IdP, so nobody could sign in: `wires issuer set <iss> \
                 --client-id <id> --login` first"
            )
        })?;
    Ok(Network::new(
        root.node_id(),
        held.directories().to_vec(),
        login,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::init::{InitArgs, init_in};
    use crate::admin::ttl::Ttl;
    use library::NodeIdentity;

    #[test]
    fn the_admins_string_follows_the_directories_and_a_node_prints_its_own() {
        let admin = Keystore::at(crate::testutil::temp_dir());
        init_in(&admin, InitArgs::default()).unwrap();
        let first = network_in(&admin).unwrap();
        assert!(first.notes[0].contains("no directory"), "{:?}", first.notes);
        let network = Network::decode(&first.stdout).unwrap();
        assert_eq!(
            Some(network.root),
            admin.network_root().unwrap(),
            "it names the root"
        );
        assert_eq!(network.login.client_id.as_str(), "wires-test-client");

        let dirs: Vec<_> = (40..43u8)
            .map(|b| NodeIdentity::from_seed([b; 32]).node_id())
            .collect();
        for d in &dirs {
            crate::admin::service::directory_add(&admin, *d, Ttl::default()).unwrap();
        }
        let later = network_in(&admin).unwrap();
        assert!(later.notes.is_empty());
        assert_eq!(
            Network::decode(&later.stdout).unwrap().directories,
            dirs[..2],
            "the first two"
        );

        // A joined node prints what it stored; one that joined nothing says how.
        let node = Keystore::at(crate::testutil::temp_dir());
        let e = network_in(&node).unwrap_err();
        assert!(format!("{e:#}").contains("wires join"), "{e:#}");
        node.save_network(&Network::decode(&later.stdout).unwrap())
            .unwrap();
        assert_eq!(network_in(&node).unwrap().stdout, later.stdout);
    }
}
