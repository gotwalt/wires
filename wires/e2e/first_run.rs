//! Starting a network, as the admin types it: no step errors, and the
//! order that works is the one each step's output names.
//!
//! [`a_network_starts_in_order_with_no_error`]: `init` → `directory add`
//! (of a node not invited yet) → `invite` (its token carries the policy) →
//! `join` → `directory serve` → an edit that reaches it. Until a directory
//! has taken a publish from this admin, an edit that reaches none is a
//! note, not a failure; after that, reaching none fails as ever.

use std::collections::BTreeSet;
use std::sync::Arc;

use iroh::address_lookup::memory::MemoryLookup;
use iroh::protocol::Router;
use library::{GOOGLE_ISSUER, Matcher};

use super::{bind_in, localhost_socks, role};
use crate::admin::init::{InitArgs, init_in};
use crate::admin::invite::{InviteArgs, invite_in};
use crate::admin::keystore::{self, Keystore};
use crate::admin::propagate::{Propagation, reached, settle};
use crate::admin::service::role_set;
use crate::admin::ttl::Ttl;
use crate::caller::join::{id_in, join_in};
use crate::clock::now_unix;
use crate::directory::serve::{Running, open_standalone};
use crate::directory::{DirectoryCmd, DirectoryEditArgs, edit_in, next_step};
use crate::host::transport::endpoint_addr;
use crate::policy::fetch::{held_directories, publish_current_on};
use crate::policy::store;

/// An admin edit as `run_edit` makes it: `edit` against `admin`, then the
/// publish over `endpoint`, settled.
async fn edit_and_publish(
    admin: &Keystore,
    endpoint: &iroh::Endpoint,
    edit: impl FnOnce(&Keystore),
) -> Propagation {
    let earlier: BTreeSet<_> = held_directories(admin).unwrap();
    edit(admin);
    let root = store::fabric(admin).unwrap().unwrap();
    let version = store::read(admin, root).unwrap().unwrap().version();
    let published = publish_current_on(endpoint, admin, &earlier).await;
    settle(admin, published.map(|r| (version, r)))
}

#[tokio::test]
async fn a_network_starts_in_order_with_no_error() {
    let book = MemoryLookup::new();
    let admin = Keystore::at(crate::testutil::temp_dir());
    init_in(&admin, InitArgs::default()).unwrap();
    let admin_node = keystore::node_identity_in(&admin).unwrap();
    let admin_ep = bind_in(&admin_node, &book).await;

    // On the directory's machine: its id.
    let dir_ks = Arc::new(Keystore::at(crate::testutil::temp_dir()));
    let (dir_id, _) = id_in(&dir_ks).unwrap();

    // The admin lists it before inviting it. Nothing runs there yet: a
    // note, exit 0, and the node's next step.
    let hint = next_step(&admin, &dir_id.hex()).unwrap();
    assert!(hint.contains("wires invite"), "{hint}");
    let listed = edit_and_publish(&admin, &admin_ep, |ks| {
        edit_in(
            ks,
            DirectoryCmd::Add(DirectoryEditArgs {
                node: dir_id.hex(),
                ttl: Ttl::default(),
            }),
        )
        .unwrap();
    })
    .await;
    assert_eq!(listed.failure, None, "{}", listed.note);
    assert!(
        listed.note.contains("no directory is running yet"),
        "{}",
        listed.note
    );
    // So is an edit made before it runs.
    let staff = || vec![Matcher::new(GOOGLE_ISSUER)];
    let before = edit_and_publish(&admin, &admin_ep, |ks| {
        role_set(ks, role("staff"), staff(), Ttl::default()).unwrap();
    })
    .await;
    assert_eq!(before.failure, None, "{}", before.note);

    // Invited now, its token carries the policy; it joins and serves.
    let token = invite_in(
        &admin,
        InviteArgs {
            node_id: dir_id.hex(),
            name: Some("dir1".into()),
            ttl: Ttl::default(),
            policy_ttl: Ttl::default(),
        },
    )
    .unwrap()
    .stdout;
    // Listing a node invited before says to re-invite it: its earlier
    // token carried no policy.
    let hint = next_step(&admin, "dir1").unwrap();
    assert!(hint.contains("re-invite"), "{hint}");
    join_in(&dir_ks, &token, now_unix()).unwrap();
    let (dir, node, badge) = open_standalone(Arc::clone(&dir_ks), 64, now_unix()).unwrap();
    let dir_ep = bind_in(&node, &book).await;
    book.add_endpoint_info(endpoint_addr(&dir_id, &localhost_socks(&dir_ep), None).unwrap());
    let router = Running::mount(Router::builder(dir_ep.clone()), &dir).spawn();
    let running = Running::start(Arc::clone(&dir), dir_ep.clone(), badge);

    // The next edit reaches it.
    let edited = edit_and_publish(&admin, &admin_ep, |ks| {
        role_set(ks, role("ops"), staff(), Ttl::default()).unwrap();
    })
    .await;
    assert_eq!(edited.failure, None, "{}", edited.note);
    assert!(
        edited.note.contains("published to 1 of 1"),
        "{}",
        edited.note
    );
    assert_eq!(reached(&admin), BTreeSet::from([dir_id]));
    let admin_version = store::read(&admin, store::fabric(&admin).unwrap().unwrap())
        .unwrap()
        .unwrap()
        .version();
    assert_eq!(dir.version(), admin_version);

    // Once one has taken a publish, an edit that reaches none fails.
    running.stop().await;
    router.shutdown().await.unwrap();
    dir_ep.close().await;
    let missed = edit_and_publish(&admin, &admin_ep, |ks| {
        role_set(ks, role("dev"), staff(), Ttl::default()).unwrap();
    })
    .await;
    assert!(missed.failure.is_some(), "{}", missed.note);
    admin_ep.close().await;
}
