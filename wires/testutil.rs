//! Fixtures shared by the unit tests of more than one role module: scratch
//! directories, and a shared mock IdP for fixtures that need a signed-in caller.

use std::path::{Path, PathBuf};

/// A fresh empty directory under the system temp directory.
pub(crate) fn temp_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "wires-cli-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Everything under `dir` (not `dir` itself, which the test made), as
/// protocol.md §8 says a keystore holds it: each directory `0700`, each
/// file and socket `0600`. Panics naming every path that isn't.
#[cfg(unix)]
pub(crate) fn assert_private(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fn walk(dir: &Path, wrong: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            let want = if meta.is_dir() { 0o700 } else { 0o600 };
            if mode != want {
                wrong.push(format!("{} is {mode:o}, not {want:o}", path.display()));
            }
            if meta.is_dir() {
                walk(&path, wrong);
            }
        }
    }
    let mut wrong = Vec::new();
    walk(dir, &mut wrong);
    assert!(wrong.is_empty(), "not private:\n{}", wrong.join("\n"));
}

/// A scratch directory for tests that bind real unix sockets, removed on drop.
///
/// A `sockaddr_un` path is capped at ~104 bytes on macOS, and macOS's
/// per-user `$TMPDIR` (`/var/folders/…`) already uses about half of that, so
/// this prefers `/tmp` and keeps its own names to a few characters.
pub(crate) struct ScratchDir {
    /// The created directory.
    path: PathBuf,
}

impl ScratchDir {
    /// Create a short-named scratch directory (`/tmp` when writable, else
    /// [`temp_dir`]'s root).
    pub(crate) fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("w{tag}{}-{n}", std::process::id());
        let short = PathBuf::from("/tmp").join(&name);
        let path = if std::fs::create_dir_all(&short).is_ok() {
            short
        } else {
            let fallback = std::env::temp_dir().join(name);
            std::fs::create_dir_all(&fallback).unwrap();
            fallback
        };
        Self { path }
    }

    /// The directory itself.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// One mock OIDC issuer for the whole test binary, on its own runtime
/// thread, so a synchronous fixture can sign a caller in (every role needs a
/// verified identity). It signs in `caller@example.com` and never stops.
pub(crate) fn test_idp() -> &'static crate::caller::mock_idp::MockIdp {
    use crate::caller::mock_idp::MockIdp;
    static IDP: std::sync::OnceLock<MockIdp> = std::sync::OnceLock::new();
    IDP.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();
            tx.send(rt.block_on(MockIdp::start("caller@example.com")))
                .unwrap();
            rt.block_on(std::future::pending::<()>());
        });
        rx.recv().unwrap()
    })
}

/// A [`test_idp`] ID token bound to `node`, valid for an hour.
pub(crate) fn test_id_token(node: &library::NodeId) -> library::IdToken {
    test_idp().mint(
        &library::OidcNonce::for_node(node),
        crate::clock::now_unix() + 3600,
    )
}

/// The role `staff`: anyone [`test_idp`] verified.
pub(crate) fn staff_role() -> (library::RoleName, Vec<library::Matcher>) {
    (
        library::RoleName::new("staff").unwrap(),
        vec![library::Matcher::new(test_idp().issuer.as_str())],
    )
}

/// Trust every issuer a role in `policy` names that it doesn't trust yet,
/// accepting the mock IdP's client id: what a test policy needs to pass
/// validation (card 36: every matcher names a trusted issuer).
pub(crate) fn trust_role_issuers(policy: &mut library::Policy) {
    let named: Vec<String> = policy
        .roles
        .values()
        .flatten()
        .map(|m| m.issuer.clone())
        .collect();
    for iss in named {
        policy
            .issuers
            .entry(library::Issuer::new(iss.as_str()))
            .or_insert_with(|| library::IssuerConfig {
                client_id: library::Audience::new(crate::caller::mock_idp::MOCK_CLIENT_ID),
                audiences: vec![library::Audience::new(
                    crate::caller::mock_idp::MOCK_CLIENT_ID,
                )],
            });
    }
}

/// `policy`, its roles' issuers trusted ([`trust_role_issuers`]), signed by
/// `root`.
pub(crate) fn signed_policy(
    root: &library::NodeIdentity,
    mut policy: library::Policy,
) -> library::SignedPolicy {
    trust_role_issuers(&mut policy);
    policy.sign(root).unwrap()
}

/// [`signed_policy`], verified and typed as a node holds it.
pub(crate) fn held(
    root: &library::NodeIdentity,
    policy: library::Policy,
) -> crate::policy::store::Held {
    crate::policy::store::Held::verify(signed_policy(root, policy), root.node_id()).unwrap()
}

/// A `host.json` `"identity"` value that trusts [`test_idp`].
pub(crate) fn test_identity_json() -> String {
    format!(
        r#"{{"issuers":[{{"issuer":"{}","audiences":["{}"]}}]}}"#,
        test_idp().issuer.as_str(),
        crate::caller::mock_idp::MOCK_CLIENT_ID
    )
}

/// The network string of `root`'s network, naming `directories` and
/// [`test_idp`] as the IdP to sign in with.
pub(crate) fn network(
    root: &library::NodeIdentity,
    directories: &[library::NodeId],
) -> library::Network {
    library::Network::new(
        root.node_id(),
        directories.to_vec(),
        library::LoginSettings {
            issuer: test_idp().issuer.clone(),
            client_id: library::Audience::new(crate::caller::mock_idp::MOCK_CLIENT_ID),
            public_client_secret: None,
        },
    )
}

/// Join `ks` to `root`'s network ([`network`]), as `wires join` does.
pub(crate) fn join(
    ks: &crate::admin::keystore::Keystore,
    root: &library::NodeIdentity,
    directories: &[library::NodeId],
) {
    ks.save_network(&network(root, directories)).unwrap();
}

/// A node no test policy bans, to cut a view for when the node doesn't
/// matter (a view depends on the node only through a node ban).
pub(crate) fn any_node() -> library::NodeId {
    library::NodeIdentity::from_seed([0xee; 32]).node_id()
}

/// A directory no test runs, whose word (a `Fresh`) tests hand to hosts so
/// callers will talk to them (card 49): list it in a policy's
/// `directories`, then [`vouch_on_disk`] or [`vouch_for`].
pub(crate) fn test_directory() -> library::NodeIdentity {
    library::NodeIdentity::from_seed([0xd1; 32])
}

/// A `Fresh` [`test_directory`] signs for `head`, current for the next hour.
pub(crate) fn test_fresh(head: &library::SignedPolicyHead) -> library::Fresh {
    let now = crate::clock::now_unix();
    library::Fresh::sign(&test_directory(), head, now - 60, now + 3600).unwrap()
}

/// Leave [`test_fresh`] for `head` in a host's keystore (`fresh.json`), as
/// a directory's beat would: a host built from it shows callers that word.
pub(crate) fn vouch_on_disk(
    ks: &crate::admin::keystore::Keystore,
    head: &library::SignedPolicyHead,
) {
    let text = serde_json::to_string(&[test_fresh(head)]).unwrap();
    std::fs::create_dir_all(ks.path("")).unwrap();
    std::fs::write(ks.path(crate::host::freshness::FRESH_FILE), text).unwrap();
}

/// Hand a running host [`test_fresh`] for the head it holds.
pub(crate) fn vouch_for(host: &crate::host::gate::ServicesHost) {
    let head = host.policy().unwrap().signed.head.clone();
    host.freshness
        .offer(&test_fresh(&head), &head, crate::clock::now_unix())
        .unwrap();
}

/// What a caller checks hosts against when it holds `state`'s every entry
/// (a view no directory cut: for tests that don't care whose view it is).
pub(crate) fn vouching(
    state: &library::SignedPolicy,
    scope: crate::caller::vouch::Scope,
) -> crate::caller::vouch::Vouching {
    let view = library::View {
        head: state.head.clone(),
        entries: state.entries().cloned().collect(),
    };
    crate::caller::vouch::Vouching::new(
        state.head.head.fabric,
        crate::caller::view::HeldView::fetched(view, None, crate::clock::now_unix()),
        scope,
    )
}
