//! Fixtures shared by the unit tests of more than one role module: scratch
//! directories, and a shared mock IdP for fixtures that need a signed-in caller.

use std::path::{Path, PathBuf};

/// A fresh empty directory, under `$TEST_TMPDIR` when bazel provides one.
pub(crate) fn temp_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let base = std::env::var_os("TEST_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!(
        "wires-cli-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A scratch directory for tests that bind real unix sockets, removed on drop.
///
/// A `sockaddr_un` path is capped at ~104 bytes on macOS, and Bazel's sandboxed
/// `$TEST_TMPDIR` is longer than that *by itself* — so a socket test that used
/// the usual temp root would fail everywhere with `path must be shorter than
/// SUN_LEN` and teach nothing. This picks the shortest writable base available
/// and keeps its own names to a few characters.
pub(crate) struct ScratchDir {
    /// The created directory.
    path: PathBuf,
}

impl ScratchDir {
    /// Create a short-named scratch directory (`/tmp` when writable, else the
    /// test temp root).
    pub(crate) fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("w{tag}{}-{n}", std::process::id());
        let short = PathBuf::from("/tmp").join(&name);
        let path = if std::fs::create_dir_all(&short).is_ok() {
            short
        } else {
            let base = std::env::var_os("TEST_TMPDIR")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            let fallback = base.join(name);
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
        crate::now_unix() + 3600,
    )
}

/// The role `staff`: anyone [`test_idp`] verified.
pub(crate) fn staff_role() -> (library::RoleName, Vec<library::Matcher>) {
    (
        library::RoleName::new("staff").unwrap(),
        vec![library::Matcher::new(test_idp().issuer.as_str())],
    )
}

/// A `host.json` `"identity"` value that trusts [`test_idp`].
pub(crate) fn test_identity_json() -> String {
    format!(
        r#"{{"issuers":[{{"issuer":"{}","audiences":["{}"]}}]}}"#,
        test_idp().issuer.as_str(),
        crate::caller::mock_idp::MOCK_CLIENT_ID
    )
}
