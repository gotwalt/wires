//! Fixtures shared by the unit tests of more than one role module: scratch
//! directories.

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
