//! Crash-safe file writes: write to a sibling temp, fsync, rename, fsync the
//! parent directory. Used for any on-disk state where a partial write would
//! corrupt the agent: pair_pending state, config.toml, topic_names.json.

use std::io::{self, Write};
use std::path::Path;

/// Write `bytes` to `path` atomically. On Unix, `mode` (when `Some`) is applied
/// to the temp file before rename so the published file lands at exactly the
/// requested permissions; on other platforms `mode` is ignored.
///
/// Guarantees on Unix: a crash at any point either leaves `path` with its
/// previous contents (if any) or with the new contents — never partial. The
/// parent directory is fsync'd so the rename itself is durable.
pub fn atomic_write(path: &Path, bytes: &[u8], mode: Option<u32>) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("atomic_write: '{}' has no parent dir", path.display()),
        )
    })?;
    std::fs::create_dir_all(parent)?;

    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("atomic_write")
    ));
    {
        let mut f = open_tmp(&tmp, mode)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    fsync_dir(parent)
}

#[cfg(unix)]
fn open_tmp(tmp: &Path, mode: Option<u32>) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    if let Some(m) = mode {
        opts.mode(m);
    }
    opts.open(tmp)
}

#[cfg(not(unix))]
fn open_tmp(tmp: &Path, _mode: Option<u32>) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(tmp)
}

#[cfg(unix)]
fn fsync_dir(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) -> io::Result<()> {
    // Windows has no equivalent of opening a directory for fsync; the rename
    // itself is atomic on NTFS via MoveFileEx, which is the durability we want.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn writes_then_reads_back() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("a.json");
        atomic_write(&p, b"hello", None).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"hello");
    }

    #[test]
    fn overwrites_existing_file() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("a.json");
        std::fs::write(&p, b"old").unwrap();
        atomic_write(&p, b"new", None).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"new");
    }

    #[test]
    fn creates_missing_parents() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("nested/sub/a.json");
        atomic_write(&p, b"x", None).unwrap();
        assert!(p.exists());
    }

    #[cfg(unix)]
    #[test]
    fn applies_mode_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        let p = td.path().join("secret");
        atomic_write(&p, b"private", Some(0o600)).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn no_temp_file_left_behind_on_success() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("a.json");
        atomic_write(&p, b"x", None).unwrap();
        let stragglers: Vec<_> = std::fs::read_dir(td.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(stragglers.is_empty(), "found temp files: {stragglers:?}");
    }
}
