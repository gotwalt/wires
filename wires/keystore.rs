//! On-disk key + CRL persistence, so the network commands work without
//! secrets on the command line.
//!
//! Files live under the wires home directory — `$WIRES_HOME`, else
//! `$XDG_CONFIG_HOME/wires`, else `~/.config/wires`:
//!
//! - `node.seed` / `root.seed`: hex-encoded 32-byte Ed25519 seeds (mode `0600`).
//! - `crl.json`: the responder's revocation list.
//!
//! The resolver helpers ([`node_identity`], [`root_identity`], [`load_crl`])
//! encode the precedence the CLI uses: an inline flag wins, then the matching
//! environment variable, then an explicit `--…-file` path, then the keystore.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use library::{Crl, NodeIdentity};

/// Resolve the wires home directory (does not create it).
pub fn home() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("WIRES_HOME") {
        return Ok(PathBuf::from(dir));
    }
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(dir).join("wires"));
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow!("cannot locate home: set $WIRES_HOME or $HOME"))?;
    Ok(PathBuf::from(home).join(".config").join("wires"))
}

/// A keystore rooted at a directory.
pub struct Keystore {
    dir: PathBuf,
}

impl Keystore {
    /// The keystore at the resolved wires home (see [`home`]).
    pub fn resolve() -> Result<Self> {
        Ok(Self { dir: home()? })
    }

    /// A keystore rooted at an explicit directory (used in tests).
    #[cfg(test)]
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The path of file `name` within the keystore.
    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Read the node identity (`node.seed`); `None` if the file is absent.
    pub fn read_node_identity(&self) -> Result<Option<NodeIdentity>> {
        read_identity_opt(&self.path("node.seed"))
    }

    /// Read the root identity (`root.seed`); `None` if the file is absent.
    pub fn read_root_identity(&self) -> Result<Option<NodeIdentity>> {
        read_identity_opt(&self.path("root.seed"))
    }

    /// Persist the node identity to `node.seed` (mode `0600`); refuse to
    /// overwrite an existing file unless `force`. Returns the written path.
    pub fn save_node(&self, id: &NodeIdentity, force: bool) -> Result<PathBuf> {
        self.save_seed("node.seed", id, force)
    }

    /// Persist the root identity to `root.seed` (mode `0600`); refuse to
    /// overwrite an existing file unless `force`. Returns the written path.
    pub fn save_root(&self, id: &NodeIdentity, force: bool) -> Result<PathBuf> {
        self.save_seed("root.seed", id, force)
    }

    fn save_seed(&self, name: &str, id: &NodeIdentity, force: bool) -> Result<PathBuf> {
        ensure_dir(&self.dir)?;
        let path = self.path(name);
        write_secret(&path, &id.seed_hex(), force)?;
        Ok(path)
    }

    /// Read `crl.json` as a [`Crl`]; an absent file is an empty CRL.
    pub fn read_crl(&self) -> Result<Crl> {
        match self.read_crl_json()? {
            Some(json) => Ok(Crl::from_json(&json)?),
            None => Ok(Crl::new()),
        }
    }

    /// Read the raw `crl.json` text; `None` if absent.
    pub fn read_crl_json(&self) -> Result<Option<String>> {
        read_to_string_opt(&self.path("crl.json"))
    }

    /// Write `crl.json` (overwriting). Returns the written path.
    pub fn save_crl_json(&self, json: &str) -> Result<PathBuf> {
        ensure_dir(&self.dir)?;
        let path = self.path("crl.json");
        write_text(&path, json)?;
        Ok(path)
    }
}

// ---------------------------------------------------------------------------
// CLI resolvers (flag > env > file > keystore)
// ---------------------------------------------------------------------------

/// Resolve a node identity for `serve` / `connect`.
pub fn node_identity(inline: Option<&str>, file: Option<&Path>) -> Result<NodeIdentity> {
    let env = std::env::var("WIRES_NODE_SEED").ok();
    resolve_identity(
        inline,
        env.as_deref(),
        file,
        "node.seed",
        "node",
        "WIRES_NODE_SEED",
    )
}

/// Resolve the root signing identity for `grant`.
pub fn root_identity(inline: Option<&str>, file: Option<&Path>) -> Result<NodeIdentity> {
    let env = std::env::var("WIRES_ROOT_SEED").ok();
    resolve_identity(
        inline,
        env.as_deref(),
        file,
        "root.seed",
        "root",
        "WIRES_ROOT_SEED",
    )
}

fn resolve_identity(
    inline: Option<&str>,
    env: Option<&str>,
    file: Option<&Path>,
    ks_name: &str,
    role: &str,
    env_name: &str,
) -> Result<NodeIdentity> {
    if let Some(hex) = inline {
        return NodeIdentity::from_seed_hex(hex).with_context(|| format!("--{role}-seed"));
    }
    if let Some(hex) = env.filter(|s| !s.is_empty()) {
        return NodeIdentity::from_seed_hex(hex).with_context(|| format!("${env_name}"));
    }
    if let Some(path) = file {
        return read_identity_file(path);
    }
    let ks = Keystore::resolve()?;
    let found = match ks_name {
        "node.seed" => ks.read_node_identity()?,
        "root.seed" => ks.read_root_identity()?,
        other => bail!("unknown keystore file {other}"),
    };
    if let Some(id) = found {
        return Ok(id);
    }
    bail!(
        "no {role} key: pass --{role}-seed, set ${env_name}, use --{role}-seed-file, \
         or run `wires keygen --save-{role}` (looked for {})",
        ks.path(ks_name).display()
    );
}

/// Load the CRL for read-only use (`serve`): inline JSON, else a file, else the
/// keystore, else empty.
pub fn load_crl(inline: Option<&str>, file: Option<&Path>) -> Result<Crl> {
    if let Some(json) = inline {
        return Ok(Crl::from_json(json)?);
    }
    if let Some(path) = file {
        return match read_to_string_opt(path)? {
            Some(json) => Ok(Crl::from_json(&json)?),
            None => Ok(Crl::new()),
        };
    }
    Keystore::resolve()?.read_crl()
}

/// Read a CRL text file; `None` if absent (used by `revoke --crl-file`).
pub fn read_crl_text(path: &Path) -> Result<Option<String>> {
    read_to_string_opt(path)
}

/// Write a CRL text file (creating parent dirs).
pub fn write_crl_text(path: &Path, json: &str) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    write_text(path, json)
}

/// Read a seed file into an identity, erroring if absent.
pub fn read_identity_file(path: &Path) -> Result<NodeIdentity> {
    read_identity_opt(path)?.ok_or_else(|| anyhow!("seed file not found: {}", path.display()))
}

// ---------------------------------------------------------------------------
// Low-level file helpers
// ---------------------------------------------------------------------------

fn read_identity_opt(path: &Path) -> Result<Option<NodeIdentity>> {
    match read_to_string_opt(path)? {
        Some(text) => Ok(Some(
            NodeIdentity::from_seed_hex(text.trim())
                .with_context(|| format!("parsing seed {}", path.display()))?,
        )),
        None => Ok(None),
    }
}

fn read_to_string_opt(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn ensure_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).ok();
    }
    Ok(())
}

/// Write a secret file with mode `0600`, refusing to clobber unless `force`.
///
/// Uses `O_EXCL` (`create_new`) for the non-`force` path so the
/// refuse-if-exists check and the create are one atomic syscall — no
/// time-of-check/time-of-use gap and no following a planted symlink.
fn write_secret(path: &Path, contents: &str, force: bool) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!(
                "{} already exists (pass --force to overwrite)",
                path.display()
            );
        }
        Err(e) => return Err(e).with_context(|| format!("writing {}", path.display())),
    };
    writeln!(f, "{contents}").with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn write_text(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn temp_dir() -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let base = std::env::var_os("TEST_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = base.join(format!("wires-ks-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn node_seed_round_trips_through_the_keystore() {
        let ks = Keystore::at(temp_dir().join("nested")); // also exercises dir creation
        assert!(ks.read_node_identity().unwrap().is_none());

        let id = NodeIdentity::from_seed([3u8; 32]);
        ks.save_node(&id, false).unwrap();
        let read = ks.read_node_identity().unwrap().unwrap();
        assert_eq!(read.node_id(), id.node_id());
    }

    #[test]
    fn save_refuses_to_clobber_without_force() {
        let ks = Keystore::at(temp_dir());
        let a = NodeIdentity::from_seed([1u8; 32]);
        let b = NodeIdentity::from_seed([2u8; 32]);
        ks.save_root(&a, false).unwrap();
        assert!(ks.save_root(&b, false).is_err());
        ks.save_root(&b, true).unwrap();
        assert_eq!(
            ks.read_root_identity().unwrap().unwrap().node_id(),
            b.node_id()
        );
    }

    #[test]
    fn crl_round_trips_and_is_empty_when_absent() {
        let ks = Keystore::at(temp_dir());
        assert!(ks.read_crl().unwrap().is_empty());

        let mut crl = Crl::new();
        crl.insert(NodeIdentity::from_seed([7u8; 32]).node_id());
        ks.save_crl_json(&crl.to_json().unwrap()).unwrap();
        assert_eq!(ks.read_crl().unwrap(), crl);
    }

    #[test]
    fn read_identity_file_errors_when_missing() {
        let path = temp_dir().join("absent.seed");
        assert!(read_identity_file(&path).is_err());
    }

    #[test]
    fn resolve_prefers_inline_then_file() {
        let inline = NodeIdentity::from_seed([5u8; 32]);
        // Inline hex wins regardless of file.
        let got = node_identity(Some(&inline.seed_hex()), None).unwrap();
        assert_eq!(got.node_id(), inline.node_id());

        // With no inline/env, an explicit file is used.
        let file_id = NodeIdentity::from_seed([6u8; 32]);
        let path = temp_dir().join("node.seed");
        write_secret(&path, &file_id.seed_hex(), true).unwrap();
        let got = node_identity(None, Some(&path)).unwrap();
        assert_eq!(got.node_id(), file_id.node_id());
    }

    #[test]
    fn rejects_bad_inline_seed() {
        assert!(node_identity(Some("nothex"), None).is_err());
    }

    #[test]
    fn load_crl_from_inline_then_file() {
        let mut crl = Crl::new();
        crl.insert(NodeIdentity::from_seed([4u8; 32]).node_id());
        let json = crl.to_json().unwrap();

        // Inline JSON wins and touches no filesystem.
        assert_eq!(load_crl(Some(&json), None).unwrap(), crl);

        // A file is read when present, treated as empty when absent.
        let dir = temp_dir();
        let path = dir.join("crl.json");
        write_crl_text(&path, &json).unwrap();
        assert_eq!(load_crl(None, Some(&path)).unwrap(), crl);
        assert!(
            load_crl(None, Some(&dir.join("absent.json")))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn crl_text_round_trips_and_is_none_when_absent() {
        let path = temp_dir().join("c.json");
        assert!(read_crl_text(&path).unwrap().is_none());
        write_crl_text(&path, r#"{"revoked":[]}"#).unwrap();
        assert_eq!(
            read_crl_text(&path).unwrap().as_deref(),
            Some(r#"{"revoked":[]}"#)
        );
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let ks = Keystore::at(temp_dir());
        let path = ks
            .save_node(&NodeIdentity::from_seed([9u8; 32]), false)
            .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
