//! On-disk key + credential persistence, so the network commands work without
//! secrets on the command line.
//!
//! Files live under the wires home directory — `$WIRES_HOME`, else
//! `$XDG_CONFIG_HOME/wires`, else `~/.config/wires`:
//!
//! - `node.seed` / `root.seed`: hex-encoded 32-byte Ed25519 seeds (mode `0600`).
//! - `network.json`: the network string `wires join` or `wires login`
//!   stored ([`Keystore::read_network`]): the root key, the first
//!   directories, the login settings.
//! - `labels.json`: the admin's labels for nodes ([`super::labels`]).
//! - `policy.json`: the admin-signed policy ([`crate::policy::store`]),
//!   and on a directory node its whole store ([`crate::directory`]).
//!
//! The resolver helper [`node_identity`] encodes the precedence the CLI
//! uses: an inline flag wins, then the matching environment variable, then
//! an explicit `--…-file` path, then the keystore.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use library::{Network, NodeId, NodeIdentity};
use zeroize::Zeroizing;

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
#[derive(Clone, Debug)]
pub struct Keystore {
    dir: PathBuf,
}

impl Keystore {
    /// The keystore at the resolved wires home (see [`home`]).
    pub fn resolve() -> Result<Self> {
        Ok(Self { dir: home()? })
    }

    /// A keystore rooted at an explicit directory (tests, and an app
    /// embedding a host, which names its keystore rather than reading
    /// `$WIRES_HOME`).
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

    /// Persist the node identity to `node.seed` (mode `0600`); an existing
    /// key is never overwritten. Returns the written path.
    pub fn save_node(&self, id: &NodeIdentity) -> Result<PathBuf> {
        self.save_seed("node.seed", id)
    }

    /// Persist the root identity to `root.seed` (mode `0600`); an existing
    /// key is never overwritten. Returns the written path.
    pub fn save_root(&self, id: &NodeIdentity) -> Result<PathBuf> {
        self.save_seed("root.seed", id)
    }

    fn save_seed(&self, name: &str, id: &NodeIdentity) -> Result<PathBuf> {
        create_private_dir(&self.dir)?;
        let path = self.path(name);
        write_secret(&path, &id.expose_seed_hex())?;
        Ok(path)
    }

    /// Read `network.json` (the network string `join` or `login` stored);
    /// `None` before either ran.
    pub fn read_network(&self) -> Result<Option<Network>> {
        let path = self.path(NETWORK_FILE);
        match read_to_string_opt(&path)? {
            Some(text) => Ok(Some(
                Network::decode(text.trim())
                    .with_context(|| format!("parsing {}", path.display()))?,
            )),
            None => Ok(None),
        }
    }

    /// Persist `network` to `network.json` as its string (mode `0600`).
    /// Returns the written path.
    pub fn save_network(&self, network: &Network) -> Result<PathBuf> {
        create_private_dir(&self.dir)?;
        let path = self.path(NETWORK_FILE);
        write_private(&path, format!("{}\n", network.encode()?))?;
        Ok(path)
    }

    /// The network this keystore is in, by its root key: the admin's own
    /// (`root.seed`), else the one `network.json` names; `None` before
    /// `init`, `join` or `login`.
    pub fn network_root(&self) -> Result<Option<NodeId>> {
        if let Some(root) = self.read_root_identity()? {
            return Ok(Some(root.node_id()));
        }
        Ok(self.read_network()?.map(|n| n.root))
    }
}

/// The file `join` and `login` store the network string in.
pub(crate) const NETWORK_FILE: &str = "network.json";

/// Resolve `wires serve`'s node identity: an inline `--node-seed` wins,
/// then an explicit `--node-seed-file` (a container mounts its key), then
/// the keystore's ([`node_identity_in`]). Every other command reads the
/// keystore's alone.
pub fn node_identity(inline: Option<&str>, file: Option<&Path>) -> Result<NodeIdentity> {
    if let Some(hex) = inline {
        return NodeIdentity::from_seed_hex(hex).context("--node-seed");
    }
    if let Some(path) = file {
        return read_identity_file(path);
    }
    node_identity_in(&Keystore::resolve()?)
}

/// The node identity in `ks` (`node.seed`), or an error naming how to make
/// one. `$WIRES_HOME` is the one way to point a command at another keystore.
pub fn node_identity_in(ks: &Keystore) -> Result<NodeIdentity> {
    ks.read_node_identity()?.ok_or_else(|| {
        anyhow!(
            "no node key at {}: a caller runs `wires login <network>`, a host or directory \
             `wires join <network>`, with the string your admin prints with `wires network` \
             (`wires id` makes the key alone)",
            ks.path("node.seed").display()
        )
    })
}

/// Read a seed file into an identity, erroring if absent.
pub fn read_identity_file(path: &Path) -> Result<NodeIdentity> {
    read_identity_opt(path)?.ok_or_else(|| anyhow!("seed file not found: {}", path.display()))
}

fn read_identity_opt(path: &Path) -> Result<Option<NodeIdentity>> {
    match read_secret_opt(path)? {
        Some(text) => Ok(Some(
            NodeIdentity::from_seed_hex(text.trim())
                .with_context(|| format!("parsing seed {}", path.display()))?,
        )),
        None => Ok(None),
    }
}

/// Read a secret file (a seed) into a scrubbed buffer sized to the file up
/// front, so a growing buffer leaves no unscrubbed copy behind. `None` if the
/// file is absent.
fn read_secret_opt(path: &Path) -> Result<Option<Zeroizing<String>>> {
    use std::io::Read;
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let len = f
        .metadata()
        .with_context(|| format!("reading {}", path.display()))?
        .len();
    let mut text = Zeroizing::new(String::with_capacity(
        usize::try_from(len).unwrap_or(0).saturating_add(1),
    ));
    f.read_to_string(&mut text)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(Some(text))
}

fn read_to_string_opt(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Create `dir` (and its parents) if missing, the new directories mode
/// `0700`: the keystore holds seeds and the signed policy.
pub(crate) fn create_private_dir(dir: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))
}

/// Write a secret file with mode `0600`, refusing to clobber an existing one.
///
/// `O_EXCL` (`create_new`) makes the refuse-if-exists check and the create
/// one atomic syscall: no time-of-check/time-of-use gap, and no following a
/// planted symlink.
fn write_secret(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!(
                "{} already exists; wires never overwrites a key",
                path.display()
            );
        }
        Err(e) => return Err(e).with_context(|| format!("writing {}", path.display())),
    };
    writeln!(f, "{contents}").with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Write `contents` to `path` **atomically**: a temporary file in the same
/// directory, then a `rename` over the target.
///
/// Every file this module writes is also read, concurrently, by something that
/// takes no lock — `policy.json` most of all, which a host re-reads on every
/// connection while a fetch adopts a newer copy from another task or
/// process. A plain `std::fs::write` is `O_TRUNC` followed by a write, so a
/// reader landing in that window sees an empty or half-written file and the
/// host fails closed ("host configuration error") over a scheduling
/// accident.
///
/// `rename(2)` within a directory is atomic, so a reader sees either the
/// previous contents or the new ones and never a splice of the two. The
/// temporary file is created with `O_EXCL` (never following a planted file or
/// symlink) and mode `0600` **from the start**, so no one else can open it
/// while it is written, and the file keeps that mode (protocol.md §8: every
/// keystore file is `0600`).
pub(crate) fn write_private(path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tmp".to_string());
    // Unique per process *and* per call: two threads in one process rewriting
    // the same file (a fetched policy and a published one, say) must not share a
    // temporary path, or one would rename the other's half-written file.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = dir.join(format!(".{name}.{}.{n}.tmp", std::process::id()));

    let result = (|| -> Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(contents.as_ref())
            .with_context(|| format!("writing {}", tmp.display()))?;
        drop(f);
        std::fs::rename(&tmp, path)
            .with_context(|| format!("renaming {} onto {}", tmp.display(), path.display()))
    })();
    if result.is_err() {
        std::fs::remove_file(&tmp).ok();
    }
    result
}

/// Open `path` for writing, creating it mode `0600` if missing and never
/// truncating it: a lock file (`policy.json.lock`).
pub(crate) fn open_private(path: &Path) -> Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .with_context(|| format!("opening {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;

    #[test]
    fn node_seed_round_trips_through_the_keystore() {
        let ks = Keystore::at(temp_dir().join("nested")); // also exercises dir creation
        assert!(ks.read_node_identity().unwrap().is_none());

        let id = NodeIdentity::from_seed([3u8; 32]);
        ks.save_node(&id).unwrap();
        let read = ks.read_node_identity().unwrap().unwrap();
        assert_eq!(read.node_id(), id.node_id());
    }

    #[test]
    fn a_saved_key_is_never_overwritten() {
        let ks = Keystore::at(temp_dir());
        let a = NodeIdentity::from_seed([1u8; 32]);
        let b = NodeIdentity::from_seed([2u8; 32]);
        ks.save_root(&a).unwrap();
        let e = format!("{:#}", ks.save_root(&b).unwrap_err());
        assert!(e.contains("never overwrites a key"), "{e}");
        assert_eq!(
            ks.read_root_identity().unwrap().unwrap().node_id(),
            a.node_id()
        );
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
        let got = node_identity(Some(&inline.expose_seed_hex()), None).unwrap();
        assert_eq!(got.node_id(), inline.node_id());

        // With no inline seed, an explicit file is used.
        let file_id = NodeIdentity::from_seed([6u8; 32]);
        let path = temp_dir().join("node.seed");
        write_secret(&path, &file_id.expose_seed_hex()).unwrap();
        let got = node_identity(None, Some(&path)).unwrap();
        assert_eq!(got.node_id(), file_id.node_id());
    }

    #[test]
    fn rejects_bad_inline_seed() {
        assert!(node_identity(Some("nothex"), None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let ks = Keystore::at(temp_dir());
        let path = ks.save_node(&NodeIdentity::from_seed([9u8; 32])).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// A file written through `write_private` (its temporary file is
    /// created `0600`) or opened through `open_private` is `0600`, whatever
    /// the umask.
    #[cfg(unix)]
    #[test]
    fn keystore_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let private = dir.join("unanswered.json");
        write_private(&private, "1\n").unwrap();
        assert_eq!(mode(&private), 0o600);
        let lock = dir.join("policy.json.lock");
        open_private(&lock).unwrap();
        assert_eq!(mode(&lock), 0o600);
        // Overwriting keeps it atomic and leaves no temporary behind.
        write_private(&private, "2\n").unwrap();
        assert_eq!(std::fs::read_to_string(&private).unwrap(), "2\n");
        let leftovers = std::fs::read_dir(&dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    fn network() -> Network {
        Network::new(
            NodeIdentity::from_seed([1u8; 32]).node_id(),
            vec![NodeIdentity::from_seed([2u8; 32]).node_id()],
            library::LoginSettings {
                issuer: library::Issuer::new("https://idp"),
                client_id: library::Audience::new("cli"),
                public_client_secret: None,
            },
        )
    }

    #[test]
    fn the_network_string_round_trips_and_names_the_root() {
        let ks = Keystore::at(temp_dir());
        assert!(ks.read_network().unwrap().is_none());
        assert!(ks.network_root().unwrap().is_none());
        ks.save_network(&network()).unwrap();
        assert_eq!(ks.read_network().unwrap(), Some(network()));
        assert_eq!(ks.network_root().unwrap(), Some(network().root));
        // The admin's root key names its network, whatever else is there.
        let root = NodeIdentity::from_seed([7u8; 32]);
        ks.save_root(&root).unwrap();
        assert_eq!(ks.network_root().unwrap(), Some(root.node_id()));
    }

    #[test]
    fn a_damaged_network_file_is_an_error() {
        let ks = Keystore::at(temp_dir());
        std::fs::write(ks.path(NETWORK_FILE), "not a token\n").unwrap();
        assert!(ks.read_network().is_err());
    }

    #[test]
    fn node_identity_in_reads_the_given_keystore() {
        let ks = Keystore::at(temp_dir());
        // Nothing installed yet: the error names the remedy and the path.
        let msg = match node_identity_in(&ks) {
            Ok(_) => panic!("an empty keystore has no node key"),
            Err(e) => format!("{e:#}"),
        };
        assert!(msg.contains("wires id"), "{msg}");
        assert!(
            msg.contains(&ks.path("node.seed").display().to_string()),
            "{msg}"
        );

        let id = NodeIdentity::from_seed([11u8; 32]);
        ks.save_node(&id).unwrap();
        assert_eq!(node_identity_in(&ks).unwrap().node_id(), id.node_id());
    }
}
