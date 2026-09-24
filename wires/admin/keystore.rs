//! On-disk key + credential persistence, so the network commands work without
//! secrets on the command line.
//!
//! Files live under the wires home directory — `$WIRES_HOME`, else
//! `$XDG_CONFIG_HOME/wires`, else `~/.config/wires`:
//!
//! - `node.seed` / `root.seed`: hex-encoded 32-byte Ed25519 seeds (mode `0600`).
//! - `membership.json`: the dialer's fabric membership token (mode `0644` — a
//!   *public* signed credential, not a secret).
//! - `names.json`: the admin's local labels for members (mode `0600`).
//! - `state.json`, `state-admin.txt`, `state-checked.txt`: the admin-signed
//!   state, where to pull it from, and when it was last checked
//!   ([`crate::state::store`]).
//!
//! The resolver helpers ([`node_identity`], [`membership`])
//! encode the precedence the CLI uses: an inline flag wins, then the matching
//! environment variable, then an explicit `--…-file` path, then the keystore.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use library::{Membership, NodeId, NodeIdentity};
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
        write_secret(&path, &id.expose_seed_hex(), force)?;
        Ok(path)
    }

    /// Read `membership.json` as a [`Membership`]; `None` if the file is absent.
    pub fn read_membership(&self) -> Result<Option<Membership>> {
        let path = self.path("membership.json");
        match read_to_string_opt(&path)? {
            Some(text) => Ok(Some(
                Membership::decode(text.trim())
                    .with_context(|| format!("parsing {}", path.display()))?,
            )),
            None => Ok(None),
        }
    }

    /// Persist `membership` to `membership.json` as its base64 token (mode
    /// `0644` — a membership is a *public* signed credential, not a secret).
    /// Returns the written path.
    pub fn save_membership(&self, membership: &Membership) -> Result<PathBuf> {
        ensure_dir(&self.dir)?;
        let path = self.path("membership.json");
        write_text_mode(&path, &membership.encode()?, Some(0o644))?;
        Ok(path)
    }

    /// The admin's local labels for members (`names.json`: name → node id).
    /// Labels, not identity: nothing but `wires remove <name>` reads them.
    /// Empty when absent.
    pub fn read_names(&self) -> Result<BTreeMap<String, NodeId>> {
        let path = self.path("names.json");
        match read_to_string_opt(&path)? {
            Some(text) => {
                serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
            }
            None => Ok(BTreeMap::new()),
        }
    }

    /// Persist the admin's member labels (`names.json`, mode `0600` — the
    /// names say who is in).
    pub fn save_names(&self, names: &BTreeMap<String, NodeId>) -> Result<PathBuf> {
        ensure_dir(&self.dir)?;
        let path = self.path("names.json");
        let json = serde_json::to_string_pretty(names).context("encoding names.json")?;
        write_secret_overwrite(&path, &json)?;
        Ok(path)
    }
}

// ---------------------------------------------------------------------------
// CLI resolvers (flag > env > file > keystore)
// ---------------------------------------------------------------------------

/// Resolve a node identity for `serve` / `call`.
pub fn node_identity(inline: Option<&str>, file: Option<&Path>) -> Result<NodeIdentity> {
    let env = std::env::var("WIRES_NODE_SEED").ok().map(Zeroizing::new);
    resolve_identity(
        inline,
        env.as_ref().map(|s| s.as_str()),
        file,
        "node.seed",
        "node",
        "WIRES_NODE_SEED",
    )
}

/// Resolve the node identity for a command that already holds a keystore
/// handle: `$WIRES_NODE_SEED` wins — the same environment variable the
/// network commands honour — then `ks`'s own `node.seed`.
pub fn node_identity_in(ks: &Keystore) -> Result<NodeIdentity> {
    if let Some(hex) = std::env::var("WIRES_NODE_SEED")
        .ok()
        .map(Zeroizing::new)
        .filter(|s| !s.is_empty())
    {
        return NodeIdentity::from_seed_hex(&hex).context("$WIRES_NODE_SEED");
    }
    ks.read_node_identity()?.ok_or_else(|| {
        anyhow!(
            "no node key: set $WIRES_NODE_SEED or run `wires id` (looked for {})",
            ks.path("node.seed").display()
        )
    })
}

/// Resolve the dialer's membership for `call`: an inline `--membership`
/// token wins, then `$WIRES_MEMBERSHIP`, then an explicit `--membership-file`,
/// then the keystore (`membership.json`). Errors if none is found.
pub fn membership(inline: Option<&str>, file: Option<&Path>) -> Result<Membership> {
    if let Some(token) = inline {
        return Membership::decode(token).context("--membership");
    }
    if let Some(token) = std::env::var("WIRES_MEMBERSHIP")
        .ok()
        .filter(|s| !s.is_empty())
    {
        return Membership::decode(&token).context("$WIRES_MEMBERSHIP");
    }
    if let Some(path) = file {
        let text = read_to_string_opt(path)?
            .ok_or_else(|| anyhow!("membership file not found: {}", path.display()))?;
        return Membership::decode(text.trim())
            .with_context(|| format!("parsing {}", path.display()));
    }
    let ks = Keystore::resolve()?;
    if let Some(m) = ks.read_membership()? {
        return Ok(m);
    }
    bail!(
        "no membership: pass --membership <token>, set $WIRES_MEMBERSHIP, use \
         --membership-file, or `wires join <token>` (looked for {})",
        ks.path("membership.json").display()
    );
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
         or run `{}` (looked for {})",
        if role == "root" {
            "wires init"
        } else {
            "wires id"
        },
        ks.path(ks_name).display()
    );
}

/// Read a seed file into an identity, erroring if absent.
pub fn read_identity_file(path: &Path) -> Result<NodeIdentity> {
    read_identity_opt(path)?.ok_or_else(|| anyhow!("seed file not found: {}", path.display()))
}

// ---------------------------------------------------------------------------
// Low-level file helpers
// ---------------------------------------------------------------------------

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

/// Write `contents` to `path` **atomically**: a temporary file in the same
/// directory, then a `rename` over the target.
///
/// Every file this module writes is also read, concurrently, by something that
/// takes no lock — `state.json` most of all, which a host re-reads on every
/// connection while `wires/state` adopts a newer copy from another task or
/// process. A plain `std::fs::write` is `O_TRUNC` followed by a write, so a
/// reader landing in that window sees an empty or half-written file and the
/// host fails closed ("responder configuration error") over a scheduling
/// accident.
///
/// `rename(2)` within a directory is atomic, so a reader sees either the
/// previous contents or the new ones and never a splice of the two. The
/// temporary file is created with `O_EXCL` (never following a planted file or
/// symlink) and mode `0600` **from the start**, so no one else can open it
/// while it is written; it is widened to `mode` (e.g. `0644` for a public
/// membership) only after the write. With no `mode` it stays `0600`.
pub(crate) fn write_text_mode(path: &Path, contents: &str, mode: Option<u32>) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tmp".to_string());
    // Unique per process *and* per call: two threads in one process rewriting
    // the same head (the admission CAS and an operator command) must not share
    // a temporary path, or one would rename the other's half-written file.
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
        f.write_all(contents.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
        drop(f);
        if let Some(mode) = mode {
            set_mode(&tmp, mode);
        }
        std::fs::rename(&tmp, path)
            .with_context(|| format!("renaming {} onto {}", tmp.display(), path.display()))
    })();
    if result.is_err() {
        std::fs::remove_file(&tmp).ok();
    }
    result
}

/// [`write_text_mode`] without a mode change (the file keeps the default).
#[cfg(test)]
fn write_text(path: &Path, contents: &str) -> Result<()> {
    write_text_mode(path, contents, None)
}

/// Set a file's unix mode (best-effort; no-op on non-unix).
fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).ok();
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}

/// Write a secret file at mode `0600`, overwriting any existing file.
fn write_secret_overwrite(path: &Path, contents: &str) -> Result<()> {
    write_text_mode(path, contents, Some(0o600))
}

/// Local consistency check run before dialing: the membership must name
/// *this* keystore's node.
///
/// Catches a membership copied to the wrong machine without a network
/// round-trip, so it never masquerades as a refusal by the responder.
pub(crate) fn preflight(node: NodeId, membership: &Membership) -> Result<(), String> {
    if membership.member != node {
        return Err(format!(
            "this membership was issued to node {}, but this keystore's node is {} — import \
             the invite minted for this node (`wires join <token>`)",
            membership.member.hex(),
            node.hex()
        ));
    }
    Ok(())
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

        // With no inline/env, an explicit file is used.
        let file_id = NodeIdentity::from_seed([6u8; 32]);
        let path = temp_dir().join("node.seed");
        write_secret(&path, &file_id.expose_seed_hex(), true).unwrap();
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
        let path = ks
            .save_node(&NodeIdentity::from_seed([9u8; 32]), false)
            .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// Card 28 §10: a file written through `write_text_mode` is never
    /// world-readable unless asked (its temporary file is created `0600`),
    /// and an explicit mode still applies.
    #[cfg(unix)]
    #[test]
    fn text_files_are_private_unless_widened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let private = dir.join("state-checked.txt");
        write_text_mode(&private, "1\n", None).unwrap();
        assert_eq!(mode(&private), 0o600);
        let public = dir.join("membership.json");
        write_text_mode(&public, "m\n", Some(0o644)).unwrap();
        assert_eq!(mode(&public), 0o644);
        // Overwriting keeps it atomic and leaves no temporary behind.
        write_text_mode(&private, "2\n", None).unwrap();
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

    fn fixture_membership() -> Membership {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let member = NodeIdentity::from_seed([2u8; 32]).node_id();
        Membership::mint(&root, member, 0, i64::MAX).unwrap()
    }

    #[test]
    fn membership_round_trips_and_is_none_when_absent() {
        let ks = Keystore::at(temp_dir());
        assert!(ks.read_membership().unwrap().is_none());
        let m = fixture_membership();
        ks.save_membership(&m).unwrap();
        assert_eq!(ks.read_membership().unwrap().unwrap(), m);
    }

    #[cfg(unix)]
    #[test]
    fn membership_file_is_0644() {
        use std::os::unix::fs::PermissionsExt;
        let ks = Keystore::at(temp_dir());
        let path = ks.save_membership(&fixture_membership()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    #[test]
    fn membership_resolver_prefers_inline_then_file() {
        let m = fixture_membership();
        // Inline token wins, touching no filesystem.
        assert_eq!(membership(Some(&m.encode().unwrap()), None).unwrap(), m);
        // Else an explicit file is decoded.
        let path = temp_dir().join("membership.json");
        write_text(&path, &m.encode().unwrap()).unwrap();
        assert_eq!(membership(None, Some(&path)).unwrap(), m);
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
        ks.save_node(&id, false).unwrap();
        assert_eq!(node_identity_in(&ks).unwrap().node_id(), id.node_id());
    }

    #[test]
    fn preflight_accepts_credentials_issued_to_this_node() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let me = NodeIdentity::from_seed([2u8; 32]).node_id();
        let membership = Membership::mint(&root, me, 0, i64::MAX).unwrap();
        assert_eq!(preflight(me, &membership), Ok(()));
    }

    #[test]
    fn preflight_rejects_a_membership_for_another_node() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let me = NodeIdentity::from_seed([2u8; 32]).node_id();
        let other = NodeIdentity::from_seed([3u8; 32]).node_id();
        let membership = Membership::mint(&root, other, 0, i64::MAX).unwrap();
        let msg = preflight(me, &membership).unwrap_err();
        assert!(
            msg.contains(&other.hex()) && msg.contains(&me.hex()),
            "{msg}"
        );
    }
}
