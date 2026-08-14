//! On-disk key + CRL persistence, so the network commands work without
//! secrets on the command line.
//!
//! Files live under the wires home directory — `$WIRES_HOME`, else
//! `$XDG_CONFIG_HOME/wires`, else `~/.config/wires`:
//!
//! - `node.seed` / `root.seed`: hex-encoded 32-byte Ed25519 seeds (mode `0600`).
//! - `crl.json`: the responder's revocation list.
//! - `membership.json`: the dialer's fabric membership token (mode `0644` — a
//!   *public* signed credential, not a secret).
//! - `roster.json`: the root's full member set + version (mode `0600` — reveals
//!   membership, so private).
//! - `roster-head.json`: the signed roster head token (mode `0644` — public).
//! - `inclusion-proof.json`: a member's own inclusion-proof token (mode `0644`).
//!
//! The resolver helpers ([`node_identity`], [`root_identity`], [`crl_source`],
//! [`membership`]) encode the precedence the CLI uses: an inline flag wins, then
//! the matching environment variable, then an explicit `--…-file` path, then the
//! keystore. The two `serve` gates that must stay live — the CRL and the roster
//! head — resolve to a *source* ([`crl_source`], [`roster_head_source`]) that the
//! responder re-reads per connection, not to a value frozen at startup.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use library::{Crl, InclusionProof, Membership, NodeIdentity, Roster, RosterHead};

use crate::transport::{CrlSource, HeadSource};

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
        write_text(&path, &membership.encode()?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).ok();
        }
        Ok(path)
    }

    /// Read `roster.json` as a [`Roster`]; `None` if the file is absent.
    pub fn read_roster(&self) -> Result<Option<Roster>> {
        let path = self.path("roster.json");
        match read_to_string_opt(&path)? {
            Some(text) => Ok(Some(
                serde_json::from_str(&text)
                    .with_context(|| format!("parsing {}", path.display()))?,
            )),
            None => Ok(None),
        }
    }

    /// Persist the root's member set to `roster.json` (mode `0600` — it reveals
    /// membership). Returns the written path.
    pub fn save_roster(&self, roster: &Roster) -> Result<PathBuf> {
        ensure_dir(&self.dir)?;
        let path = self.path("roster.json");
        let json = serde_json::to_string(roster).context("encoding roster")?;
        write_secret_overwrite(&path, &json)?;
        Ok(path)
    }

    /// Read `roster-head.json` as a [`RosterHead`]; `None` if absent.
    pub fn read_roster_head(&self) -> Result<Option<RosterHead>> {
        let path = self.path("roster-head.json");
        match read_to_string_opt(&path)? {
            Some(text) => Ok(Some(
                RosterHead::decode(text.trim())
                    .with_context(|| format!("parsing {}", path.display()))?,
            )),
            None => Ok(None),
        }
    }

    /// Persist `head` to `roster-head.json` as its token (mode `0644` — public).
    pub fn save_roster_head(&self, head: &RosterHead) -> Result<PathBuf> {
        ensure_dir(&self.dir)?;
        let path = self.path("roster-head.json");
        write_text(&path, &head.encode()?)?;
        set_mode(&path, 0o644);
        Ok(path)
    }

    /// Read `inclusion-proof.json` as an [`InclusionProof`]; `None` if absent.
    pub fn read_inclusion_proof(&self) -> Result<Option<InclusionProof>> {
        let path = self.path("inclusion-proof.json");
        match read_to_string_opt(&path)? {
            Some(text) => Ok(Some(
                InclusionProof::decode(text.trim())
                    .with_context(|| format!("parsing {}", path.display()))?,
            )),
            None => Ok(None),
        }
    }

    /// Persist `proof` to `inclusion-proof.json` as its token (mode `0644`). The
    /// symmetric half of [`read_inclusion_proof`](Self::read_inclusion_proof):
    /// `wires import --inclusion-proof-file <p>` installs the proof an operator
    /// emitted with `wires roster commit --out DIR`, after which `wires connect`
    /// finds it with no flags.
    pub fn save_inclusion_proof(&self, proof: &InclusionProof) -> Result<PathBuf> {
        ensure_dir(&self.dir)?;
        let path = self.path("inclusion-proof.json");
        write_text(&path, &proof.encode()?)?;
        set_mode(&path, 0o644);
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

/// Resolve the dialer's membership for `connect`: an inline `--membership`
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
         --membership-file, or run `wires member --subject <id> --save` (looked for {})",
        ks.path("membership.json").display()
    );
}

/// Resolve *where* `serve` reads its enforced roster head from: an inline
/// `--roster-head` token, then `$WIRES_ROSTER_HEAD` (both pinned for the
/// process's life), then `--roster-head-file`, then the keystore's
/// `roster-head.json` — the two file cases are re-read per connection.
///
/// The keystore case is [`HeadSource::Keystore`], which re-checks *existence*
/// per connection rather than at startup: a responder started before its head
/// was imported enforces from the dial after `wires import --roster-head…`
/// lands, with no restart. Until a head has ever been seen it enforces nothing
/// (the pre-roster membership + CRL + TTL behavior); once one has, a missing or
/// malformed file fails closed, like [`HeadSource::File`].
pub fn roster_head_source(inline: Option<&str>, file: Option<PathBuf>) -> Result<HeadSource> {
    if let Some(token) = inline {
        return Ok(HeadSource::Fixed(
            RosterHead::decode(token).context("--roster-head")?,
        ));
    }
    if let Some(token) = std::env::var("WIRES_ROSTER_HEAD")
        .ok()
        .filter(|s| !s.is_empty())
    {
        return Ok(HeadSource::Fixed(
            RosterHead::decode(&token).context("$WIRES_ROSTER_HEAD")?,
        ));
    }
    if let Some(path) = file {
        return Ok(HeadSource::File(path));
    }
    Ok(HeadSource::Keystore {
        path: Keystore::resolve()?.path("roster-head.json"),
        armed: std::sync::atomic::AtomicBool::new(false),
    })
}

/// Resolve an inclusion proof: inline `--inclusion-proof` token, then
/// `$WIRES_INCLUSION_PROOF`, then `--inclusion-proof-file`, then the keystore
/// (`inclusion-proof.json`). `None` when none is configured.
pub fn inclusion_proof(
    inline: Option<&str>,
    file: Option<&Path>,
) -> Result<Option<InclusionProof>> {
    if let Some(token) = inline {
        return Ok(Some(
            InclusionProof::decode(token).context("--inclusion-proof")?,
        ));
    }
    if let Some(token) = std::env::var("WIRES_INCLUSION_PROOF")
        .ok()
        .filter(|s| !s.is_empty())
    {
        return Ok(Some(
            InclusionProof::decode(&token).context("$WIRES_INCLUSION_PROOF")?,
        ));
    }
    if let Some(path) = file {
        let text = read_to_string_opt(path)?
            .ok_or_else(|| anyhow!("inclusion proof file not found: {}", path.display()))?;
        return Ok(Some(
            InclusionProof::decode(text.trim())
                .with_context(|| format!("parsing {}", path.display()))?,
        ));
    }
    Keystore::resolve()?.read_inclusion_proof()
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

/// Resolve *where* `serve` reads its revocation list from: inline `--crl-json`
/// (parsed once, pinned), else `--crl-file`, else the keystore's `crl.json` —
/// the two file cases are re-read per connection, so `wires revoke` lands
/// without a restart. A missing file is an empty list.
pub fn crl_source(inline: Option<&str>, file: Option<PathBuf>) -> Result<CrlSource> {
    if let Some(json) = inline {
        return Ok(CrlSource::Fixed(Crl::from_json(json)?));
    }
    if let Some(path) = file {
        return Ok(CrlSource::File(path));
    }
    Ok(CrlSource::File(Keystore::resolve()?.path("crl.json")))
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

/// Write a secret file at mode `0600`, overwriting any existing file (used for
/// `roster.json`, rewritten in place by `roster add`/`remove`/`commit`).
fn write_secret_overwrite(path: &Path, contents: &str) -> Result<()> {
    write_text(path, contents)?;
    set_mode(path, 0o600);
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
    fn crl_round_trips_and_is_empty_when_absent() {
        let ks = Keystore::at(temp_dir());
        let source = CrlSource::File(ks.path("crl.json"));
        assert!(source.load().unwrap().is_empty());

        let mut crl = Crl::new();
        crl.insert(NodeIdentity::from_seed([7u8; 32]).node_id());
        ks.save_crl_json(&crl.to_json().unwrap()).unwrap();
        // Same source object, re-read: what makes `wires revoke` land without a
        // responder restart.
        assert_eq!(source.load().unwrap(), crl);
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
    fn crl_source_prefers_inline_then_file() {
        let mut crl = Crl::new();
        crl.insert(NodeIdentity::from_seed([4u8; 32]).node_id());
        let json = crl.to_json().unwrap();

        // Inline JSON is parsed once and pinned; no filesystem is touched.
        let inline = crl_source(Some(&json), None).unwrap();
        assert!(matches!(inline, CrlSource::Fixed(_)));
        assert_eq!(inline.load().unwrap(), crl);

        // An explicit file becomes a re-read-per-connection source.
        let dir = temp_dir();
        let path = dir.join("crl.json");
        write_crl_text(&path, &json).unwrap();
        assert_eq!(crl_source(None, Some(path)).unwrap().load().unwrap(), crl);
        assert!(
            crl_source(None, Some(dir.join("absent.json")))
                .unwrap()
                .load()
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

    fn fixture_roster() -> (NodeIdentity, library::Roster) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut roster = library::Roster::new(root.node_id());
        roster.insert(NodeIdentity::from_seed([2u8; 32]).node_id());
        roster.insert(NodeIdentity::from_seed([3u8; 32]).node_id());
        (root, roster)
    }

    #[test]
    fn roster_round_trips_and_is_none_when_absent() {
        let ks = Keystore::at(temp_dir());
        assert!(ks.read_roster().unwrap().is_none());
        let (_root, roster) = fixture_roster();
        ks.save_roster(&roster).unwrap();
        assert_eq!(ks.read_roster().unwrap().unwrap(), roster);
    }

    #[test]
    fn roster_head_and_proof_round_trip() {
        let ks = Keystore::at(temp_dir());
        let (root, mut roster) = fixture_roster();
        let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        ks.save_roster_head(&head).unwrap();
        assert_eq!(ks.read_roster_head().unwrap().unwrap(), head);

        let proof = proofs.into_iter().next().unwrap().1;
        ks.save_inclusion_proof(&proof).unwrap();
        assert_eq!(ks.read_inclusion_proof().unwrap().unwrap(), proof);
    }

    #[cfg(unix)]
    #[test]
    fn roster_file_modes() {
        use std::os::unix::fs::PermissionsExt;
        let ks = Keystore::at(temp_dir());
        let (root, mut roster) = fixture_roster();
        let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let rp = ks.save_roster(&roster).unwrap();
        let hp = ks.save_roster_head(&head).unwrap();
        let pp = ks.save_inclusion_proof(&proofs[0].1).unwrap();
        assert_eq!(
            std::fs::metadata(&rp).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&hp).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(
            std::fs::metadata(&pp).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn roster_head_source_prefers_inline_then_file() {
        let (root, mut roster) = fixture_roster();
        let (head, _) = roster.commit(&root, 0, i64::MAX).unwrap();
        let inline = roster_head_source(Some(&head.encode().unwrap()), None).unwrap();
        assert_eq!(inline.load().unwrap().unwrap(), head);

        let path = temp_dir().join("roster-head.json");
        write_text(&path, &head.encode().unwrap()).unwrap();
        let from_file = roster_head_source(None, Some(path)).unwrap();
        assert!(matches!(from_file, HeadSource::File(_)));
        assert_eq!(from_file.load().unwrap().unwrap(), head);
    }

    #[test]
    fn inclusion_proof_resolver_prefers_inline_then_file() {
        let (root, mut roster) = fixture_roster();
        let (_head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let proof = proofs.into_iter().next().unwrap().1;
        assert_eq!(
            inclusion_proof(Some(&proof.encode().unwrap()), None)
                .unwrap()
                .unwrap(),
            proof
        );
        let path = temp_dir().join("inclusion-proof.json");
        write_text(&path, &proof.encode().unwrap()).unwrap();
        assert_eq!(inclusion_proof(None, Some(&path)).unwrap().unwrap(), proof);
    }
}
