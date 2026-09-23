//! On-disk key + credential persistence, so the network commands work without
//! secrets on the command line.
//!
//! Files live under the wires home directory — `$WIRES_HOME`, else
//! `$XDG_CONFIG_HOME/wires`, else `~/.config/wires`:
//!
//! - `node.seed` / `root.seed`: hex-encoded 32-byte Ed25519 seeds (mode `0600`).
//! - `membership.json`: the dialer's fabric membership token (mode `0644` — a
//!   *public* signed credential, not a secret).
//! - `roster.json`: the root's full member set + version (mode `0600` — reveals
//!   membership, so private).
//! - `roster-head.json`: the signed roster head token (mode `0644` — public).
//! - `inclusion-proof.json`: a member's own inclusion-proof token (mode `0644`).
//! - `roster-directory.json`: the current head's proof for every member this
//!   node has heard of, from the admin's re-keys (mode `0600`).
//! - `channel.json`: the channel `wires init` / `wires join` recorded.
//! - `names.json`: the admin's local labels for members (mode `0600`).
//! - `keyring/<version>.key`: the hex fabric data key for one roster version
//!   (mode `0600`, directory `0700`) — the plaintext half of the
//!   [`SealedFabricKey`](library::SealedFabricKey) an operator handed over.
//!   Old versions are kept forever: replayed history stays readable.
//!
//! The resolver helpers ([`node_identity`], [`root_identity`], [`membership`])
//! encode the precedence the CLI uses: an inline flag wins, then the matching
//! environment variable, then an explicit `--…-file` path, then the keystore.
//! The `serve` gate that must stay live — the roster head — resolves to a
//! *source* ([`roster_head_source`]) that the responder re-reads per
//! connection, not to a value frozen at startup.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use library::{
    FabricKey, InclusionProof, Membership, NodeId, NodeIdentity, ProofDirectory, Roster,
    RosterHead, RosterVersion,
};

use crate::host::transport::HeadSource;

/// The file name of the proof directory, beside `roster-head.json` (see
/// [`Keystore::read_directory`]).
pub const DIRECTORY_FILE: &str = "roster-directory.json";

/// `channel.json`'s shape.
#[derive(serde::Serialize, serde::Deserialize)]
struct ChannelFile {
    /// The topic name, e.g. `ops`.
    name: String,
}

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
        write_text_mode(&path, &head.encode()?, Some(0o644))?;
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
    /// `wires advanced import --inclusion-proof-file <p>` installs the proof an operator
    /// emitted with `wires advanced roster commit --out DIR`, after which `wires call`
    /// finds it with no flags.
    pub fn save_inclusion_proof(&self, proof: &InclusionProof) -> Result<PathBuf> {
        ensure_dir(&self.dir)?;
        let path = self.path("inclusion-proof.json");
        write_text_mode(&path, &proof.encode()?, Some(0o644))?;
        Ok(path)
    }

    /// Read `roster-directory.json` — the current head's proof for every
    /// member this node has heard of ([`ProofDirectory`]); `None` if absent.
    pub fn read_directory(&self) -> Result<Option<ProofDirectory>> {
        let path = self.path(DIRECTORY_FILE);
        match read_to_string_opt(&path)? {
            Some(text) => Ok(Some(
                serde_json::from_str(&text)
                    .with_context(|| format!("parsing {}", path.display()))?,
            )),
            None => Ok(None),
        }
    }

    /// Persist `directory` to `roster-directory.json` (mode `0600`: it lists
    /// the member set, like the root's `roster.json`). Atomic, because the
    /// session gate and the admission handler read it on every connection.
    pub fn save_directory(&self, directory: &ProofDirectory) -> Result<PathBuf> {
        ensure_dir(&self.dir)?;
        let path = self.path(DIRECTORY_FILE);
        let json = serde_json::to_string(directory).context("encoding the proof directory")?;
        write_secret_overwrite(&path, &json)?;
        Ok(path)
    }

    /// The channel this keystore joined (`channel.json`), set by `wires init`
    /// and `wires join`; `None` before either.
    pub fn read_channel(&self) -> Result<Option<String>> {
        let path = self.path("channel.json");
        match read_to_string_opt(&path)? {
            Some(text) => {
                let channel: ChannelFile = serde_json::from_str(&text)
                    .with_context(|| format!("parsing {}", path.display()))?;
                Ok(Some(channel.name))
            }
            None => Ok(None),
        }
    }

    /// Record `name` as this keystore's channel (`channel.json`, mode
    /// `0644` — a topic name is not a secret from the node that holds it).
    pub fn save_channel(&self, name: &str) -> Result<PathBuf> {
        ensure_dir(&self.dir)?;
        let path = self.path("channel.json");
        let json = serde_json::to_string(&ChannelFile {
            name: name.to_string(),
        })
        .context("encoding channel.json")?;
        write_text_mode(&path, &json, Some(0o644))?;
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

    /// The keyring directory (`<home>/keyring`, mode `0700`), holding one
    /// `<version>.key` file per roster version whose fabric key this node holds.
    pub fn keyring_dir(&self) -> PathBuf {
        self.dir.join("keyring")
    }

    /// The path of the fabric key file for roster `version`.
    pub fn fabric_key_path(&self, version: RosterVersion) -> PathBuf {
        self.keyring_dir().join(format!("{}.key", version.0))
    }

    /// Persist `key` as `keyring/<version>.key` (hex, mode `0600`), returning
    /// the written path.
    ///
    /// Unlike [`save_node`](Self::save_node) this **overwrites**: a key is
    /// identified by its roster version, so re-importing the same
    /// [`SealedFabricKey`](library::SealedFabricKey) rewrites identical bytes
    /// and re-running `wires advanced import` is safe. (A *different* key for a version
    /// already held would also overwrite — but only the root mints keys, and it
    /// mints exactly one per commit, so there is no second key to install.)
    pub fn save_fabric_key(&self, version: RosterVersion, key: &FabricKey) -> Result<PathBuf> {
        ensure_dir(&self.dir)?; // `0700` on the home too, if this is its first file
        ensure_dir(&self.keyring_dir())?;
        let path = self.fabric_key_path(version);
        write_secret(&path, &key.hex(), true)?;
        // `write_secret`'s mode applies at creation only; re-assert it so an
        // overwrite cannot inherit looser permissions from a pre-existing file.
        set_mode(&path, 0o600);
        Ok(path)
    }

    /// Read the fabric key for `version`; `None` when this node does not hold
    /// it (the late-joiner case — pre-join history stays unreadable).
    ///
    /// `#[cfg(test)]`: the resident node loads the whole keyring
    /// ([`read_keyring`](Self::read_keyring)) once and keeps it, because a
    /// message can name any past version; reading one version at a time is how
    /// the suite asserts *which* keys a member ended up holding — the
    /// late-joiner claim in particular.
    #[cfg(test)]
    pub fn read_fabric_key(&self, version: RosterVersion) -> Result<Option<FabricKey>> {
        let path = self.fabric_key_path(version);
        match read_to_string_opt(&path)? {
            Some(text) => Ok(Some(parse_fabric_key(&path, &text)?)),
            None => Ok(None),
        }
    }

    /// Read every key in the keyring, ordered by roster version.
    ///
    /// An absent keyring directory is an empty map (a node that has never run
    /// `wires advanced import --fabric-key`), and files that are not named
    /// `<decimal>.key` are ignored rather than fatal — but a `<decimal>.key`
    /// whose contents are not a 32-byte hex key is an error naming the file, so
    /// a truncated write is reported instead of silently losing history.
    pub fn read_keyring(&self) -> Result<BTreeMap<RosterVersion, FabricKey>> {
        let dir = self.keyring_dir();
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
        };
        let mut keyring = BTreeMap::new();
        for entry in entries {
            let path = entry
                .with_context(|| format!("listing {}", dir.display()))?
                .path();
            let Some(version) = keyring_file_version(&path) else {
                continue;
            };
            // A file that vanished between the listing and the read is simply
            // not in the keyring.
            if let Some(text) = read_to_string_opt(&path)? {
                keyring.insert(version, parse_fabric_key(&path, &text)?);
            }
        }
        Ok(keyring)
    }

    /// The highest-versioned key in the keyring — the one a fresh `publish`
    /// seals under. `None` when the keyring is empty.
    pub fn latest_fabric_key(&self) -> Result<Option<(RosterVersion, FabricKey)>> {
        Ok(self.read_keyring()?.into_iter().next_back())
    }
}

/// The roster version a keyring filename encodes, or `None` when the file is
/// not a `<decimal>.key` (editor backups and the like are not keys).
fn keyring_file_version(path: &Path) -> Option<RosterVersion> {
    if path.extension()? != "key" {
        return None;
    }
    path.file_stem()?
        .to_str()?
        .parse::<u64>()
        .ok()
        .map(RosterVersion)
}

/// Parse a keyring file's hex contents, naming the file and the remedy.
fn parse_fabric_key(path: &Path, text: &str) -> Result<FabricKey> {
    FabricKey::from_hex(text.trim()).with_context(|| {
        format!(
            "parsing {} (expected 64 hex characters; delete it and re-run \
             `wires advanced import --fabric-key <token>`)",
            path.display()
        )
    })
}

// ---------------------------------------------------------------------------
// CLI resolvers (flag > env > file > keystore)
// ---------------------------------------------------------------------------

/// Resolve a node identity for `serve` / `call`.
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

/// Resolve the node identity for an offline command that already holds a
/// keystore handle (`wires advanced import --fabric-key`, which must open a sealed key
/// as *this* node): `$WIRES_NODE_SEED` wins — the same environment variable the
/// network commands honour — then `ks`'s own `node.seed`.
///
/// There is no inline-flag tier because `import` takes no key flags: the point
/// of the command is to fill the keystore the other commands read from.
pub fn node_identity_in(ks: &Keystore) -> Result<NodeIdentity> {
    if let Some(hex) = std::env::var("WIRES_NODE_SEED")
        .ok()
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

/// Resolve the root signing identity (the admin's commands).
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
         --membership-file, or run `wires advanced member --subject <id> --save` (looked for {})",
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
/// was imported enforces from the dial after `wires advanced import --roster-head…`
/// lands, with no restart. Until a head has ever been seen it enforces nothing
/// (the pre-roster membership + TTL behavior); once one has, a missing or
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

/// Write `contents` to `path` **atomically**: a temporary file in the same
/// directory, then a `rename` over the target.
///
/// Every file this module writes is also read, concurrently, by something that
/// takes no lock — `roster-head.json` most of all, which the admission handler
/// and the watchdog re-read on every handshake and every pass while `wires
/// import` and `wires advanced roster commit` rewrite it from other processes. A plain
/// `std::fs::write` is `O_TRUNC` followed by a write, so a reader landing in
/// that window sees an empty or half-written token; the admission path answers
/// "responder configuration error" and the watchdog treats an unloadable head as
/// *evict everyone*, tearing the whole mesh down over a scheduling accident.
///
/// `rename(2)` within a directory is atomic, so a reader sees either the
/// previous contents or the new ones and never a splice of the two. The mode is
/// set on the temporary file *before* the rename, so the target is never
/// momentarily world-readable either.
fn write_text_mode(path: &Path, contents: &str, mode: Option<u32>) -> Result<()> {
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
        std::fs::write(&tmp, contents).with_context(|| format!("writing {}", tmp.display()))?;
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

/// Write a secret file at mode `0600`, overwriting any existing file (used for
/// `roster.json`, rewritten in place by `roster add`/`remove`/`commit`).
fn write_secret_overwrite(path: &Path, contents: &str) -> Result<()> {
    write_text_mode(path, contents, Some(0o600))
}

/// Read a credential token from an inline flag or a file, trimming whitespace.
/// `None` when neither was supplied.
pub(crate) fn token_arg(
    inline: Option<&str>,
    file: Option<&Path>,
    flag: &str,
) -> anyhow::Result<Option<String>> {
    if let Some(text) = inline {
        return Ok(Some(text.trim().to_string()));
    }
    match file {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("{flag}-file: reading {}", path.display()))?;
            Ok(Some(text.trim().to_string()))
        }
        None => Ok(None),
    }
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
             the membership minted for this node (`wires advanced import --membership …`)",
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

    /// A reader that takes no lock must never see a half-written head.
    ///
    /// The regression: `save_roster_head` used to be `O_TRUNC` + write, and
    /// every reader of `roster-head.json` — the admission handler on each
    /// handshake, the watchdog on each pass, in this process and in the `wires
    /// import` / `wires advanced roster commit` ones — reads it with no lock at all. A
    /// reader landing in the truncation window got a decode error, which the
    /// watchdog reads as *evict every peer*: one scheduling accident tore the
    /// whole mesh down. With the write atomic (temp file + rename) the reader
    /// sees the old token or the new one, never a splice.
    #[test]
    fn a_concurrent_reader_never_sees_a_torn_roster_head() {
        let (root, mut roster) = fixture_roster();
        let ks = std::sync::Arc::new(Keystore::at(temp_dir()));
        let mut heads = Vec::new();
        for _ in 0..40 {
            heads.push(roster.commit(&root, 0, i64::MAX).unwrap().0);
        }
        ks.save_roster_head(&heads[0]).unwrap();

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = {
            let (ks, stop) = (std::sync::Arc::clone(&ks), std::sync::Arc::clone(&stop));
            std::thread::spawn(move || {
                let mut reads = 0usize;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    // Any `Err` here is a torn read; `None` would mean the file
                    // vanished, which a rename never does either.
                    let head = ks.read_roster_head().expect("a torn roster head");
                    assert!(head.is_some(), "the head file must never disappear");
                    reads += 1;
                }
                reads
            })
        };
        for head in &heads {
            ks.save_roster_head(head).unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(reader.join().unwrap() > 0, "the reader must have run");
        assert_eq!(
            ks.read_roster_head().unwrap().unwrap(),
            *heads.last().unwrap()
        );
        // No temp file is left behind for the next reader to trip over.
        let strays: Vec<_> = std::fs::read_dir(ks.path("."))
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(strays.is_empty(), "temporary files left behind: {strays:?}");
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
    fn fabric_key_round_trips_through_the_keyring() {
        let ks = Keystore::at(temp_dir().join("nested")); // also exercises dir creation
        assert!(ks.read_fabric_key(RosterVersion(3)).unwrap().is_none());

        let key = FabricKey::generate();
        let path = ks.save_fabric_key(RosterVersion(3), &key).unwrap();
        assert!(path.ends_with("keyring/3.key"));
        assert_eq!(ks.read_fabric_key(RosterVersion(3)).unwrap().unwrap(), key);
        // Overwrite-idempotent: re-importing the same key is not an error.
        ks.save_fabric_key(RosterVersion(3), &key).unwrap();
        assert_eq!(ks.read_fabric_key(RosterVersion(3)).unwrap().unwrap(), key);
    }

    #[test]
    fn keyring_is_empty_before_any_import() {
        let ks = Keystore::at(temp_dir());
        assert!(ks.read_keyring().unwrap().is_empty());
        assert!(ks.latest_fabric_key().unwrap().is_none());
    }

    #[test]
    fn latest_fabric_key_is_the_highest_version() {
        let ks = Keystore::at(temp_dir());
        let (v2, v10, v7) = (
            FabricKey::generate(),
            FabricKey::generate(),
            FabricKey::generate(),
        );
        ks.save_fabric_key(RosterVersion(2), &v2).unwrap();
        ks.save_fabric_key(RosterVersion(10), &v10).unwrap();
        ks.save_fabric_key(RosterVersion(7), &v7).unwrap();
        // Numeric, not lexicographic: "10" must beat "7".
        assert_eq!(
            ks.latest_fabric_key().unwrap().unwrap(),
            (RosterVersion(10), v10)
        );

        // Old versions are kept forever so replayed history stays readable.
        let keyring = ks.read_keyring().unwrap();
        assert_eq!(keyring.len(), 3);
        assert_eq!(keyring[&RosterVersion(2)], v2);
        assert_eq!(keyring[&RosterVersion(7)], v7);

        // A file that is not `<decimal>.key` is ignored, not fatal.
        write_text(&ks.keyring_dir().join("notes.txt"), "hello").unwrap();
        write_text(&ks.keyring_dir().join("backup.key"), "hello").unwrap();
        assert_eq!(ks.read_keyring().unwrap().len(), 3);
    }

    #[test]
    fn corrupt_keyring_file_names_the_file_and_the_remedy() {
        let ks = Keystore::at(temp_dir());
        ks.save_fabric_key(RosterVersion(1), &FabricKey::generate())
            .unwrap();
        let path = ks.fabric_key_path(RosterVersion(1));
        write_text(&path, "not-a-key").unwrap();

        for err in [
            ks.read_fabric_key(RosterVersion(1)).unwrap_err(),
            ks.read_keyring().unwrap_err(),
        ] {
            let msg = format!("{err:#}");
            assert!(msg.contains(&path.display().to_string()), "{msg}");
            assert!(msg.contains("wires advanced import --fabric-key"), "{msg}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn keyring_files_are_0600_in_a_0700_dir() {
        use std::os::unix::fs::PermissionsExt;
        let ks = Keystore::at(temp_dir());
        let path = ks
            .save_fabric_key(RosterVersion(4), &FabricKey::generate())
            .unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&ks.keyring_dir()), 0o700);
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
