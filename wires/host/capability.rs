//! The per-call push capability (card 28 §1): how a service pushes back to
//! **its own caller** without holding any of the host's authority.
//!
//! A service child runs with none of the host's keystore (no `WIRES_HOME`).
//! When `host.json` enables `push`, `serve` mints a fresh random
//! [`PushToken`] for every call it spawns and hands the child two variables:
//!
//! - `WIRES_PUSH_SOCKET`: the **child-facing** control socket, in a private
//!   directory made for this `serve` outside the keystore ([`ChildDir`]:
//!   `$XDG_RUNTIME_DIR/wires-<random>/push.sock`, else the same under the
//!   temp dir), so the path names neither `WIRES_HOME` nor the operator's
//!   `run/serve.sock`;
//! - `WIRES_PUSH_TOKEN`: the token, 64 hex characters.
//!
//! `wires push` in the child sees `WIRES_PUSH_TOKEN` and sends
//! `{"caller_push":{"token":…,"push":{…}}}` to that socket (no keystore
//! needed). The child socket accepts a push only when:
//!
//! 1. the token is one this `serve` minted and is still live: for the whole
//!    call, and [`CAPABILITY_GRACE`] after it ends (so a background job the
//!    call started, e.g. a CI build, can still report);
//! 2. `to` is exactly that call's caller node (never a role, never another
//!    node).
//!
//! The push then goes through the same `push.allow` check as any other, and
//! its call-log records name the call whose capability sent it.
//!
//! The operator socket keeps full `wires push --to <node|role>` power. The
//! child is told neither where it is nor where the keystore is, but a child
//! running as the host's own Unix user can still find the keystore at its
//! default path (and the operator socket in it) and open anything that user
//! can. That is accepted for now: isolating services (a separate user, or a
//! rootless microVM later) is left open (`docs/protocol.md` §5).

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use library::{CallId, NodeId, ServiceName};

/// How long a call's push token stays live after the call ends: long enough
/// for a build or job the call started to report back, short enough that a
/// leaked token soon dies. Tokens are memory-only, so a `serve` restart
/// kills them all.
pub(crate) const CAPABILITY_GRACE: Duration = Duration::from_secs(10 * 60);

/// The child-facing socket's file name inside its [`ChildDir`].
pub(crate) const CHILD_SOCKET: &str = "push.sock";

/// The variable naming the child-facing control socket.
pub(crate) const ENV_SOCKET: &str = "WIRES_PUSH_SOCKET";

/// The variable holding the call's push token.
pub(crate) const ENV_TOKEN: &str = "WIRES_PUSH_TOKEN";

/// A call's push token: 32 random bytes, written as 64 lowercase hex
/// characters. `Debug` shows only a prefix, so a token never lands whole in
/// a log line.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct PushToken([u8; 32]);

impl PushToken {
    /// A fresh random token (the OS CSPRNG).
    pub(crate) fn generate() -> Self {
        use ring::rand::SecureRandom as _;
        let mut bytes = [0u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut bytes)
            .expect("the OS random source failed");
        Self(bytes)
    }

    /// The 64-hex form handed to the child.
    pub(crate) fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parse the 64-hex form; `None` for anything else.
    pub(crate) fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mut bytes = [0u8; 32];
        for (i, out) in bytes.iter_mut().enumerate() {
            *out = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
        }
        Some(Self(bytes))
    }
}

impl fmt::Debug for PushToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PushToken({}…)", &self.hex()[..8])
    }
}

/// What a live token entitles its holder to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Grant {
    /// The call's caller: the only node the token can push to.
    pub(crate) caller: NodeId,
    /// The service the call ran.
    pub(crate) service: ServiceName,
    /// The call's id in the call log, once its `Started` record exists.
    pub(crate) call: Option<CallId>,
    /// When the token dies; `None` while the call is still running.
    pub(crate) expires: Option<Instant>,
}

/// Why the child socket refused a push. `Display` is what the child is told.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CapabilityRefusal {
    /// Not a token this `serve` minted, or one that has expired.
    Unknown,
    /// The token is live, but `to` is not its call's caller.
    NotTheCaller {
        /// The caller the token can reach.
        caller: NodeId,
    },
}

impl fmt::Display for CapabilityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapabilityRefusal::Unknown => write!(
                f,
                "unknown or expired push token (a call's token lasts until {} min after the call \
                 ends)",
                CAPABILITY_GRACE.as_secs() / 60
            ),
            CapabilityRefusal::NotTheCaller { caller } => write!(
                f,
                "this call's push capability reaches only its caller ({}); --to must be \
                 $WIRES_CALLER_NODE",
                caller.hex()
            ),
        }
    }
}

/// Every live push token of one `serve`, in memory only.
#[derive(Debug, Default)]
pub(crate) struct Capabilities {
    /// Token → what it grants.
    grants: Mutex<HashMap<PushToken, Grant>>,
}

impl Capabilities {
    /// Mint a token for a call by `caller` to `service`, live until the
    /// returned handle is dropped plus [`CAPABILITY_GRACE`].
    pub(crate) fn mint(self: &Arc<Self>, caller: NodeId, service: ServiceName) -> CallCapability {
        let token = PushToken::generate();
        let mut grants = self.lock();
        prune(&mut grants, Instant::now());
        grants.insert(
            token.clone(),
            Grant {
                caller,
                service,
                call: None,
                expires: None,
            },
        );
        CallCapability {
            caps: Arc::clone(self),
            token,
        }
    }

    /// Attach the call-log id of the call `token` was minted for.
    pub(crate) fn bind_call(&self, token: &PushToken, call: CallId) {
        if let Some(g) = self.lock().get_mut(token) {
            g.call = Some(call);
        }
    }

    /// The call `token` was minted for ended at `at`: it dies
    /// [`CAPABILITY_GRACE`] later.
    pub(crate) fn finish(&self, token: &PushToken, at: Instant) {
        if let Some(g) = self.lock().get_mut(token) {
            g.expires = Some(at + CAPABILITY_GRACE);
        }
    }

    /// May the holder of `token` push to `to` (the request's `--to`) at
    /// `now`? The grant on success.
    pub(crate) fn check(
        &self,
        token: &PushToken,
        to: &str,
        now: Instant,
    ) -> Result<Grant, CapabilityRefusal> {
        let mut grants = self.lock();
        prune(&mut grants, now);
        let grant = grants.get(token).ok_or(CapabilityRefusal::Unknown)?;
        let exact = to.len() == 64 && NodeId::from_hex(to).is_ok_and(|n| n == grant.caller);
        if !exact {
            return Err(CapabilityRefusal::NotTheCaller {
                caller: grant.caller,
            });
        }
        Ok(grant.clone())
    }

    /// How many tokens are held (live or not yet pruned).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<PushToken, Grant>> {
        self.grants.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Drop every grant expired at `now`.
fn prune(grants: &mut HashMap<PushToken, Grant>, now: Instant) {
    grants.retain(|_, g| g.expires.is_none_or(|t| t > now));
}

/// One call's token, held by the session for as long as the child runs.
/// Dropping it starts the [`CAPABILITY_GRACE`] countdown, so a call that
/// fails half-way still has its token expire.
#[derive(Debug)]
pub(crate) struct CallCapability {
    /// The registry it was minted in.
    caps: Arc<Capabilities>,
    /// The token.
    token: PushToken,
}

impl CallCapability {
    /// The token (for the child's environment).
    pub(crate) fn token(&self) -> &PushToken {
        &self.token
    }

    /// Attach the call's log id (see [`Capabilities::bind_call`]).
    pub(crate) fn bind_call(&self, call: CallId) {
        self.caps.bind_call(&self.token, call);
    }
}

impl Drop for CallCapability {
    fn drop(&mut self) {
        self.caps.finish(&self.token, Instant::now());
    }
}

/// What `serve` hands its sessions when push is on: the token registry and
/// where the child socket is.
#[derive(Clone, Debug)]
pub(crate) struct PushGrants {
    /// The live tokens.
    pub(crate) caps: Arc<Capabilities>,
    /// The private directory holding the child socket; removed when the last
    /// holder drops it (and explicitly when `serve` exits).
    pub(crate) dir: Arc<ChildDir>,
    /// The child-facing control socket (`WIRES_PUSH_SOCKET`).
    pub(crate) socket: PathBuf,
}

impl PushGrants {
    /// Fresh grants, with a new [`ChildDir`] for the socket.
    pub(crate) fn new() -> std::io::Result<Self> {
        let dir = Arc::new(ChildDir::create()?);
        Ok(Self {
            caps: Arc::default(),
            socket: dir.socket(),
            dir,
        })
    }
}

/// One `serve`'s private directory for the child socket: `wires-<16 random
/// hex>`, mode `0700`, under `$XDG_RUNTIME_DIR` when set, else the temp dir,
/// else `/tmp` (the first whose socket path fits a `sockaddr_un`). It is
/// outside the keystore, so the path a child is given reveals neither
/// `WIRES_HOME` nor the operator socket; random, so it names nothing else
/// either. Created at `serve` start, removed when dropped.
#[derive(Debug)]
pub(crate) struct ChildDir {
    /// The directory.
    path: PathBuf,
}

impl ChildDir {
    /// Make a fresh one (see the type docs).
    pub(crate) fn create() -> std::io::Result<Self> {
        let mut bases = Vec::new();
        if let Some(run) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from)
            && run.is_absolute()
            && run.is_dir()
        {
            bases.push(run);
        }
        bases.push(std::env::temp_dir());
        bases.push(PathBuf::from("/tmp"));
        let mut last = std::io::Error::other("no base directory for the child socket");
        for base in bases {
            let path = base.join(format!("wires-{}", &PushToken::generate().hex()[..16]));
            if !crate::host::control::fits_sockaddr(&path.join(CHILD_SOCKET)) {
                continue;
            }
            match make_private_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// The directory.
    #[cfg(test)]
    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// The child socket's path in it.
    pub(crate) fn socket(&self) -> PathBuf {
        self.path.join(CHILD_SOCKET)
    }

    /// Remove the directory and what is in it (idempotent).
    pub(crate) fn remove(&self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

impl Drop for ChildDir {
    fn drop(&mut self) {
        self.remove();
    }
}

/// Create `path` (not its parents) with mode `0700`; fails if it exists.
fn make_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::NodeIdentity;
    use proptest::prelude::*;

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    fn svc() -> ServiceName {
        ServiceName::new("deploy").unwrap()
    }

    #[test]
    fn a_token_is_64_hex_and_round_trips() {
        let t = PushToken::generate();
        assert_eq!(t.hex().len(), 64);
        assert_eq!(PushToken::from_hex(&t.hex()), Some(t.clone()));
        assert_ne!(t, PushToken::generate());
        assert!(
            !format!("{t:?}").contains(&t.hex()),
            "Debug must not leak it"
        );
        for bad in ["", "zz", &"g".repeat(64), &"a".repeat(63), &"a".repeat(65)] {
            assert_eq!(PushToken::from_hex(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_live_token_pushes_only_to_its_caller() {
        let caps = Arc::new(Capabilities::default());
        let cap = caps.mint(node(2), svc());
        let now = Instant::now();
        let grant = caps.check(cap.token(), &node(2).hex(), now).unwrap();
        assert_eq!(grant.caller, node(2));
        assert_eq!(grant.call, None);
        let call = CallId::generate();
        cap.bind_call(call);
        assert_eq!(
            caps.check(cap.token(), &node(2).hex(), now).unwrap().call,
            Some(call)
        );
        for to in [
            node(3).hex(),
            "analyst".into(),
            "member".into(),
            String::new(),
        ] {
            assert_eq!(
                caps.check(cap.token(), &to, now),
                Err(CapabilityRefusal::NotTheCaller { caller: node(2) }),
                "{to}"
            );
        }
        // A token nobody minted.
        assert_eq!(
            caps.check(&PushToken::generate(), &node(2).hex(), now),
            Err(CapabilityRefusal::Unknown)
        );
    }

    #[test]
    fn a_token_dies_a_grace_period_after_its_call_ends() {
        let caps = Arc::new(Capabilities::default());
        let cap = caps.mint(node(2), svc());
        let token = cap.token().clone();
        let to = node(2).hex();
        // While the call runs, no clock kills it.
        let far = Instant::now() + CAPABILITY_GRACE * 10;
        assert!(caps.check(&token, &to, far).is_ok());
        let ended = Instant::now();
        drop(cap);
        assert!(
            caps.check(&token, &to, ended + CAPABILITY_GRACE / 2)
                .is_ok()
        );
        assert_eq!(
            caps.check(
                &token,
                &to,
                ended + CAPABILITY_GRACE + Duration::from_secs(1)
            ),
            Err(CapabilityRefusal::Unknown)
        );
        // And it is gone for good, not just refused.
        assert_eq!(caps.len(), 0);
        assert!(caps.check(&token, &to, ended).is_err());
    }

    /// Card 28 §1/§9: the child socket's directory is private, outside
    /// any keystore, fits a unix socket path, is fresh per `serve`, and is
    /// gone when dropped.
    #[test]
    fn the_child_dir_is_private_fresh_and_removed() {
        let a = ChildDir::create().unwrap();
        let b = ChildDir::create().unwrap();
        assert_ne!(a.path(), b.path());
        assert!(crate::host::control::fits_sockaddr(&a.socket()));
        assert_eq!(a.socket().parent(), Some(a.path()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(a.path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        let name = a.path().file_name().unwrap().to_str().unwrap().to_string();
        assert!(name.starts_with("wires-") && name.len() == 6 + 16, "{name}");
        let path = a.path().to_path_buf();
        drop(a);
        assert!(!path.exists());
        b.remove();
        b.remove();
    }

    proptest! {
        /// Whatever `--to` says, a capability admits exactly its caller's
        /// 64-hex id and nothing else.
        #[test]
        fn only_the_exact_caller_id_is_admitted(to in "[0-9a-zA-Z]{0,70}", pick in 0u8..3) {
            let caps = Arc::new(Capabilities::default());
            let cap = caps.mint(node(2), svc());
            let to = match pick {
                0 => node(2).hex(),
                1 => node(2).hex().to_uppercase(),
                _ => to,
            };
            let ok = caps.check(cap.token(), &to, Instant::now()).is_ok();
            let want = NodeId::from_hex(&to).is_ok_and(|n| n == node(2)) && to.len() == 64;
            prop_assert_eq!(ok, want);
        }
    }
}
