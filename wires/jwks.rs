//! OIDC discovery and JWKS fetching for ID-token verification (board card 04).
//!
//! [`library::verify_claim`] is pure: it checks a token against a [`Jwks`]
//! the caller already holds. This module is the part that holds it — it
//! resolves an issuer's discovery document
//! (`<issuer>/.well-known/openid-configuration`), fetches its `jwks_uri`, and
//! caches the key set:
//!
//! - **in memory** per [`KeyFetcher`], and
//! - **on disk** under `$WIRES_HOME/jwks/`, so a short-lived `wires tail` or
//!   a restarted responder does not refetch on every start.
//!
//! The cache TTL is the response's `Cache-Control: max-age`, clamped to
//! [`MIN_TTL`]..=[`MAX_TTL`] ([`DEFAULT_TTL`] when absent). A token whose
//! `kid` is not in the cached set triggers **one** refetch (keys rotate), at
//! most once per [`MIN_TTL`] per issuer so a stream of bogus `kid`s cannot turn
//! an observer into a request amplifier.
//!
//! **HTTPS only**, with one exception: plain `http` to a loopback host
//! (`127.0.0.1`, `::1`, `localhost`) — which is how the hermetic mock issuer
//! in the test suite is reached, and cannot leave the machine.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use library::{Audience, IdTokenError, IdentityClaim, Issuer, Jwks, Principal, verify_claim};
use serde::{Deserialize, Serialize};
use url::Url;

/// TTL used when the JWKS response carries no `max-age`.
pub(crate) const DEFAULT_TTL: i64 = 3600;
/// Shortest cache lifetime honored (and the minimum gap between forced
/// unknown-`kid` refetches).
pub(crate) const MIN_TTL: i64 = 60;
/// Longest cache lifetime honored, whatever the issuer says.
pub(crate) const MAX_TTL: i64 = 86_400;
/// Per-request HTTP timeout.
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
/// Largest discovery / JWKS / token document accepted.
const MAX_DOC_BYTES: usize = 256 * 1024;

/// The subset of an OIDC discovery document `wires` uses.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct Discovery {
    /// Must equal the issuer it was fetched for (OIDC Discovery §4.3).
    pub issuer: String,
    /// Where the browser is sent to authenticate.
    pub authorization_endpoint: Url,
    /// Where the authorization code is exchanged for tokens.
    pub token_endpoint: Url,
    /// Where the issuer's signing keys are published.
    pub jwks_uri: Url,
}

/// A cached key set and when it goes stale (unix seconds).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Cached {
    /// The issuer this set belongs to (guards against a hash collision or a
    /// hand-copied file).
    issuer: Issuer,
    /// Unix seconds after which the set must be refetched.
    expires_at: i64,
    /// The key set.
    jwks: Jwks,
}

/// Fetches and caches issuers' discovery documents and key sets.
pub(crate) struct KeyFetcher {
    /// Shared HTTP client (rustls + the ring provider).
    http: reqwest::Client,
    /// `$WIRES_HOME/jwks`, or `None` for memory-only.
    cache_dir: Option<PathBuf>,
    /// In-memory key sets.
    keys: Mutex<HashMap<Issuer, Cached>>,
    /// In-memory discovery documents.
    discovery: Mutex<HashMap<Issuer, Discovery>>,
    /// When each issuer was last force-refetched for an unknown `kid`.
    forced: Mutex<HashMap<Issuer, i64>>,
}

impl KeyFetcher {
    /// A fetcher caching on disk under `cache_dir` (created on first write).
    pub(crate) fn new(cache_dir: Option<PathBuf>) -> Result<Self> {
        Ok(Self {
            http: http_client()?,
            cache_dir,
            keys: Mutex::new(HashMap::new()),
            discovery: Mutex::new(HashMap::new()),
            forced: Mutex::new(HashMap::new()),
        })
    }

    /// The shared HTTP client, for the token exchange in `login`.
    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// The issuer's discovery document (memoized for this fetcher's life).
    pub(crate) async fn discover(&self, issuer: &Issuer) -> Result<Discovery> {
        if let Some(d) = self.discovery.lock().expect("poisoned").get(issuer) {
            return Ok(d.clone());
        }
        let url = discovery_url(issuer)?;
        let (body, _) = self.get(&url).await?;
        let doc: Discovery = serde_json::from_slice(&body)
            .with_context(|| format!("discovery document at {url} is not valid"))?;
        if doc.issuer != issuer.as_str() {
            bail!(
                "discovery document at {url} names issuer {:?}, not {:?}",
                doc.issuer,
                issuer.as_str()
            );
        }
        for endpoint in [
            &doc.authorization_endpoint,
            &doc.token_endpoint,
            &doc.jwks_uri,
        ] {
            require_secure(endpoint)?;
        }
        self.discovery
            .lock()
            .expect("poisoned")
            .insert(issuer.clone(), doc.clone());
        Ok(doc)
    }

    /// The issuer's key set, from cache when fresh. When `kid` is given and
    /// the cached set lacks it, refetch once (rate-limited per issuer).
    pub(crate) async fn keys(&self, issuer: &Issuer, kid: Option<&str>, now: i64) -> Result<Jwks> {
        let cached = self.cached(issuer, now);
        match (&cached, kid) {
            (Some(jwks), Some(kid)) if !jwks.has_kid(kid) => {
                let mut forced = self.forced.lock().expect("poisoned");
                let last = forced.get(issuer).copied();
                if last.is_some_and(|t| now - t < MIN_TTL) {
                    return Ok(jwks.clone());
                }
                forced.insert(issuer.clone(), now);
            }
            (Some(jwks), _) => return Ok(jwks.clone()),
            (None, _) => {}
        }
        self.fetch(issuer, now).await
    }

    /// Verify `claim` against its issuer's current keys.
    ///
    /// The issuer is read (unverified) from the token only to pick which keys
    /// to fetch, and must be in `trusted` — an observer never fetches from a
    /// URL an arbitrary channel member chose.
    pub(crate) async fn verify(
        &self,
        claim: &IdentityClaim,
        trusted: &[Issuer],
        audiences: &[Audience],
        now: i64,
    ) -> Result<Principal, VerifyError> {
        let issuer = claim
            .id_token
            .unverified_issuer()
            .map_err(VerifyError::from)?;
        if !trusted.contains(&issuer) {
            return Err(VerifyError::Untrusted(issuer));
        }
        let kid = claim.id_token.unverified_kid().map_err(VerifyError::from)?;
        let jwks = self
            .keys(&issuer, kid.as_deref(), now)
            .await
            .map_err(|e| VerifyError::Unavailable(format!("{e:#}")))?;
        match verify_claim(claim, &issuer, &jwks, audiences, now) {
            // Every other check passed as of its own expiry: say *who* the
            // stale claim was for, not just that it is stale.
            Err(library::Error::IdToken(IdTokenError::Expired { exp })) => {
                match verify_claim(claim, &issuer, &jwks, audiences, exp) {
                    Ok(principal) => Err(VerifyError::Expired(principal)),
                    Err(e) => Err(e.into()),
                }
            }
            other => other.map_err(VerifyError::from),
        }
    }

    /// A fresh cached set from memory, else disk.
    fn cached(&self, issuer: &Issuer, now: i64) -> Option<Jwks> {
        let mut mem = self.keys.lock().expect("poisoned");
        if let Some(c) = mem.get(issuer)
            && c.expires_at > now
        {
            return Some(c.jwks.clone());
        }
        let c = self.read_disk(issuer)?;
        if c.issuer != *issuer || c.expires_at <= now {
            return None;
        }
        let jwks = c.jwks.clone();
        mem.insert(issuer.clone(), c);
        Some(jwks)
    }

    /// Fetch the key set over the network and cache it.
    async fn fetch(&self, issuer: &Issuer, now: i64) -> Result<Jwks> {
        let doc = self.discover(issuer).await?;
        let (body, max_age) = self.get(&doc.jwks_uri).await?;
        let text = std::str::from_utf8(&body).context("JWKS is not UTF-8")?;
        let jwks = Jwks::from_json(text)
            .with_context(|| format!("JWKS at {} is not valid", doc.jwks_uri))?;
        let ttl = max_age.unwrap_or(DEFAULT_TTL).clamp(MIN_TTL, MAX_TTL);
        let cached = Cached {
            issuer: issuer.clone(),
            expires_at: now + ttl,
            jwks: jwks.clone(),
        };
        self.write_disk(&cached);
        self.keys
            .lock()
            .expect("poisoned")
            .insert(issuer.clone(), cached);
        Ok(jwks)
    }

    /// GET `url` (HTTPS or loopback only); body plus `Cache-Control` max-age.
    async fn get(&self, url: &Url) -> Result<(Vec<u8>, Option<i64>)> {
        require_secure(url)?;
        let resp = self
            .http
            .get(url.clone())
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        let status = resp.status();
        if !status.is_success() {
            bail!("GET {url}: HTTP {status}");
        }
        let max_age = resp
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_max_age);
        let body = resp.bytes().await.with_context(|| format!("GET {url}"))?;
        if body.len() > MAX_DOC_BYTES {
            bail!("GET {url}: document larger than {MAX_DOC_BYTES} bytes");
        }
        Ok((body.to_vec(), max_age))
    }

    /// The on-disk cache file for `issuer`.
    fn disk_path(&self, issuer: &Issuer) -> Option<PathBuf> {
        let digest = ring::digest::digest(&ring::digest::SHA256, issuer.as_str().as_bytes());
        let name = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref());
        Some(self.cache_dir.as_ref()?.join(format!("{name}.json")))
    }

    /// Read a cache file; any problem is a miss, never an error.
    fn read_disk(&self, issuer: &Issuer) -> Option<Cached> {
        let text = std::fs::read_to_string(self.disk_path(issuer)?).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Write a cache file; failures are logged and ignored (the memory cache
    /// still holds the set).
    fn write_disk(&self, cached: &Cached) {
        let Some(path) = self.disk_path(&cached.issuer) else {
            return;
        };
        let write = || -> Result<()> {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, serde_json::to_vec(cached)?)?;
            std::fs::rename(&tmp, &path)?;
            Ok(())
        };
        if let Err(e) = write() {
            tracing::debug!(path = %path.display(), "jwks cache not written: {e:#}");
        }
    }
}

/// Why an identity claim could not be shown as verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerifyError {
    /// The token's issuer is not one this reader trusts.
    Untrusted(Issuer),
    /// The issuer's keys could not be fetched (network, bad document).
    Unavailable(String),
    /// Verification ran and failed; the variant says which check.
    Rejected(IdTokenError),
    /// Every check passes except freshness: the token was valid for this
    /// principal until [`Principal::not_after`].
    Expired(Principal),
}

impl From<library::Error> for VerifyError {
    fn from(e: library::Error) -> Self {
        match e {
            library::Error::IdToken(e) => VerifyError::Rejected(e),
            // `verify_claim` only fails with `IdToken`; anything else is a
            // local problem, not a verdict on the token.
            other => VerifyError::Unavailable(other.to_string()),
        }
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Untrusted(iss) => write!(
                f,
                "issuer {:?} is not trusted here (add it to WIRES_OIDC_ISSUER)",
                iss.as_str()
            ),
            VerifyError::Unavailable(e) => write!(f, "issuer keys unavailable: {e}"),
            VerifyError::Rejected(e) => write!(f, "{e}"),
            VerifyError::Expired(p) => write!(f, "expired at {}", p.not_after),
        }
    }
}

/// `<issuer>/.well-known/openid-configuration` (OIDC Discovery §4).
pub(crate) fn discovery_url(issuer: &Issuer) -> Result<Url> {
    let base = issuer.as_str().trim_end_matches('/');
    let url = Url::parse(&format!("{base}/.well-known/openid-configuration"))
        .with_context(|| format!("issuer {:?} is not a URL", issuer.as_str()))?;
    require_secure(&url)?;
    Ok(url)
}

/// Refuse anything but `https`, except `http` to a loopback host.
pub(crate) fn require_secure(url: &Url) -> Result<()> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback(url) => Ok(()),
        other => Err(anyhow!(
            "refusing {other}:// URL {url}: OIDC endpoints must be https (http is allowed only to \
             a loopback host)"
        )),
    }
}

/// Whether `url`'s host is the local machine.
pub(crate) fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

/// `max-age=N` from a `Cache-Control` value (`no-store` / `no-cache` → 0).
pub(crate) fn parse_max_age(value: &str) -> Option<i64> {
    let mut out = None;
    for directive in value.split(',').map(str::trim) {
        let lower = directive.to_ascii_lowercase();
        if lower == "no-store" || lower == "no-cache" {
            return Some(0);
        }
        if let Some(n) = lower.strip_prefix("max-age=") {
            out = n.trim_matches('"').parse::<i64>().ok();
        }
    }
    out
}

/// A reqwest client on rustls with the `ring` provider.
///
/// iroh builds reqwest with `rustls-no-provider`, so a process-wide rustls
/// provider must be installed before the first client; installing is
/// idempotent (a second install is a harmless `Err`).
pub(crate) fn http_client() -> Result<reqwest::Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent(concat!("wires/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building the HTTP client")
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn only_https_or_loopback_http_is_allowed() {
        for ok in [
            "https://accounts.google.com/x",
            "http://127.0.0.1:8080/x",
            "http://[::1]/x",
            "http://localhost:1/x",
        ] {
            require_secure(&Url::parse(ok).unwrap()).unwrap();
        }
        for bad in [
            "http://accounts.google.com/x",
            "http://10.0.0.1/x",
            "ftp://127.0.0.1/x",
            "http://localhost.evil.example/x",
        ] {
            assert!(require_secure(&Url::parse(bad).unwrap()).is_err(), "{bad}");
        }
    }

    #[test]
    fn discovery_url_appends_the_well_known_path() {
        assert_eq!(
            discovery_url(&Issuer::new("https://accounts.google.com"))
                .unwrap()
                .as_str(),
            "https://accounts.google.com/.well-known/openid-configuration"
        );
        assert_eq!(
            discovery_url(&Issuer::new("https://idp.example/tenant/"))
                .unwrap()
                .as_str(),
            "https://idp.example/tenant/.well-known/openid-configuration"
        );
        assert!(discovery_url(&Issuer::new("http://idp.example")).is_err());
    }

    #[test]
    fn cache_control_max_age_is_parsed() {
        assert_eq!(
            parse_max_age("public, max-age=21600, must-revalidate"),
            Some(21600)
        );
        assert_eq!(parse_max_age("Max-Age=\"5\""), Some(5));
        assert_eq!(parse_max_age("no-store"), Some(0));
        assert_eq!(parse_max_age("public"), None);
    }

    proptest! {
        /// Any max-age round-trips, whatever surrounds it.
        #[test]
        fn max_age_round_trips(n in 0i64..=10_000_000, pre in "[a-z-]{0,10}") {
            let header = format!("{pre}, max-age={n}, private");
            let got = parse_max_age(&header);
            if pre == "no-store" || pre == "no-cache" {
                prop_assert_eq!(got, Some(0));
            } else {
                prop_assert_eq!(got, Some(n));
            }
        }
    }

    #[test]
    fn a_fresh_disk_cache_is_used_and_a_stale_one_is_not() {
        let dir = crate::ipc::ScratchDir::new("jwks");
        let issuer = Issuer::new("https://idp.example");
        let a = KeyFetcher::new(Some(dir.path().to_path_buf())).unwrap();
        let jwks = Jwks::from_json(r#"{"keys":[{"kty":"EC","kid":"k"}]}"#).unwrap();
        a.write_disk(&Cached {
            issuer: issuer.clone(),
            expires_at: 1_000,
            jwks: jwks.clone(),
        });
        // A new fetcher (a restarted process) sees it until it expires.
        let b = KeyFetcher::new(Some(dir.path().to_path_buf())).unwrap();
        assert_eq!(b.cached(&issuer, 999), Some(jwks));
        let c = KeyFetcher::new(Some(dir.path().to_path_buf())).unwrap();
        assert_eq!(c.cached(&issuer, 1_000), None);
        // Another issuer's file is not mistaken for this one.
        assert_eq!(c.cached(&Issuer::new("https://other.example"), 0), None);
    }
}
