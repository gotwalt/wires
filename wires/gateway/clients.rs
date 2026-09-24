//! Who may start an authorization: the OAuth clients the gateway knows.
//!
//! Two ways in, both from the MCP authorization spec (2026-07-28):
//!
//! - **Client ID Metadata Documents** (preferred): the `client_id` is an
//!   `https` URL; the gateway fetches the JSON document there and checks
//!   that its `client_id` is that URL exactly and that the redirect URI is
//!   one it lists. Fetches are cached briefly and refused for hosts that
//!   resolve to private or loopback addresses (the gateway must not be a
//!   way to probe its own network).
//! - **Dynamic Client Registration** (RFC 7591, deprecated in 2026-07-28 but
//!   what many clients still do): `POST /register` returns a `client_id`
//!   that *is* the registration, MAC'd with the gateway's key. Nothing is
//!   stored, so a registration survives restarts and redeploys, and a
//!   forged or altered id fails the MAC.
//!
//! Every client is public (`token_endpoint_auth_method: none`): PKCE, not a
//! secret, protects the code.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Result, anyhow};
use base64::Engine as _;
use library::B64;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

/// The prefix of a DCR-issued `client_id`.
pub(crate) const DCR_PREFIX: &str = "wires-dcr.";
/// The largest metadata document the gateway reads.
pub(crate) const MAX_METADATA_BYTES: usize = 64 * 1024;
/// How long a fetched metadata document is trusted.
pub(crate) const METADATA_TTL: Duration = Duration::from_secs(300);
/// How long a metadata fetch may take.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest client name kept (characters).
pub(crate) const MAX_CLIENT_NAME: usize = 100;
/// Most redirect URIs a client may register or declare.
pub(crate) const MAX_REDIRECT_URIS: usize = 8;
/// Longest redirect URI accepted (bytes).
pub(crate) const MAX_REDIRECT_URI_LEN: usize = 1024;
/// Most metadata documents cached; the oldest is evicted past this.
pub(crate) const MAX_CACHED_METADATA: usize = 256;

/// A client the gateway will run an authorization for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Client {
    /// Its `client_id`, as presented.
    pub(crate) id: String,
    /// Its display name (shown on the consent page).
    pub(crate) name: String,
    /// Where it may receive codes.
    pub(crate) redirect_uris: Vec<Url>,
}

impl Client {
    /// Whether `uri` is one of this client's redirect URIs: an exact match,
    /// except that a loopback `http` URI may differ in port (RFC 8252 §7.3).
    pub(crate) fn allows_redirect(&self, uri: &Url) -> bool {
        self.redirect_uris.iter().any(|r| {
            r == uri
                || (r.scheme() == "http"
                    && crate::net::is_loopback(r)
                    && r.scheme() == uri.scheme()
                    && r.host_str() == uri.host_str()
                    && r.path() == uri.path()
                    && r.query() == uri.query())
        })
    }
}

/// Why a client was refused. `Display` is the OAuth `error_description`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ClientError(pub(crate) String);

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn refuse<T>(why: impl Into<String>) -> Result<T, ClientError> {
    Err(ClientError(why.into()))
}

/// A redirect URI a client may register: absolute, no fragment, and either
/// `https` or `http` on a loopback host (a native client).
pub(crate) fn valid_redirect_uri(uri: &Url) -> bool {
    uri.fragment().is_none()
        && uri.has_host()
        && (uri.scheme() == "https" || (uri.scheme() == "http" && crate::net::is_loopback(uri)))
}

/// An RFC 7591 registration request (only the fields the gateway reads).
#[derive(Debug, Deserialize)]
pub(crate) struct RegistrationRequest {
    /// Required: where codes may be sent.
    #[serde(default)]
    pub(crate) redirect_uris: Vec<String>,
    /// Optional display name.
    pub(crate) client_name: Option<String>,
}

/// The MAC'd body of a DCR `client_id`.
#[derive(Serialize, Deserialize)]
struct Registered {
    /// Display name.
    n: String,
    /// Redirect URIs.
    r: Vec<String>,
    /// Issued at, Unix seconds.
    t: i64,
}

/// The key DCR client ids are MAC'd with (HMAC-SHA256).
pub(crate) struct ClientKey(ring::hmac::Key);

impl ClientKey {
    /// A key from 32 bytes of secret.
    pub(crate) fn new(secret: &[u8; 32]) -> Self {
        Self(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret))
    }

    /// Register a client: validate `req` and mint its `client_id`.
    pub(crate) fn register(
        &self,
        req: &RegistrationRequest,
        now: i64,
    ) -> Result<Client, ClientError> {
        if req.redirect_uris.is_empty() {
            return refuse("redirect_uris is required");
        }
        if req.redirect_uris.len() > MAX_REDIRECT_URIS {
            return refuse(format!("at most {MAX_REDIRECT_URIS} redirect_uris"));
        }
        if req
            .redirect_uris
            .iter()
            .any(|u| u.len() > MAX_REDIRECT_URI_LEN)
        {
            return refuse(format!(
                "a redirect URI is longer than {MAX_REDIRECT_URI_LEN} bytes"
            ));
        }
        let mut uris = Vec::new();
        for raw in &req.redirect_uris {
            let uri =
                Url::parse(raw).map_err(|_| ClientError(format!("bad redirect URI {raw}")))?;
            if !valid_redirect_uri(&uri) {
                return refuse(format!(
                    "redirect URI {raw} must be https, or http on a loopback host"
                ));
            }
            uris.push(uri);
        }
        let name: String = req
            .client_name
            .clone()
            .filter(|n| !n.trim().is_empty())
            .map(|n| n.chars().take(MAX_CLIENT_NAME).collect())
            .unwrap_or_else(|| "an MCP client".into());
        let body = Registered {
            n: name.clone(),
            r: req.redirect_uris.clone(),
            t: now,
        };
        let body = B64.encode(serde_json::to_vec(&body).expect("serializable"));
        let mac = B64.encode(ring::hmac::sign(&self.0, body.as_bytes()));
        Ok(Client {
            id: format!("{DCR_PREFIX}{body}.{mac}"),
            name,
            redirect_uris: uris,
        })
    }

    /// The client a DCR `client_id` names, if its MAC holds.
    pub(crate) fn registered(&self, client_id: &str) -> Result<Client, ClientError> {
        let bad = || ClientError("unknown client_id".into());
        let rest = client_id.strip_prefix(DCR_PREFIX).ok_or_else(bad)?;
        let (body, mac) = rest.split_once('.').ok_or_else(bad)?;
        let mac = B64.decode(mac).map_err(|_| bad())?;
        ring::hmac::verify(&self.0, body.as_bytes(), &mac).map_err(|_| bad())?;
        let reg: Registered =
            serde_json::from_slice(&B64.decode(body).map_err(|_| bad())?).map_err(|_| bad())?;
        let redirect_uris = reg
            .r
            .iter()
            .map(|u| Url::parse(u))
            .collect::<Result<_, _>>()
            .map_err(|_| bad())?;
        Ok(Client {
            id: client_id.to_owned(),
            name: reg.n,
            redirect_uris,
        })
    }
}

/// Whether `client_id` is a metadata-document URL rather than a DCR id.
pub(crate) fn is_metadata_url(client_id: &str) -> bool {
    client_id.starts_with("https://")
}

/// Check a metadata document fetched from `url` (draft-ietf-oauth-client-id-
/// metadata-document, as the MCP spec profiles it).
pub(crate) fn validate_metadata(url: &Url, body: &[u8]) -> Result<Client, ClientError> {
    let doc: Value = serde_json::from_slice(body)
        .map_err(|_| ClientError("the client metadata document is not JSON".into()))?;
    let Some(doc) = doc.as_object() else {
        return refuse("the client metadata document is not a JSON object");
    };
    if doc.get("client_id").and_then(Value::as_str) != Some(url.as_str()) {
        return refuse("the client metadata document's client_id is not its own URL");
    }
    let Some(name) = doc
        .get("client_name")
        .and_then(Value::as_str)
        .filter(|n| !n.trim().is_empty())
    else {
        return refuse("the client metadata document has no client_name");
    };
    match doc
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
    {
        None | Some("none") => {}
        Some(other) => {
            return refuse(format!(
                "token_endpoint_auth_method {other} is not supported (public clients only)"
            ));
        }
    }
    let uris = doc
        .get("redirect_uris")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| ClientError("the client metadata document has no redirect_uris".into()))?;
    if uris.len() > MAX_REDIRECT_URIS {
        return refuse(format!(
            "the client metadata document lists more than {MAX_REDIRECT_URIS} redirect_uris"
        ));
    }
    let mut redirect_uris = Vec::new();
    for u in uris {
        let uri = u
            .as_str()
            .and_then(|s| Url::parse(s).ok())
            .filter(valid_redirect_uri)
            .ok_or_else(|| ClientError(format!("bad redirect URI {u} in the metadata document")))?;
        redirect_uris.push(uri);
    }
    Ok(Client {
        id: url.as_str().to_owned(),
        name: name.chars().take(MAX_CLIENT_NAME).collect(),
        redirect_uris,
    })
}

/// A metadata-document URL the gateway will fetch: `https`, a path beyond
/// `/`, no fragment, no credentials.
pub(crate) fn fetchable_metadata_url(client_id: &str) -> Result<Url, ClientError> {
    let url = Url::parse(client_id).map_err(|_| ClientError("bad client_id URL".into()))?;
    if url.scheme() != "https"
        || url.path() == "/"
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
    {
        return refuse("a URL client_id must be https with a path, and no fragment or credentials");
    }
    Ok(url)
}

/// Whether `ip` is on the public internet (not loopback, private, link-local,
/// CGNAT, unique-local, multicast or unspecified).
pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// Fetches and caches client metadata documents.
pub(crate) struct MetadataFetcher {
    cache: Mutex<HashMap<String, (Client, std::time::Instant)>>,
}

impl MetadataFetcher {
    /// An empty fetcher.
    pub(crate) fn new() -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Ok(Self {
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The client whose metadata document is at `client_id`.
    ///
    /// A failed fetch says only that it failed: the details (which could
    /// map the gateway's view of the network) go to the log.
    pub(crate) async fn client(&self, client_id: &str) -> Result<Client, ClientError> {
        if let Some((client, at)) = self.lock().get(client_id)
            && at.elapsed() < METADATA_TTL
        {
            return Ok(client.clone());
        }
        let url = fetchable_metadata_url(client_id)?;
        let body = self.fetch(&url).await.map_err(|e| {
            tracing::info!("gateway: client metadata {url}: {e:#}");
            ClientError("the client metadata document could not be fetched".into())
        })?;
        let client = validate_metadata(&url, &body)?;
        let mut cache = self.lock();
        cache.retain(|_, (_, at)| at.elapsed() < METADATA_TTL);
        while cache.len() >= MAX_CACHED_METADATA {
            let oldest = cache
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(k, _)| k.clone())
                .expect("non-empty");
            cache.remove(&oldest);
        }
        cache.insert(
            client_id.to_owned(),
            (client.clone(), std::time::Instant::now()),
        );
        Ok(client)
    }

    /// GET `url`, connecting only to the public addresses its host resolved
    /// to when checked: the client is pinned to them, so a second DNS answer
    /// (rebinding) can't send the request somewhere private.
    async fn fetch(&self, url: &Url) -> Result<Vec<u8>> {
        let host = url.host_str().ok_or_else(|| anyhow!("no host"))?;
        let port = url.port_or_known_default().unwrap_or(443);
        let addrs: Vec<_> = tokio::net::lookup_host((host, port)).await?.collect();
        if addrs.is_empty() || !addrs.iter().all(|a| is_public_ip(a.ip())) {
            anyhow::bail!("{host} does not resolve to public addresses only");
        }
        let http = reqwest::Client::builder()
            .user_agent(concat!("wires/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .timeout(FETCH_TIMEOUT)
            .resolve_to_addrs(host, &addrs)
            .build()?;
        let mut resp = http
            .get(url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("HTTP {}", resp.status());
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            body.extend_from_slice(&chunk);
            if body.len() > MAX_METADATA_BYTES {
                anyhow::bail!("larger than {MAX_METADATA_BYTES} bytes");
            }
        }
        Ok(body)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (Client, std::time::Instant)>> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn key() -> ClientKey {
        ClientKey::new(&[7; 32])
    }

    fn req(uris: &[&str], name: Option<&str>) -> RegistrationRequest {
        RegistrationRequest {
            redirect_uris: uris.iter().map(|s| s.to_string()).collect(),
            client_name: name.map(str::to_owned),
        }
    }

    const CLAUDE: &str = "https://claude.ai/api/mcp/auth_callback";

    #[test]
    fn a_registration_is_its_own_client_id() {
        let c = key().register(&req(&[CLAUDE], Some("Claude")), 1).unwrap();
        assert!(c.id.starts_with(DCR_PREFIX));
        assert_eq!(key().registered(&c.id), Ok(c.clone()));
        assert_eq!(c.name, "Claude");
        assert!(c.allows_redirect(&Url::parse(CLAUDE).unwrap()));
        assert!(!c.allows_redirect(&Url::parse("https://evil.example/cb").unwrap()));
    }

    #[test]
    fn a_forged_or_foreign_client_id_is_unknown() {
        let c = key().register(&req(&[CLAUDE], None), 1).unwrap();
        assert!(
            ClientKey::new(&[8; 32]).registered(&c.id).is_err(),
            "other key"
        );
        let body = B64.encode(br#"{"n":"x","r":["https://evil.example/cb"],"t":1}"#);
        let (_, mac) = c.id.rsplit_once('.').unwrap();
        let forged = format!("{DCR_PREFIX}{body}.{mac}");
        assert!(key().registered(&forged).is_err(), "swapped body");
        for junk in ["", "abc", DCR_PREFIX, "wires-dcr.x.y"] {
            assert!(key().registered(junk).is_err(), "{junk}");
        }
    }

    #[test]
    fn registrations_are_bounded() {
        let many: Vec<String> = (0..=MAX_REDIRECT_URIS)
            .map(|i| format!("https://c.example/{i}"))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(key().register(&req(&many, None), 1).is_err());
        let long = format!("https://c.example/{}", "a".repeat(MAX_REDIRECT_URI_LEN));
        assert!(key().register(&req(&[&long], None), 1).is_err());
        let name = "n".repeat(10 * MAX_CLIENT_NAME);
        let c = key().register(&req(&[CLAUDE], Some(&name)), 1).unwrap();
        assert_eq!(c.name.chars().count(), MAX_CLIENT_NAME);
    }

    #[test]
    fn registration_checks_redirect_uris() {
        assert!(key().register(&req(&[], None), 1).is_err());
        for bad in [
            "http://claude.ai/cb",
            "https://claude.ai/cb#frag",
            "not a url",
            "javascript:alert(1)",
        ] {
            assert!(key().register(&req(&[bad], None), 1).is_err(), "{bad}");
        }
        let native = key()
            .register(&req(&["http://127.0.0.1:3000/callback"], None), 1)
            .unwrap();
        assert_eq!(native.name, "an MCP client");
        assert!(native.allows_redirect(&Url::parse("http://127.0.0.1:49152/callback").unwrap()));
        assert!(!native.allows_redirect(&Url::parse("http://127.0.0.1:49152/other").unwrap()));
    }

    #[test]
    fn a_metadata_document_must_name_itself() {
        let url = Url::parse("https://claude.ai/oauth/mcp-client.json").unwrap();
        let doc = |v: Value| serde_json::to_vec(&v).unwrap();
        let good = json!({
            "client_id": url.as_str(), "client_name": "Claude",
            "redirect_uris": [CLAUDE], "token_endpoint_auth_method": "none"
        });
        let c = validate_metadata(&url, &doc(good.clone())).unwrap();
        assert_eq!(c.name, "Claude");
        assert!(c.allows_redirect(&Url::parse(CLAUDE).unwrap()));

        let mut other = good.clone();
        other["client_id"] = json!("https://evil.example/c.json");
        assert!(validate_metadata(&url, &doc(other)).is_err());
        let mut secret = good.clone();
        secret["token_endpoint_auth_method"] = json!("private_key_jwt");
        assert!(validate_metadata(&url, &doc(secret)).is_err());
        let mut no_name = good.clone();
        no_name.as_object_mut().unwrap().remove("client_name");
        assert!(validate_metadata(&url, &doc(no_name)).is_err());
        let mut no_uris = good.clone();
        no_uris["redirect_uris"] = json!([]);
        assert!(validate_metadata(&url, &doc(no_uris)).is_err());
        assert!(validate_metadata(&url, b"[]").is_err());
    }

    #[test]
    fn only_https_urls_with_a_path_are_fetched() {
        assert!(fetchable_metadata_url("https://claude.ai/oauth/client.json").is_ok());
        for bad in [
            "http://claude.ai/c.json",
            "https://claude.ai/",
            "https://claude.ai",
            "https://u:p@claude.ai/c.json",
            "https://claude.ai/c.json#x",
        ] {
            assert!(fetchable_metadata_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn private_addresses_are_not_public() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.7.6",
            "169.254.169.254",
            "100.113.142.97",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!is_public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["160.79.104.10", "8.8.8.8", "2606:4700::1111"] {
            assert!(is_public_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    proptest! {
        #[test]
        fn any_valid_registration_round_trips(
            name in "[A-Za-z0-9 ]{1,40}",
            paths in proptest::collection::vec("[a-z]{1,12}", 1..4),
        ) {
            let uris: Vec<String> =
                paths.iter().map(|p| format!("https://client.example/{p}")).collect();
            let r = RegistrationRequest { redirect_uris: uris.clone(), client_name: Some(name) };
            let c = key().register(&r, 5).unwrap();
            prop_assert_eq!(key().registered(&c.id), Ok(c.clone()));
            for u in &uris {
                prop_assert!(c.allows_redirect(&Url::parse(u).unwrap()));
            }
        }

        #[test]
        fn a_flipped_character_breaks_the_id(i in 0usize..200) {
            let c = key().register(&req(&[CLAUDE], Some("Claude")), 5).unwrap();
            let idx = DCR_PREFIX.len() + i % (c.id.len() - DCR_PREFIX.len());
            let mut bytes = c.id.clone().into_bytes();
            bytes[idx] = if bytes[idx] == b'A' { b'B' } else { b'A' };
            let tampered = String::from_utf8(bytes).unwrap();
            prop_assume!(tampered != c.id);
            prop_assert!(key().registered(&tampered).is_err());
        }
    }
}
