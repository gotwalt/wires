//! Small URL predicates shared by the roles.

use url::Url;

/// Whether `url`'s host is this machine: a loopback IP, or `localhost`. The
/// one case where plain `http` is allowed (OIDC endpoints, OTLP collectors,
/// OAuth redirect URIs).
pub(crate) fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_hosts() {
        for yes in ["http://127.0.0.1:1/", "http://[::1]/", "http://LocalHost/x"] {
            assert!(is_loopback(&Url::parse(yes).unwrap()), "{yes}");
        }
        for no in [
            "http://10.0.0.1/",
            "http://localhost.example/",
            "file:///tmp",
        ] {
            assert!(!is_loopback(&Url::parse(no).unwrap()), "{no}");
        }
    }
}
