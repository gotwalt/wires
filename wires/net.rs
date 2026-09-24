//! Small network helpers shared by the roles: URL predicates and socket
//! addresses.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

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

/// `sock` as something to dial: a wildcard bind (`0.0.0.0` / `[::]`) becomes
/// localhost on the same port, anything else is kept. What a hint for this
/// machine's own endpoint names (the hints file, the loopback tests).
pub(crate) fn dialable(sock: SocketAddr) -> SocketAddr {
    match sock {
        SocketAddr::V4(v4) if v4.ip().is_unspecified() => (Ipv4Addr::LOCALHOST, v4.port()).into(),
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => (Ipv6Addr::LOCALHOST, v6.port()).into(),
        other => other,
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

    #[test]
    fn wildcard_binds_dial_localhost() {
        let dial = |s: &str| dialable(s.parse().unwrap()).to_string();
        assert_eq!(dial("0.0.0.0:7"), "127.0.0.1:7");
        assert_eq!(dial("[::]:7"), "[::1]:7");
        assert_eq!(dial("10.0.0.1:7"), "10.0.0.1:7");
        assert_eq!(dial("[fe80::1]:7"), "[fe80::1]:7");
    }
}
