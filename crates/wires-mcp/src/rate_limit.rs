//! In-memory sliding-window rate limiter, per opaque source key. Used by the
//! DCR endpoint to bound anonymous client registrations per source IP.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    max: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max: usize, window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max,
            window,
        }
    }

    /// Production default for `POST /oauth/register`: 10 registrations per
    /// source IP per hour (spec §4.4).
    pub fn dcr_default() -> Self {
        Self::new(10, Duration::from_secs(3600))
    }

    /// Returns `Ok(())` if the source is under the limit (and records the
    /// event). Returns `Err(retry_after_seconds)` when the source is at the
    /// limit; the `Retry-After` value is the number of whole seconds until
    /// the oldest event in the window ages out.
    pub fn check(&self, key: &str, now: Instant) -> Result<(), u64> {
        let mut g = self.inner.lock();
        let entry = g.entry(key.to_string()).or_default();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        entry.retain(|t| *t > cutoff);
        if entry.len() >= self.max {
            let earliest = entry[0];
            let elapsed = now.saturating_duration_since(earliest);
            let retry_after = self.window.saturating_sub(elapsed).as_secs().max(1);
            return Err(retry_after);
        }
        entry.push(now);
        Ok(())
    }
}

/// Pick the source-IP key from request headers. Deployments typically place
/// `wires-mcp` behind a reverse proxy that terminates TLS and injects
/// `X-Forwarded-For`. Falls back to `X-Real-IP`, then to a single shared
/// `"unknown"` bucket — which is the correct behavior for a non-proxied
/// deployment serving a single fabric: every request is the same source.
pub fn source_ip_key(headers: &axum::http::HeaderMap) -> String {
    if let Some(h) = headers.get("x-forwarded-for")
        && let Ok(s) = h.to_str()
        && let Some(first) = s.split(',').next()
    {
        let trimmed = first.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Some(h) = headers.get("x-real-ip")
        && let Ok(s) = h.to_str()
    {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_max_then_denies_with_retry_after() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        let now = Instant::now();
        assert!(rl.check("1.2.3.4", now).is_ok());
        assert!(rl.check("1.2.3.4", now).is_ok());
        assert!(rl.check("1.2.3.4", now).is_ok());
        let err = rl.check("1.2.3.4", now).unwrap_err();
        assert!(
            (1..=60).contains(&err),
            "retry_after seconds out of band: {err}"
        );
    }

    #[test]
    fn buckets_are_keyed_independently() {
        let rl = RateLimiter::new(1, Duration::from_secs(60));
        let now = Instant::now();
        assert!(rl.check("a", now).is_ok());
        assert!(rl.check("b", now).is_ok());
        assert!(rl.check("a", now).is_err());
        assert!(rl.check("b", now).is_err());
    }

    #[test]
    fn events_age_out_of_window() {
        let rl = RateLimiter::new(1, Duration::from_millis(50));
        let now = Instant::now();
        assert!(rl.check("k", now).is_ok());
        assert!(rl.check("k", now).is_err());
        let later = now + Duration::from_millis(75);
        assert!(rl.check("k", later).is_ok());
    }

    #[test]
    fn source_ip_picks_xff_first_value() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-for", "1.2.3.4, 10.0.0.1".parse().unwrap());
        assert_eq!(source_ip_key(&h), "1.2.3.4");
    }

    #[test]
    fn source_ip_falls_back_to_real_ip() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-real-ip", "5.6.7.8".parse().unwrap());
        assert_eq!(source_ip_key(&h), "5.6.7.8");
    }

    #[test]
    fn source_ip_unknown_when_no_proxy_headers() {
        let h = axum::http::HeaderMap::new();
        assert_eq!(source_ip_key(&h), "unknown");
    }
}
