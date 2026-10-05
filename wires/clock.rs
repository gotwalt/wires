//! The wall clock, in the two units the crate stamps things with.

use std::time::{SystemTime, UNIX_EPOCH};

/// Unix time now, in seconds (expiries: signed policies, freshness, ID tokens).
pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Unix time now, in milliseconds (a push's `at_ms` and expiry).
pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
