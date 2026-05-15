//! Wall-clock helper. Returns `0` if the system clock is before the Unix
//! epoch — callers treat it as a best-effort millisecond stamp, not a
//! monotonic source.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
