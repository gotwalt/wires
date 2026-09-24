//! [`Ttl`]: a lifetime typed the way people say it, shared by every command
//! that takes one (`--ttl`, `--state-ttl`, `--timeout`).

use std::str::FromStr;

/// A lifetime typed the way people say it: `30d`, `12h`, `90m`, `45s`, `2w`,
/// or bare seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ttl(i64);

impl Ttl {
    /// The default for memberships (`init` / `invite --ttl`) and for the
    /// signed state (every edit's `--state-ttl`): long, because nothing
    /// renews them yet (card 14 notes the renewal story as a follow-up).
    pub(crate) const DEFAULT: &'static str = "30d";

    /// The expiry `now_unix + self`, saturating.
    pub(crate) fn not_after(self, now_unix: i64) -> i64 {
        now_unix.saturating_add(self.0)
    }

    /// The span as a [`Duration`](std::time::Duration) (`wires push --ttl`,
    /// `wires inbox --timeout` parse the same forms).
    pub(crate) fn duration(self) -> std::time::Duration {
        std::time::Duration::from_secs(self.0.max(0) as u64)
    }
}

impl Default for Ttl {
    /// [`Ttl::DEFAULT`].
    fn default() -> Self {
        Ttl::DEFAULT.parse().expect("the default lifetime parses")
    }
}

impl FromStr for Ttl {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (digits, unit) = match s.char_indices().last() {
            Some((i, c)) if c.is_ascii_alphabetic() => (&s[..i], c),
            _ => (s, 's'),
        };
        let n: i64 = digits
            .parse()
            .map_err(|_| format!("{s:?} is not a lifetime (try 30d, 12h, 90m or 3600)"))?;
        let unit = match unit {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            'w' => 7 * 86_400,
            other => {
                return Err(format!(
                    "unknown unit {other:?} in {s:?} (use s, m, h, d or w)"
                ));
            }
        };
        if n <= 0 {
            return Err(format!("{s:?}: a lifetime must be positive"));
        }
        n.checked_mul(unit)
            .map(Ttl)
            .ok_or_else(|| format!("{s:?} is too long"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn lifetimes_parse_the_way_people_type_them() {
        assert_eq!("30d".parse(), Ok(Ttl(30 * 86_400)));
        assert_eq!("12h".parse(), Ok(Ttl(12 * 3600)));
        assert_eq!("90m".parse(), Ok(Ttl(5400)));
        assert_eq!("45s".parse(), Ok(Ttl(45)));
        assert_eq!("2w".parse(), Ok(Ttl(14 * 86_400)));
        assert_eq!("3600".parse(), Ok(Ttl(3600)));
        for bad in ["", "d", "0d", "-1h", "3y", "1.5h", "99999999999999999w"] {
            assert!(bad.parse::<Ttl>().is_err(), "{bad:?} parsed");
        }
        assert_eq!(Ttl::default().not_after(100), 100 + 30 * 86_400);
    }

    proptest! {
        /// Every unit is a whole number of the next smaller one, so `n` of a
        /// unit is the same lifetime as `n × k` of the smaller one; and a
        /// bare number is seconds.
        #[test]
        fn units_agree_with_each_other(n in 1i64..10_000) {
            let ttl = |s: String| s.parse::<Ttl>().unwrap();
            prop_assert_eq!(ttl(format!("{n}")), ttl(format!("{n}s")));
            prop_assert_eq!(ttl(format!("{n}m")), ttl(format!("{}s", n * 60)));
            prop_assert_eq!(ttl(format!("{n}h")), ttl(format!("{}m", n * 60)));
            prop_assert_eq!(ttl(format!("{n}d")), ttl(format!("{}h", n * 24)));
            prop_assert_eq!(ttl(format!("{n}w")), ttl(format!("{}d", n * 7)));
        }
    }
}
