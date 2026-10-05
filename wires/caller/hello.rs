//! The caller's half of the handshakes: the ID token `wires login` stored,
//! which travels in each session's, inbox fetch's and directory request's
//! `hello`; and what the caller says when a host or directory answers that
//! it is not admitted ([`explain_not_admitted`]).

use base64::Engine as _;
use library::IdToken;
use serde_json::Value;

use crate::admin::keystore::Keystore;
use crate::caller::login::ID_TOKEN_FILE;
use crate::host::gate::NOT_ADMITTED;

/// The ID token `wires login` stored, if any. A missing token is not an
/// error (the host decides whether the service needs one).
pub(crate) fn stored_token(ks: &Keystore) -> Option<IdToken> {
    let text = std::fs::read_to_string(ks.path(ID_TOKEN_FILE)).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| IdToken::new(text))
}

/// The claims of an unverified compact JWS: what this caller reads from its
/// own stored token, never a basis for a decision.
pub(crate) fn unverified_claims(jws: &str) -> Option<Value> {
    let payload = jws.split('.').nth(1)?;
    let bytes = library::B64.decode(payload.trim_end_matches('=')).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// What a signed-in caller says when a host or directory answered
/// [`NOT_ADMITTED`], read from its own stored token (nothing is sent): the
/// responder tells no reason apart, but the person can act on one of these.
///
/// - no token: [`NOT_SIGNED_IN`](crate::help::NOT_SIGNED_IN);
/// - expired at `now`: sign in again;
/// - no verified email: the network admits only a verified email;
/// - otherwise: no role matches that email, or they were removed.
pub(crate) fn explain_not_admitted(token: Option<&IdToken>, now: i64) -> String {
    let Some(token) = token else {
        return format!(
            "not admitted to this network: {}",
            crate::help::NOT_SIGNED_IN
        );
    };
    let claims = unverified_claims(token.as_str()).unwrap_or(Value::Null);
    if claims
        .get("exp")
        .and_then(Value::as_i64)
        .is_some_and(|exp| now > exp)
    {
        return "not admitted to this network: your sign-in has expired; run `wires login`".into();
    }
    let verified = matches!(claims.get("email_verified"), Some(Value::Bool(true)))
        || claims.get("email_verified").and_then(Value::as_str) == Some("true");
    match claims.get("email").and_then(Value::as_str) {
        Some(email) if verified => format!(
            "not admitted to this network: no role in this network matches {email}, or you were \
             removed: ask your admin"
        ),
        _ => "not admitted to this network: your sign-in carries no verified email, and this \
              network admits only a verified email: ask your admin"
            .into(),
    }
}

/// [`explain_not_admitted`] for `ks`'s stored token, now.
pub(crate) fn explain_not_admitted_in(ks: &Keystore) -> String {
    explain_not_admitted(stored_token(ks).as_ref(), crate::clock::now_unix())
}

/// A responder's refusal `reason` as this caller says it: the
/// [`explain_not_admitted`] sentence for [`NOT_ADMITTED`], else `reason`.
pub(crate) fn say_refusal(ks: &Keystore, reason: &str) -> String {
    if reason == NOT_ADMITTED {
        explain_not_admitted_in(ks)
    } else {
        reason.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A token whose payload is `claims` (unsigned: only read here).
    fn token(claims: Value) -> IdToken {
        IdToken::new(format!(
            "e30.{}.sig",
            library::B64.encode(claims.to_string())
        ))
    }

    /// Each kind of signed-in caller hears what it can act on, and each
    /// names the next step.
    #[test]
    fn a_signed_in_caller_says_what_its_person_can_act_on() {
        let now = 1_000;
        let alice = token(serde_json::json!({
            "email": "alice@x.com", "email_verified": true, "exp": 2_000
        }));
        assert_eq!(
            explain_not_admitted(Some(&alice), now),
            "not admitted to this network: no role in this network matches alice@x.com, or you \
             were removed: ask your admin"
        );
        let unverified = token(serde_json::json!({
            "email": "alice@x.com", "email_verified": false, "exp": 2_000
        }));
        let no_email = token(serde_json::json!({"sub": "1", "exp": 2_000}));
        for t in [&unverified, &no_email] {
            assert!(
                explain_not_admitted(Some(t), now).contains("no verified email"),
                "{}",
                explain_not_admitted(Some(t), now)
            );
        }
        assert!(explain_not_admitted(Some(&alice), 3_000).contains("expired; run `wires login`"));
        assert!(explain_not_admitted(None, now).contains("run `wires login`"));
        for t in [Some(&alice), Some(&no_email), None] {
            assert!(crate::help::has_next_step(&explain_not_admitted(t, now)));
        }
        // Garbage is read as no email, never a panic.
        let junk = IdToken::new("not-a-jws");
        assert!(explain_not_admitted(Some(&junk), now).contains("no verified email"));
    }

    #[test]
    fn reads_the_stored_token_trimmed() {
        let ks = Keystore::at(crate::testutil::temp_dir());
        assert_eq!(stored_token(&ks), None);
        std::fs::write(ks.path(ID_TOKEN_FILE), "\n").unwrap();
        assert_eq!(stored_token(&ks), None);
        std::fs::write(ks.path(ID_TOKEN_FILE), "a.b.c\n").unwrap();
        assert_eq!(stored_token(&ks), Some(IdToken::new("a.b.c")));
    }
}
