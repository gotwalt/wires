//! The caller's half of the handshakes: the ID token `wires login` stored,
//! which travels in each session's, inbox fetch's and directory request's
//! `hello`.

use library::IdToken;

use crate::admin::keystore::Keystore;
use crate::caller::login::ID_TOKEN_FILE;

/// The ID token `wires login` stored, if any. A missing token is not an
/// error (the host decides whether the service needs one).
pub(crate) fn stored_token(ks: &Keystore) -> Option<IdToken> {
    let text = std::fs::read_to_string(ks.path(ID_TOKEN_FILE)).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| IdToken::new(text))
}

#[cfg(test)]
mod tests {
    use super::*;

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
